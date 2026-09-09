"""Target adapters: the system under test.

A Target hides whatever sits between us and the model — a chat endpoint, an
agent with tools, a support bot behind a WAF. Attacks never see the transport;
they build a :class:`Conversation` and the target decides how to deliver it.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from ..types import Conversation, Response, Role, Turn
from ..util import redact_tree, safe_url

# Capability flags an attack can require. A suite silently skips attacks whose
# requirements the configured target cannot satisfy (reported as "skipped").
CAP_SYSTEM_PROMPT = "system_prompt"
CAP_MULTI_TURN = "multi_turn"
CAP_ASSISTANT_PREFILL = "assistant_prefill"
CAP_TOOLS = "tools"
CAP_SEEDING = "seeding"  # harness may inject its own system prompt / canary

# Turn.meta is our own bookkeeping. Only these keys mean anything to a provider,
# and only on a tool turn — everything else must be stripped before the request,
# or strict APIs reject the whole call with a 400.
PROVIDER_META_KEYS = frozenset({"name", "tool_call_id"})

# Target options that are safe to publish in a report, by name. This is an
# allowlist on purpose: a denylist cannot anticipate where an operator puts a
# secret — nested inside a body template, in an `extra_body`, in a shell
# command's argv — and reports are written to be shared. Anything not listed is
# reported as present-but-withheld rather than echoed.
PUBLIC_OPTION_KEYS = frozenset({
    "model", "profile", "response_path", "blocked_path", "temperature",
    "max_tokens", "timeout", "anthropic_version", "api_key_env",
    "supports_system_prompt", "supports_prefill", "prompt_arg", "cwd",
})
# Shown, but with userinfo and query string stripped.
URL_OPTION_KEYS = frozenset({"url", "base_url"})

# Schemes http_post_json will talk. urllib's default opener also handles
# file:, ftp: and data:, which are not endpoints and would turn a mistyped
# target into a local file read reported as model output.
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


class TargetError(RuntimeError):
    """Transport-level failure; the runner retries these."""


class Target(ABC):
    """Base class for everything under test."""

    id: str = "base"
    capabilities: set[str] = {CAP_MULTI_TURN}

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.name: str = options.get("name", self.id)
        # Prepended to every conversation when the target supports it. Used to
        # install canaries and app-like policies against a bare model endpoint.
        self.system_prompt: str | None = options.get("system_prompt")

    @abstractmethod
    async def send(self, conversation: Conversation) -> Response:
        """Deliver the conversation and return what the target said."""

    def supports(self, caps: set[str]) -> bool:
        return caps.issubset(self.capabilities)

    async def aclose(self) -> None:
        """Release transport resources. Safe to call more than once."""

    # -- helpers for subclasses -------------------------------------------------

    def _message(self, turn: Turn) -> dict[str, Any]:
        """One turn as a provider-shaped message.

        ``Turn.meta`` is deliberately not passed through: it carries harness
        bookkeeping that strict endpoints reject as an unknown property, which
        would fail the request rather than test the target.
        """
        msg: dict[str, Any] = {"role": turn.role.value, "content": turn.content}
        if turn.role is Role.TOOL and CAP_TOOLS in self.capabilities:
            msg.update({k: v for k, v in turn.meta.items() if k in PROVIDER_META_KEYS})
        return msg

    def _with_system(self, conversation: Conversation) -> list[dict[str, Any]]:
        """Conversation as provider-style dicts, with the configured system prompt."""
        msgs = [self._message(t) for t in conversation.turns]
        has_system = any(m["role"] == Role.SYSTEM.value for m in msgs)
        if self.system_prompt and not has_system:
            msgs.insert(0, {"role": Role.SYSTEM.value, "content": self.system_prompt})
        return msgs

    def describe(self) -> dict[str, Any]:
        """Metadata for the report header, with credentials withheld.

        Only allowlisted option names are echoed; URLs are stripped of
        userinfo and query string; everything else is named but not shown, so
        the reader can still see how the target was configured without the
        report carrying the operator's secrets.
        """
        shown: dict[str, Any] = {}
        withheld: list[str] = []
        for key, value in self.options.items():
            if key in URL_OPTION_KEYS and isinstance(value, str):
                shown[key] = safe_url(value)
            elif key in PUBLIC_OPTION_KEYS:
                shown[key] = value
            elif key != "name":
                withheld.append(key)

        described = {
            "type": self.id,
            "name": self.name,
            "capabilities": sorted(self.capabilities),
            "options": shown,
            "options_withheld": sorted(withheld),
        }
        # Belt and braces: an allowlisted value could still quote a secret.
        return redact_tree(described)


async def http_post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> tuple[dict[str, Any], float]:
    """POST JSON and return (decoded body, latency ms).

    Uses urllib in a worker thread so the package has no runtime HTTP
    dependency; proxy settings are picked up from the environment as usual.
    """

    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise TargetError(
            f"refusing to request {scheme or 'scheme-less'} URL: targets must be "
            f"http or https, got {safe_url(url)}"
        )

    body = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", **(headers or {})}

    def _call() -> tuple[dict[str, Any], float]:
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:800]
            raise TargetError(f"HTTP {exc.code} from {url}: {detail}") from None
        except urllib.error.URLError as exc:
            raise TargetError(f"connection error for {url}: {exc.reason}") from None
        latency = (time.perf_counter() - started) * 1000
        try:
            return json.loads(raw), latency
        except json.JSONDecodeError:
            raise TargetError(f"non-JSON response from {url}: {raw[:400]}") from None

    return await asyncio.to_thread(_call)


def dig(data: Any, path: str, default: Any = None) -> Any:
    """Look up a dotted path with numeric segments for lists.

    ``dig(body, "choices.0.message.content")`` — enough for every chat API
    shape we have met, without pulling in a JSONPath dependency.
    """
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default
        elif isinstance(cur, dict):
            if part not in cur:
                return default
            cur = cur[part]
        else:
            return default
    return cur


def error_response(exc: BaseException, started: float) -> Response:
    return Response(
        text="",
        error=f"{type(exc).__name__}: {exc}",
        latency_ms=(time.perf_counter() - started) * 1000,
    )
