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
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from ..types import Conversation, Response, Role

# Capability flags an attack can require. A suite silently skips attacks whose
# requirements the configured target cannot satisfy (reported as "skipped").
CAP_SYSTEM_PROMPT = "system_prompt"
CAP_MULTI_TURN = "multi_turn"
CAP_ASSISTANT_PREFILL = "assistant_prefill"
CAP_TOOLS = "tools"
CAP_SEEDING = "seeding"  # harness may inject its own system prompt / canary


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

    def _with_system(self, conversation: Conversation) -> list[dict[str, Any]]:
        """Conversation as provider-style dicts, with the configured system prompt."""
        msgs = [t.to_dict() for t in conversation.turns]
        has_system = any(m["role"] == Role.SYSTEM.value for m in msgs)
        if self.system_prompt and not has_system:
            msgs.insert(0, {"role": Role.SYSTEM.value, "content": self.system_prompt})
        return msgs

    def describe(self) -> dict[str, Any]:
        """Metadata for the report header. Never includes credentials."""
        safe = {
            k: v
            for k, v in self.options.items()
            if k not in {"api_key", "headers", "token", "auth"}
        }
        return {
            "type": self.id,
            "name": self.name,
            "capabilities": sorted(self.capabilities),
            "options": safe,
        }


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
