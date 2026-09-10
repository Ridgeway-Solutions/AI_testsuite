"""Generic JSON-over-HTTP target for a bespoke application endpoint.

Most real apps are not an OpenAI-shaped API — they expose something like
``POST /api/chat {"message": ..., "conversation_id": ...}``. Describe that shape
in YAML and this adapter fills it in::

    type: http
    url: https://staging.example.com/api/chat
    headers: { Authorization: "Bearer ${APP_TOKEN}" }
    body:
      message: "{{prompt}}"
      history: "{{messages}}"
      conversation_id: "{{session_id}}"
    response_path: data.reply
    blocked_path: data.guardrail_triggered
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from ..registry import register_target
from ..types import Conversation, Response
from .base import (
    CAP_MULTI_TURN,
    CAP_SEEDING,
    CAP_SYSTEM_PROMPT,
    Target,
    dig,
    error_response,
    http_post_json,
)


@register_target("http")
class HttpJsonTarget(Target):
    capabilities = {CAP_MULTI_TURN}

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self.url = options["url"]
        self.body_template: Any = options.get("body", {"messages": "{{messages}}"})
        self.response_path = options.get("response_path", "choices.0.message.content")
        self.blocked_path = options.get("blocked_path")
        self.timeout = options.get("timeout", 60.0)
        if options.get("supports_system_prompt"):
            # If the endpoint takes our system prompt, we can seed a canary into
            # it — so the confidentiality objectives become testable here.
            self.capabilities = self.capabilities | {CAP_SYSTEM_PROMPT, CAP_SEEDING}

    async def send(self, conversation: Conversation) -> Response:
        messages = self._with_system(conversation)
        ctx = {
            "prompt": conversation.last_user_content,
            "messages": messages,
            "session_id": conversation.meta.get("session_id") or uuid.uuid4().hex,
        }
        payload = _fill(self.body_template, ctx)
        started = time.perf_counter()
        try:
            body, latency = await http_post_json(
                self.url, payload, self.options.get("headers", {}), self.timeout
            )
        except Exception as exc:  # noqa: BLE001
            return error_response(exc, started)

        text = dig(body, self.response_path)
        if text is None:
            return Response(
                text="",
                raw=body,
                latency_ms=latency,
                error=f"response_path {self.response_path!r} not found in response",
            )
        blocked = bool(dig(body, self.blocked_path)) if self.blocked_path else False
        return Response(
            text=text if isinstance(text, str) else str(text),
            raw=body,
            latency_ms=latency,
            blocked=blocked,
        )


def _fill(node: Any, ctx: dict[str, Any]) -> Any:
    """Substitute {{placeholders}} through a nested body template.

    A string that is *exactly* a placeholder is replaced by the raw value (so
    ``"{{messages}}"`` becomes a list, not its repr); otherwise it interpolates
    as text.
    """
    if isinstance(node, dict):
        return {k: _fill(v, ctx) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill(v, ctx) for v in node]
    if isinstance(node, str):
        stripped = node.strip()
        for key, value in ctx.items():
            if stripped == "{{%s}}" % key:
                return value
        for key, value in ctx.items():
            if isinstance(value, str):
                node = node.replace("{{%s}}" % key, value)
        return node
    return node
