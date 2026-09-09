"""Any OpenAI-compatible /chat/completions endpoint.

Covers OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio, OpenRouter, Together and
most self-hosted gateways — point ``base_url`` at yours.
"""

from __future__ import annotations

import os
import time
from typing import Any

from ..registry import register_target
from ..types import Conversation, Response
from .base import (
    CAP_ASSISTANT_PREFILL,
    CAP_MULTI_TURN,
    CAP_SEEDING,
    CAP_SYSTEM_PROMPT,
    Target,
    dig,
    error_response,
    http_post_json,
)


@register_target("openai")
class OpenAICompatTarget(Target):
    # Assistant prefill is NOT a /chat/completions feature: a trailing assistant
    # message starts a new turn rather than being continued, so a "prefill" here
    # measures something else entirely. Servers that do support continuation
    # (vLLM's continue_final_message, some gateways) opt in with
    # `supports_prefill: true`.
    capabilities = {CAP_SYSTEM_PROMPT, CAP_MULTI_TURN, CAP_SEEDING}

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        if options.get("supports_prefill"):
            self.capabilities = self.capabilities | {CAP_ASSISTANT_PREFILL}
        self.base_url = options.get("base_url", "https://api.openai.com/v1").rstrip("/")
        self.model = options.get("model", "gpt-4o-mini")
        self.api_key = options.get("api_key") or os.environ.get(
            options.get("api_key_env", "OPENAI_API_KEY"), ""
        )
        self.temperature = options.get("temperature", 0.0)
        self.max_tokens = options.get("max_tokens", 512)
        self.timeout = options.get("timeout", 60.0)
        self.extra_body: dict[str, Any] = options.get("extra_body", {})

    async def send(self, conversation: Conversation) -> Response:
        payload = {
            "model": self.model,
            "messages": self._with_system(conversation),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            **self.extra_body,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        headers.update(self.options.get("headers", {}))
        started = time.perf_counter()
        try:
            body, latency = await http_post_json(
                f"{self.base_url}/chat/completions", payload, headers, self.timeout
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as an errored attempt
            return error_response(exc, started)

        finish = dig(body, "choices.0.finish_reason")
        # Providers signal their own moderation layer here.
        blocked = finish in {"content_filter", "safety"}
        text = dig(body, "choices.0.message.content")
        if text is None and not blocked:
            # A null content with no block reason is a broken response, not an
            # empty answer. Scoring it as one makes the model look silent —
            # which the refusal detector reads as a confident over-refusal.
            return Response(
                text="",
                raw={"finish_reason": finish},
                latency_ms=latency,
                error=f"response contained no content (finish_reason={finish!r})",
            )
        return Response(
            text=text if isinstance(text, str) else ("" if text is None else str(text)),
            raw={"finish_reason": finish, "usage": body.get("usage")},
            latency_ms=latency,
            blocked=blocked,
        )
