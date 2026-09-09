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
    capabilities = {CAP_SYSTEM_PROMPT, CAP_MULTI_TURN, CAP_ASSISTANT_PREFILL, CAP_SEEDING}

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
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

        text = dig(body, "choices.0.message.content") or ""
        finish = dig(body, "choices.0.finish_reason")
        return Response(
            text=text if isinstance(text, str) else str(text),
            raw={"finish_reason": finish, "usage": body.get("usage")},
            latency_ms=latency,
            # Providers signal their own moderation layer here.
            blocked=finish in {"content_filter", "safety"},
        )
