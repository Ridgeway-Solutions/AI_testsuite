"""Anthropic Messages API target."""

from __future__ import annotations

import os
import time
from typing import Any

from ..registry import register_target
from ..types import Conversation, Response, Role
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


@register_target("anthropic")
class AnthropicTarget(Target):
    capabilities = {CAP_SYSTEM_PROMPT, CAP_MULTI_TURN, CAP_ASSISTANT_PREFILL, CAP_SEEDING}

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self.base_url = options.get("base_url", "https://api.anthropic.com/v1").rstrip("/")
        self.model = options.get("model", "claude-sonnet-5")
        self.api_key = options.get("api_key") or os.environ.get(
            options.get("api_key_env", "ANTHROPIC_API_KEY"), ""
        )
        self.max_tokens = options.get("max_tokens", 512)
        self.temperature = options.get("temperature", 0.0)
        self.timeout = options.get("timeout", 60.0)
        self.version = options.get("anthropic_version", "2023-06-01")

    async def send(self, conversation: Conversation) -> Response:
        system_parts: list[str] = []
        if self.system_prompt:
            system_parts.append(self.system_prompt)
        messages: list[dict[str, Any]] = []
        for turn in conversation.turns:
            if turn.role is Role.SYSTEM:
                system_parts.append(turn.content)
            else:
                # The Messages API accepts only user/assistant; tool output is
                # replayed as a user turn so indirect-injection probes still work.
                role = "assistant" if turn.role is Role.ASSISTANT else "user"
                messages.append({"role": role, "content": turn.content})

        messages = _merge_consecutive(messages)
        if messages and messages[-1]["role"] == "assistant":
            # The API rejects trailing whitespace on a prefill turn outright.
            messages[-1]["content"] = messages[-1]["content"].rstrip()

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        headers = {"x-api-key": self.api_key, "anthropic-version": self.version}
        headers.update(self.options.get("headers", {}))
        started = time.perf_counter()
        try:
            body, latency = await http_post_json(
                f"{self.base_url}/messages", payload, headers, self.timeout
            )
        except Exception as exc:  # noqa: BLE001
            return error_response(exc, started)

        blocks = body.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        return Response(
            text=text,
            raw={"stop_reason": dig(body, "stop_reason"), "usage": body.get("usage")},
            latency_ms=latency,
        )


def _merge_consecutive(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The API rejects two turns in a row from the same role; fold them."""
    merged: list[dict[str, Any]] = []
    for msg in messages:
        if merged and merged[-1]["role"] == msg["role"]:
            merged[-1]["content"] += "\n\n" + msg["content"]
        else:
            merged.append(dict(msg))
    return merged
