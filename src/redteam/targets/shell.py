"""Drive a local CLI application as the target.

For agents and chat apps that are easiest to reach through their own binary::

    type: shell
    command: ["python", "-m", "myapp.chat", "--json"]
    prompt_arg: null      # null => prompt is written to stdin
    response_path: reply  # omit to use raw stdout
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from ..registry import register_target
from ..types import Conversation, Response, Role
from .base import CAP_MULTI_TURN, Target, dig, error_response


@register_target("shell")
class ShellTarget(Target):
    capabilities = {CAP_MULTI_TURN}

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self.command: list[str] = list(options["command"])
        self.prompt_arg: str | None = options.get("prompt_arg")
        self.response_path: str | None = options.get("response_path")
        self.timeout = options.get("timeout", 120.0)
        self.cwd = options.get("cwd")

    async def send(self, conversation: Conversation) -> Response:
        prompt = _render_transcript(conversation, self.system_prompt)
        argv = list(self.command)
        stdin_data = b""
        if self.prompt_arg:
            argv += [self.prompt_arg, prompt]
        else:
            stdin_data = prompt.encode()

        started = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cwd,
            )
        except Exception as exc:  # noqa: BLE001
            return error_response(exc, started)

        try:
            out, err = await asyncio.wait_for(proc.communicate(stdin_data), self.timeout)
        except asyncio.TimeoutError:
            # wait_for only cancels the read; the child keeps running. Over a
            # few hundred attempts that is a few hundred orphaned processes.
            await _terminate(proc)
            return Response(
                text="",
                latency_ms=(time.perf_counter() - started) * 1000,
                error=f"target did not respond within {self.timeout}s (process killed)",
            )
        except Exception as exc:  # noqa: BLE001
            await _terminate(proc)
            return error_response(exc, started)

        latency = (time.perf_counter() - started) * 1000
        text = out.decode("utf-8", "replace").strip()
        if proc.returncode != 0 and not text:
            return Response(
                text="",
                latency_ms=latency,
                error=f"exit {proc.returncode}: {err.decode('utf-8', 'replace')[:400]}",
            )
        if self.response_path:
            try:
                text = str(dig(json.loads(text), self.response_path, ""))
            except json.JSONDecodeError:
                return Response(text="", latency_ms=latency, error="stdout was not JSON")
        return Response(text=text, latency_ms=latency)


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Terminate, then kill if it will not go, and always reap."""
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    except ProcessLookupError:
        pass


def _render_transcript(conversation: Conversation, system_prompt: str | None = None) -> str:
    """Flatten multi-turn history for CLIs that take a single string.

    The configured system prompt is prepended; without it the target under test
    is not the one the operator deployed.
    """
    parts = []
    if system_prompt and not any(t.role is Role.SYSTEM for t in conversation.turns):
        parts.append(f"[system] {system_prompt}")
    if not parts and len(conversation.turns) == 1:
        return conversation.turns[0].content
    parts += [f"[{t.role.value}] {t.content}" for t in conversation.turns]
    return "\n\n".join(parts)
