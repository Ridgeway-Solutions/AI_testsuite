"""Orchestration: run every (attack × objective) pair against the target.

Concurrency is bounded at the request level rather than the pair level, so a
long adaptive attack does not monopolise the budget, and a shared rate limiter
keeps the whole run inside whatever the target will tolerate. Results stream to
disk as they land, so an interrupted scan still leaves usable evidence.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .attacks.base import Attack, AttackContext
from .config import SuiteConfig
from .detectors.base import JudgeContext, judge_all
from .objectives import filter_objectives, load_objectives
from .registry import available, get, load_plugins
from .scoring import Scoreboard, score
from .targets.base import CAP_SEEDING, Target
from .types import Attempt, Conversation, Objective, Response
from .util import RateLimiter, redact, stable_rng

EventHook = Callable[[str, dict[str, Any]], None]


@dataclass
class Skip:
    attack_id: str
    objective_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"attack": self.attack_id, "objective": self.objective_id, "reason": self.reason}


@dataclass
class RunResult:
    config: SuiteConfig
    target_info: dict[str, Any]
    attempts: list[Attempt] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    objectives: list[Objective] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    stopped_early: bool = False

    @property
    def duration_s(self) -> float:
        return max(0.0, (self.finished_at or time.time()) - self.started_at)

    def scoreboard(self) -> Scoreboard:
        board = score(self.attempts)
        return board


def build_target(spec: dict[str, Any]) -> Target:
    spec = dict(spec)
    kind = spec.pop("type", "mock")
    return get("target", kind)(**spec)


def select_attacks(names: Iterable[str]) -> list[Attack]:
    names = list(names)
    table = available("attack")
    if not names or "all" in names:
        chosen = list(table)
    else:
        chosen = []
        for name in names:
            if name not in table:
                raise KeyError(
                    f"unknown attack {name!r}. Available: {', '.join(sorted(table))}"
                )
            chosen.append(name)
    return [table[name]() for name in chosen]


class Runner:
    def __init__(
        self,
        config: SuiteConfig,
        target: Target | None = None,
        objectives: list[Objective] | None = None,
        attacks: list[Attack] | None = None,
        on_event: EventHook | None = None,
        stream_path: Path | None = None,
    ) -> None:
        load_plugins(config.plugins)
        self.config = config
        self.settings = config.run
        self.target = target or build_target(config.target)
        self.attacks = attacks if attacks is not None else select_attacks(config.attacks)
        self.objectives = objectives if objectives is not None else filter_objectives(
            load_objectives(config.resolve_objectives_file()),
            ids=config.include_objectives,
            categories=config.categories,
            tags=config.tags,
        )
        self.on_event = on_event or (lambda kind, payload: None)
        self.stream_path = stream_path
        self._limiter = RateLimiter(self.settings.rate_limit_rps)
        self._sem = asyncio.Semaphore(max(1, self.settings.concurrency))
        self._stop = asyncio.Event()
        self._criticals = 0
        self._stream = None

    # -- planning ---------------------------------------------------------------

    def plan(self) -> tuple[list[tuple[Attack, Objective]], list[Skip]]:
        """Decide what will actually run, and why the rest will not."""
        pairs: list[tuple[Attack, Objective]] = []
        skips: list[Skip] = []
        caps = self.target.capabilities
        seeded = CAP_SEEDING in caps and bool(self.target.system_prompt)
        for attack in self.attacks:
            for objective in self.objectives:
                if objective.only_attacks and attack.id not in objective.only_attacks:
                    skips.append(
                        Skip(
                            attack.id,
                            objective.id,
                            "objective is scoped to specific techniques "
                            f"({', '.join(objective.only_attacks)})",
                        )
                    )
                    continue
                if not attack.requires.issubset(caps):
                    missing = sorted(attack.requires - caps)
                    skips.append(Skip(attack.id, objective.id, f"target lacks {missing}"))
                    continue
                if objective.requires_seed and not seeded:
                    skips.append(
                        Skip(
                            attack.id,
                            objective.id,
                            "objective needs a harness-seeded system prompt "
                            "(set target.system_prompt, or use a target you control)",
                        )
                    )
                    continue
                pairs.append((attack, objective))
        return pairs, skips

    # -- execution --------------------------------------------------------------

    async def run(self) -> RunResult:
        pairs, skips = self.plan()
        result = RunResult(
            config=self.config,
            target_info=self.target.describe(),
            skipped=skips,
            objectives=list(self.objectives),
        )
        self.on_event("run_start", {
            "pairs": len(pairs),
            "attacks": len(self.attacks),
            "objectives": len(self.objectives),
            "skipped": len(skips),
            "target": result.target_info,
        })

        if self.stream_path:
            self.stream_path.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.stream_path.open("w", encoding="utf-8")

        try:
            tasks = [
                asyncio.create_task(self._run_pair(attack, objective, result))
                for attack, objective in pairs
            ]
            if tasks:
                await asyncio.gather(*tasks)
        finally:
            if self._stream:
                self._stream.close()
                self._stream = None
            await self.target.aclose()

        result.finished_at = time.time()
        result.stopped_early = self._stop.is_set()
        self.on_event("run_end", {
            "attempts": len(result.attempts),
            "duration_s": round(result.duration_s, 2),
            "stopped_early": result.stopped_early,
        })
        return result

    async def _run_pair(self, attack: Attack, objective: Objective, result: RunResult) -> None:
        ctx = AttackContext(
            objective=objective,
            rng=stable_rng(self.settings.seed, attack.id, objective.id),
            send=lambda conv: self._execute(attack, objective, conv, result),
            max_turns=self.settings.max_turns,
            target_capabilities=set(self.target.capabilities),
        )
        try:
            async for _ in attack.run(ctx):
                if self._stop.is_set():
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad attack must not kill the run
            self.on_event("attack_error", {
                "attack": attack.id, "objective": objective.id, "error": repr(exc),
            })

    async def _execute(
        self, attack: Attack, objective: Objective, conversation: Conversation, result: RunResult
    ) -> Attempt:
        response = await self._send_with_retries(conversation)
        verdicts = await judge_all(
            objective.detectors,
            JudgeContext(
                objective=objective,
                conversation=conversation,
                response=response,
                system_prompt=self.target.system_prompt,
                canary=getattr(self.target, "canary", None)
                or self.target.options.get("canary"),
            ),
        )
        attempt = Attempt(
            attack_id=attack.id,
            objective_id=objective.id,
            conversation=conversation,
            response=response,
            verdicts=verdicts,
            severity=objective.severity,
            variant=conversation.label,
            turn_count=len(conversation.turns),
            tags=list(objective.tags),
        )
        result.attempts.append(attempt)
        self._record(attempt)
        return attempt

    async def _send_with_retries(self, conversation: Conversation) -> Response:
        last: Response | None = None
        for i in range(max(1, self.settings.retries + 1)):
            await self._limiter.acquire()
            async with self._sem:
                response = await self.target.send(conversation)
            if response.ok:
                return response
            last = response
            if i < self.settings.retries:
                await asyncio.sleep(min(8.0, 1.5 * (2**i)))
        return last or Response(text="", error="no response")

    def _record(self, attempt: Attempt) -> None:
        # Credential-shaped strings never reach disk or the console.
        attempt.response.text = redact(attempt.response.text)
        payload = attempt.to_dict(include_payload=self.settings.include_payloads)
        if self._stream:
            self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._stream.flush()
        self.on_event("attempt", payload)

        if attempt.success and attempt.severity.weight >= 0.8 and attempt.confidence >= 0.5:
            self._criticals += 1
            limit = self.settings.stop_after_criticals
            if limit and self._criticals >= limit and not self._stop.is_set():
                self._stop.set()
                self.on_event("stop_early", {"criticals": self._criticals})
