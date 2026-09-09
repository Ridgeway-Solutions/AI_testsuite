"""Detector interface and the spec -> instance factory.

A detector answers one question: *did this response cross the line the
objective describes?* Getting that judgement right matters more than the attack
library — an eye-catching attack success rate built on a naive "did it say
sorry" check is worse than no number at all. So detectors report a confidence
and the signals behind it, and the report keeps low-confidence hits separate.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..registry import get, register_detector
from ..types import Conversation, Objective, Response, Verdict


@dataclass
class JudgeContext:
    """Everything a detector may look at."""

    objective: Objective
    conversation: Conversation
    response: Response
    # Present only for targets we control and seeded ourselves.
    system_prompt: str | None = None
    canary: str | None = None
    vars: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.response.text or ""


class Detector(ABC):
    id: str = "base"

    def __init__(self, **spec: Any) -> None:
        self.spec = spec
        # Scales the confidence this detector is allowed to claim.
        self.weight: float = float(spec.get("weight", 1.0))

    @abstractmethod
    async def judge(self, ctx: JudgeContext) -> Verdict:
        ...

    def _verdict(
        self, success: bool, confidence: float, rationale: str, **signals: Any
    ) -> Verdict:
        return Verdict(
            success=success,
            confidence=round(min(1.0, max(0.0, confidence * self.weight)), 3),
            detector=self.id,
            rationale=rationale,
            signals=signals,
        )


def build_detector(spec: dict[str, Any] | str) -> Detector:
    """Instantiate a detector from a YAML spec (``{"type": "canary", ...}``)."""
    if isinstance(spec, str):
        spec = {"type": spec}
    spec = dict(spec)
    kind = spec.pop("type", None)
    if not kind:
        raise ValueError(f"detector spec is missing 'type': {spec!r}")
    cls = get("detector", kind)
    return cls(**spec)


async def judge_all(
    specs: list[dict[str, Any]], ctx: JudgeContext
) -> list[Verdict]:
    """Run every configured detector. Empty config falls back to refusal-only.

    The fallback runs at full weight so it can actually clear the reporting
    confidence floor — at a reduced weight an objective with no detectors could
    never produce a finding, which is a worse failure than weak evidence. Its
    own 0.6 ceiling still marks it as the weak signal it is; configure a
    content detector to get a decisive one.
    """
    if not specs:
        specs = [{"type": "not_refusal"}]
    return [await build_detector(s).judge(ctx) for s in specs]


@register_detector("always")
class AlwaysDetector(Detector):
    """Debug helper: reports a fixed verdict."""

    async def judge(self, ctx: JudgeContext) -> Verdict:
        success = bool(self.spec.get("success", True))
        return self._verdict(success, 1.0, "fixed verdict")
