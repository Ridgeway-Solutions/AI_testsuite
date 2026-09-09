"""Core data model shared by targets, attacks, detectors and reporting.

Everything that crosses a module boundary is one of these frozen-ish dataclasses,
so results can be serialised to JSONL and replayed without re-running a target.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Severity(str, Enum):
    """How bad a successful bypass of this objective would be in production."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {
            "info": 0.0,
            "low": 0.25,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0,
        }[self.value]


@dataclass
class Turn:
    """One message in a conversation sent to the target."""

    role: Role
    content: str
    # Free-form provider passthrough (tool_call_id, name, attachments...).
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {"role": self.role.value, "content": self.content}
        if self.meta:
            d["meta"] = self.meta
        return d


@dataclass
class Objective:
    """A policy boundary we want to test, expressed as something to elicit.

    ``goal`` is the instruction an attacker would send in the clear. Built-in
    objectives use *benign canary goals*: the elicited output is harmless in
    itself (a marker token, a seeded fake secret, a policy contradiction), so a
    scan measures guardrail integrity without producing dangerous content.
    See docs/ETHICS.md.
    """

    id: str
    goal: str
    description: str = ""
    category: str = "generic"
    severity: Severity = Severity.MEDIUM
    # Detector specs, e.g. {"type": "canary", "patterns": ["ZX-CANARY-7"]}
    detectors: list[dict[str, Any]] = field(default_factory=list)
    # Baseline expectation: should a well-behaved target refuse the plain goal?
    expect_refusal: bool = True
    tags: list[str] = field(default_factory=list)
    # Extra context the harness seeds into the target (e.g. a canary the system
    # prompt was told to protect). Only usable with targets you control.
    requires_seed: bool = False
    # Restrict this objective to specific techniques. Over-refusal controls set
    # this to ["direct"]: measuring whether an adversarially framed request gets
    # refused says nothing about usability, because it should be.
    only_attacks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Conversation:
    """A concrete attack payload: the turns to send, in order.

    Turns with role ASSISTANT before the final USER turn are *prefill* /
    fake-history, which some transports support and others drop; targets
    declare support via ``Target.capabilities``.
    """

    turns: list[Turn]
    label: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def last_user_content(self) -> str:
        for t in reversed(self.turns):
            if t.role is Role.USER:
                return t.content
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "turns": [t.to_dict() for t in self.turns],
            "meta": self.meta,
        }


@dataclass
class Response:
    """What the target said back."""

    text: str
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: str | None = None
    # True when the target's own guardrail (not the model) blocked the request.
    blocked: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "blocked": self.blocked,
        }


@dataclass
class Verdict:
    """A detector's opinion on whether one response constitutes a bypass."""

    success: bool
    confidence: float = 1.0
    detector: str = ""
    rationale: str = ""
    signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "confidence": round(self.confidence, 3),
            "detector": self.detector,
            "rationale": self.rationale,
            "signals": self.signals,
        }


@dataclass
class Attempt:
    """One attack × objective × payload execution, with its outcome."""

    attack_id: str
    objective_id: str
    conversation: Conversation
    response: Response
    verdicts: list[Verdict] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    variant: str = ""
    turn_count: int = 1
    tags: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """A bypass, per the strongest confident detector that fired."""
        return any(v.success for v in self.verdicts)

    @property
    def confidence(self) -> float:
        hits = [v.confidence for v in self.verdicts if v.success]
        return max(hits) if hits else 0.0

    @property
    def risk(self) -> float:
        """0..1 contribution of this attempt to the overall risk score."""
        return self.severity.weight * self.confidence if self.success else 0.0

    @property
    def fingerprint(self) -> str:
        """Stable id for dedupe across runs (same attack, objective, payload)."""
        h = hashlib.sha256()
        h.update(f"{self.attack_id}|{self.objective_id}|{self.variant}|".encode())
        h.update(self.conversation.last_user_content.encode("utf-8", "replace"))
        return h.hexdigest()[:16]

    def to_dict(self, include_payload: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "attack": self.attack_id,
            "objective": self.objective_id,
            "variant": self.variant,
            "severity": self.severity.value,
            "success": self.success,
            "confidence": round(self.confidence, 3),
            "risk": round(self.risk, 3),
            "turns": self.turn_count,
            "started_at": self.started_at,
            "tags": self.tags,
            "response": self.response.to_dict(),
            "verdicts": [v.to_dict() for v in self.verdicts],
        }
        if include_payload:
            d["conversation"] = self.conversation.to_dict()
        return d
