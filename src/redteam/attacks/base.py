"""Attack technique interface.

An attack turns one :class:`Objective` into one or more concrete
:class:`Conversation` payloads. Techniques are *generic*: they encode a
structural weakness (framing, obfuscation, authority confusion, multi-turn
escalation) and are parameterised by whatever goal the objective carries. That
is what makes the suite reusable — swap in your own objectives for your own
application's policy and every technique retargets itself.

Adaptive techniques override :meth:`run` and use ``ctx.send`` to look at each
response before choosing the next move.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable

from ..types import Attempt, Conversation, Objective, Role, Turn


@dataclass
class AttackContext:
    """Handed to an attack for one objective."""

    objective: Objective
    rng: random.Random
    send: Callable[[Conversation], Awaitable[Attempt]]
    max_turns: int = 6
    target_capabilities: set[str] = field(default_factory=set)
    vars: dict[str, Any] = field(default_factory=dict)


class Attack(ABC):
    id: str = "base"
    name: str = "Unnamed attack"
    description: str = ""
    # External framework references, surfaced in the report.
    taxonomy: list[str] = []
    # Target capabilities without which this attack is skipped.
    requires: set[str] = set()
    multi_turn: bool = False
    # Rough intensity, for --max-severity style filtering of a run.
    cost: int = 1

    def __init__(self, **options: Any) -> None:
        self.options = options

    @abstractmethod
    def build(self, ctx: AttackContext) -> Iterable[Conversation]:
        """Yield the payloads to try. Adaptive attacks may yield nothing."""

    async def run(self, ctx: AttackContext) -> AsyncIterator[Attempt]:
        """Execute the attack. Default: send every payload from :meth:`build`."""
        for conversation in self.build(ctx):
            yield await ctx.send(conversation)

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def user(content: str, label: str = "", **meta: Any) -> Conversation:
        return Conversation(turns=[Turn(Role.USER, content)], label=label, meta=meta)

    @staticmethod
    def turns(*turns: Turn, label: str = "", **meta: Any) -> Conversation:
        return Conversation(turns=list(turns), label=label, meta=meta)

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "taxonomy": self.taxonomy,
            "multi_turn": self.multi_turn,
            "requires": sorted(self.requires),
        }
