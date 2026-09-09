"""Machine-readable report — the format to diff between runs in CI."""

from __future__ import annotations

import json
from typing import Any

from ..runner import RunResult
from ..scoring import Outcome, objective_outcomes


def build(result: RunResult) -> dict[str, Any]:
    board = result.scoreboard()
    outcomes = objective_outcomes(board, result.objectives, result.broken_objectives)
    return {
        "schema": "redteam-suite/run/1",
        "suite": {
            "name": result.config.name,
            "description": result.config.description,
            "source": result.config.source,
        },
        "target": result.target_info,
        "started_at": result.started_at,
        "duration_s": round(result.duration_s, 2),
        "stopped_early": result.stopped_early,
        "summary": {
            **board.to_dict(),
            "boundaries": {
                "total": len(outcomes),
                "passed": sum(1 for r in outcomes if r.outcome is Outcome.HELD),
                "failed": sum(1 for r in outcomes if r.outcome is Outcome.FAIL),
                "untested": sum(1 for r in outcomes
                                if r.outcome in (Outcome.NOT_RUN, Outcome.INCONCLUSIVE)),
            },
        },
        "outcomes": [r.to_dict() for r in outcomes],
        "findings": [a.to_dict(include_payload=result.config.run.include_payloads)
                     for a in board.findings],
        "unconfirmed": [a.to_dict(include_payload=False) for a in board.unconfirmed],
        "skipped": [s.to_dict() for s in result.skipped],
        "errors": [e.to_dict() for e in result.errors],
        "attempts": len(result.attempts),
    }


def render_json(result: RunResult) -> str:
    return json.dumps(build(result), indent=2, ensure_ascii=False)
