"""Machine-readable report — the format to diff between runs in CI."""

from __future__ import annotations

import json
from typing import Any

from ..runner import RunResult


def build(result: RunResult) -> dict[str, Any]:
    board = result.scoreboard()
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
        "summary": board.to_dict(),
        "findings": [a.to_dict(include_payload=result.config.run.include_payloads)
                     for a in board.findings],
        "unconfirmed": [a.to_dict(include_payload=False) for a in board.unconfirmed],
        "skipped": [s.to_dict() for s in result.skipped],
        "attempts": len(result.attempts),
    }


def render_json(result: RunResult) -> str:
    return json.dumps(build(result), indent=2, ensure_ascii=False)
