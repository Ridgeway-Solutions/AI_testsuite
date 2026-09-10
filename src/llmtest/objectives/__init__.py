"""Objective loading: built-in catalogue plus user-supplied YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml

from ..types import Objective, Severity

CATALOG = Path(__file__).with_name("catalog.yaml")


def objective_from_dict(data: dict[str, Any]) -> Objective:
    data = dict(data)
    severity = data.pop("severity", "medium")
    goal = (data.pop("goal", "") or "").strip()
    if not data.get("id") or not goal:
        raise ValueError(f"objective needs an 'id' and a 'goal': {data!r}")
    return Objective(
        id=data.pop("id"),
        goal=goal,
        description=(data.pop("description", "") or "").strip(),
        category=data.pop("category", "generic"),
        severity=Severity(severity),
        detectors=data.pop("detectors", []) or [],
        expect_refusal=bool(data.pop("expect_refusal", True)),
        tags=data.pop("tags", []) or [],
        requires_seed=bool(data.pop("requires_seed", False)),
        only_attacks=data.pop("only_attacks", []) or [],
    )


def load_objectives(path: str | Path | None = None) -> list[Objective]:
    """Load from a YAML file, or the built-in catalogue when path is None."""
    source = Path(path) if path else CATALOG
    if not source.exists():
        raise FileNotFoundError(f"objectives file not found: {source}")
    data = yaml.safe_load(source.read_text()) or {}
    entries = data.get("objectives", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError(f"{source}: expected a list of objectives")
    objectives = [objective_from_dict(e) for e in entries]
    seen: set[str] = set()
    for obj in objectives:
        if obj.id in seen:
            raise ValueError(f"{source}: duplicate objective id {obj.id!r}")
        seen.add(obj.id)
    return objectives


def filter_objectives(
    objectives: Iterable[Objective],
    ids: list[str] | None = None,
    categories: list[str] | None = None,
    tags: list[str] | None = None,
) -> list[Objective]:
    out = []
    for obj in objectives:
        if ids and obj.id not in ids:
            continue
        if categories and obj.category not in categories:
            continue
        if tags and not set(tags) & set(obj.tags):
            continue
        out.append(obj)
    return out
