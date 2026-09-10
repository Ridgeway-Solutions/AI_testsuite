"""Suite configuration: declarative YAML in, validated objects out."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


def expand_env(node: Any) -> Any:
    """Expand ``${VAR}`` and ``${VAR:-default}`` throughout a config tree.

    Credentials belong in the environment, not in a suite file that gets
    committed. A missing variable expands to empty rather than raising, so a
    config can be inspected (``llmtest plan``) without secrets present.
    """
    if isinstance(node, dict):
        return {k: expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [expand_env(v) for v in node]
    if isinstance(node, str):
        return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), node)
    return node


@dataclass
class RunSettings:
    concurrency: int = 4
    rate_limit_rps: float = 0.0
    retries: int = 2
    max_turns: int = 6
    seed: int = 1337
    timeout: float = 60.0
    # Store full attack payloads in the report. Turn off if reports are shared
    # more widely than the people authorised to run the tests.
    include_payloads: bool = True
    # Stop the whole run after this many confirmed criticals (0 = never).
    stop_after_criticals: int = 0


@dataclass
class SuiteConfig:
    name: str = "unnamed"
    description: str = ""
    target: dict[str, Any] = field(default_factory=lambda: {"type": "mock"})
    attacks: list[str] = field(default_factory=lambda: ["all"])
    objectives_file: str | None = None
    include_objectives: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    run: RunSettings = field(default_factory=RunSettings)
    # Extra python modules to import so custom plugins register themselves.
    plugins: list[str] = field(default_factory=list)
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> "SuiteConfig":
        data = expand_env(dict(data))
        objectives = data.get("objectives") or {}
        if isinstance(objectives, list):  # shorthand: a bare list of ids
            objectives = {"include": objectives}
        run_data = data.get("run") or {}
        unknown = set(run_data) - set(RunSettings.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown run settings: {sorted(unknown)}")
        return cls(
            name=data.get("name", Path(source).stem if source else "unnamed"),
            description=data.get("description", ""),
            target=data.get("target") or {"type": "mock"},
            attacks=data.get("attacks") or ["all"],
            objectives_file=objectives.get("file"),
            include_objectives=objectives.get("include") or [],
            categories=objectives.get("categories") or [],
            tags=objectives.get("tags") or [],
            run=RunSettings(**run_data),
            plugins=data.get("plugins") or [],
            source=source,
        )

    @classmethod
    def load(cls, path: str | Path) -> "SuiteConfig":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"suite not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}
        return cls.from_dict(data, source=str(path))

    def resolve_objectives_file(self) -> Path | None:
        """Objective paths are relative to the suite file that names them."""
        if not self.objectives_file:
            return None
        p = Path(self.objectives_file)
        if not p.is_absolute() and self.source:
            candidate = Path(self.source).parent / p
            if candidate.exists():
                return candidate
        return p
