"""Tiny plugin registry.

Attacks, targets and detectors register themselves at import time; the CLI and
config loader resolve them by string id so suites stay declarative YAML.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Callable, Iterable, TypeVar

_REGISTRIES: dict[str, dict[str, Any]] = {"attack": {}, "target": {}, "detector": {}}

T = TypeVar("T")


def _register(kind: str, ident: str) -> Callable[[type[T]], type[T]]:
    def deco(cls: type[T]) -> type[T]:
        table = _REGISTRIES[kind]
        if ident in table and table[ident] is not cls:
            raise ValueError(f"duplicate {kind} id {ident!r}")
        table[ident] = cls
        setattr(cls, "id", ident)
        return cls

    return deco


def register_attack(ident: str):
    return _register("attack", ident)


def register_target(ident: str):
    return _register("target", ident)


def register_detector(ident: str):
    return _register("detector", ident)


def get(kind: str, ident: str) -> Any:
    load_plugins()
    try:
        return _REGISTRIES[kind][ident]
    except KeyError:
        known = ", ".join(sorted(_REGISTRIES[kind])) or "<none>"
        raise KeyError(f"unknown {kind} {ident!r}. Available: {known}") from None


def available(kind: str) -> dict[str, Any]:
    load_plugins()
    return dict(sorted(_REGISTRIES[kind].items()))


_loaded = False


def load_plugins(extra_modules: Iterable[str] = ()) -> None:
    """Import every built-in plugin subpackage exactly once (plus user modules)."""
    global _loaded
    if not _loaded:
        for sub in ("targets", "attacks", "detectors"):
            pkg = importlib.import_module(f"redteam.{sub}")
            for mod in pkgutil.iter_modules(pkg.__path__):
                if not mod.name.startswith("_"):
                    importlib.import_module(f"redteam.{sub}.{mod.name}")
        _loaded = True
    for name in extra_modules:
        importlib.import_module(name)
