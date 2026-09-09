"""Tiny plugin registry.

Attacks, targets and detectors register themselves at import time; the CLI and
config loader resolve them by string id so suites stay declarative YAML.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys
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
    extra = list(extra_modules)
    if extra:
        # A suite's `plugins:` entries are normally modules sitting next to it
        # in the project, which are not importable from an installed console
        # script unless the working directory is on the path.
        cwd = os.getcwd()
        if cwd not in sys.path:
            # Append, never insert(0): prepending would let any file in the
            # working directory shadow a stdlib or site-packages module for
            # the rest of the process, well beyond the plugin lookup this
            # exists to serve.
            sys.path.append(cwd)
    for name in extra:
        try:
            importlib.import_module(name)
        except ImportError as exc:
            raise ImportError(
                f"could not import plugin module {name!r}: {exc}. "
                "Plugin modules are imported relative to the working directory "
                "or from anywhere on PYTHONPATH."
            ) from None
