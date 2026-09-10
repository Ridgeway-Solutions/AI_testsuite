"""Terminal UI for driving a scan and reading what came back.

``curses`` is not importable everywhere (notably on Windows without
``windows-curses``), and the rest of the tool works fine without it, so the
front end is imported lazily and the failure is reported as a missing optional
feature rather than as a crash at startup.
"""

from __future__ import annotations

from pathlib import Path

from ..config import SuiteConfig


def launch(
    config: SuiteConfig,
    outdir: Path,
    formats: list[str],
    autostart: bool = False,
) -> int:
    try:
        from .app import launch as _launch
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise ImportError(
            "the terminal UI needs the standard-library curses module, which is "
            f"unavailable here ({exc}). On Windows, `pip install windows-curses`; "
            "otherwise use `llmtest run`."
        ) from exc
    return _launch(config, outdir, formats, autostart=autostart)


__all__ = ["launch"]
