"""Report writers."""

from __future__ import annotations

from pathlib import Path

from ..runner import RunResult
from .html import render_html
from .json_report import render_json
from .markdown import render_markdown

WRITERS = {"json": render_json, "md": render_markdown, "html": render_html}


def write_reports(result: RunResult, outdir: Path, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in formats:
        if fmt not in WRITERS:
            raise ValueError(f"unknown report format {fmt!r}; use one of {list(WRITERS)}")
        path = outdir / f"report.{fmt}"
        path.write_text(WRITERS[fmt](result), encoding="utf-8")
        written.append(path)
    return written
