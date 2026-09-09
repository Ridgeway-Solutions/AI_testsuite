"""Human-readable Markdown report."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..registry import available
from ..runner import RunResult
from ..util import truncate
from .remediation import ATTACK_NOTES, for_categories

BAR = "█"


def _bar(fraction: float, width: int = 12) -> str:
    filled = round(fraction * width)
    return BAR * filled + "·" * (width - filled)


def render_markdown(result: RunResult) -> str:
    board = result.scoreboard()
    attacks = available("attack")
    ts = datetime.fromtimestamp(result.started_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    w = out.append

    w(f"# Adversarial robustness report — {result.config.name}")
    w("")
    w(f"**Target:** `{result.target_info['name']}` ({result.target_info['type']})  ")
    w(f"**Run:** {ts} · {result.duration_s:.1f}s · {len(result.attempts)} attempts  ")
    w(f"**Risk score:** {board.risk_score}/100 — **{board.grade}**")
    w("")
    if result.stopped_early:
        w("> Run stopped early on the configured critical-finding limit; "
          "coverage is partial.")
        w("")

    confirmed = len(board.findings)
    w(f"{confirmed} confirmed finding{'s' if confirmed != 1 else ''}, "
      f"{len(board.unconfirmed)} low-confidence hit(s), "
      f"{board.total.errors} transport error(s), {len(result.skipped)} skipped.")
    w("")

    # -- findings ---------------------------------------------------------------
    w("## Findings")
    w("")
    if not board.findings:
        w("No confirmed bypasses. Check the coverage section below before "
          "reading that as a clean bill of health — an empty result with most "
          "probes skipped means the suite could not reach the boundary.")
        w("")
    else:
        w("| # | Severity | Objective | Technique | Variant | Conf. | Evidence |")
        w("|---|----------|-----------|-----------|---------|-------|----------|")
        for i, a in enumerate(board.findings[:40], 1):
            evidence = truncate(a.response.text.replace("\n", " ").replace("|", "\\|"), 90)
            w(f"| {i} | **{a.severity.value}** | `{a.objective_id}` | `{a.attack_id}` "
              f"| {a.variant or '—'} | {a.confidence:.2f} | {evidence} |")
        if len(board.findings) > 40:
            w(f"| … | | | | | | {len(board.findings) - 40} more in report.json |")
        w("")

    # -- technique effectiveness -------------------------------------------------
    w("## Attack success rate by technique")
    w("")
    w("ASR is measured against non-errored attempts. Compare every row to "
      "`direct` — a technique only tells you something if it beats simply asking.")
    w("")
    w("| Technique | ASR | | Hits | Attempts | Peak severity |")
    w("|-----------|-----|---|------|----------|---------------|")
    for name, cell in sorted(
        board.by_attack.items(), key=lambda kv: (kv[1].asr, kv[1].risk), reverse=True
    ):
        peak = max(
            (a.severity.value for a in board.findings if a.attack_id == name),
            key=lambda s: ["info", "low", "medium", "high", "critical"].index(s),
            default="—",
        )
        w(f"| `{name}` | {cell.asr:.0%} | `{_bar(cell.asr)}` | {cell.successes} "
          f"| {cell.attempts} | {peak} |")
    w("")

    # -- objective view ----------------------------------------------------------
    w("## Boundaries tested")
    w("")
    w("| Objective | Category | Severity | Bypassed by | ASR |")
    w("|-----------|----------|----------|-------------|-----|")
    by_id = {o.id: o for o in result.objectives}
    for obj_id, cell in sorted(board.by_objective.items()):
        breakers = sorted({a.attack_id for a in board.findings if a.objective_id == obj_id})
        obj = by_id.get(obj_id)
        cat = obj.category if obj else "—"
        sev = obj.severity.value if obj else "—"
        w(f"| `{obj_id}` | {cat} | {sev} "
          f"| {', '.join(f'`{b}`' for b in breakers) or '—'} | {cell.asr:.0%} |")
    w("")

    # -- what to do --------------------------------------------------------------
    if board.findings:
        w("## Recommended fixes")
        w("")
        seen: set[str] = set()
        for a in board.findings:
            note = ATTACK_NOTES.get(a.attack_id)
            if note and a.attack_id not in seen:
                seen.add(a.attack_id)
                w(f"- **`{a.attack_id}`** — {note}")
        w("")
        objective_cats = sorted({
            by_id[a.objective_id].category
            for a in board.findings
            if a.objective_id in by_id
        })
        for category, items in for_categories(objective_cats):
            w(f"### {category.replace('_', ' ').title()}")
            for item in items:
                w(f"- {item}")
            w("")

    # -- coverage ---------------------------------------------------------------
    w("## Coverage")
    w("")
    w(f"- Techniques run: {len(board.by_attack)} of {len(attacks)} registered")
    w(f"- Objectives run: {len(board.by_objective)}")
    if result.skipped:
        w(f"- Skipped pairs: {len(result.skipped)}")
        for reason, count in Counter(s.reason for s in result.skipped).most_common(6):
            w(f"  - {count}× {reason}")
    w("")
    w("---")
    w("")
    w("Generated by redteam-suite. Findings are evidence of a reachable "
      "boundary, not proof of exploitability in production — confirm each one "
      "against the deployed configuration before filing it.")
    return "\n".join(out) + "\n"
