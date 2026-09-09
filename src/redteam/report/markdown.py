"""Human-readable Markdown report."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..registry import available
from ..runner import RunResult
from ..scoring import Outcome, objective_outcomes
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
    if result.errors:
        w(f"> **{len(result.errors)} technique(s) crashed mid-run**, so their "
          "remaining payloads never ran. Coverage below is incomplete:")
        for err in result.errors[:8]:
            w(f"> - `{err.attack_id}` on `{err.objective_id}`: {err.error}")
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
    by_id = {o.id: o for o in result.objectives}
    outcomes = objective_outcomes(board, result.objectives, result.broken_objectives)
    passed = sum(1 for r in outcomes if r.outcome is Outcome.PASS)
    failed = sum(1 for r in outcomes if r.outcome is Outcome.FAIL)
    untested = len(outcomes) - passed - failed

    w("## Boundaries tested")
    w("")
    w(f"**{passed} held, {failed} bypassed"
      + (f", {untested} untested**" if untested else "**")
      + f" — out of {len(outcomes)} boundaries.")
    w("")
    w("| Result | Objective | Category | Severity | Bypassed by | ASR |")
    w("|--------|-----------|----------|----------|-------------|-----|")
    for row in outcomes:
        marker = " †" if row.needs_review else ""
        w(f"| **{row.outcome.value}**{marker} | `{row.objective.id}` "
          f"| {row.objective.category} | {row.objective.severity.value} "
          f"| {', '.join(f'`{b}`' for b in row.breakers) or '—'} "
          f"| {row.asr:.0%} |")
    w("")
    if any(r.needs_review for r in outcomes):
        w("† Held, but not cleanly: low-confidence hits below the reporting "
          "threshold, or a technique crashed before finishing. Worth reading the "
          "attempts before calling it clean.")
        w("")
    if untested:
        w("`NOT RUN` means the boundary was never exercised — the target could not "
          "support the probes, or the suite filtered it out. `INCONCLUSIVE` means "
          "every attempt errored. Neither is a pass.")
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
