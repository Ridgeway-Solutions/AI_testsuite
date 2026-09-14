"""What the terminal UI shows, kept free of curses.

``app`` owns the screen and the keyboard; every decision about *what* is on
screen lives here, so the interesting logic is testable with no terminal
attached.

The scan runs on a worker thread and its events reach this object on the main
thread through a queue, so a ``TuiState`` is only ever touched from one thread.
The views are built from those event payloads rather than from the live
``RunResult`` for the same reason: iterating a list another thread is appending
to is a race, and the payloads already carry everything a view needs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ..runner import RunResult, Skip
from ..scoring import CONFIDENCE_FLOOR, Outcome, objective_outcomes, score
from ..types import Objective

# The activity feed is a log, not a record — attempts.jsonl is the record — so
# it is bounded and old lines fall off rather than growing without limit.
MAX_FEED = 2000
# Model responses and many-shot payloads can be enormous. A detail pane is for
# reading evidence, not for holding all of it; the full text is in the reports.
MAX_DETAIL_LINES = 400
MAX_DETAIL_LINE = 2000


class Phase(str, Enum):
    SETUP = "setup"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class View(str, Enum):
    BOUNDARIES = "Boundaries"
    FINDINGS = "Findings"
    TECHNIQUES = "Techniques"
    ACTIVITY = "Activity"


VIEWS: list[View] = list(View)

# Row kinds drive colour in the renderer. Kept as plain strings so this module
# never has to know what a curses attribute is.
KIND_PLAIN = "plain"
KIND_FAIL = "fail"
KIND_HELD = "held"
KIND_UNTESTED = "untested"
KIND_HIT = "hit"
KIND_WEAK = "weak"
KIND_ERROR = "error"
KIND_WARN = "warn"
KIND_MUTED = "muted"


@dataclass
class Row:
    """One line in a list view, plus the evidence behind it."""

    text: str
    kind: str = KIND_PLAIN
    detail: list[str] = field(default_factory=list)


@dataclass
class FeedLine:
    text: str
    kind: str = KIND_PLAIN


def _clip(text: str, limit: int = MAX_DETAIL_LINE) -> str:
    text = text.replace("\t", "    ")
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def _block(raw: str) -> list[str]:
    """Split target- or attacker-controlled text into displayable lines."""
    if not raw:
        return ["(empty)"]
    lines = [_clip(line) for line in raw.splitlines()] or ["(empty)"]
    if len(lines) > MAX_DETAIL_LINES:
        dropped = len(lines) - MAX_DETAIL_LINES
        lines = lines[:MAX_DETAIL_LINES] + [f"…[{dropped} more lines truncated]"]
    return lines


def _severity_kind(severity: str) -> str:
    """Colour for a confirmed finding. Distinct from KIND_WEAK, which means a
    hit below the confidence floor — a different claim entirely."""
    return KIND_HIT if severity in ("high", "critical") else KIND_WARN


def finding_detail(payload: dict[str, Any]) -> list[str]:
    """The evidence pane for one attempt, built from its serialised form."""
    response = payload.get("response") or {}
    lines = [
        f"objective    {payload['objective']}  "
        f"({payload.get('category', '?')}, {payload.get('severity', '?')})",
        f"technique    {payload['attack']}/{payload.get('variant') or '-'}  "
        f"· {payload.get('turns', 1)} turn(s)",
        f"confidence   {payload.get('confidence', 0):.2f}   "
        f"risk {payload.get('risk', 0):.2f}   "
        f"latency {response.get('latency_ms', 0):.0f}ms",
        "",
    ]

    fired = [v for v in payload.get("verdicts", []) if v.get("success")]
    lines.append("── detectors " + "─" * 40)
    if fired:
        for verdict in fired:
            lines.append(
                f"  {verdict.get('detector', '?')} "
                f"(conf {verdict.get('confidence', 0):.2f})"
            )
            if verdict.get("rationale"):
                lines.append(f"    {_clip(verdict['rationale'])}")
    else:
        lines.append("  none fired")

    conversation = payload.get("conversation")
    lines.append("")
    if conversation:
        lines.append("── payload " + "─" * 42)
        for turn in conversation.get("turns", []):
            lines.append(f"  [{turn.get('role', '?')}]")
            lines.extend("    " + line for line in _block(turn.get("content", "")))
    else:
        # --no-payloads, or a report meant for a wider audience than the
        # people authorised to run the scan.
        lines.append("── payload " + "─" * 42)
        lines.append("  withheld (payloads disabled for this run)")

    lines.append("")
    lines.append("── response " + "─" * 41)
    if response.get("error"):
        lines.append(f"  error: {_clip(response['error'])}")
    else:
        lines.extend("  " + line for line in _block(response.get("text", "")))
    if response.get("blocked"):
        lines.append("  (the target's own guardrail reported blocking this)")
    return lines


class TuiState:
    """Everything on screen, advanced by runner events."""

    def __init__(
        self,
        suite_name: str,
        target_label: str,
        objectives: Iterable[Objective],
        pairs: int = 0,
        skips: Iterable[Skip] = (),
        outdir: str = "",
    ) -> None:
        self.suite_name = suite_name
        self.target_label = target_label
        self.objectives = list(objectives)
        self.outdir = outdir
        self.skips = list(skips)

        self.phase = Phase.SETUP
        self.view = View.BOUNDARIES
        self.status = ""
        self.error_message = ""
        self.reports: list[str] = []
        self.stopping = False

        self.total_pairs = pairs
        self.pairs_done = 0
        self.attempts = 0
        self.errored = 0
        self.duration_s = 0.0
        self.stopped_early = False

        self.feed: deque[FeedLine] = deque(maxlen=MAX_FEED)
        self.findings: list[dict[str, Any]] = []
        self.unconfirmed = 0
        # Live tallies, keyed by id: {attempts, hits, errors, breakers}
        self.by_objective: dict[str, dict[str, Any]] = {}
        self.by_attack: dict[str, dict[str, Any]] = {}
        self.crashes: list[dict[str, str]] = []

        # Authoritative, and only available once the run has fully finished.
        self.result: RunResult | None = None
        self.outcomes: list[Any] = []
        self.risk_score = 0.0
        self.grade = ""

        self.cursor: dict[View, int] = {view: 0 for view in VIEWS}
        self.scroll: dict[View, int] = {view: 0 for view in VIEWS}
        self.detail_open = False
        self.detail_scroll = 0

    # -- lifecycle ------------------------------------------------------------

    def reset_for_run(self, pairs: int, skips: Iterable[Skip]) -> None:
        """Clear the last run's results so a re-run does not blend into it."""
        self.total_pairs = pairs
        self.skips = list(skips)
        self.pairs_done = 0
        self.attempts = 0
        self.errored = 0
        self.duration_s = 0.0
        self.stopped_early = False
        self.stopping = False
        self.feed.clear()
        self.findings.clear()
        self.unconfirmed = 0
        self.by_objective.clear()
        self.by_attack.clear()
        self.crashes.clear()
        self.result = None
        self.outcomes = []
        self.risk_score = 0.0
        self.grade = ""
        self.reports = []
        self.error_message = ""
        self.detail_open = False
        for view in VIEWS:
            self.cursor[view] = 0
            self.scroll[view] = 0
        self.phase = Phase.RUNNING

    def set_plan(self, target_label: str, pairs: int, skips: Iterable[Skip]) -> None:
        """Re-cost the run after the target was changed from the command line.

        Planning sends nothing, so this is safe to do on every edit — the
        pair count on screen always describes the target as it stands now.
        """
        self.target_label = target_label
        self.total_pairs = pairs
        self.skips = list(skips)

    @property
    def progress(self) -> float:
        if not self.total_pairs:
            return 0.0
        return min(1.0, self.pairs_done / self.total_pairs)

    def log(self, text: str, kind: str = KIND_PLAIN) -> None:
        self.feed.append(FeedLine(text, kind))

    # -- events ---------------------------------------------------------------

    def handle(self, kind: str, payload: dict[str, Any]) -> None:
        handler = getattr(self, f"_on_{kind}", None)
        if handler is not None:
            handler(payload)

    def _on_run_start(self, payload: dict[str, Any]) -> None:
        self.phase = Phase.RUNNING
        self.total_pairs = payload.get("pairs", self.total_pairs)
        self.log(
            f"{payload.get('pairs', 0)} attack×objective pairs "
            f"({payload.get('attacks', 0)} techniques, "
            f"{payload.get('objectives', 0)} objectives"
            + (f", {payload['skipped']} skipped" if payload.get("skipped") else "")
            + ")"
        )

    def _on_pair_end(self, payload: dict[str, Any]) -> None:
        self.pairs_done += 1

    def _on_attempt(self, payload: dict[str, Any]) -> None:
        self.attempts += 1
        response = payload.get("response") or {}
        errored = bool(response.get("error"))
        severity = payload.get("severity", "medium")
        confidence = payload.get("confidence", 0.0)
        # Mirrors scoring.score(): an errored attempt has no output to judge, so
        # it can never be a finding however loudly a detector fires on "".
        confirmed = (
            payload.get("success", False)
            and not errored
            and confidence >= CONFIDENCE_FLOOR
        )

        for table, key in (
            (self.by_objective, payload["objective"]),
            (self.by_attack, payload["attack"]),
        ):
            cell = table.setdefault(
                key, {"attempts": 0, "hits": 0, "errors": 0, "breakers": set()}
            )
            cell["attempts"] += 1
            cell["errors"] += errored
            cell["hits"] += confirmed

        if confirmed:
            self.findings.append(payload)
            self.by_objective[payload["objective"]]["breakers"].add(payload["attack"])
            mark = "!" if severity in ("high", "critical") else "+"
            self.log(
                f"{mark} {payload['objective']} via {payload['attack']}"
                f"/{payload.get('variant') or '-'} "
                f"[{severity}, conf {confidence:.2f}]",
                _severity_kind(severity),
            )
        elif payload.get("success") and not errored:
            self.unconfirmed += 1
            self.log(
                f"~ {payload['objective']} via {payload['attack']}"
                f"/{payload.get('variant') or '-'} "
                f"[low confidence {confidence:.2f}]",
                KIND_WEAK,
            )
        elif errored:
            self.errored += 1
            self.log(
                f"✗ {payload['attack']}/{payload['objective']}: "
                f"{_clip(str(response.get('error')), 160)}",
                KIND_ERROR,
            )

    def _on_attack_error(self, payload: dict[str, Any]) -> None:
        self.crashes.append(dict(payload))
        self.log(
            f"✗ {payload.get('attack')}/{payload.get('objective')} crashed: "
            f"{_clip(str(payload.get('error')), 160)}",
            KIND_ERROR,
        )

    def _on_warning(self, payload: dict[str, Any]) -> None:
        targets = ", ".join(payload.get("objectives", []))
        self.log(
            f"warning: {payload.get('message')}" + (f": {targets}" if targets else ""),
            KIND_WARN,
        )

    def _on_stop_early(self, payload: dict[str, Any]) -> None:
        self.log("critical limit reached — stopping", KIND_WARN)

    def _on_run_end(self, payload: dict[str, Any]) -> None:
        self.duration_s = payload.get("duration_s", 0.0)
        self.stopped_early = payload.get("stopped_early", False)
        self.log(
            f"done: {payload.get('attempts', 0)} attempts in "
            f"{self.duration_s}s"
            + (" (stopped early)" if self.stopped_early else "")
        )

    def finish(self, result: RunResult, reports: Iterable[str] = ()) -> None:
        """Swap the live tallies for the authoritative scoreboard."""
        self.result = result
        board = score(result.attempts)
        self.outcomes = objective_outcomes(
            board, result.objectives, result.broken_objectives
        )
        self.risk_score = board.risk_score
        self.grade = board.grade
        self.reports = list(reports)
        self.phase = Phase.DONE
        self.stopping = False
        # The header already carries the score; leave the status line for the
        # report paths, which are the thing a reader needs next.
        self.status = ""

    def fail(self, message: str) -> None:
        self.phase = Phase.FAILED
        self.error_message = message
        self.stopping = False
        self.log(f"run failed: {message}", KIND_ERROR)

    # -- views ----------------------------------------------------------------

    def rows(self, view: View | None = None) -> list[Row]:
        view = view or self.view
        if view is View.BOUNDARIES:
            return self._boundary_rows()
        if view is View.FINDINGS:
            return self._finding_rows()
        if view is View.TECHNIQUES:
            return self._technique_rows()
        return self._activity_rows()

    def _boundary_rows(self) -> list[Row]:
        if self.outcomes:
            return [self._outcome_row(o) for o in self.outcomes]
        # Mid-run: live tallies only. Deliberately not labelled PASS/FAIL — a
        # boundary nothing has hit *yet* is not a boundary that held.
        rows = []
        for objective in self.objectives:
            cell = self.by_objective.get(objective.id)
            if not cell:
                rows.append(
                    Row(
                        f"  ····  {objective.id:<34} {objective.severity.value:<9} "
                        "not started",
                        KIND_MUTED,
                    )
                )
                continue
            breakers = sorted(cell["breakers"])
            label = f"{cell['hits']} hit(s)" if breakers else "no hits yet"
            rows.append(
                Row(
                    f"  {'····':<4}  {objective.id:<34} "
                    f"{objective.severity.value:<9} "
                    f"{cell['attempts']:>4} tried · {label}"
                    + (f" · {', '.join(breakers)}" if breakers else ""),
                    KIND_HIT if breakers else KIND_PLAIN,
                )
            )
        return rows

    def _outcome_row(self, outcome: Any) -> Row:
        kind = {
            Outcome.FAIL: KIND_FAIL,
            Outcome.HELD: KIND_HELD,
            Outcome.INCONCLUSIVE: KIND_UNTESTED,
            Outcome.NOT_RUN: KIND_UNTESTED,
        }[outcome.outcome]
        mark = "†" if outcome.needs_review else " "
        text = (
            f"  {outcome.outcome.value:<13}{mark} {outcome.objective.id:<34} "
            f"{outcome.objective.severity.value:<9} "
            f"{outcome.attempts:>4} tried · ASR {outcome.asr:.0%}"
        )
        if outcome.breakers:
            text += f" · broken by {', '.join(outcome.breakers)}"
        elif outcome.outcome is Outcome.NOT_RUN:
            text += " · never exercised"

        detail = [
            f"{outcome.objective.id} — {outcome.outcome.value}",
            "",
            f"goal         {outcome.objective.goal}",
            f"category     {outcome.objective.category}",
            f"severity     {outcome.objective.severity.value}",
            f"attempts     {outcome.attempts} ({outcome.errors} errored)",
            f"ASR          {outcome.asr:.1%}",
        ]
        if outcome.objective.description:
            detail.insert(3, f"note         {outcome.objective.description}")
        if outcome.breakers:
            detail.append(f"bypassed by  {', '.join(outcome.breakers)}")
        if outcome.unconfirmed:
            detail.append(
                f"unconfirmed  {outcome.unconfirmed} low-confidence hit(s) — "
                "worth reading, not counted as findings"
            )
        if outcome.partial:
            detail.append(
                "coverage     partial: a technique crashed part-way through"
            )
        if outcome.outcome is Outcome.NOT_RUN:
            reasons = sorted(
                {s.reason for s in self.skips if s.objective_id == outcome.objective.id}
            )
            detail.append("")
            detail.append("Never exercised. Reasons given at plan time:")
            detail.extend(f"  - {r}" for r in (reasons or ["(filtered out)"]))
        return Row(text, kind, detail)

    def _finding_rows(self) -> list[Row]:
        if not self.findings:
            return [Row("  no confirmed findings", KIND_MUTED)]
        ordered = sorted(
            self.findings,
            key=lambda p: (p.get("risk", 0.0), p.get("confidence", 0.0)),
            reverse=True,
        )
        return [
            Row(
                f"  {p.get('severity', '?'):<9} {p['objective']:<30} "
                f"{p['attack'] + '/' + (p.get('variant') or '-'):<34} "
                f"conf {p.get('confidence', 0):.2f}",
                _severity_kind(p.get("severity", "medium")),
                finding_detail(p),
            )
            for p in ordered
        ]

    def _technique_rows(self) -> list[Row]:
        if not self.by_attack:
            return [Row("  nothing has run yet", KIND_MUTED)]
        # The control condition is the yardstick: every other technique is only
        # interesting as lift over just asking.
        baseline = self.by_attack.get("direct")
        baseline_asr = _asr(baseline) if baseline else None
        rows = []
        for attack_id, cell in sorted(
            self.by_attack.items(), key=lambda kv: (-_asr(kv[1]), kv[0])
        ):
            asr = _asr(cell)
            if attack_id == "direct":
                lift = "  (control)"
            elif baseline_asr is None:
                lift = "  (no control ran)"
            else:
                lift = f"  {asr - baseline_asr:+.0%} vs control"
            rows.append(
                Row(
                    f"  {attack_id:<24} {cell['attempts']:>4} tried · "
                    f"{cell['hits']:>3} hit · ASR {asr:>5.0%}{lift}",
                    KIND_HIT if cell["hits"] else KIND_PLAIN,
                )
            )
        return rows

    def _activity_rows(self) -> list[Row]:
        if not self.feed:
            return [Row("  nothing yet", KIND_MUTED)]
        return [Row("  " + line.text, line.kind) for line in self.feed]

    # -- navigation -----------------------------------------------------------

    def set_view(self, view: View) -> None:
        if view is not self.view:
            self.view = view
            self.detail_open = False
            self.detail_scroll = 0

    def cycle_view(self, delta: int) -> None:
        self.set_view(VIEWS[(VIEWS.index(self.view) + delta) % len(VIEWS)])

    def move(self, delta: int) -> None:
        if self.detail_open:
            self.detail_scroll = max(0, self.detail_scroll + delta)
            return
        count = len(self.rows())
        if not count:
            return
        self.cursor[self.view] = max(0, min(count - 1, self.cursor[self.view] + delta))

    def jump(self, to_end: bool) -> None:
        if self.detail_open:
            self.detail_scroll = 0 if not to_end else self.detail_scroll
            return
        count = len(self.rows())
        self.cursor[self.view] = (count - 1) if to_end else 0

    def selected(self) -> Row | None:
        rows = self.rows()
        if not rows:
            return None
        index = min(self.cursor[self.view], len(rows) - 1)
        return rows[index]

    def toggle_detail(self) -> None:
        row = self.selected()
        if self.detail_open:
            self.detail_open = False
        elif row is not None and row.detail:
            self.detail_open = True
        self.detail_scroll = 0


def _asr(cell: dict[str, Any]) -> float:
    scored = cell["attempts"] - cell["errors"]
    return cell["hits"] / scored if scored else 0.0
