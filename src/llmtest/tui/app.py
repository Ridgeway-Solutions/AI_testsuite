"""The curses front end: screen, keyboard, and the thread a scan runs on.

The scan is asyncio and the screen is a blocking read loop, so the two are kept
apart: a worker thread owns an event loop and the ``Runner``, and hands events
back through a queue that the draw loop drains between frames. Nothing in the
worker touches ``TuiState``, and nothing in the draw loop touches the runner
except through ``call_soon_threadsafe``.
"""

from __future__ import annotations

import asyncio
import curses
import queue
import threading
from pathlib import Path
from typing import Any

from ..config import SuiteConfig
from ..report import write_reports
from ..runner import Runner
from .state import (
    KIND_ERROR,
    KIND_FAIL,
    KIND_HELD,
    KIND_HIT,
    KIND_MUTED,
    KIND_PLAIN,
    KIND_UNTESTED,
    KIND_WARN,
    KIND_WEAK,
    VIEWS,
    Phase,
    Row,
    TuiState,
    View,
)

REFRESH_MS = 120

BANNER = (
    "Authorised use only — run this against systems you own or have written "
    "permission to test."
)

# Curses colour pair ids, allocated in _init_colours.
_PAIRS: dict[str, int] = {}
_COLOURS = [
    (KIND_FAIL, curses.COLOR_RED),
    (KIND_HIT, curses.COLOR_RED),
    (KIND_HELD, curses.COLOR_GREEN),
    (KIND_UNTESTED, curses.COLOR_YELLOW),
    (KIND_WARN, curses.COLOR_YELLOW),
    (KIND_WEAK, curses.COLOR_CYAN),
    (KIND_ERROR, curses.COLOR_MAGENTA),
    (KIND_MUTED, curses.COLOR_BLUE),
]

HELP = [
    "Keys",
    "",
    "  r          run the suite (again, once it has finished)",
    "  x          stop a run in progress, keeping the coverage so far",
    "  s          write the reports again",
    "  tab / ← →  switch view      1-4  jump straight to a view",
    "  ↑ ↓ / j k  move             PgUp/PgDn  page      g / G  top / bottom",
    "  enter      show the evidence behind the selected row",
    "  ?          this help                     q  quit",
    "",
    "Views",
    "",
    "  Boundaries  one row per objective, and whether it held",
    "  Findings    confirmed bypasses, worst first",
    "  Techniques  attack success rate per technique, against the control",
    "  Activity    the raw event feed",
]


def _init_colours() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    try:
        curses.use_default_colors()
        background = -1
    except curses.error:  # a terminal that will not do transparent backgrounds
        background = curses.COLOR_BLACK
    for index, (kind, colour) in enumerate(_COLOURS, start=1):
        try:
            curses.init_pair(index, colour, background)
        except curses.error:
            continue
        _PAIRS[kind] = index


def _attr(kind: str) -> int:
    pair = _PAIRS.get(kind)
    if pair is None:
        # No colour available: keep the distinction visible with weight alone.
        return curses.A_BOLD if kind in (KIND_FAIL, KIND_HIT) else curses.A_NORMAL
    attr = curses.color_pair(pair)
    if kind in (KIND_FAIL, KIND_HIT):
        attr |= curses.A_BOLD
    if kind == KIND_MUTED:
        attr |= curses.A_DIM
    return attr


def _wrap(text: str, width: int) -> list[str]:
    """Hard-wrap for a pane. Model output is arbitrary, so never assume words."""
    if width < 4:
        return [text[:width]]
    out: list[str] = []
    for line in text.splitlines() or [""]:
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return out


class App:
    def __init__(
        self,
        stdscr: Any,
        config: SuiteConfig,
        outdir: Path,
        formats: list[str],
    ) -> None:
        self.stdscr = stdscr
        self.config = config
        self.outdir = outdir
        self.formats = formats
        self.events: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue()
        self.thread: threading.Thread | None = None
        self.runner: Runner | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.show_help = False

        # Planning is pure and cheap — nothing is sent — so the setup screen can
        # show what a run would cost before anyone commits to it.
        probe = Runner(config)
        pairs, skips = probe.plan()
        self.state = TuiState(
            suite_name=config.name,
            target_label=f"{probe.target.name} ({probe.target.id})",
            objectives=probe.objectives,
            pairs=len(pairs),
            skips=skips,
            outdir=str(outdir),
        )

    # -- the run --------------------------------------------------------------

    def start_run(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        runner = Runner(
            self.config,
            on_event=lambda kind, payload: self.events.put((kind, payload)),
            stream_path=self.outdir / "attempts.jsonl",
        )
        pairs, skips = runner.plan()
        self.state.reset_for_run(len(pairs), skips)
        self.runner = runner
        # The loop is created here rather than in the worker so that a stop
        # requested in the first few milliseconds has something to land on;
        # call_soon_threadsafe on a loop that has not started yet just queues.
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self._worker, args=(runner, self.loop), daemon=True,
            name="llmtest-run",
        )
        self.thread.start()

    def _worker(self, runner: Runner, loop: asyncio.AbstractEventLoop) -> None:
        try:
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(runner.run())
        except Exception as exc:  # noqa: BLE001 — a crash must reach the screen
            self.events.put(("_failed", {"error": repr(exc)}))
            return
        finally:
            self.loop = None
            asyncio.set_event_loop(None)
            loop.close()

        # Reports are written here rather than on the draw thread so a big run
        # cannot freeze the UI, and so an interrupted scan still leaves them.
        try:
            written = write_reports(result, self.outdir, self.formats)
        except Exception as exc:  # noqa: BLE001
            self.events.put(("_finished", {"result": result, "reports": []}))
            self.events.put(("_report_error", {"error": repr(exc)}))
            return
        self.events.put(
            ("_finished", {"result": result, "reports": [str(p) for p in written]})
        )

    def stop_run(self) -> None:
        loop, runner = self.loop, self.runner
        if loop is None or runner is None or self.state.phase is not Phase.RUNNING:
            return
        self.state.stopping = True
        self.state.log("stop requested — finishing the payloads in flight", KIND_WARN)
        try:
            loop.call_soon_threadsafe(runner.request_stop)
        except RuntimeError:
            # The loop closed between the check and the call: the run is over
            # anyway, so there is nothing left to stop.
            self.state.stopping = False

    def _drain(self) -> None:
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                return
            if kind == "_finished":
                self.state.finish(payload["result"], payload["reports"])
            elif kind == "_failed":
                self.state.fail(payload["error"])
            elif kind == "_report_error":
                self.state.log(f"reports could not be written: {payload['error']}",
                               KIND_ERROR)
            else:
                self.state.handle(kind, payload)

    def save_reports(self) -> None:
        if self.state.result is None:
            self.state.status = "nothing to write yet — run the suite first"
            return
        try:
            written = write_reports(self.state.result, self.outdir, self.formats)
        except Exception as exc:  # noqa: BLE001
            self.state.status = f"could not write reports: {exc}"
            return
        self.state.reports = [str(p) for p in written]
        self.state.status = f"wrote {len(written)} report(s) to {self.outdir}"

    # -- input ----------------------------------------------------------------

    def handle_key(self, key: int) -> bool:
        """Returns False to quit."""
        state = self.state
        if self.show_help:
            self.show_help = False
            return True

        if key in (ord("q"), 27):
            if state.phase is Phase.RUNNING and not state.stopping:
                self.stop_run()
                return True
            return False
        if key == ord("?"):
            self.show_help = True
        elif key == ord("r") and state.phase is not Phase.RUNNING:
            self.start_run()
        elif key == ord("x"):
            self.stop_run()
        elif key == ord("s"):
            self.save_reports()
        elif key in (curses.KEY_UP, ord("k")):
            state.move(-1)
        elif key in (curses.KEY_DOWN, ord("j")):
            state.move(1)
        elif key == curses.KEY_PPAGE:
            state.move(-10)
        elif key == curses.KEY_NPAGE:
            state.move(10)
        elif key == ord("g"):
            state.jump(to_end=False)
        elif key == ord("G"):
            state.jump(to_end=True)
        elif key in (curses.KEY_ENTER, 10, 13):
            state.toggle_detail()
        elif key in (9, curses.KEY_RIGHT):
            state.cycle_view(1)
        elif key in (curses.KEY_BTAB, curses.KEY_LEFT):
            state.cycle_view(-1)
        elif ord("1") <= key <= ord("4"):
            state.set_view(VIEWS[key - ord("1")])
        return True

    # -- drawing --------------------------------------------------------------

    def _put(self, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        height, width = self.stdscr.getmaxyx()
        if y < 0 or y >= height or x >= width:
            return
        # Writing the last cell of the last line moves the cursor off-screen and
        # raises, which is the classic way a curses app dies on a resize.
        try:
            self.stdscr.addnstr(y, x, text, max(0, width - x - 1), attr)
        except curses.error:
            pass

    def draw(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 8 or width < 40:
            self._put(0, 0, "terminal too small")
            self.stdscr.refresh()
            return

        self._draw_header(width)
        body_top, body_bottom = 4, height - 2
        if self.show_help:
            self._draw_lines(HELP, body_top, body_bottom, width)
        elif self.state.phase is Phase.SETUP:
            self._draw_setup(body_top, body_bottom, width)
        else:
            self._draw_body(body_top, body_bottom, width)
        self._draw_keybar(height - 1, width)
        self.stdscr.refresh()

    def _draw_header(self, width: int) -> None:
        state = self.state
        self._put(0, 0, f" {state.suite_name} → {state.target_label} ".ljust(width - 1),
                  curses.A_REVERSE | curses.A_BOLD)

        if state.phase is Phase.SETUP:
            line, attr = BANNER, _attr(KIND_WARN)
        elif state.phase is Phase.RUNNING:
            line, attr = self._progress_line(width), curses.A_NORMAL
        elif state.phase is Phase.FAILED:
            line, attr = f"run failed: {state.error_message}", _attr(KIND_ERROR)
        else:
            grade_kind = {
                "critical": KIND_FAIL, "poor": KIND_FAIL, "fair": KIND_UNTESTED,
                "good": KIND_HELD, "strong": KIND_HELD,
            }.get(state.grade, KIND_PLAIN)
            line, attr = (
                f" risk {state.risk_score}/100 ({state.grade}) · "
                f"{len(state.findings)} confirmed · "
                f"{state.unconfirmed} low-confidence · "
                f"{state.attempts} attempts in {state.duration_s}s"
                + (" · STOPPED EARLY" if state.stopped_early else ""),
                _attr(grade_kind) | curses.A_BOLD,
            )
        self._put(1, 0, line, attr)

        if state.phase is not Phase.SETUP:
            x = 1
            for index, view in enumerate(VIEWS, start=1):
                label = f" {index} {view.value} "
                selected = view is state.view
                self._put(2, x, label,
                          curses.A_REVERSE if selected else curses.A_DIM)
                x += len(label) + 1
        status = state.status or (
            f"reports: {', '.join(state.reports)}" if state.reports else ""
        )
        self._put(3, 1, status, curses.A_DIM)

    def _progress_line(self, width: int) -> str:
        state = self.state
        bar_width = max(10, min(30, width - 52))
        filled = int(state.progress * bar_width)
        bar = "█" * filled + "·" * (bar_width - filled)
        return (
            f" [{bar}] {state.pairs_done}/{state.total_pairs} pairs · "
            f"{state.attempts} attempts · {len(state.findings)} findings"
            + (" · stopping…" if state.stopping else "")
        )

    def _draw_setup(self, top: int, bottom: int, width: int) -> None:
        state = self.state
        lines = [
            ("Ready to run.", curses.A_BOLD),
            ("", 0),
            (f"  suite        {state.suite_name}", 0),
            (f"  target       {state.target_label}", 0),
            (f"  objectives   {len(state.objectives)}", 0),
            (f"  pairs        {state.total_pairs} attack×objective", 0),
            (f"  output       {state.outdir}", 0),
            ("", 0),
        ]
        if state.skips:
            reasons: dict[str, int] = {}
            for skip in state.skips:
                reasons[skip.reason] = reasons.get(skip.reason, 0) + 1
            lines.append((f"  {len(state.skips)} pair(s) will be skipped:",
                          _attr(KIND_UNTESTED)))
            for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
                for index, chunk in enumerate(_wrap(f"{count}× {reason}", width - 8)):
                    lines.append((("    - " if index == 0 else "      ") + chunk,
                                  _attr(KIND_UNTESTED)))
            lines.append(("", 0))
        lines.append(("  Press r to start, ? for keys, q to quit.", curses.A_BOLD))

        y = top
        for text, attr in lines:
            if y >= bottom:
                break
            self._put(y, 2, text, attr or curses.A_NORMAL)
            y += 1

    def _draw_body(self, top: int, bottom: int, width: int) -> None:
        state = self.state
        rows = state.rows()
        list_bottom = bottom
        if state.detail_open:
            # Give the list only what it needs, so the evidence pane — the
            # reason the reader opened it — gets the rest of the screen.
            list_bottom = top + max(3, min(len(rows), (bottom - top) // 3))

        self._draw_list(rows, top, list_bottom, width)
        if state.detail_open:
            row = state.selected()
            self._draw_detail(row, list_bottom, bottom, width)

    def _draw_list(self, rows: list[Row], top: int, bottom: int, width: int) -> None:
        state = self.state
        visible = max(1, bottom - top)
        cursor = min(state.cursor[state.view], max(0, len(rows) - 1))
        state.cursor[state.view] = cursor

        # The activity feed is a log: pin it to the newest line unless the
        # reader has moved the cursor up into the history.
        offset = state.scroll[state.view]
        if cursor < offset:
            offset = cursor
        elif cursor >= offset + visible:
            offset = cursor - visible + 1
        offset = max(0, min(offset, max(0, len(rows) - visible)))
        if state.view is View.ACTIVITY and state.phase is Phase.RUNNING and cursor == 0:
            offset = max(0, len(rows) - visible)
        state.scroll[state.view] = offset

        for index, row in enumerate(rows[offset : offset + visible]):
            attr = _attr(row.kind)
            if offset + index == cursor and state.view is not View.ACTIVITY:
                attr |= curses.A_REVERSE
            marker = "›" if (offset + index == cursor and row.detail) else " "
            self._put(top + index, 0, marker + row.text, attr)

        if len(rows) > visible:
            self._put(bottom - 1, width - 12,
                      f"{offset + 1}-{min(len(rows), offset + visible)}/{len(rows)}",
                      curses.A_DIM)

    def _draw_detail(self, row: Row | None, top: int, bottom: int, width: int) -> None:
        self._put(top, 0, "─" * (width - 1), curses.A_DIM)
        if row is None:
            return
        wrapped: list[str] = []
        for line in row.detail:
            wrapped.extend(_wrap(line, width - 3))
        visible = max(1, bottom - top - 1)
        offset = max(0, min(self.state.detail_scroll, max(0, len(wrapped) - visible)))
        self.state.detail_scroll = offset
        for index, line in enumerate(wrapped[offset : offset + visible]):
            self._put(top + 1 + index, 1, line)
        if len(wrapped) > visible:
            self._put(top, width - 14,
                      f" {offset + 1}-{offset + visible}/{len(wrapped)} ",
                      curses.A_DIM)

    def _draw_lines(self, lines: list[str], top: int, bottom: int, width: int) -> None:
        for index, line in enumerate(lines[: bottom - top]):
            self._put(top + index, 2, line,
                      curses.A_BOLD if line and not line.startswith(" ") else 0)

    def _draw_keybar(self, y: int, width: int) -> None:
        if self.show_help:
            keys = "any key: back"
        elif self.state.phase is Phase.SETUP:
            keys = "r run · ? help · q quit"
        elif self.state.phase is Phase.RUNNING:
            keys = "x stop · tab view · ↑↓ move · enter evidence · ? help · q stop"
        else:
            keys = ("r re-run · s save reports · tab view · ↑↓ move · "
                    "enter evidence · ? help · q quit")
        self._put(y, 0, f" {keys} ".ljust(width - 1), curses.A_REVERSE)

    # -- loop -----------------------------------------------------------------

    def loop_forever(self) -> int:
        curses.curs_set(0)
        self.stdscr.timeout(REFRESH_MS)
        while True:
            self._drain()
            self.draw()
            key = self.stdscr.getch()
            if key == -1:
                continue
            if key == curses.KEY_RESIZE:
                continue
            if not self.handle_key(key):
                break
        # A daemon worker would be killed mid-write on exit. Give a stopping run
        # a moment to close attempts.jsonl and finish its reports.
        if self.thread is not None and self.thread.is_alive():
            self.stop_run()
            self.thread.join(timeout=10)
        return 0


def launch(config: SuiteConfig, outdir: Path, formats: list[str],
           autostart: bool = False) -> int:
    def _main(stdscr: Any) -> int:
        _init_colours()
        stdscr.keypad(True)
        app = App(stdscr, config, outdir, formats)
        if autostart:
            app.start_run()
        return app.loop_forever()

    return curses.wrapper(_main)
