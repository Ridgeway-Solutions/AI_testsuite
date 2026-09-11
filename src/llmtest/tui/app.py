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
from ..types import Conversation, Role, Turn
from ..util import redact
from .console import Console
from .target_form import TargetForm
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
    "  :          the command line — point this at your own endpoint:",
    "               :target https://my-app.internal/api/chat",
    "               :response-path data.reply",
    "               :auth APP_TOKEN        (names the variable, not the key)",
    "               :test    one benign request, to prove it answers",
    "               :run     start the scan        :help  every command",
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


def _redact_target(target: dict[str, Any]) -> dict[str, Any]:
    """A target block safe to write to disk.

    ``:save-suite`` writes a file people commit. Anything that reached the
    target as a literal credential — typed at the prompt rather than named as
    an environment variable — is replaced by a reference, so the file says what
    to set instead of carrying the secret.
    """
    def clean(key: str, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: clean(k, v) for k, v in value.items()}
        # A value that already names an environment variable is the safe form,
        # wherever the reference sits in it ("Bearer ${APP_TOKEN}").
        if not isinstance(value, str) or "${" in value:
            return value
        looks_sensitive = any(
            word in key.lower()
            for word in ("authorization", "api_key", "token", "secret", "password", "key")
        )
        if looks_sensitive and value:
            return "${SET_THIS_IN_YOUR_ENVIRONMENT}"
        return redact(value)

    return {k: clean(k, v) for k, v in target.items()}


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
        self.should_quit = False
        self.probing = False
        # The target is editable from the command line, so it is held as a
        # model rather than read straight off the config: a half-typed target
        # must not become the thing a run is aimed at.
        self.form = TargetForm(config.target)
        self.console = Console(self)

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

    def start_run(self) -> str:
        """Start a scan. Returns "" or why it could not start."""
        if self.thread is not None and self.thread.is_alive():
            return "a run is already in progress"
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
        return ""

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
            elif kind == "_probe":
                self._show_probe(payload)
            elif kind == "_report_error":
                self.state.log(f"reports could not be written: {payload['error']}",
                               KIND_ERROR)
            else:
                self.state.handle(kind, payload)

    def save_reports(self) -> str:
        if self.state.result is None:
            self.state.status = "nothing to write yet — run the suite first"
            return self.state.status
        try:
            written = write_reports(self.state.result, self.outdir, self.formats)
        except Exception as exc:  # noqa: BLE001
            self.state.status = f"could not write reports: {exc}"
            return self.state.status
        self.state.reports = [str(p) for p in written]
        self.state.status = f"wrote {len(written)} report(s) to {self.outdir}"
        return self.state.status

    # -- what the command line can do -----------------------------------------
    #
    # The console owns no state of its own: every verb lands here, so the UI
    # and the command line can never disagree about what is being tested.

    def apply_target(self) -> str:
        """Adopt the edited target and re-cost the run. "" or the problem."""
        previous = self.config.target
        self.config.target = self.form.to_target()
        try:
            probe = Runner(self.config)
            pairs, skips = probe.plan()
        except Exception as exc:  # noqa: BLE001 — a bad target is the user's to fix
            self.config.target = previous
            return f"that target cannot be built: {exc}"
        self.state.set_plan(f"{probe.target.name} ({probe.target.id})",
                            len(pairs), skips)
        return ""

    def set_outdir(self, path: str) -> str:
        self.outdir = Path(path).expanduser()
        self.state.outdir = str(self.outdir)
        return str(self.outdir)

    def load_suite(self, path: str) -> str:
        try:
            config = SuiteConfig.load(path)
        except Exception as exc:  # noqa: BLE001
            return f"could not load {path}: {exc}"
        self.config = config
        self.form = TargetForm(config.target)
        self.state.suite_name = config.name
        return self.apply_target()

    def save_suite(self, path: str) -> str:
        """Write the current setup out as a suite file, so it is repeatable."""
        import yaml

        target = self.form.to_target(expand=False)
        objectives: dict[str, Any] = {}
        if self.config.objectives_file:
            objectives["file"] = self.config.objectives_file
        if self.config.include_objectives:
            objectives["include"] = self.config.include_objectives
        if self.config.categories:
            objectives["categories"] = self.config.categories
        data: dict[str, Any] = {
            "name": self.config.name,
            "target": _redact_target(target),
            "attacks": list(self.config.attacks),
            "run": {
                "concurrency": self.config.run.concurrency,
                "rate_limit_rps": self.config.run.rate_limit_rps,
                "max_turns": self.config.run.max_turns,
            },
        }
        if objectives:
            data["objectives"] = objectives
        out = Path(path).expanduser()
        out.write_text(yaml.safe_dump(data, sort_keys=False))
        return str(out)

    def plan_lines(self) -> list[str]:
        state = self.state
        lines = [
            f"{state.total_pairs} attack×objective pairs against "
            f"{state.target_label}",
            f"{len(state.objectives)} objectives · "
            f"{', '.join(self.config.attacks)}",
        ]
        if state.skips:
            reasons: dict[str, int] = {}
            for skip in state.skips:
                reasons[skip.reason] = reasons.get(skip.reason, 0) + 1
            lines.append(f"{len(state.skips)} pair(s) skipped:")
            lines += [f"  {count}× {reason}"
                      for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])]
        lines.append("nothing was sent — this is a plan")
        return lines

    def test_connection(self) -> None:
        """Send one benign request, so a wrong path or token fails in seconds.

        A scan is hundreds of requests; finding out from those that the URL was
        wrong wastes everyone's time, the endpoint's included.
        """
        if self.probing:
            return
        self.probing = True
        target = self.config.target

        def _probe() -> None:
            payload: dict[str, Any] = {}
            try:
                runner = Runner(self.config)
                conversation = Conversation(turns=[
                    Turn(Role.USER, "Hello — replying to this confirms the "
                                    "connection works.")
                ])
                response = asyncio.run(runner.target.send(conversation))
                payload = {
                    "error": response.error,
                    "text": (response.text or "")[:400],
                    "latency_ms": response.latency_ms,
                    "keys": sorted(response.raw)[:12]
                    if isinstance(response.raw, dict) else [],
                }
            except Exception as exc:  # noqa: BLE001
                payload = {"error": repr(exc), "text": "", "latency_ms": 0.0,
                           "keys": []}
            finally:
                self.events.put(("_probe", payload))

        threading.Thread(target=_probe, daemon=True, name="llmtest-probe").start()
        _ = target

    def quit(self) -> None:
        self.should_quit = True

    # -- input ----------------------------------------------------------------

    def handle_key(self, key: int) -> bool:
        """Returns False to quit."""
        state = self.state
        if self.console.open:
            self._console_key(key)
            return not self.should_quit
        if self.show_help:
            self.show_help = False
            return True

        # ':' is the way in to everything the keys do not cover — above all,
        # pointing this at an endpoint of your own.
        if key == ord(":"):
            self.console.begin()
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
        return not self.should_quit

    def _console_key(self, key: int) -> None:
        """Keys while the `:` prompt is open. Everything is text but these."""
        console = self.console
        if key in (curses.KEY_ENTER, 10, 13):
            console.submit()
        elif key == 27:                                    # esc
            console.close()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            console.backspace()
        elif key == curses.KEY_DC:
            # Delete-forward: drop the character under the cursor.
            if console.cursor < len(console.buffer):
                console.move_cursor(1)
                console.backspace()
        elif key == curses.KEY_LEFT:
            console.move_cursor(-1)
        elif key == curses.KEY_RIGHT:
            console.move_cursor(1)
        elif key == curses.KEY_HOME:
            console.cursor = 0
        elif key == curses.KEY_END:
            console.cursor = len(console.buffer)
        elif key == curses.KEY_UP:
            console.recall(-1)
        elif key == curses.KEY_DOWN:
            console.recall(1)
        elif 32 <= key < 127 or key > 159:
            console.type_char(chr(key))

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
        # Repaint every cell instead of trusting the diff curses computes
        # against its model of the terminal. That model drifts here: these
        # screens are full of multi-byte glyphs (· × → █ ↑↓) and addnstr
        # counts bytes where the terminal counts columns, so a frame shorter
        # than the one before it was leaving fragments of the old one behind —
        # including a "2 pairs will be skipped" panel sitting over a run that
        # had stopped skipping them. Stale text that reads as current is the
        # one rendering bug worth paying for, and drawing is change-driven
        # (see _signature), so an idle screen still sends nothing at all.
        self.stdscr.clearok(True)
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
            if self.console.open and self.console.output:
                # Mid-run the results view owns the screen, so the console's
                # replies appear over the bottom of it while it is in use.
                overlay = min(8, max(0, body_bottom - body_top - 2))
                if overlay:
                    self._draw_console(body_bottom - overlay, body_bottom, width)
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
                "good": KIND_HELD, "strong": KIND_HELD, "untested": KIND_UNTESTED,
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

    def _show_probe(self, payload: dict[str, Any]) -> None:
        """Report the one test request, in the console where it was asked for."""
        self.probing = False
        error = payload.get("error")
        if error:
            self.console.error(f"no answer: {error}")
            if payload.get("keys"):
                self.console.echo(
                    "  the endpoint replied, but not where we looked. "
                    "Keys in the response: " + ", ".join(payload["keys"]),
                    KIND_WARN)
                self.console.echo("  set the right one with :response-path", KIND_WARN)
            return
        self.console.ok(f"answered in {payload.get('latency_ms', 0):.0f}ms")
        for line in _wrap(payload.get("text") or "(empty reply)", 76)[:6]:
            self.console.echo(f"  {line}", KIND_MUTED)
        self.console.echo("  ready — :run starts the scan", KIND_MUTED)

    def _draw_setup(self, top: int, bottom: int, width: int) -> None:
        state = self.state
        lines = [
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
        if self.form.kind == "mock":
            # Nobody installed this to scan a fake. Say so on the screen they
            # land on, with the line that fixes it.
            lines += [
                ("  This is the offline mock: it answers with canned text and "
                 "proves nothing about your system.", _attr(KIND_WARN)),
                ("  Point it at your own endpoint:", curses.A_BOLD),
                ("      :target https://your-app.example/api/chat", curses.A_BOLD),
                ("      :response-path data.reply     where the reply sits in "
                 "the JSON", 0),
                ("      :auth  APP_TOKEN              env var holding the token",
                 0),
                ("      :test                         one benign request", 0),
                ("", 0),
                ("  Or an API:  :target openai gpt-4o-mini  ·  "
                 ":target anthropic claude-sonnet-5", 0),
            ]
        else:
            for problem in self.form.problems():
                lines.append((f"  {problem}", _attr(KIND_WARN)))
        lines.append(("", 0))
        lines.append(("  : commands (:help)   r run   ? keys   q quit",
                      curses.A_BOLD))

        y = top
        for text, attr in lines:
            if y >= bottom - 1:
                break
            self._put(y, 2, text, attr or curses.A_NORMAL)
            y += 1
        if self.console.output:
            self._draw_console(y + 1, bottom, width)

    def _draw_console(self, top: int, bottom: int, width: int) -> None:
        """The command line's scrollback: the last lines that still fit."""
        room = max(0, bottom - top)
        if room <= 0:
            return
        lines = list(self.console.output)[-room:]
        for index, line in enumerate(lines):
            self._put(top + index, 2, line.text[:width - 3], _attr(line.kind))

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
        if self.console.open:
            # The prompt replaces the key bar: while it is open every key is
            # text, so advertising single-key shortcuts there would be a lie.
            prompt = ":" + self.console.buffer
            self._put(y, 0, prompt.ljust(width - 1), curses.A_BOLD)
            # A block on the character under the cursor stands in for a real
            # terminal cursor, which stays hidden so the rest of the UI is calm.
            column = 1 + self.console.cursor
            if column < width - 1:
                under = self.console.buffer[self.console.cursor:self.console.cursor + 1]
                self._put(y, column, under or " ", curses.A_REVERSE | curses.A_BOLD)
            return
        if self.show_help:
            keys = "any key: back"
        elif self.state.phase is Phase.SETUP:
            keys = ": commands · r run · ? help · q quit"
        elif self.state.phase is Phase.RUNNING:
            keys = (": commands · x stop · tab view · ↑↓ move · enter evidence · "
                    "? help · q stop")
        else:
            keys = (": commands · r re-run · s save reports · tab view · ↑↓ move · "
                    "enter evidence · ? help · q quit")
        self._put(y, 0, f" {keys} ".ljust(width - 1), curses.A_REVERSE)

    # -- loop -----------------------------------------------------------------

    def _signature(self) -> tuple:
        """What is on screen right now, cheaply.

        Redrawing on a timer regardless of whether anything changed means the
        terminal never stops receiving output: it flickers, it burns CPU on an
        idle setup screen, and any tool reading the stream sees a repaint mid-
        flight rather than a settled frame. So the frame is drawn when — and
        only when — one of these has moved.
        """
        state = self.state
        return (
            state.phase, state.view, state.status, state.stopping,
            state.pairs_done, state.attempts, state.errored,
            len(state.findings), state.unconfirmed, len(state.feed),
            state.total_pairs, len(state.skips), state.target_label,
            state.grade, state.risk_score, tuple(state.reports),
            state.cursor[state.view], state.scroll[state.view],
            state.detail_open, state.detail_scroll,
            self.show_help, self.console.open, self.console.buffer,
            self.console.cursor, len(self.console.output), self.probing,
            self.stdscr.getmaxyx(),
        )

    def loop_forever(self) -> int:
        curses.curs_set(0)
        self.stdscr.timeout(REFRESH_MS)
        signature = None
        while True:
            self._drain()
            current = self._signature()
            if current != signature:
                self.draw()
                signature = current
            key = self.stdscr.getch()
            if key == -1:
                continue
            if key == curses.KEY_RESIZE:
                signature = None          # the whole frame has to be rebuilt
                continue
            if not self.handle_key(key) or self.should_quit:
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
