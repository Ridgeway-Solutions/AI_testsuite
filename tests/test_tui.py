"""The terminal UI, tested without a terminal.

Everything that decides what is on screen lives in ``tui.state``, so almost all
of this runs against plain data. The curses layer is exercised only for the
parts that are pure logic anyway: key dispatch and text wrapping.
"""

import asyncio

import pytest

from llmtest.config import SuiteConfig
from llmtest.objectives import load_objectives
from llmtest.runner import Runner, Skip
from llmtest.scoring import CONFIDENCE_FLOOR, Outcome
from llmtest.tui.state import (
    KIND_FAIL,
    KIND_HELD,
    KIND_MUTED,
    KIND_UNTESTED,
    VIEWS,
    Phase,
    TuiState,
    View,
    finding_detail,
)

CATALOG = load_objectives()


def only(ids):
    return [o for o in CATALOG if o.id in ids]


def state(ids=("canary.secret_token", "leak.system_prompt"), **kw):
    return TuiState(
        suite_name="t",
        target_label="mock (mock)",
        objectives=only(set(ids)),
        **kw,
    )


def attempt(
    objective="canary.secret_token",
    attack="obfuscation",
    success=True,
    confidence=1.0,
    severity="critical",
    error=None,
    variant="base64",
):
    return {
        "id": "a" * 12,
        "objective": objective,
        "attack": attack,
        "variant": variant,
        "category": "confidentiality",
        "severity": severity,
        "success": success,
        "confidence": confidence,
        "risk": confidence if success else 0.0,
        "turns": 1,
        "response": {"text": "here you go", "latency_ms": 3.0, "error": error,
                     "blocked": False},
        "verdicts": [{"success": success, "confidence": confidence,
                      "detector": "canary", "rationale": "canary present",
                      "signals": {}}],
        "conversation": {"label": variant, "meta": {},
                         "turns": [{"role": "user", "content": "decode this"}]},
    }


# -- event handling ----------------------------------------------------------


def test_run_start_sets_the_pair_total():
    s = state()
    s.handle("run_start", {"pairs": 12, "attacks": 3, "objectives": 4, "skipped": 2})
    assert s.phase is Phase.RUNNING
    assert s.total_pairs == 12
    assert s.progress == 0.0


def test_progress_tracks_completed_pairs():
    s = state()
    s.handle("run_start", {"pairs": 4, "attacks": 1, "objectives": 4, "skipped": 0})
    s.handle("pair_end", {"attack": "direct", "objective": "x"})
    assert s.progress == pytest.approx(0.25)
    for _ in range(9):
        s.handle("pair_end", {"attack": "direct", "objective": "x"})
    # More pair_end events than planned pairs must not report 250% done.
    assert s.progress == 1.0


def test_progress_is_zero_when_nothing_is_planned():
    assert state().progress == 0.0


def test_a_confident_hit_becomes_a_finding():
    s = state()
    s.handle("attempt", attempt())
    assert len(s.findings) == 1
    assert s.unconfirmed == 0
    assert s.by_objective["canary.secret_token"]["hits"] == 1
    assert s.by_objective["canary.secret_token"]["breakers"] == {"obfuscation"}


def test_a_hit_below_the_confidence_floor_is_not_a_finding():
    s = state()
    s.handle("attempt", attempt(confidence=CONFIDENCE_FLOOR - 0.01))
    assert s.findings == []
    assert s.unconfirmed == 1
    assert s.by_objective["canary.secret_token"]["hits"] == 0


def test_an_errored_attempt_can_never_be_a_finding():
    # Mirrors scoring.score(): there is no model output to judge, so a detector
    # firing on "" must not read as a bypass.
    s = state()
    s.handle("attempt", attempt(success=True, confidence=1.0, error="timeout"))
    assert s.findings == []
    assert s.unconfirmed == 0
    assert s.errored == 1
    assert s.by_objective["canary.secret_token"]["errors"] == 1


def test_a_crashed_technique_is_recorded_not_swallowed():
    s = state()
    s.handle("attack_error", {"attack": "crescendo", "objective": "x",
                              "error": "RuntimeError()"})
    assert len(s.crashes) == 1
    assert any("crashed" in line.text for line in s.feed)


def test_warnings_and_stop_early_reach_the_feed():
    s = state()
    s.handle("warning", {"message": "no detectors", "objectives": ["a", "b"]})
    s.handle("stop_early", {"criticals": 3})
    text = " ".join(line.text for line in s.feed)
    assert "no detectors" in text and "a, b" in text
    assert "critical limit reached" in text


def test_unknown_events_are_ignored():
    s = state()
    s.handle("something_new", {"whatever": 1})  # must not raise
    assert not s.feed


def test_the_feed_is_bounded():
    from llmtest.tui.state import MAX_FEED

    s = state()
    for i in range(MAX_FEED + 50):
        s.log(f"line {i}")
    assert len(s.feed) == MAX_FEED


# -- views -------------------------------------------------------------------


def test_mid_run_boundaries_never_claim_a_pass():
    # A boundary nothing has hit *yet* is not a boundary that held. Showing
    # PASS mid-run would be the same lie as scoring an untested boundary green.
    s = state()
    s.handle("attempt", attempt(objective="leak.system_prompt", success=False,
                                confidence=0.0, severity="high"))
    text = " ".join(row.text for row in s.rows(View.BOUNDARIES))
    assert "PASS" not in text and "FAIL" not in text
    assert "no hits yet" in text


def test_an_objective_with_no_attempts_reads_as_not_started():
    s = state()
    rows = s.rows(View.BOUNDARIES)
    assert all(row.kind == KIND_MUTED for row in rows)
    assert all("not started" in row.text for row in rows)


def test_finished_boundaries_use_the_authoritative_outcomes():
    config = SuiteConfig.from_dict(
        {"name": "t", "target": {"type": "mock", "profile": "vulnerable"},
         "attacks": ["direct", "obfuscation"]}
    )
    objectives = only({"canary.secret_token", "leak.system_prompt"})
    result = asyncio.run(Runner(config, objectives=objectives).run())

    s = state(ids={o.id for o in objectives})
    s.finish(result, reports=["runs/latest/report.md"])
    assert s.phase is Phase.DONE
    assert s.reports == ["runs/latest/report.md"]
    assert s.grade
    rows = s.rows(View.BOUNDARIES)
    assert len(rows) == len(objectives)
    assert {row.kind for row in rows} <= {KIND_FAIL, KIND_HELD, KIND_UNTESTED}
    assert any(o.outcome is Outcome.FAIL for o in s.outcomes)


def test_a_skipped_boundary_explains_why_it_never_ran():
    objective = only({"canary.secret_token"})[0]
    skip = Skip("prefill", objective.id, "target lacks ['prefill']")
    s = state(ids={objective.id}, skips=[skip])

    config = SuiteConfig.from_dict({"name": "t", "target": {"type": "mock"}})
    result = asyncio.run(
        Runner(config, objectives=[objective], attacks=[]).run()
    )
    s.finish(result)

    row = s.rows(View.BOUNDARIES)[0]
    assert "NOT RUN" in row.text
    assert row.kind == KIND_UNTESTED
    assert any("target lacks" in line for line in row.detail)


def test_findings_are_ordered_worst_first():
    s = state()
    s.handle("attempt", attempt(severity="medium", confidence=0.6,
                                objective="leak.system_prompt"))
    s.handle("attempt", attempt(severity="critical", confidence=1.0))
    rows = s.rows(View.FINDINGS)
    assert "critical" in rows[0].text
    assert rows[0].detail  # evidence is attached


def test_no_findings_says_so():
    rows = state().rows(View.FINDINGS)
    assert len(rows) == 1
    assert "no confirmed findings" in rows[0].text
    assert not rows[0].detail


def test_techniques_are_scored_as_lift_over_the_control():
    s = state()
    s.handle("attempt", attempt(attack="direct", success=False, confidence=0.0))
    s.handle("attempt", attempt(attack="obfuscation"))
    rows = {row.text.split()[0]: row.text for row in s.rows(View.TECHNIQUES)}
    assert "(control)" in rows["direct"]
    assert "+100% vs control" in rows["obfuscation"]


def test_techniques_say_so_when_no_control_ran():
    s = state()
    s.handle("attempt", attempt(attack="obfuscation"))
    assert "(no control ran)" in s.rows(View.TECHNIQUES)[0].text


def test_asr_ignores_errored_attempts():
    s = state()
    s.handle("attempt", attempt(attack="direct", error="boom"))
    s.handle("attempt", attempt(attack="direct"))
    # One errored, one confirmed hit. An unreachable endpoint must not dilute
    # the rate: that is 1 of 1 scored, not 1 of 2.
    row = s.rows(View.TECHNIQUES)[0].text
    assert "2 tried" in row and "1 hit" in row
    assert "ASR  100%" in row


def test_an_all_errored_technique_does_not_divide_by_zero():
    s = state()
    s.handle("attempt", attempt(attack="direct", error="boom"))
    assert "ASR    0%" in s.rows(View.TECHNIQUES)[0].text


# -- evidence pane -----------------------------------------------------------


def test_finding_detail_shows_payload_detector_and_response():
    lines = "\n".join(finding_detail(attempt()))
    assert "canary.secret_token" in lines
    assert "obfuscation/base64" in lines
    assert "decode this" in lines
    assert "here you go" in lines
    assert "canary present" in lines


def test_finding_detail_says_when_payloads_were_withheld():
    payload = attempt()
    del payload["conversation"]
    lines = "\n".join(finding_detail(payload))
    assert "withheld" in lines


def test_finding_detail_shows_a_transport_error_instead_of_text():
    lines = "\n".join(finding_detail(attempt(error="connection refused")))
    assert "connection refused" in lines


def test_finding_detail_truncates_a_huge_response():
    from llmtest.tui.state import MAX_DETAIL_LINES

    payload = attempt()
    payload["response"]["text"] = "\n".join(str(i) for i in range(MAX_DETAIL_LINES * 3))
    lines = finding_detail(payload)
    assert any("truncated" in line for line in lines)
    assert len(lines) < MAX_DETAIL_LINES * 3


def test_finding_detail_survives_a_sparse_payload():
    # Payload shape is stable, but a detail pane must not be the thing that
    # crashes the UI if a field is ever missing.
    lines = finding_detail({"objective": "o", "attack": "a", "response": {}})
    assert "o" in "\n".join(lines)


# -- navigation --------------------------------------------------------------


def test_the_cursor_stays_inside_the_list():
    s = state()
    for _ in range(3):
        s.handle("attempt", attempt())
    s.set_view(View.FINDINGS)
    s.move(50)
    assert s.cursor[View.FINDINGS] == 2
    s.move(-50)
    assert s.cursor[View.FINDINGS] == 0


def test_views_cycle_both_ways():
    s = state()
    s.cycle_view(-1)
    assert s.view is VIEWS[-1]
    s.cycle_view(1)
    assert s.view is VIEWS[0]


def test_switching_view_closes_the_detail_pane():
    s = state()
    s.handle("attempt", attempt())
    s.set_view(View.FINDINGS)
    s.toggle_detail()
    assert s.detail_open
    s.set_view(View.TECHNIQUES)
    assert not s.detail_open


def test_detail_only_opens_on_a_row_that_has_evidence():
    s = state()
    s.set_view(View.TECHNIQUES)  # technique rows carry no detail
    s.handle("attempt", attempt())
    s.toggle_detail()
    assert not s.detail_open


def test_move_scrolls_the_detail_pane_when_it_is_open():
    s = state()
    s.handle("attempt", attempt())
    s.set_view(View.FINDINGS)
    s.toggle_detail()
    s.move(5)
    assert s.detail_scroll == 5
    assert s.cursor[View.FINDINGS] == 0  # the list did not move underneath it
    s.move(-99)
    assert s.detail_scroll == 0


def test_jump_goes_to_the_ends():
    s = state()
    for i in range(4):
        s.handle("attempt", attempt(variant=f"v{i}"))
    s.set_view(View.FINDINGS)
    s.jump(to_end=True)
    assert s.cursor[View.FINDINGS] == 3
    s.jump(to_end=False)
    assert s.cursor[View.FINDINGS] == 0


def test_selected_survives_the_list_shrinking_under_the_cursor():
    s = state()
    for i in range(3):
        s.handle("attempt", attempt(variant=f"v{i}"))
    s.set_view(View.FINDINGS)
    s.jump(to_end=True)
    s.findings.clear()  # e.g. a re-run started
    assert s.selected() is not None


# -- lifecycle ---------------------------------------------------------------


def test_reset_clears_the_previous_run():
    s = state()
    s.handle("attempt", attempt())
    s.handle("attack_error", {"attack": "a", "objective": "b", "error": "e"})
    s.reset_for_run(pairs=8, skips=[])
    assert s.phase is Phase.RUNNING
    assert s.findings == [] and s.crashes == [] and not s.feed
    assert s.by_attack == {} and s.by_objective == {}
    assert s.total_pairs == 8 and s.pairs_done == 0
    assert s.outcomes == [] and s.result is None


def test_a_failed_run_is_reported_not_hidden():
    s = state()
    s.fail("ConnectionError()")
    assert s.phase is Phase.FAILED
    assert "ConnectionError" in s.error_message
    assert any("run failed" in line.text for line in s.feed)


# -- the curses layer --------------------------------------------------------

app_module = pytest.importorskip("llmtest.tui.app")


def test_wrap_breaks_lines_that_have_no_spaces():
    # Model output can be one enormous token; wrapping must not depend on words.
    wrapped = app_module._wrap("x" * 250, 80)
    assert all(len(line) <= 80 for line in wrapped)
    assert "".join(wrapped) == "x" * 250


def test_wrap_keeps_existing_newlines():
    assert app_module._wrap("a\nb", 80) == ["a", "b"]


def test_wrap_survives_an_absurdly_narrow_pane():
    assert app_module._wrap("hello", 1)  # must not loop forever or raise


def test_attr_falls_back_to_weight_without_colour():
    app_module._PAIRS.clear()
    import curses

    assert app_module._attr(KIND_FAIL) == curses.A_BOLD
    assert app_module._attr("plain") == curses.A_NORMAL


class FakeScreen:
    """Just enough stdscr for key dispatch, which never draws."""

    def getmaxyx(self):
        return (40, 120)

    def addnstr(self, *a, **k):
        pass

    def erase(self):
        pass

    def refresh(self):
        pass

    def timeout(self, ms):
        pass

    def keypad(self, flag):
        pass


def make_app(tmp_path, attacks=("direct",), rate_limit_rps=0.0, **target):
    config = SuiteConfig.from_dict(
        {"name": "t", "target": {"type": "mock", **target},
         "attacks": list(attacks),
         "objectives": {"include": ["canary.secret_token"]},
         "run": {"rate_limit_rps": rate_limit_rps}}
    )
    return app_module.App(FakeScreen(), config, tmp_path, ["json"])


def test_the_app_plans_before_running_anything(tmp_path):
    app = make_app(tmp_path)
    assert app.state.phase is Phase.SETUP
    assert app.state.total_pairs >= 1
    assert not (tmp_path / "attempts.jsonl").exists()


def test_number_keys_select_views(tmp_path):
    app = make_app(tmp_path)
    for index, view in enumerate(VIEWS, start=1):
        app.handle_key(ord(str(index)))
        assert app.state.view is view


def test_q_quits_when_nothing_is_running(tmp_path):
    assert make_app(tmp_path).handle_key(ord("q")) is False


def test_help_opens_and_any_key_closes_it(tmp_path):
    app = make_app(tmp_path)
    app.handle_key(ord("?"))
    assert app.show_help
    assert app.handle_key(ord("q")) is True  # dismisses rather than quitting
    assert not app.show_help


def test_saving_before_a_run_says_there_is_nothing_to_save(tmp_path):
    app = make_app(tmp_path)
    app.handle_key(ord("s"))
    assert "nothing to write" in app.state.status


def test_a_full_run_through_the_app_produces_reports(tmp_path):
    app = make_app(tmp_path, profile="vulnerable")
    app.start_run()
    app.thread.join(timeout=60)
    assert not app.thread.is_alive()
    app._drain()

    assert app.state.phase is Phase.DONE
    assert app.state.result is not None
    assert app.state.attempts > 0
    assert app.state.pairs_done == app.state.total_pairs
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "attempts.jsonl").exists()
    assert app.state.reports


def test_stopping_a_run_that_is_not_running_is_a_no_op(tmp_path):
    app = make_app(tmp_path)
    app.stop_run()  # must not raise
    assert not app.state.stopping


def test_re_running_clears_the_previous_result(tmp_path):
    app = make_app(tmp_path, profile="vulnerable")
    app.start_run()
    app.thread.join(timeout=60)
    app._drain()
    first = app.state.attempts
    assert first > 0

    app.handle_key(ord("r"))
    assert app.state.phase is Phase.RUNNING
    assert app.state.attempts == 0
    app.thread.join(timeout=60)
    app._drain()
    assert app.state.phase is Phase.DONE


def test_a_run_will_not_start_twice(tmp_path):
    # Rate-limited so the run is certainly still in flight when the second
    # start_run lands. Against the unthrottled mock it finishes in
    # milliseconds, and this test then raced it: replacing a thread that has
    # already exited is correct behaviour, so the assertion failed for a
    # reason that had nothing to do with the guard being tested.
    app = make_app(tmp_path, attacks=["direct", "obfuscation", "persona"],
                   rate_limit_rps=2)
    app.start_run()
    thread = app.thread
    assert thread.is_alive()

    app.start_run()
    assert app.thread is thread  # the second call was a no-op

    app.stop_run()
    thread.join(timeout=60)
    assert not thread.is_alive()


# -- the : command line ------------------------------------------------------
#
# The console is how someone points this at their own endpoint without writing
# YAML, so these drive it the way a user does: by typing lines.

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

from llmtest.tui.console import Console
from llmtest.tui.target_form import TargetForm


class FakeHost:
    """Everything the console is allowed to do, recorded rather than done."""

    def __init__(self, config=None, pairs=4):
        self.config = config or SuiteConfig()
        self.form = TargetForm(self.config.target)
        self.outdir = Path("reports")
        self.state = SimpleNamespace(total_pairs=pairs, target_label="t (t)",
                                     objectives=[], skips=[])
        self.applied = 0
        self.runs = 0
        self.stops = 0
        self.probes = 0
        self.quits = 0
        self.saved_suite = None
        self.apply_error = ""

    def apply_target(self):
        self.applied += 1
        if not self.apply_error:
            self.config.target = self.form.to_target()
        return self.apply_error

    def set_outdir(self, path):
        self.outdir = Path(path)
        return str(self.outdir)

    def load_suite(self, path):
        return f"could not load {path}: no such file"

    def save_suite(self, path):
        self.saved_suite = path
        return path

    def plan_lines(self):
        return ["a plan", "another line", "1 pair(s) skipped:", "  1× because"]

    def test_connection(self):
        self.probes += 1

    def start_run(self):
        self.runs += 1
        return ""

    def stop_run(self):
        self.stops += 1

    def save_reports(self):
        return "wrote 1 report(s)"

    def quit(self):
        self.quits += 1


def console(**kw):
    return Console(FakeHost(**kw))


def test_a_url_points_the_run_at_your_own_endpoint():
    c = console()
    c.execute("target https://my-app.internal/api/chat")
    assert c.host.form.kind == "http"
    assert c.host.config.target["url"] == "https://my-app.internal/api/chat"
    assert c.host.applied == 1


def test_a_provider_and_model_can_be_named_in_one_line():
    c = console()
    c.execute("target anthropic claude-sonnet-5")
    target = c.host.config.target
    assert target["type"] == "anthropic"
    assert target["model"] == "claude-sonnet-5"


def test_switching_provider_keeps_each_ones_model():
    # Comparing two providers is a normal thing to do; typing the model in
    # again each time is not.
    c = console()
    c.execute("target openai gpt-4o-mini")
    c.execute("target anthropic claude-sonnet-5")
    c.execute("target openai")
    assert c.host.config.target["model"] == "gpt-4o-mini"


def test_only_http_and_https_targets_are_accepted():
    # This sends attack payloads. "Point it at anything" must not extend to
    # file:// (read the disk) or gopher:// (whatever that reaches).
    c = console()
    for bad in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x"):
        c.execute(f"target {bad}")
        assert "not allowed" in c.last, bad
    assert c.host.form.kind != "http" or not c.host.form.value_of(
        next(f for f in c.host.form.fields if f.key == "url")
    )


def test_a_pasted_key_is_refused_in_favour_of_its_variable_name():
    # A key typed at a prompt lands in scrollback and in screenshots.
    c = console()
    c.execute("auth sk-live-abcdef0123456789")
    assert "looks like a key" in c.last
    assert "api_key_env" not in c.host.config.target


def test_auth_names_an_environment_variable(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "s3cret")
    c = console()
    c.execute("target https://my-app.internal/api/chat")
    c.execute("auth APP_TOKEN")
    # The suite-facing target holds the resolved header, and the form still
    # holds the reference, so a saved suite carries the variable not the value.
    assert c.host.config.target["headers"]["Authorization"] == "Bearer s3cret"
    assert c.host.form.to_target(expand=False)["headers"]["Authorization"] == \
        "Bearer ${APP_TOKEN}"


def test_an_unknown_command_says_so_rather_than_dying():
    c = console()
    c.execute("trget https://x")
    assert "unknown command" in c.last


def test_an_unbalanced_quote_is_reported_not_raised():
    c = console()
    c.execute('header x-api-key "unclosed')
    assert "could not parse" in c.last


def test_run_is_refused_until_the_target_is_complete():
    c = console()
    c.execute("target http")          # type set, no url yet
    c.execute("run")
    assert c.host.runs == 0
    assert "required" in c.last


def test_run_is_refused_when_every_pair_would_be_skipped():
    # The dangerous case: an empty plan finishes instantly and would otherwise
    # report a clean bill of health for a system that was never sent anything.
    c = console(pairs=0)
    c.execute("target https://my-app.internal/api/chat")
    c.execute("run")
    assert c.host.runs == 0
    assert "nothing to run" in c.output[-4].text


def test_test_sends_one_request_only_when_the_target_is_usable():
    c = console()
    c.execute("target http")          # an http target with no url yet
    c.execute("test")
    assert c.host.probes == 0
    assert "required" in c.last
    c.execute("target https://my-app.internal/api/chat")
    c.execute("test")
    assert c.host.probes == 1


def test_the_prompt_keeps_a_history():
    c = console()
    c.begin()
    for char in "show":
        c.type_char(char)
    c.submit()
    c.begin()
    c.recall(-1)
    assert c.buffer == "show"
    c.recall(1)
    assert c.buffer == ""


def test_backspacing_off_the_start_closes_the_prompt():
    c = console()
    c.begin()
    c.type_char("x")
    c.backspace()
    assert c.open
    c.backspace()
    assert not c.open


def test_help_lists_every_command_and_explains_one():
    c = console()
    c.execute("help")
    listed = "\n".join(line.text for line in c.output)
    assert ":target" in listed and ":run" in listed
    c.execute("help response-path")
    assert "where the reply sits" in "\n".join(line.text for line in c.output)


# -- end to end: a real endpoint, pointed at from inside the UI ---------------


class _Endpoint(BaseHTTPRequestHandler):
    """A deliberately weak app: it repeats its system prompt when pushed.

    Weak on purpose — a scan that can never find anything proves only that the
    request plumbing works, and the plumbing is exactly what this test is for.
    """

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        messages = body.get("messages")
        if isinstance(messages, list):
            system = " ".join(str(m.get("content", "")) for m in messages
                              if m.get("role") == "system")
            asked = " ".join(str(m.get("content", "")) for m in messages
                             if m.get("role") != "system")
        else:
            system, asked = "", str(body.get("message", ""))
        reply = "I can't help with that."
        if system and len(asked) > 0:
            reply = f"Of course! My instructions say: {system}"
        payload = json.dumps({"data": {"reply": reply}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def endpoint():
    server = HTTPServer(("127.0.0.1", 0), _Endpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/api/chat"
    server.shutdown()
    server.server_close()


def drain_until(app, done, limit=600):
    import time

    for _ in range(limit):
        app._drain()
        if done():
            return True
        time.sleep(0.02)
    return False


def test_a_downloaded_copy_can_be_pointed_at_an_endpoint_and_run(tmp_path, endpoint):
    # The whole reason the console exists: install, open the UI, type where
    # your thing lives, and scan it. No suite file is written or read.
    config = SuiteConfig.from_dict({
        "name": "adhoc",
        "attacks": ["direct", "obfuscation"],
        "objectives": {"include": ["canary.secret_token"]},
        "run": {"concurrency": 2},
    })
    app = app_module.App(FakeScreen(), config, tmp_path, ["json"])
    assert app.form.kind == "mock", "with no suite it starts on the offline fake"

    app.console.execute(f"target {endpoint}")
    app.console.execute("response-path data.reply")
    app.console.execute("field messages")
    app.console.execute("system You are Acme support. The token is SWORDFISH-4417.")

    app.console.execute("test")
    assert drain_until(app, lambda: not app.probing), "the probe never came back"
    assert "answered in" in "\n".join(line.text for line in app.console.output)

    app.console.execute("run")
    assert drain_until(app, lambda: app.state.phase in (Phase.DONE, Phase.FAILED))
    assert app.state.phase is Phase.DONE, app.state.error_message
    assert app.state.attempts > 0
    # It really talked to the endpoint: the weak app leaks its instructions, so
    # the canary objective has to have fired.
    assert app.state.findings, "a leaking endpoint produced no finding"
    assert app.state.grade != "untested"


def test_a_saved_suite_carries_the_variable_name_not_the_key(tmp_path, endpoint,
                                                             monkeypatch):
    # :save-suite writes a file people commit. It must never contain the token.
    monkeypatch.setenv("APP_TOKEN", "sk-live-do-not-commit-me")
    app = app_module.App(FakeScreen(), SuiteConfig(), tmp_path, ["json"])
    app.console.execute(f"target {endpoint}")
    app.console.execute("auth APP_TOKEN")
    written = Path(app.save_suite(str(tmp_path / "adhoc.yaml")))

    text = written.read_text()
    assert "sk-live-do-not-commit-me" not in text
    assert "${APP_TOKEN}" in text
    # And it is a suite the CLI can actually run.
    reloaded = SuiteConfig.load(written)
    assert reloaded.target["url"] == endpoint


def test_an_empty_plan_is_never_graded_as_a_pass():
    # The most dangerous output this tool could produce: a clean bill of health
    # for a system that was never sent a single payload.
    from llmtest.scoring import score

    assert score([]).grade == "untested"


def test_an_all_errored_run_is_not_graded_as_a_pass():
    # A wrong URL, a dead service or a response path that matches nothing all
    # produce a wall of errors. None of them is evidence a boundary held, so
    # the run is untested — the same as one that sent nothing.
    from llmtest.scoring import score
    from llmtest.types import Attempt, Response, Severity

    def errored():
        return Attempt(
            attack_id="direct", objective_id="canary.secret_token",
            conversation=None, response=Response(text="", error="connection refused"),
            verdicts=[], severity=Severity.CRITICAL, category="confidentiality",
            variant=None,
        )

    board = score([errored(), errored()])
    assert board.total.attempts == 2
    assert board.grade == "untested"


def test_the_screen_is_repainted_whole(tmp_path):
    # erase() alone left fragments of the previous frame behind — these screens
    # are full of multi-byte glyphs and curses' model of the terminal drifts.
    # A stale panel reads as current, so the frame is painted in full.
    class Clearing(FakeScreen):
        cleared = False

        def clearok(self, flag):
            Clearing.cleared = bool(flag)

    app = app_module.App(Clearing(), SuiteConfig(), tmp_path, ["json"])
    app.draw()
    assert Clearing.cleared, "draw() must repaint every cell"


def test_an_idle_screen_is_not_redrawn(tmp_path):
    # The other half of the deal: a full repaint on a timer would never stop
    # writing to the terminal. Nothing changed means nothing is drawn.
    app = make_app(tmp_path)
    before = app._signature()
    assert app._signature() == before
    app.console.execute("show")
    assert app._signature() != before, "console output has to force a redraw"
