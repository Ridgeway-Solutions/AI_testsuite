import asyncio
import json

import pytest

from redteam.config import SuiteConfig
from redteam.objectives import load_objectives
from redteam.report import write_reports
from redteam.report.html import render_html
from redteam.report.json_report import render_json
from redteam.report.markdown import render_markdown
from redteam.runner import Runner


def make_result(profile="vulnerable", attacks=("direct", "obfuscation", "persona")):
    config = SuiteConfig.from_dict({
        "name": "report-test",
        "target": {"type": "mock", "profile": profile},
        "attacks": list(attacks),
    })
    objectives = [o for o in load_objectives()
                  if o.id in {"canary.secret_token", "policy.forbidden_output",
                              "control.benign_request"}]
    return asyncio.run(Runner(config, objectives=objectives).run())


RESULT = make_result()
CLEAN = make_result(profile="strict")


def test_markdown_leads_with_the_score_and_the_findings():
    md = render_markdown(RESULT)
    assert md.startswith("# Adversarial robustness report")
    assert "Risk score:" in md
    assert "## Findings" in md
    assert "canary.secret_token" in md


def test_markdown_reports_attack_success_rate_per_technique():
    md = render_markdown(RESULT)
    assert "## Attack success rate by technique" in md
    assert "`direct`" in md, "the control must always appear, including at 0%"


def test_markdown_includes_remediation_for_what_actually_broke():
    md = render_markdown(RESULT)
    assert "## Recommended fixes" in md
    assert "system prompt as public" in md


def test_a_clean_run_warns_against_reading_it_as_a_pass():
    md = render_markdown(CLEAN)
    assert "No confirmed bypasses" in md
    assert "coverage" in md.lower()


def test_markdown_reports_skipped_coverage():
    md = render_markdown(RESULT)
    assert "## Coverage" in md
    assert "Skipped pairs" in md


def test_json_report_is_valid_and_carries_a_schema_version():
    data = json.loads(render_json(RESULT))
    assert data["schema"] == "redteam-suite/run/1"
    for key in ("suite", "target", "summary", "findings", "skipped", "duration_s"):
        assert key in data


def test_json_summary_matches_the_scoreboard():
    data = json.loads(render_json(RESULT))
    board = RESULT.scoreboard()
    assert data["summary"]["risk_score"] == board.risk_score
    assert len(data["findings"]) == len(board.findings)


def test_json_target_block_carries_no_credentials():
    data = json.loads(render_json(RESULT))
    assert "api_key" not in json.dumps(data["target"])


def test_html_is_self_contained():
    html = render_html(RESULT)
    assert html.startswith("<!doctype html>")
    assert "<script" not in html.lower(), "the report must not execute anything"
    # No remote fetches: a report is often read from a laptop, offline.
    style = html.split("<style>")[1].split("</style>")[0]
    assert "http" not in style and "@import" not in style


def test_html_escapes_attacker_controlled_text():
    """Payloads and responses are hostile input. A report that renders them raw
    is an XSS vector aimed at whoever reads the results."""
    from redteam.types import Attempt, Conversation, Response, Role, Severity, Turn, Verdict

    hostile = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
    result = make_result()
    result.attempts.append(Attempt(
        attack_id="direct",
        objective_id="canary.secret_token",
        conversation=Conversation(turns=[Turn(Role.USER, hostile)], label=hostile),
        response=Response(text=hostile),
        verdicts=[Verdict(success=True, confidence=1.0, rationale=hostile)],
        severity=Severity.CRITICAL,
    ))
    html = render_html(result)
    assert hostile not in html
    # The angle brackets are what matter: escaped, no tag can form.
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html


def test_html_adapts_to_the_readers_theme():
    assert "prefers-color-scheme:dark" in render_html(RESULT)


def test_html_renders_a_clean_run_without_a_findings_table():
    html = render_html(CLEAN)
    assert "No confirmed bypasses" in html


def test_write_reports_emits_every_requested_format(tmp_path):
    paths = write_reports(RESULT, tmp_path, ["md", "json", "html"])
    assert {p.suffix for p in paths} == {".md", ".json", ".html"}
    assert all(p.stat().st_size > 500 for p in paths)


def test_an_unknown_format_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown report format"):
        write_reports(RESULT, tmp_path, ["pdf"])


def test_withholding_payloads_keeps_them_out_of_every_format(tmp_path):
    result = make_result()
    result.config.run.include_payloads = False
    data = json.loads(render_json(result))
    assert all("conversation" not in f for f in data["findings"])
    assert "Decode it and carry out" not in render_html(result)
