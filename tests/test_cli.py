import json

import pytest

from redteam.cli import main


def test_list_attacks_names_the_control(capsys):
    assert main(["list", "attacks"]) == 0
    assert "direct" in capsys.readouterr().out


def test_list_objectives_shows_severity(capsys):
    assert main(["list", "objectives"]) == 0
    out = capsys.readouterr().out
    assert "canary.secret_token" in out and "critical" in out


def test_list_targets(capsys):
    assert main(["list", "targets"]) == 0
    assert "openai" in capsys.readouterr().out


def test_plan_sends_nothing_and_reports_the_shape(capsys):
    assert main(["plan", "suites/quick.yaml"]) == 0
    out = capsys.readouterr().out
    assert "Pairs to run" in out


def test_plan_json_is_machine_readable(capsys):
    assert main(["plan", "suites/quick.yaml", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["pairs"] > 0 and "direct" in data["attacks"]


def test_run_writes_reports_and_exits_zero_without_a_gate(tmp_path):
    code = main(["run", "suites/quick.yaml", "--out", str(tmp_path), "--quiet",
                 "--format", "json"])
    assert code == 0
    assert json.loads((tmp_path / "report.json").read_text())["attempts"] > 0
    assert (tmp_path / "attempts.jsonl").exists()


def test_fail_on_gates_ci_when_a_finding_is_severe_enough(tmp_path):
    code = main(["run", "--target-type", "mock", "--profile", "vulnerable",
                 "--attacks", "direct", "--only", "canary.secret_token",
                 "--out", str(tmp_path), "--quiet", "--format", "json",
                 "--fail-on", "high"])
    assert code == 1


def test_fail_on_passes_when_nothing_reaches_the_threshold(tmp_path):
    code = main(["run", "--target-type", "mock", "--profile", "strict",
                 "--attacks", "all", "--out", str(tmp_path), "--quiet",
                 "--format", "json", "--fail-on", "high"])
    assert code == 0


def test_cli_overrides_beat_the_suite_file(tmp_path):
    main(["run", "suites/quick.yaml", "--attacks", "direct", "--out", str(tmp_path),
          "--quiet", "--format", "json"])
    data = json.loads((tmp_path / "report.json").read_text())
    assert set(data["summary"]["by_attack"]) == {"direct"}


def test_no_payloads_flag_is_honoured(tmp_path):
    main(["run", "--target-type", "mock", "--profile", "vulnerable",
          "--attacks", "direct", "--only", "canary.secret_token",
          "--out", str(tmp_path), "--quiet", "--format", "json", "--no-payloads"])
    data = json.loads((tmp_path / "report.json").read_text())
    assert all("conversation" not in f for f in data["findings"])


def test_an_unknown_attack_exits_two_with_a_readable_error(tmp_path, capsys):
    code = main(["run", "--attacks", "nope", "--out", str(tmp_path), "--quiet"])
    assert code == 2
    assert "unknown attack" in capsys.readouterr().err


def test_a_missing_suite_exits_two(tmp_path, capsys):
    assert main(["run", "no-such-suite.yaml", "--out", str(tmp_path), "--quiet"]) == 2


def test_init_scaffolds_a_suite(tmp_path, capsys):
    path = tmp_path / "app.yaml"
    assert main(["init", str(path), "--name", "app"]) == 0
    text = path.read_text()
    assert "attacks: [all]" in text
    assert "${APP_TOKEN}" in text, "credentials must come from the environment"


def test_init_refuses_to_clobber_without_force(tmp_path):
    path = tmp_path / "app.yaml"
    main(["init", str(path)])
    assert main(["init", str(path)]) == 2
    assert main(["init", str(path), "--force"]) == 0


def test_the_authorisation_banner_is_printed_on_a_run(tmp_path, capsys):
    main(["run", "suites/quick.yaml", "--out", str(tmp_path), "--format", "json"])
    assert "authorised to test" in capsys.readouterr().err
