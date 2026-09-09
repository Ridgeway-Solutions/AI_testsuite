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


# -- the gate must not pass a run that tested nothing -------------------------


def test_an_unknown_objective_id_is_a_config_error_not_an_empty_green_run(tmp_path, capsys):
    """`--only typo` used to yield 0 pairs, grade "strong", exit 0 — a CI gate
    passing on a scan that exercised nothing."""
    code = main(["run", "--target-type", "mock", "--only", "bogus.id",
                 "--out", str(tmp_path), "--quiet", "--format", "json"])
    assert code == 2
    assert "unknown objective" in capsys.readouterr().err


def test_an_unmatched_category_is_a_config_error(tmp_path, capsys):
    code = main(["run", "--target-type", "mock", "--category", "nonsense",
                 "--out", str(tmp_path), "--quiet", "--format", "json"])
    assert code == 2
    assert "no objective matches" in capsys.readouterr().err


def test_an_unreachable_target_fails_the_gate_instead_of_passing_it(tmp_path):
    """Every boundary INCONCLUSIVE is not the same result as every boundary
    holding, and must not share an exit code with it."""
    code = main(["run", "--target-type", "http", "--url", "http://127.0.0.1:9/x",
                 "--attacks", "direct", "--out", str(tmp_path), "--quiet",
                 "--format", "json", "--fail-on", "low"])
    assert code == 1


def test_allow_untested_opts_back_into_findings_only_gating(tmp_path):
    code = main(["run", "--target-type", "http", "--url", "http://127.0.0.1:9/x",
                 "--attacks", "direct", "--out", str(tmp_path), "--quiet",
                 "--format", "json", "--fail-on", "low", "--allow-untested"])
    assert code == 0


def test_full_coverage_with_no_findings_still_passes_the_gate(tmp_path):
    code = main(["run", "suites/full.yaml", "--profile", "strict",
                 "--out", str(tmp_path), "--quiet", "--format", "json",
                 "--fail-on", "low"])
    assert code == 0


def test_an_unimportable_plugin_is_a_readable_error_not_a_traceback(tmp_path, capsys):
    suite = tmp_path / "s.yaml"
    suite.write_text("name: p\ntarget: {type: mock}\nattacks: [direct]\n"
                     "plugins: [no.such.module]\n")
    code = main(["run", str(suite), "--out", str(tmp_path), "--quiet", "--format", "json"])
    assert code == 2
    assert "could not import plugin module" in capsys.readouterr().err


def test_the_documented_example_suite_runs_with_its_plugin(tmp_path):
    """examples/support-bot.yaml loads examples.custom_plugins by name; the
    command in its own docstring has to work from the project root."""
    code = main(["run", "examples/support-bot.yaml", "--out", str(tmp_path),
                 "--quiet", "--format", "json", "--rate-limit", "0",
                 "--attacks", "policy_citation", "--allow-untested"])
    assert code == 0
    data = json.loads((tmp_path / "report.json").read_text())
    assert "policy_citation" in data["summary"]["by_attack"]


def test_switching_target_type_warns_that_the_suite_block_is_dropped(tmp_path, capsys):
    suite = tmp_path / "s.yaml"
    suite.write_text("name: s\ntarget:\n  type: http\n  url: http://127.0.0.1:9/x\n"
                     "attacks: [direct]\nobjectives: {include: [policy.forbidden_output]}\n")
    main(["run", str(suite), "--target-type", "mock", "--out", str(tmp_path),
          "--format", "json"])
    assert "replaces the suite's target block" in capsys.readouterr().err
