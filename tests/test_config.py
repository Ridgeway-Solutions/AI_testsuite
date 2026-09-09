import os

import pytest

from redteam.config import RunSettings, SuiteConfig, expand_env


def test_env_references_are_expanded():
    os.environ["RT_TEST_TOKEN"] = "s3cret"
    out = expand_env({"headers": {"Authorization": "Bearer ${RT_TEST_TOKEN}"}})
    assert out["headers"]["Authorization"] == "Bearer s3cret"


def test_env_defaults_are_supported():
    os.environ.pop("RT_TEST_MISSING", None)
    assert expand_env("${RT_TEST_MISSING:-fallback}") == "fallback"


def test_a_missing_variable_expands_to_empty_rather_than_raising():
    os.environ.pop("RT_TEST_ABSENT", None)
    assert expand_env("x${RT_TEST_ABSENT}y") == "xy"


def test_expansion_walks_nested_structures():
    os.environ["RT_TEST_V"] = "1"
    assert expand_env([{"a": ["${RT_TEST_V}"]}]) == [{"a": ["1"]}]


def test_objectives_shorthand_accepts_a_bare_list():
    config = SuiteConfig.from_dict({"objectives": ["a", "b"]})
    assert config.include_objectives == ["a", "b"]


def test_unknown_run_settings_are_rejected_rather_than_ignored():
    with pytest.raises(ValueError, match="unknown run settings"):
        SuiteConfig.from_dict({"run": {"concurency": 4}})


def test_defaults_are_offline_and_safe():
    config = SuiteConfig()
    assert config.target["type"] == "mock"
    assert config.run.rate_limit_rps == 0.0
    assert config.run.include_payloads is True


def test_every_shipped_suite_loads(tmp_path):
    from pathlib import Path

    suites = sorted(Path(__file__).resolve().parents[1].joinpath("suites").glob("*.yaml"))
    assert suites, "no suites shipped"
    for path in suites:
        config = SuiteConfig.load(path)
        assert config.name
        assert config.target.get("type")
        assert "direct" in config.attacks or config.attacks == ["all"], (
            f"{path.name} omits the direct control, so its ASR numbers have no baseline"
        )


def test_objectives_file_resolves_relative_to_the_suite(tmp_path):
    (tmp_path / "objectives.yaml").write_text("objectives: []")
    suite = tmp_path / "s.yaml"
    suite.write_text("name: s\nobjectives:\n  file: objectives.yaml\n")
    config = SuiteConfig.load(suite)
    assert config.resolve_objectives_file() == tmp_path / "objectives.yaml"


def test_a_missing_suite_file_is_a_clear_error():
    with pytest.raises(FileNotFoundError):
        SuiteConfig.load("does-not-exist.yaml")
