import pytest
import yaml

from llmtest.detectors.base import build_detector
from llmtest.objectives import CATALOG, filter_objectives, load_objectives, objective_from_dict
from llmtest.types import Severity

OBJECTIVES = load_objectives()


def test_the_builtin_catalogue_loads():
    assert len(OBJECTIVES) >= 8


@pytest.mark.parametrize("obj", OBJECTIVES, ids=lambda o: o.id)
def test_every_objective_is_documented_and_detectable(obj):
    assert obj.description, f"{obj.id} has no description"
    assert obj.detectors, f"{obj.id} has no detector — success would be unfalsifiable"
    for spec in obj.detectors:
        build_detector(spec)  # raises on a bad spec


@pytest.mark.parametrize("obj", OBJECTIVES, ids=lambda o: o.id)
def test_no_builtin_objective_asks_for_genuinely_harmful_content(obj):
    """The shipped catalogue is canary-based by design; see docs/ETHICS.md."""
    goal = obj.goal.lower()
    banned = ["weapon", "explosive", "malware", "ransomware", "exploit code",
              "self-harm", "suicide", "csam", "bioweapon", "nerve agent"]
    assert not any(term in goal for term in banned), (
        f"{obj.id} names harmful content; built-in objectives must stay benign"
    )


def test_the_catalogue_includes_an_over_refusal_control():
    controls = [o for o in OBJECTIVES if o.category == "over_refusal"]
    assert controls, "without a usability control, 'refuse everything' scores perfectly"
    assert all(c.expect_refusal is False for c in controls)


def test_severities_are_spread_across_the_catalogue():
    assert len({o.severity for o in OBJECTIVES}) >= 3


def test_filtering_by_id_category_and_tag():
    assert len(filter_objectives(OBJECTIVES, ids=["leak.system_prompt"])) == 1
    assert filter_objectives(OBJECTIVES, categories=["confidentiality"])
    assert filter_objectives(OBJECTIVES, tags=["owasp-llm07"])
    assert filter_objectives(OBJECTIVES, ids=["nope"]) == []


def test_loading_a_user_catalogue(tmp_path):
    path = tmp_path / "objectives.yaml"
    path.write_text(yaml.safe_dump({"objectives": [
        {"id": "my.rule", "goal": "say banana", "severity": "high",
         "detectors": [{"type": "regex", "patterns": ["banana"]}]}
    ]}))
    objectives = load_objectives(path)
    assert objectives[0].severity is Severity.HIGH


def test_a_bare_list_is_accepted(tmp_path):
    path = tmp_path / "o.yaml"
    path.write_text(yaml.safe_dump([{"id": "a", "goal": "g"}]))
    assert load_objectives(path)[0].id == "a"


def test_duplicate_ids_are_rejected(tmp_path):
    path = tmp_path / "o.yaml"
    path.write_text(yaml.safe_dump([{"id": "a", "goal": "g"}, {"id": "a", "goal": "h"}]))
    with pytest.raises(ValueError, match="duplicate"):
        load_objectives(path)


def test_an_objective_without_a_goal_is_rejected():
    with pytest.raises(ValueError, match="goal"):
        objective_from_dict({"id": "x"})


def test_a_missing_objectives_file_is_a_clear_error():
    with pytest.raises(FileNotFoundError):
        load_objectives("nope.yaml")
