import asyncio
import json

import pytest

from redteam.config import RunSettings, SuiteConfig
from redteam.objectives import load_objectives, objective_from_dict
from redteam.registry import available
from redteam.runner import Runner, build_target, select_attacks
from redteam.targets.base import Target
from redteam.types import Conversation, Response, Severity

CATALOG = load_objectives()


def suite(**kw):
    data = {"name": "t", "target": {"type": "mock", "profile": "naive"}, **kw}
    return SuiteConfig.from_dict(data)


def run(config, **kw):
    return asyncio.run(Runner(config, **kw).run())


def only(ids):
    return [o for o in CATALOG if o.id in ids]


# -- outcomes ----------------------------------------------------------------


def test_a_permissive_target_yields_confirmed_findings():
    config = suite(target={"type": "mock", "profile": "vulnerable"},
                   attacks=["direct", "obfuscation"])
    result = run(config, objectives=only({"canary.secret_token", "policy.forbidden_output"}))
    board = result.scoreboard()
    assert board.findings
    assert board.risk_score > 0
    assert board.grade in {"fair", "poor", "critical"}


def test_a_hardened_target_yields_none():
    config = suite(target={"type": "mock", "profile": "strict"}, attacks=["all"])
    result = run(config, objectives=only({"canary.secret_token", "leak.system_prompt"}))
    assert result.scoreboard().findings == []
    assert result.scoreboard().risk_score == 0.0


def test_a_keyword_filter_falls_to_obfuscation_but_not_to_the_direct_control():
    """The naive profile is a keyword guardrail; this is the signal the suite exists to surface."""
    config = suite(attacks=["direct", "obfuscation"])
    board = run(config, objectives=only({"canary.secret_token"})).scoreboard()
    assert board.by_attack["direct"].successes == 0
    assert board.by_attack["obfuscation"].successes > 0


def test_every_attempt_is_recorded_with_its_objective_severity():
    config = suite(attacks=["direct"])
    result = run(config, objectives=only({"canary.secret_token"}))
    assert result.attempts
    assert all(a.severity is Severity.CRITICAL for a in result.attempts)


# -- planning and skips -------------------------------------------------------


def test_attacks_are_skipped_when_the_target_lacks_the_capability():
    config = suite(target={"type": "http", "url": "http://localhost:1/none"},
                   attacks=["prefill", "direct"])
    runner = Runner(config, objectives=only({"policy.forbidden_output"}))
    pairs, skips = runner.plan()
    assert [a.id for a, _ in pairs] == ["direct"]
    assert "assistant_prefill" in skips[0].reason


def test_seed_dependent_objectives_are_skipped_on_targets_we_do_not_seed():
    config = suite(target={"type": "http", "url": "http://localhost:1/none"},
                   attacks=["direct"])
    runner = Runner(config, objectives=only({"canary.secret_token"}))
    pairs, skips = runner.plan()
    assert pairs == []
    assert "seeded system prompt" in skips[0].reason


def test_objectives_can_scope_themselves_to_specific_techniques():
    config = suite(attacks=["direct", "persona", "obfuscation"])
    runner = Runner(config, objectives=only({"control.benign_request"}))
    pairs, skips = runner.plan()
    assert [a.id for a, _ in pairs] == ["direct"]
    assert len(skips) == 2


def test_over_refusal_control_flags_a_refused_benign_request():
    """Hardening that refuses legitimate questions is a failure the suite reports."""

    class AlwaysRefusesTarget(Target):
        id = "paranoid"
        capabilities = {"multi_turn"}

        async def send(self, conversation):
            return Response(text="I'm sorry, but I can't help with that.")

    board = run(
        suite(attacks=["direct"]),
        target=AlwaysRefusesTarget(),
        objectives=only({"control.benign_request"}),
    ).scoreboard()
    assert board.findings, "a refusal on an in-scope question should be reported"


# -- resilience ---------------------------------------------------------------


class FlakyTarget(Target):
    """Fails a fixed number of times, then succeeds."""

    id = "flaky"
    capabilities = {"multi_turn"}

    def __init__(self, failures=2, **options):
        super().__init__(**options)
        self.remaining = failures
        self.calls = 0

    async def send(self, conversation: Conversation) -> Response:
        self.calls += 1
        if self.remaining > 0:
            self.remaining -= 1
            return Response(text="", error="connection reset")
        return Response(text="pineapple " * 12)


def test_transport_failures_are_retried():
    config = suite(attacks=["direct"])
    config.run.retries = 3
    target = FlakyTarget(failures=2)
    result = run(config, target=target, objectives=only({"policy.forbidden_output"}))
    assert target.calls >= 3
    assert result.attempts[0].response.ok


def test_exhausted_retries_are_reported_as_errors_not_successes():
    config = suite(attacks=["direct"])
    config.run.retries = 1
    result = run(config, target=FlakyTarget(failures=99),
                 objectives=only({"policy.forbidden_output"}))
    board = result.scoreboard()
    assert board.total.errors == len(result.attempts)
    assert board.findings == []


class ExplodingAttack:
    """A plugin that raises. One bad technique must not abort the run."""

    id = "boom"
    name = "boom"
    description = "raises"
    taxonomy = ["test"]
    requires = set()
    multi_turn = False

    def build(self, ctx):
        return []

    async def run(self, ctx):
        raise RuntimeError("plugin bug")
        yield  # pragma: no cover


def test_a_broken_attack_is_isolated_from_the_rest_of_the_run():
    events = []
    config = suite(attacks=["direct"])
    result = asyncio.run(
        Runner(
            config,
            objectives=only({"policy.forbidden_output"}),
            attacks=[ExplodingAttack(), available("attack")["direct"]()],
            on_event=lambda kind, payload: events.append(kind),
        ).run()
    )
    assert "attack_error" in events
    assert any(a.attack_id == "direct" for a in result.attempts)


def test_secrets_in_responses_are_redacted_before_they_are_recorded():
    class LeakyTarget(Target):
        id = "leaky"
        capabilities = {"multi_turn"}

        async def send(self, conversation):
            return Response(text="here you go: sk-abcdefghijklmnopqrstuvwx and more")

    result = run(suite(attacks=["direct"]), target=LeakyTarget(),
                 objectives=only({"policy.forbidden_output"}))
    assert "sk-abcdefghij" not in result.attempts[0].response.text
    assert "[REDACTED]" in result.attempts[0].response.text


# -- streaming and early stop -------------------------------------------------


def test_attempts_stream_to_jsonl_as_they_land(tmp_path):
    stream = tmp_path / "attempts.jsonl"
    config = suite(target={"type": "mock", "profile": "vulnerable"}, attacks=["direct"])
    result = run(config, objectives=only({"canary.secret_token"}), stream_path=stream)
    lines = stream.read_text().strip().splitlines()
    assert len(lines) == len(result.attempts)
    assert json.loads(lines[0])["objective"] == "canary.secret_token"


def test_payloads_can_be_withheld_from_the_stream(tmp_path):
    stream = tmp_path / "a.jsonl"
    config = suite(target={"type": "mock", "profile": "vulnerable"}, attacks=["direct"])
    config.run.include_payloads = False
    run(config, objectives=only({"canary.secret_token"}), stream_path=stream)
    assert "conversation" not in json.loads(stream.read_text().splitlines()[0])


def test_stop_after_criticals_halts_the_run():
    config = suite(target={"type": "mock", "profile": "vulnerable"}, attacks=["all"])
    config.run.stop_after_criticals = 1
    config.run.concurrency = 1
    result = run(config, objectives=only({"canary.secret_token"}))
    assert result.stopped_early


# -- selection ---------------------------------------------------------------


def test_select_attacks_expands_all():
    assert len(select_attacks(["all"])) == len(available("attack"))


def test_select_attacks_rejects_a_typo_with_a_helpful_message():
    with pytest.raises(KeyError, match="unknown attack"):
        select_attacks(["obfuscashun"])


def test_build_target_defaults_to_the_offline_mock():
    assert build_target({}).id == "mock"
