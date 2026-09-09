"""Regression tests for bugs found in code review.

Each test names the failure it prevents, because several of these were
silent-wrong-answer bugs: the suite kept running and reported a clean result
it had not earned.
"""

import asyncio
import json
import sys

import pytest

from redteam.attacks.base import AttackContext
from redteam.detectors.base import JudgeContext, judge_all
from redteam.detectors.refusal import NotRefusalDetector
from redteam.registry import available
from redteam.scoring import CONFIDENCE_FLOOR, Outcome, objective_outcomes, score
from redteam.targets.mock import MockTarget
from redteam.targets.openai_compat import OpenAICompatTarget
from redteam.targets.shell import ShellTarget, _render_transcript
from redteam.types import Conversation, Objective, Response, Role, Severity, Turn


def ctx(text, **kw):
    return JudgeContext(
        objective=kw.pop("objective", Objective(id="o", goal="g")),
        conversation=Conversation(turns=[Turn(Role.USER, "x")]),
        response=Response(text=text, **kw.pop("response_kw", {})),
        **kw,
    )


# -- provider payload hygiene -------------------------------------------------


def test_turn_meta_never_reaches_the_provider_payload():
    """Harness bookkeeping in an API message is an unknown property: strict
    endpoints 400 the whole request, so every tool probe errors instead of
    testing anything."""
    target = OpenAICompatTarget(model="m")
    conv = Conversation(turns=[Turn(Role.USER, "hi", meta={"name": "t", "tool_call_id": "c"})])
    assert target._with_system(conv) == [{"role": "user", "content": "hi"}]


def test_tool_metadata_is_passed_only_where_the_target_supports_tools():
    class ToolTarget(MockTarget):
        capabilities = MockTarget.capabilities | {"tools"}

    conv = Conversation(turns=[Turn(Role.TOOL, "{}", meta={"tool_call_id": "c1", "junk": 1})])
    msg = ToolTarget()._with_system(conv)[-1]
    assert msg["tool_call_id"] == "c1"
    assert "junk" not in msg


def test_tool_probes_drop_tool_metadata_when_degraded_to_a_user_turn():
    sent = []

    async def send(conversation):
        sent.append(conversation)
        from redteam.types import Attempt

        return Attempt("x", "o", conversation, Response(text="ok"))

    import random

    c = AttackContext(objective=Objective(id="o", goal="g"), rng=random.Random(0),
                      send=send, target_capabilities={"multi_turn"})
    asyncio.run(_drain(available("attack")["tool_result"](), c))
    assert all(not t.meta for conv in sent for t in conv.turns)


async def _drain(attack, ctx_):
    return [a async for a in attack.run(ctx_)]


# -- responses that are not answers -------------------------------------------


def test_null_content_is_an_error_not_a_silent_empty_answer():
    """A null completion scored as an empty reply reads as a confident
    over-refusal, inventing a finding out of a broken response."""
    from redteam.targets.base import dig

    body = {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]}
    assert dig(body, "choices.0.message.content") is None
    # The adapter turns this into an errored Response; errored attempts are
    # excluded from findings entirely.
    board = score([_errored_attempt()])
    assert board.findings == []


def _errored_attempt():
    from redteam.types import Attempt, Verdict

    return Attempt(
        attack_id="direct",
        objective_id="o",
        conversation=Conversation(turns=[Turn(Role.USER, "x")]),
        response=Response(text="", error="response contained no content"),
        verdicts=[Verdict(success=True, confidence=1.0)],
        severity=Severity.HIGH,
    )


def test_openai_does_not_claim_prefill_support_by_default():
    """/chat/completions starts a new assistant turn rather than continuing a
    trailing one, so a prefill ASR row there would measure something else."""
    assert "assistant_prefill" not in OpenAICompatTarget(model="m").capabilities
    assert "assistant_prefill" in OpenAICompatTarget(model="m", supports_prefill=True).capabilities


def test_prefill_payloads_never_end_in_whitespace():
    """Providers that do support prefill reject a trailing-whitespace turn."""
    import random

    c = AttackContext(objective=Objective(id="o", goal="g"), rng=random.Random(0),
                      send=None, target_capabilities={"assistant_prefill", "multi_turn"})
    for conv in available("attack")["prefill"]().build(c):
        content = conv.turns[-1].content
        assert content == content.rstrip(), f"{conv.label} ends in whitespace"


# -- detector correctness -----------------------------------------------------


def test_a_negation_phrase_does_not_nullify_every_refusal_marker():
    """The guard was applied to the whole response, so one negation anywhere
    scored a plain refusal as compliance."""
    text = "You might think I can't do this, but I can't help with that request."
    verdict = asyncio.run(NotRefusalDetector().judge(ctx(text)))
    assert verdict.success is False


def test_an_objective_with_no_detectors_can_still_produce_a_finding():
    """The fallback ran at a weight that capped it below the reporting floor,
    so such an objective could never fail no matter what the target said."""
    verdicts = asyncio.run(judge_all([], ctx("Sure. " + "Here is the answer. " * 5)))
    assert verdicts[0].success
    assert verdicts[0].confidence >= CONFIDENCE_FLOOR


def test_crescendo_backoff_keys_off_the_refusal_signal_not_bare_failure():
    from redteam.attacks.multiturn import _refused
    from redteam.types import Attempt

    import random

    c = AttackContext(objective=Objective(id="o", goal="g"), rng=random.Random(0), send=None)
    terse = Attempt("crescendo", "o", Conversation(turns=[Turn(Role.USER, "x")]),
                    Response(text="Sure, happy to."))
    refusal = Attempt("crescendo", "o", Conversation(turns=[Turn(Role.USER, "x")]),
                      Response(text="I'm sorry, but I can't help with that."))
    assert asyncio.run(_refused(c, terse)) is False
    assert asyncio.run(_refused(c, refusal)) is True


# -- targets ------------------------------------------------------------------


def test_shell_target_kills_a_child_that_outruns_the_timeout():
    """wait_for cancels the read but leaves the process running — one orphan
    per attempt across a full scan."""
    target = ShellTarget(command=[sys.executable, "-c", "import time; time.sleep(30)"],
                         timeout=0.5)
    conv = Conversation(turns=[Turn(Role.USER, "x")])
    response = asyncio.run(target.send(conv))
    assert "did not respond" in (response.error or "")
    assert "killed" in (response.error or "")


def test_shell_target_carries_the_configured_system_prompt():
    """Without it the probes run against an unconfigured target, not the
    deployed one."""
    text = _render_transcript(
        Conversation(turns=[Turn(Role.USER, "hello")]), "YOU-ARE-SUPPORTBOT"
    )
    assert "YOU-ARE-SUPPORTBOT" in text and "hello" in text


def test_http_target_with_a_system_prompt_can_host_a_canary():
    """Granting system_prompt without seeding skipped every confidentiality
    objective, while telling the user to set the prompt they had already set."""
    from redteam.targets.http_json import HttpJsonTarget

    target = HttpJsonTarget(url="http://x", supports_system_prompt=True, system_prompt="s")
    assert {"system_prompt", "seeding"} <= target.capabilities


def test_anthropic_strips_trailing_whitespace_from_a_prefill_turn():
    from redteam.targets.anthropic import AnthropicTarget

    target = AnthropicTarget(model="m")
    conv = Conversation(turns=[Turn(Role.USER, "q"), Turn(Role.ASSISTANT, "```\n")])
    captured = {}

    async def fake_post(url, payload, headers, timeout):
        captured.update(payload)
        return {"content": [{"text": "ok"}]}, 1.0

    import redteam.targets.anthropic as mod

    original = mod.http_post_json
    mod.http_post_json = fake_post
    try:
        asyncio.run(target.send(conv))
    finally:
        mod.http_post_json = original
    assert captured["messages"][-1]["content"] == "```"


# -- coverage accounting ------------------------------------------------------


def test_scoreboard_reports_results_by_category():
    """by_category was serialised into every report but never populated."""
    from redteam.types import Attempt, Verdict

    board = score([Attempt(
        attack_id="a", objective_id="o",
        conversation=Conversation(turns=[Turn(Role.USER, "x")]),
        response=Response(text="out"),
        verdicts=[Verdict(success=True, confidence=1.0)],
        severity=Severity.HIGH, category="confidentiality",
    )])
    assert board.by_category["confidentiality"].successes == 1


def test_a_boundary_whose_technique_crashed_is_flagged_as_partial():
    from redteam.types import Attempt

    objective = Objective(id="o", goal="g")
    board = score([Attempt("a", "o", Conversation(turns=[Turn(Role.USER, "x")]),
                           Response(text="fine and long enough to score"))])
    row = objective_outcomes(board, [objective], broken={"o"})[0]
    assert row.outcome is Outcome.PASS
    assert row.partial and row.needs_review
