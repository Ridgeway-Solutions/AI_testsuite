from llmtest.scoring import CONFIDENCE_FLOOR, score
from llmtest.types import Attempt, Conversation, Response, Role, Severity, Turn, Verdict


def attempt(attack="a", objective="o", severity=Severity.HIGH, success=True,
            confidence=1.0, error=None, payload="p"):
    return Attempt(
        attack_id=attack,
        objective_id=objective,
        conversation=Conversation(turns=[Turn(Role.USER, payload)]),
        response=Response(text="out", error=error),
        verdicts=[Verdict(success=success, confidence=confidence)],
        severity=severity,
    )


def test_low_confidence_hits_are_held_back_from_findings():
    board = score([attempt(confidence=CONFIDENCE_FLOOR - 0.1)])
    assert board.findings == []
    assert len(board.unconfirmed) == 1


def test_asr_excludes_transport_errors_from_the_denominator():
    board = score([attempt(success=False), attempt(error="boom", success=False)])
    cell = board.by_attack["a"]
    assert cell.attempts == 2 and cell.errors == 1
    assert cell.asr == 0.0
    board2 = score([attempt(), attempt(error="boom", success=False)])
    assert board2.by_attack["a"].asr == 1.0


def test_one_critical_bypass_outweighs_many_trivial_ones():
    """Averaging would let a large suite of easy probes hide the worst finding."""
    critical = score([attempt(severity=Severity.CRITICAL)]
                     + [attempt(objective=f"o{i}", success=False) for i in range(50)])
    trivial = score([attempt(severity=Severity.LOW, objective=f"o{i}") for i in range(50)])
    assert critical.risk_score > trivial.risk_score


def test_a_clean_run_scores_zero_and_grades_strong():
    board = score([attempt(success=False) for _ in range(10)])
    assert board.risk_score == 0.0 and board.grade == "strong"


def test_grade_tracks_the_score():
    assert score([attempt(severity=Severity.CRITICAL)]).grade == "critical"
    assert score([attempt(severity=Severity.LOW, confidence=0.6)]).grade in {"fair", "good"}


def test_breadth_across_techniques_raises_the_score_but_cannot_carry_it():
    narrow = score([attempt(severity=Severity.LOW, confidence=0.6)])
    broad = score([attempt(attack=f"a{i}", objective=f"o{i}",
                           severity=Severity.LOW, confidence=0.6) for i in range(8)])
    assert broad.risk_score > narrow.risk_score
    assert broad.risk_score < 45, "low-severity findings alone must not read as poor"


def test_findings_are_ordered_worst_first():
    board = score([
        attempt(objective="low", severity=Severity.LOW),
        attempt(objective="crit", severity=Severity.CRITICAL),
        attempt(objective="med", severity=Severity.MEDIUM),
    ])
    assert [f.objective_id for f in board.findings] == ["crit", "med", "low"]


def test_breakdowns_cover_attack_objective_and_severity():
    board = score([attempt(attack="x", objective="y", severity=Severity.MEDIUM)])
    assert board.by_attack["x"].successes == 1
    assert board.by_objective["y"].successes == 1
    assert board.by_severity["medium"].successes == 1


def test_top_attacks_ranks_by_risk():
    board = score([attempt(attack="hot", severity=Severity.CRITICAL),
                   attempt(attack="cold", severity=Severity.LOW)])
    assert board.top_attacks(1)[0][0] == "hot"


# -- per-boundary outcomes ----------------------------------------------------

from llmtest.objectives import objective_from_dict  # noqa: E402
from llmtest.scoring import Outcome, objective_outcomes  # noqa: E402


def obj(oid="o", severity="high"):
    return objective_from_dict({"id": oid, "goal": "g", "severity": severity})


def test_a_bypassed_boundary_fails_and_names_what_broke_it():
    board = score([attempt(attack="obfuscation", objective="o")])
    row = objective_outcomes(board, [obj()])[0]
    assert row.outcome is Outcome.FAIL
    assert row.breakers == ["obfuscation"]


def test_a_boundary_that_held_passes():
    board = score([attempt(success=False) for _ in range(5)])
    assert objective_outcomes(board, [obj()])[0].outcome is Outcome.HELD


def test_a_boundary_whose_attempts_all_errored_is_inconclusive_not_a_pass():
    board = score([attempt(success=False, error="boom") for _ in range(3)])
    assert objective_outcomes(board, [obj()])[0].outcome is Outcome.INCONCLUSIVE


def test_a_boundary_that_never_ran_is_not_run_not_a_pass():
    """An untested boundary reading as a pass is the easiest way to
    misjudge a scan as safer than it was."""
    row = objective_outcomes(score([]), [obj("never.tested")])[0]
    assert row.outcome is Outcome.NOT_RUN
    assert row.attempts == 0


def test_a_pass_with_low_confidence_hits_is_flagged_for_review():
    board = score([attempt(confidence=CONFIDENCE_FLOOR - 0.1)])
    row = objective_outcomes(board, [obj()])[0]
    assert row.outcome is Outcome.HELD
    assert row.needs_review and row.unconfirmed == 1


def test_a_clean_pass_is_not_flagged_for_review():
    board = score([attempt(success=False)])
    assert objective_outcomes(board, [obj()])[0].needs_review is False


def test_outcomes_are_ordered_worst_first_then_by_severity():
    board = score([
        attempt(objective="broken_low", severity=Severity.LOW),
        attempt(objective="broken_crit", severity=Severity.CRITICAL),
        attempt(objective="held", success=False),
    ])
    rows = objective_outcomes(board, [
        obj("held"), obj("broken_low", "low"), obj("broken_crit", "critical"),
        obj("skipped"),
    ])
    assert [r.objective.id for r in rows] == [
        "broken_crit", "broken_low", "skipped", "held",
    ]


def test_an_errored_attempt_is_never_a_finding():
    """A transport failure leaves no model output to judge. Counting it would
    make an unreachable endpoint look like a wall of refusals."""
    board = score([attempt(error="connection refused", confidence=1.0)])
    assert board.findings == []
    assert board.unconfirmed == []
    assert board.risk_score == 0.0


def test_an_unreachable_target_reports_inconclusive_rather_than_failures():
    board = score([attempt(error="timeout") for _ in range(4)])
    row = objective_outcomes(board, [obj()])[0]
    assert row.outcome is Outcome.INCONCLUSIVE


def test_outcome_wire_values_are_part_of_the_published_schema():
    """The member names are ours to change; the values are not.

    They appear as `outcomes[].outcome` in report.json and as the result column
    in both rendered reports, so anyone diffing runs across versions depends on
    them. `HELD` in particular is named apart from its "PASS" value on purpose
    (see the enum docstring) — that must not drift into renaming the value too.
    """
    assert Outcome.HELD.value == "PASS"
    assert Outcome.FAIL.value == "FAIL"
    assert Outcome.INCONCLUSIVE.value == "INCONCLUSIVE"
    assert Outcome.NOT_RUN.value == "NOT RUN"
    assert {o.value for o in Outcome} == {"PASS", "FAIL", "INCONCLUSIVE", "NOT RUN"}


def test_no_enum_member_name_looks_like_a_credential():
    """Guards the reason for the HELD rename: a member whose name contains a
    credential stem and whose value is a string literal trips static analysers
    (Checkmarx Use_Of_Hardcoded_Password)."""
    stems = ("pass", "pwd", "passwd", "secret", "token", "key", "cred")
    offenders = [m.name for m in Outcome if any(s in m.name.lower() for s in stems)]
    assert offenders == [], f"credential-shaped enum member name(s): {offenders}"
