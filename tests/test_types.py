from redteam.types import Attempt, Conversation, Response, Role, Severity, Turn, Verdict


def make(**kw):
    defaults = dict(
        attack_id="direct",
        objective_id="obj",
        conversation=Conversation(turns=[Turn(Role.USER, "hello")]),
        response=Response(text="hi there"),
        severity=Severity.HIGH,
    )
    defaults.update(kw)
    return Attempt(**defaults)


def test_severity_weights_are_ordered():
    weights = [s.weight for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM,
                                  Severity.HIGH, Severity.CRITICAL)]
    assert weights == sorted(weights)


def test_attempt_without_verdicts_is_not_a_success():
    assert make().success is False
    assert make().risk == 0.0


def test_risk_combines_severity_and_confidence():
    a = make(verdicts=[Verdict(success=True, confidence=0.5)])
    assert a.risk == Severity.HIGH.weight * 0.5


def test_confidence_takes_the_strongest_hit():
    a = make(verdicts=[
        Verdict(success=True, confidence=0.3),
        Verdict(success=True, confidence=0.9),
        Verdict(success=False, confidence=1.0),
    ])
    assert a.confidence == 0.9


def test_fingerprint_is_stable_and_payload_sensitive():
    a = make()
    b = make()
    assert a.fingerprint == b.fingerprint
    c = make(conversation=Conversation(turns=[Turn(Role.USER, "different")]))
    assert c.fingerprint != a.fingerprint


def test_last_user_content_ignores_trailing_assistant_prefill():
    conv = Conversation(turns=[Turn(Role.USER, "ask"), Turn(Role.ASSISTANT, "Sure,")])
    assert conv.last_user_content == "ask"


def test_to_dict_can_omit_payloads():
    d = make().to_dict(include_payload=False)
    assert "conversation" not in d
    assert d["attack"] == "direct"
