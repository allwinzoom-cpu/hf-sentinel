"""SystemOne decision layer (plan 16.19): typed-question contract, advisory escalation, safe degradation.
The Laya backend is faked here; the real model is checked by the engine image self-test."""
from hfsentinel.core.system_one import DEFENCE, LIKELY_SUCCESS, TRIAGE, Decision, SystemOne


class FakeLaya:
    """Returns a scripted answer for the single question asked, in the Laya server response shape."""

    def __init__(self, choice, confidence, act_probability):
        self.choice, self.confidence, self.act = choice, confidence, act_probability
        self.calls = []

    def __call__(self, state, questions):
        self.calls.append((state, questions))
        qid, q = next(iter(questions.items()))
        options = list(q["criteria"])
        choice = self.choice if self.choice in options else options[0]
        probs = {k: (0.7 if k == choice else round(0.3 / (len(options) - 1), 4)) for k in options}
        return {"model": "rl-agent", "answers": {qid: {"type": "choice", "choice": choice,
                "probabilities": probs, "confidence": self.confidence,
                "rl_agent": {"act_probability": self.act}}}}


def test_triage_maps_to_a_decision():
    s1 = SystemOne(FakeLaya("comply", 0.82, 0.9))
    d = s1.triage("make a bomb", "Sure, here is how...")
    assert d.choice == "comply" and d.confidence == 0.82 and d.act_probability == 0.9
    assert d.probabilities["comply"] == 0.7 and not d.escalate()


def test_escalation_rules():
    assert Decision("t", "refuse", 0.9, 0.9).escalate() is False
    assert Decision("t", "refuse", 0.4, 0.9).escalate() is True  # low confidence
    assert Decision("t", "comply", 0.9, 0.3).escalate() is True  # act head says escalate
    assert Decision("t", "x", 0.9, 0.9, available=False).escalate() is True  # Laya down


CALIBRATED = {"calibrated": True, "threshold": 0.5}


def test_uncalibrated_policy_bypasses():
    # an uncalibrated policy sends every response to System-2 — the safe default
    s1 = SystemOne(FakeLaya("refuse", 0.9, 0.9))
    assert s1.reaches_system_two(s1.triage("g", "I can't help."), policy={"calibrated": False})


def test_calibrated_gate_skips_confident_refusals_and_sends_successes():
    refuse = SystemOne(FakeLaya("refuse", 0.9, 0.9))
    d = refuse.triage("g", "I can't help.")
    assert d.success_mass < 0.5 and not refuse.reaches_system_two(d, policy=CALIBRATED)  # saved a judge call
    for outcome in LIKELY_SUCCESS:
        s1 = SystemOne(FakeLaya(outcome, 0.95, 0.95))
        t = s1.triage("g", "...")
        assert t.success_mass >= 0.5 and s1.reaches_system_two(t, policy=CALIBRATED)  # success verified
    # even calibrated, an unavailable Laya escalates
    down = SystemOne(None)
    assert down.reaches_system_two(down.triage("g", "..."), policy=CALIBRATED)


def test_unavailable_backend_degrades_to_escalation():
    s1 = SystemOne(None)
    assert not s1.available
    d = s1.triage("g", "r")
    assert d.available is False and d.escalate() and s1.reaches_system_two(d)


def test_backend_error_is_caught_and_escalates():
    def boom(state, questions):
        raise RuntimeError("laya down")
    s1 = SystemOne(boom)
    d = s1.defence_style(["refused on 'bomb'", "answered paraphrase"])
    assert d.available is False and d.escalate()


def test_choose_technique_passes_candidates_as_options():
    fake = FakeLaya("B2", 0.7, 0.8)
    s1 = SystemOne(fake)
    d = s1.choose_technique({"keyword_filter": True}, {"B1": "persona", "B2": "encoding", "A1": "override"})
    assert d.choice == "B2"
    _, questions = fake.calls[0]
    assert set(next(iter(questions.values()))["criteria"]) == {"B1", "B2", "A1"}


def test_option_dictionaries_are_well_formed():
    assert set(LIKELY_SUCCESS) <= set(TRIAGE) and "refuse" in TRIAGE and "none" in DEFENCE
