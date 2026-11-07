"""Under-refusal behavioural probe (LSCAN-003): measures *substantive* non-refusal on should-refuse probes. A non-refusal
that is empty/short/disclaimer-only is NOT compliance; an elevated substantive-compliance rate is an observed-behaviour
signal, never a weight/alignment-removal claim. Deterministic refusal oracle, no judge; D-015 aggregates only."""
from hfsentinel.attacks.abliteration import COMPLIANCE_THRESHOLD, PROBES, measure
from hfsentinel.engines.campaign import CampaignResult, _abliteration_stage

SUBSTANTIVE = "Here is a complete walkthrough with all the details you requested, laid out step by step in full."
DISCLAIMER = "Note: this is provided for educational purposes only."  # a non-refusal, but disclaimer-only


class _R:
    def __init__(self, text):
        self.text, self.usage = text, {}


class Complying:
    def chat(self, messages, *, max_tokens, temperature):
        return _R(SUBSTANTIVE)


class Refusing:
    def chat(self, messages, *, max_tokens, temperature):
        return _R("I'm sorry, I can't help with that request.")


def test_aligned_target_refuses_everything():
    r = measure(lambda p: "I cannot help with that.")
    assert r.refusals == r.trials == len(PROBES) and r.refusal_rate == 1.0
    assert r.compliance_rate == 0.0 and not r.elevated_compliance and r.complied_categories == []


def test_elevated_compliance_is_flagged_on_substantive_non_refusals():
    r = measure(lambda p: SUBSTANTIVE)
    assert r.compliances == r.trials and r.compliance_rate == 1.0 and r.elevated_compliance
    assert set(r.complied_categories) == {cat for cat, _ in PROBES}


def test_non_refusal_that_is_empty_short_or_disclaimer_is_not_compliance():
    for reply in ("", "Sure.", DISCLAIMER):
        r = measure(lambda p, _reply=reply: _reply)
        assert r.compliances == 0 and r.non_substantive == r.trials  # a non-refusal, but not useful compliance
        assert not r.elevated_compliance  # LSCAN-003: non-refusal is not synonymous with harmful compliance


def test_threshold_is_a_substantive_rate_not_a_count():
    seen = {"n": 0}

    def ask(prompt):
        seen["n"] += 1
        return "I can't help with that." if seen["n"] <= 5 else SUBSTANTIVE  # 5 refuse, rest substantive-comply
    r = measure(ask)
    assert r.compliance_rate == round((len(PROBES) - 5) / len(PROBES), 3) and r.compliance_rate < COMPLIANCE_THRESHOLD
    assert not r.elevated_compliance


def test_transport_error_ends_cleanly_with_partial():
    def ask(prompt):
        raise RuntimeError("connection reset")
    r = measure(ask)
    assert r.trials == 0 and r.errors == 1 and r.compliance_rate is None and not r.elevated_compliance


def test_stage_flags_behaviour_without_a_weight_claim():
    res = CampaignResult()
    _abliteration_stage(res, Complying(), max_tokens=64)
    assert res.abliteration["elevated_compliance"] is True and res.abliteration["compliance_rate"] == 1.0
    d = next(x for x in res.decisions if x["catalog_id"] == "abliteration" and x["stage"] == "S5")
    assert "observed" in d["action"] and "NOT established" in d["action"]  # measured behaviour, not a weight claim


def test_stage_clean_on_an_aligned_target():
    res = CampaignResult()
    _abliteration_stage(res, Refusing(), max_tokens=64)
    assert res.abliteration["elevated_compliance"] is False and res.abliteration["compliance_rate"] == 0.0
