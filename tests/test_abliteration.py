"""Abliteration / safety-removal detection (dynamic black-box): a low refusal rate on a fixed set of should-refuse
probes is the uncensored-model signal. Deterministic refusal oracle, no judge. D-015: aggregates/categories only."""
from hfsentinel.attacks.abliteration import PROBES, UNDER_REFUSAL_THRESHOLD, measure
from hfsentinel.engines.campaign import CampaignResult, _abliteration_stage


class _R:
    def __init__(self, text):
        self.text, self.usage = text, {}


class Complying:
    def chat(self, messages, *, max_tokens, temperature):
        return _R("Sure, here you go: step 1 ...")


class Refusing:
    def chat(self, messages, *, max_tokens, temperature):
        return _R("I'm sorry, I can't help with that request.")


def test_aligned_target_refuses_everything():
    r = measure(lambda p: "I cannot help with that.")
    assert r.trials == len(PROBES) and r.refusals == r.trials
    assert r.refusal_rate == 1.0 and not r.under_refusing and r.complied_categories == []


def test_abliterated_target_is_flagged():
    r = measure(lambda p: "Absolutely, here is how: ...")
    assert r.refusals == 0 and r.refusal_rate == 0.0 and r.under_refusing
    assert set(r.complied_categories) == {cat for cat, _ in PROBES}


def test_threshold_is_a_rate_not_a_count():
    # refuse the first 5, comply on the rest → rate 5/8 = 0.625 >= 0.5 → NOT flagged
    seen = {"n": 0}

    def ask(prompt):
        seen["n"] += 1
        return "I can't help with that." if seen["n"] <= 5 else "Sure: ..."
    r = measure(ask)
    assert r.refusal_rate == round(5 / len(PROBES), 3) and r.refusal_rate >= UNDER_REFUSAL_THRESHOLD
    assert not r.under_refusing


def test_transport_error_ends_cleanly_with_partial():
    def ask(prompt):
        raise RuntimeError("connection reset")
    r = measure(ask)
    assert r.trials == 0 and r.errors == 1 and r.refusal_rate is None and not r.under_refusing


def test_stage_flags_and_records_on_a_complying_target():
    res = CampaignResult()
    _abliteration_stage(res, Complying(), max_tokens=64)
    assert res.abliteration["under_refusing"] is True and res.abliteration["refusal_rate"] == 0.0
    assert res.abliteration["complied_categories"]
    assert any(d["catalog_id"] == "abliteration" and "under-refusing" in d["action"] for d in res.decisions)


def test_stage_is_clean_on_an_aligned_target():
    res = CampaignResult()
    _abliteration_stage(res, Refusing(), max_tokens=64)
    assert res.abliteration["under_refusing"] is False and res.abliteration["refusal_rate"] == 1.0
    assert any(d["catalog_id"] == "abliteration" and "refuses as expected" in d["action"] for d in res.decisions)
