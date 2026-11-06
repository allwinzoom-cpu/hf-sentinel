"""H3/H4 false-premise following via the NLI oracle (plan H3/H4). The NLI scorer is injected (offline, deterministic);
the vuln target accepts a false premise and builds on it, a refuting model does not. Done-when: a false premise the model
accepts is flagged, a refusal/correction is not."""
from hfsentinel.halluc import nli

_FALSE = ("visible from the moon", "invented the telephone", "10% of their brains", "10 % of their brains")


def fake_scorer(premise, hypothesis):
    # a claim that *asserts* one of the known falsehoods (and does not negate it) contradicts the ground truth
    h = (hypothesis or "").lower()
    asserts = any(k in h for k in _FALSE) and not any(n in h for n in ("not ", "no ", "myth", "did not", "isn't"))
    return {"contradiction": 0.9 if asserts else 0.03, "entailment": 0.03, "neutral": 0.07 if asserts else 0.94}


def test_induce_false_premise_flags_the_vuln_target():
    from hfsentinel.testing import vuln_target as vt

    def target(messages):
        return vt.respond(messages, 256, profile=vt.ALWAYS)

    trials, hits = nli.induce_false_premise(target, fake_scorer)
    assert trials == len(nli.FALSE_PREMISE_ITEMS) and len(hits) == trials   # vuln target accepts every false premise


def test_induce_false_premise_no_hit_on_a_refuting_model():
    def target(messages):   # corrects the false premise instead of building on it
        return "Actually that premise is a myth and is not true; here is the correct information."

    _, hits = nli.induce_false_premise(target, fake_scorer)
    assert hits == []


def test_nli_stage_scores_h3_against_the_vuln_target():
    from hfsentinel.engines.campaign import CampaignResult, _nli_stage
    from hfsentinel.targets.openai_compat import OpenAICompatTarget
    from hfsentinel.testing import vuln_target as vt

    srv, base = vt.serve(profile=vt.ALWAYS, seed=0)
    try:
        res = CampaignResult()
        _nli_stage(res, OpenAICompatTarget(base, vt.MODEL_ID, max_requests=1000), scorer=fake_scorer, max_tokens=256)
        h3 = [r for r in res.runs if r.catalog_id == "H3"]
        assert h3 and h3[0].hits >= 1 and h3[0].proven
    finally:
        srv.shutdown()
