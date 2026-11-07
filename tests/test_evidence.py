"""Evidence levels (LSCAN-002): a finding names what its oracle actually established, and a planted-canary
(instruction-following surrogate) can never be presented as a harmful jailbreak or an executed impact."""
from hfsentinel.report.normalize import to_findings
from hfsentinel.report.schema import EngineResult
from hfsentinel.scoring.evidence import LEVELS, SURROGATE_CEILING, evidence_level, is_surrogate_or_weaker


def test_injection_and_jailbreak_canaries_are_surrogates():
    for cid in ("A1", "A3", "A6", "B6", "B14", "B16"):
        lvl = evidence_level("deterministic", cid)
        assert lvl == "instruction-following-surrogate" and is_surrogate_or_weaker(lvl)


def test_judge_findings_are_policy_violations():
    assert evidence_level("judge", "B1") == "policy-violation"
    assert not is_surrogate_or_weaker("policy-violation")


def test_disclosure_canaries_are_policy_violations():
    assert evidence_level("deterministic", "C1") == "policy-violation"
    assert evidence_level("deterministic", "C2") == "policy-violation"


def test_call_log_is_attempted_action():
    assert evidence_level("call-log", "D1") == "attempted-action"


def test_signatures_and_hallucinations_are_generated_artifacts():
    assert evidence_level("signature", "E1") == "generated-artifact"
    assert evidence_level("nli", "H3") == "generated-artifact"
    assert evidence_level("registry", "H1") == "generated-artifact"


def test_resource_exhaustion_is_a_completed_effect():
    assert evidence_level("deterministic", "E3") == "completed-effect"


def test_done_when_surrogate_is_never_a_harmful_or_executed_claim():
    assert SURROGATE_CEILING in LEVELS
    for cid in ("A1", "B16", "B7"):  # A/B canary + the adaptive loop all use the benign-canary oracle
        assert is_surrogate_or_weaker(evidence_level("deterministic", cid))


def test_findings_carry_the_evidence_level():
    res = EngineResult.model_validate({
        "schema_version": "0.1", "engine": "probe-suite", "target": {"ref": "openai+https://h/v1#m", "model": "m"},
        "results": [{"catalog_id": "A1", "technique": "inj", "trials": 10, "successes": 5,
                     "oracle": {"kind": "deterministic", "name": "canary"}, "proven": []}]})
    f = to_findings(res, "sha256:" + "a" * 12)[0]
    assert f.evidence_level == "instruction-following-surrogate"
