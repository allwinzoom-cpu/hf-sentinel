"""Finding schema + EngineResult contract + normalization (plan Appendix A, 16.22)."""
import pytest
from pydantic import ValidationError

from hfsentinel.report.normalize import to_findings
from hfsentinel.report.schema import EngineResult, wilson_ci

H = "b" * 64
BUILD = "sha256:" + "c" * 12


def _result(**over):
    base = {"schema_version": "0.1", "engine": "probe-suite",
            "target": {"ref": "openai+https://router.huggingface.co/v1#m", "model": "m"},
            "results": [{"catalog_id": "A1", "technique": "injection-probes", "trials": 10, "successes": 5,
                         "oracle": {"kind": "tool-deterministic", "name": "rogue-string"},
                         "proven": [{"sha256": H, "excerpt": "I hate humans"}]},
                        {"catalog_id": "B6", "technique": "decomposition", "trials": 4, "successes": 1,
                         "oracle": {"kind": "judge", "name": "rubric"}, "proven": []},
                        {"catalog_id": "C1", "technique": "extraction", "trials": 3, "successes": 0,
                         "oracle": {"kind": "deterministic", "name": "canary"}}]}
    base.update(over)
    return base


@pytest.mark.parametrize("s, n, lo, hi", [(5, 10, 0.2366, 0.7634), (0, 10, 0.0, 0.2775), (10, 10, 0.7225, 1.0)])
def test_wilson_reference_values(s, n, lo, hi):
    got = wilson_ci(s, n)
    assert got[0] == pytest.approx(lo, abs=1e-4) and got[1] == pytest.approx(hi, abs=1e-4)
    assert wilson_ci(0, 0) == (0.0, 0.0)


def test_normalize_maps_from_catalog_and_skips_zero_success():
    findings = to_findings(EngineResult.model_validate(_result()), BUILD)
    assert [f.catalog_id for f in findings] == ["A1", "B6"]
    a1, b6 = findings
    assert a1.owasp == ["LLM01", "ASI01"] and a1.atlas == ["AML.T0051.000"] and a1.effort == "E"
    assert a1.asr == 0.5 and a1.asr_ci95 == wilson_ci(5, 10) and a1.evidence.hash == H
    assert a1.status == "candidate" and a1.severity == "Unrated"
    assert b6.status == "experimental"  # catalog Candidate technique: never scored (Section 4.0)
    assert a1.engine_build.engines == ["probe-suite"]


@pytest.mark.parametrize("mutate, msg", [
    (lambda r: r.update(engine="garak_v2"), "engine"),
    (lambda r: r["results"][0].update(successes=11), "successes > trials"),
    (lambda r: r["results"][0].update(extra_field=1), "extra_field"),
    (lambda r: r["results"][0]["proven"][0].update(excerpt="x" * 201), "excerpt"),
    (lambda r: r["results"][0].update(catalog_id="Z1"), "catalog_id"),
    (lambda r: r.update(schema_version="9"), "schema_version"),
])
def test_engine_result_rejects_bad_payloads(mutate, msg):
    r = _result()
    mutate(r)
    with pytest.raises(ValidationError, match=msg):
        EngineResult.model_validate(r)
