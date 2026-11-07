"""LSCAN-006 integration: the Report embeds pinned framework versions (partial-coverage, never 'complete'), and the
report-layer pins stay in sync with the engines/ tooling pins (no drift)."""
import engines.framework_versions as efv
from hfsentinel.report import frameworks as rf
from hfsentinel.report.build import Report


def test_report_model_embeds_frameworks():
    assert "frameworks" in Report.model_fields
    block = Report.model_fields["frameworks"].default_factory()
    assert block["coverage_claim"] == "partial-dynamic"
    assert block["frameworks"]["owasp_llm"]["edition"]
    assert block["frameworks"]["mitre_atlas"]["revision"] == "5.6.0"
    assert block["untested_boundaries"]


def test_report_frameworks_match_engines_pins_no_drift():
    a, b = rf.report_block()["frameworks"], efv.load()["frameworks"]
    for k in ("owasp_llm", "owasp_agentic", "mitre_atlas"):
        assert a[k] == b[k], k


def test_coverage_is_partial_not_complete():
    assert rf.COVERAGE_CLAIM != "complete" and rf.report_block()["coverage_claim"] == "partial-dynamic"
