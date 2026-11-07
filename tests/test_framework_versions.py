"""LSCAN-006: framework versions are pinned and surfaced, and coverage is reported as partial-dynamic — never a
'Top 10 complete' claim from merely listing categories."""
import copy

import engines.framework_versions as fw


def test_pins_pass_the_contract():
    assert fw.check() == []


def test_atlas_revision_matches_the_catalog_ids_file():
    atlas = fw.load()["frameworks"]["mitre_atlas"]
    assert atlas["revision"] == "5.6.0" and "atlas_ids_5.6.0" in atlas["ids_file"]


def test_report_block_has_versions_and_partial_claim():
    b = fw.report_block()
    assert b["frameworks"]["owasp_llm"]["edition"] and b["frameworks"]["owasp_agentic"]["edition"]
    assert b["coverage_claim"] == "partial-dynamic" and b["untested_boundaries"]


def test_complete_claim_is_rejected():
    d = copy.deepcopy(fw.load())
    d["coverage_claim"] = "complete"
    assert any("must not be 'complete'" in v for v in fw.check(d))


def test_missing_pin_is_a_violation():
    d = copy.deepcopy(fw.load())
    d["frameworks"]["mitre_atlas"].pop("revision")
    assert any("mitre_atlas" in v for v in fw.check(d))
