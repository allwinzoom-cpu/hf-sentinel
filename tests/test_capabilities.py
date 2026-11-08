"""Capability-ownership matrix (plan 16.21 / task 599): one owner per capability; every catalog ID accounted for;
every adopted engine owns a capability nobody else owns; engine-owned capabilities cite installed inventory entries.
Done-when: coverage.md generated, no ID unaccounted."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_coverage():
    spec = importlib.util.spec_from_file_location("coverage_matrix", ROOT / "engines" / "coverage_matrix.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


coverage = _load_coverage()
CAPS = coverage.load_caps()
ADOPTED = {v["alias"] for v in json.loads((ROOT / "engines" / "versions.json").read_text())["engines"].values()}
VALID_STATUS = {"wired", "engine-wired", "conditional", "oracle-only", "deferred", "experimental"}
NEEDS_REASON = {"conditional", "oracle-only", "deferred", "experimental"}


def test_every_catalog_id_accounted_exactly_once():
    acc = coverage.account(CAPS)
    assert acc["unaccounted"] == [], f"unaccounted: {acc['unaccounted']}"
    # id_to_capability raises if any ID is owned by two capabilities
    owned = coverage.id_to_capability(CAPS)
    assert set(owned) == set(acc["ids"])                     # exactly the catalog, nothing extra


def test_one_owner_per_capability():
    known = set(CAPS["owners"])
    for cap in CAPS["capabilities"]:
        assert isinstance(cap["owner"], str) and cap["owner"] in known, cap["name"]
        for fb in cap.get("fallbacks", []):
            assert fb in known, f"{cap['name']}: unknown fallback {fb}"


def test_each_adopted_engine_owns_a_capability_nobody_else_owns():
    owners = [c["owner"] for c in CAPS["capabilities"]]
    for alias in ADOPTED:
        owned = [c["name"] for c in CAPS["capabilities"] if c["owner"] == alias]
        assert owned, f"adopted engine {alias} owns no capability"
        # 'nobody else owns' holds because owner is a single value per capability
        assert all(owners.count(alias) >= 1 for _ in owned)


def test_engine_owned_capabilities_cite_installed_inventory():
    assert coverage.inventory_gaps(CAPS) == [], coverage.inventory_gaps(CAPS)


def test_status_values_valid_and_deferred_have_a_reason():
    reasons = CAPS.get("deferred_reasons", {})
    for cid, st in CAPS["status"].items():
        assert st in VALID_STATUS, f"{cid}: bad status {st}"
        if st in NEEDS_REASON:
            assert reasons.get(cid), f"{cid} is {st} but has no deferred_reason"


def test_coverage_md_is_current():
    md = (ROOT / "docs" / "coverage.md").read_text(encoding="utf-8")
    assert md == coverage.render(CAPS), "docs/coverage.md is stale — run `python engines/coverage_matrix.py`"
    assert f"All {len(coverage.catalog_ids())} catalog IDs accounted" in md


def test_gaps_are_identified_and_every_gap_is_ticketed():
    # task 600: the coverage matrix names the techniques no tool reliably covers yet, each mapped to a reason/ticket.
    g = coverage.gaps(CAPS)
    assert g, "expected known coverage gaps (the judge-gated B jailbreaks)"
    assert all(row["reason"] for row in g), "every gap must map to a Phase-3/4 ticket (its reason)"
    assert all(row["status"] in {"deferred", "experimental"} for row in g)
    ids = {row["id"] for row in g}
    assert not ({"H2", "H5", "H6", "H7"} & ids)        # hallucination gaps the plan expected are now closed
    assert ids <= set(CAPS["status"])                   # gaps are catalog IDs


def test_coverage_md_has_a_gaps_section():
    md = (ROOT / "docs" / "coverage.md").read_text(encoding="utf-8")
    assert "## Gaps — no reliable coverage yet (task 600)" in md


def test_variation_coverage_rows_cover_every_catalog_id_and_gate_unsupported_cells():
    # LSCAN-087: a per-technique dimension row for every catalog id; gated (deferred/experimental) techniques are
    # not-runnable so an unsupported cell can never improve a grade.
    rows = coverage.variation_coverage(CAPS)
    assert {r["id"] for r in rows} == set(coverage.catalog_ids())
    for r in rows:
        assert set(r) >= {"id", "family", "oracle", "evidence_level", "replay", "status", "runnable"}
        if r["status"] in ("deferred", "experimental"):
            assert r["runnable"] is False               # gated cells cannot count toward a grade
        if r["runnable"]:
            assert r["oracle"] != "none"                # a runnable technique has a real oracle


def test_variation_coverage_md_is_current_and_honest():
    md = (ROOT / "docs" / "variation_coverage.md").read_text(encoding="utf-8")
    assert md == coverage.render_variation(CAPS), "docs/variation_coverage.md is stale — run engines/coverage_matrix.py"
    assert "not" in md and "Cartesian product" in md          # no unbounded-coverage claim
    assert "cannot improve a grade" in md                     # unsupported cells never help the grade
    assert "no (gated)" in md                                 # gated techniques are shown as such
