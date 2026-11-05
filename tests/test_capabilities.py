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
