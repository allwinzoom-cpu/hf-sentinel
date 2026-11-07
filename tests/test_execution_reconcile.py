"""LSCAN-001: reconcile the catalog's scored-status with the capabilities.json run-status, so a technique that is
actually scored can never be recorded as `experimental` (the drift this task fixed), and vice versa. A tested oracle
alone does not imply a runnable scan — this guards the recorded execution status against code drift."""
import json
from pathlib import Path

from hfsentinel.attacks.catalog import load_catalog

CAPS = json.loads((Path(__file__).resolve().parents[1] / "engines" / "capabilities.json").read_text(encoding="utf-8"))
STATUS = CAPS["status"]
CATALOG = load_catalog().by_id()


def test_catalog_ready_ids_are_not_recorded_experimental():
    for cid, a in CATALOG.items():
        if a.status == "ready":
            assert STATUS.get(cid) != "experimental", f"{cid} is catalog-ready but capabilities records 'experimental'"


def test_capabilities_experimental_ids_are_catalog_candidates():
    for cid, s in STATUS.items():
        if s == "experimental":
            assert CATALOG[cid].status == "candidate", \
                f"{cid} is capabilities-'experimental' but catalog status is '{CATALOG[cid].status}'"


def test_catalog_candidates_are_not_recorded_scored():
    scored = {"wired", "engine-wired"}  # a catalog candidate must not be recorded as a scored/runnable technique
    for cid, a in CATALOG.items():
        if a.status == "candidate":
            assert STATUS.get(cid) not in scored, f"{cid} is a catalog candidate but capabilities records it scored"


def test_this_sessions_promotions_are_reconciled():
    # B6/B14/B16 became scaffold-scored, B23 became conditional-scored this session
    assert STATUS["B6"] == "wired" and STATUS["B14"] == "wired" and STATUS["B16"] == "wired"
    assert STATUS["B23"] == "conditional"
