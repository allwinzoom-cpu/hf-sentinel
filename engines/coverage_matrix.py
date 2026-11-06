"""Capability coverage matrix (plan 16.21 / task 599).

    python engines/coverage_matrix.py            # regenerate docs/coverage.md from engines/capabilities.json + the catalog
    python engines/coverage_matrix.py --check    # exit non-zero if any catalog ID is unaccounted (no write)

Single source of truth is engines/capabilities.json (one owner per capability). This renders the human-readable matrix
and provides `account()` / `inventory_gaps()` for the enforcement test (tests/test_capabilities.py).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPS = ROOT / "engines" / "capabilities.json"
CATALOG = ROOT / "hfsentinel" / "attacks" / "catalog.yaml"
INVENTORY = ROOT / "engines" / "inventory"
OUT = ROOT / "docs" / "coverage.md"

ACCOUNTED = {"wired", "engine-wired", "conditional", "oracle-only", "deferred", "experimental"}


def load_caps() -> dict:
    return json.loads(CAPS.read_text(encoding="utf-8"))


def catalog_ids() -> list[str]:
    import yaml

    doc = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    return [a["id"] for a in doc["attacks"]]


def id_to_capability(caps: dict) -> dict[str, dict]:
    """Map each catalog ID to the single capability that owns it (and so its owner)."""
    out: dict[str, dict] = {}
    for cap in caps["capabilities"]:
        for cid in cap.get("catalog_ids", []):
            if cid in out:
                raise ValueError(f"{cid} owned by two capabilities: {out[cid]['name']} and {cap['name']}")
            out[cid] = cap
    return out


def account(caps: dict | None = None) -> dict:
    """Return {ids, owned, status, unaccounted, double_owned} for the whole catalog."""
    caps = caps or load_caps()
    status = caps["status"]
    owned = id_to_capability(caps)
    ids = catalog_ids()
    unaccounted = [c for c in ids if c not in owned or c not in status or status[c] not in ACCOUNTED]
    return {"ids": ids, "owned": owned, "status": status, "unaccounted": unaccounted,
            "reasons": caps.get("deferred_reasons", {})}


GAP_STATUSES = {"deferred", "experimental"}  # not reliably runnable today = a coverage gap (task 600)


def gaps(caps: dict | None = None) -> list[dict]:
    """Catalog IDs no tool reliably covers yet (status deferred/experimental), each with its owner and the reason that
    doubles as its Phase-3/4 ticket (task 600). Conditionals are not gaps — they run once their precondition is met."""
    caps = caps or load_caps()
    owned = id_to_capability(caps)
    reasons = caps.get("deferred_reasons", {})
    out = []
    for cid in catalog_ids():
        if caps["status"].get(cid) in GAP_STATUSES:
            out.append({"id": cid, "owner": owned.get(cid, {}).get("owner", "—"),
                        "status": caps["status"][cid], "reason": reasons.get(cid, "")})
    return out


def inventory_gaps(caps: dict | None = None) -> list[str]:
    """Engine-owned capabilities must cite inventory entries present in engines/inventory/<alias>.json."""
    caps = caps or load_caps()
    gaps: list[str] = []
    for cap in caps["capabilities"]:
        cites = cap.get("inventory")
        if not cites:
            continue
        inv_path = INVENTORY / f"{cap['owner']}.json"
        if not inv_path.is_file():
            gaps.append(f"{cap['name']}: no inventory file {inv_path.name}")
            continue
        feats = json.loads(inv_path.read_text(encoding="utf-8")).get("features", {})
        for cite in cites:
            key, _, entry = cite.partition(":")
            if entry not in (feats.get(key) or []):
                gaps.append(f"{cap['name']}: cited {cite} absent from {inv_path.name}")
    return gaps


def render(caps: dict | None = None) -> str:
    caps = caps or load_caps()
    acc = account(caps)
    owned, status, reasons = acc["owned"], acc["status"], acc["reasons"]
    lines = ["# Capability coverage matrix", "",
             ("Generated from `engines/capabilities.json` by `engines/coverage_matrix.py` (plan 16.21 / task 599). "
              "Each capability has exactly one owner; every catalog ID is accounted for below."), ""]

    lines += ["## Capabilities (one owner each)", "",
              "| Capability | Owner | Catalog IDs | Fallbacks |", "|---|---|---|---|"]
    for cap in caps["capabilities"]:
        cids = ", ".join(cap.get("catalog_ids", [])) or "—"
        fb = ", ".join(cap.get("fallbacks", [])) or "—"
        lines.append(f"| {cap['name']} | `{cap['owner']}` | {cids} | {fb} |")

    by_status: dict[str, int] = {}
    for c in acc["ids"]:
        by_status[status.get(c, "?")] = by_status.get(status.get(c, "?"), 0) + 1
    lines += ["", "## Catalog accounting", "",
              f"All {len(acc['ids'])} catalog IDs accounted for · "
              + " · ".join(f"{k}: {v}" for k, v in sorted(by_status.items())), "",
              "| ID | Owner | Capability | Status | Note |", "|---|---|---|---|---|"]
    for cid in acc["ids"]:
        cap = owned.get(cid, {})
        note = reasons.get(cid, "")
        lines.append(f"| {cid} | `{cap.get('owner', '—')}` | {cap.get('name', '—')} | "
                     f"{status.get(cid, '—')} | {note} |")

    g = gaps(caps)
    lines += ["", "## Gaps — no reliable coverage yet (task 600)", ""]
    if g:
        lines += [f"{len(g)} technique(s) not reliably runnable today; each maps to a Phase-3/4 ticket (its reason).", "",
                  "| ID | Owner | Status | Ticket / reason |", "|---|---|---|---|"]
        lines += [f"| {row['id']} | `{row['owner']}` | {row['status']} | {row['reason']} |" for row in g]
    else:
        lines.append("None — every catalog ID is reliably covered or conditional on a target precondition.")

    if acc["unaccounted"]:
        lines += ["", f"> UNACCOUNTED: {', '.join(acc['unaccounted'])}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    acc = account()
    gaps = inventory_gaps()
    if acc["unaccounted"]:
        print(f"UNACCOUNTED catalog IDs: {acc['unaccounted']}", file=sys.stderr)
        return 1
    if gaps:
        print(f"inventory citation gaps: {gaps}", file=sys.stderr)
        return 1
    if "--check" in argv:
        print(f"OK: {len(acc['ids'])} catalog IDs accounted, inventory citations verified")
        return 0
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(acc['ids'])} IDs accounted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
