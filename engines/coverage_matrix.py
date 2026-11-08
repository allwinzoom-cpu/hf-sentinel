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


def routing(caps: dict, ids: list[str]) -> list[tuple[str, list[str]]]:
    """Group the given catalog IDs by their capability owner (plan 16.21 / task 599), most-covered owner first. IDs with
    no owner in the matrix are grouped under 'unassigned'. Used by the CLI plan print to show real engine routing."""
    owned = id_to_capability(caps)
    groups: dict[str, list[str]] = {}
    for cid in ids:
        groups.setdefault(owned.get(cid, {}).get("owner", "unassigned"), []).append(cid)
    return sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))


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


VARIATION_OUT = ROOT / "docs" / "variation_coverage.md"

# Implemented delivery surfaces (LSCAN-087) -> the catalog techniques each one actually exercises. This is the real,
# bounded surface list, not an unbounded Cartesian product of every placement x protocol x feature combination.
DELIVERY_SURFACES: dict[str, tuple[str, ...]] = {
    "direct-chat": ("A1", "A6"),
    "indirect/hidden-injection": ("A2", "A3"),
    "image-input": ("A4",),
    "exfiltration-channel": ("A5",),
    "encoding-mutator": ("B2", "B6", "B14", "B15", "B16"),
    "persona-scaffold": ("B1", "B9", "B10", "B17", "B18", "B19", "B21"),
    "many-shot / long-context": ("B5",),
    "multilingual": ("B3",),
    "structured-output": ("B23",),
    "best-of-n": ("B13",),
    "multi-turn": ("B4", "B11"),
    "adaptive-search (PAIR/TAP)": ("B7",),
    "extraction": ("C1", "C2", "C3", "C4"),
    "active-content / code": ("E1", "E2", "E3", "E5"),
}


def variation_coverage(caps: dict | None = None) -> list[dict]:
    """Per-technique coverage across the implemented dimensions (LSCAN-087): family, oracle kind, evidence level, replay
    level and run status, derived only from implemented metadata (catalog + oracle registry + evidence rules + the
    capability matrix). A gated technique (deferred/experimental) is marked not-runnable so an unsupported cell can never
    improve a grade."""
    from hfsentinel.attacks.oracles import ORACLES
    from hfsentinel.scoring.evidence import evidence_level
    caps = caps or load_caps()
    cat = _catalog_by_id()
    status = caps["status"]
    rows = []
    for cid in catalog_ids():
        a = cat.get(cid)
        orc = ORACLES.get(cid)
        kind = orc.kind if orc else "none"
        try:
            ev = evidence_level(kind, cid)
        except Exception:  # noqa: BLE001 — an unmapped kind just yields an unknown level, never a crash
            ev = "unknown"
        st = status.get(cid, "?")
        rows.append({"id": cid, "family": a.category if a else "?", "oracle": kind,
                     "evidence_level": ev, "replay": "exact" if kind == "deterministic" else "recipe-only",
                     "status": st, "runnable": st not in ("deferred", "experimental", "?")})
    return rows


def _catalog_by_id() -> dict:
    import types

    import yaml

    doc = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    return {a["id"]: types.SimpleNamespace(**a) for a in doc["attacks"]}


def render_variation(caps: dict | None = None) -> str:
    caps = caps or load_caps()
    rows = variation_coverage(caps)
    runnable = [r for r in rows if r["runnable"]]
    gated = [r for r in rows if not r["runnable"]]
    surfaces_ids = {c for ids in DELIVERY_SURFACES.values() for c in ids}
    unmapped = sorted(r["id"] for r in rows if r["id"] not in surfaces_ids)
    lines = ["# Variation coverage (LSCAN-087)", "",
             ("Per-technique coverage across the implemented dimensions — family, oracle, evidence level, replay level "
              "and run status — derived from implemented metadata only (catalog + oracle registry + evidence rules + the "
              "capability matrix). This is bounded per-technique coverage, **not** an exhaustive Cartesian product of "
              "every placement x protocol x feature combination."), "",
             (f"**{len(runnable)} of {len(rows)} techniques are runnable**; {len(gated)} are gated "
              "(deferred/experimental) and **cannot improve a grade**. A \"no findings\" result is reported only with "
              "this tested coverage and its limitations — absence of a capability is observed in recon, never assumed."),
             "", "## Techniques", "",
             "| ID | Family | Oracle | Evidence level | Replay | Status | Runnable |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['family']} | {r['oracle']} | {r['evidence_level']} | {r['replay']} | "
                     f"{r['status']} | {'yes' if r['runnable'] else 'no (gated)'} |")
    lines += ["", "## Delivery surfaces (implemented)", "", "| Surface | Catalog IDs |", "|---|---|"]
    for surface, ids in DELIVERY_SURFACES.items():
        lines.append(f"| {surface} | {', '.join(ids)} |")
    lines += ["", (f"> Techniques not mapped to a delivery surface above: {', '.join(unmapped) or 'none'} "
                   "(untested combination, reported — not claimed).")]
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
    VARIATION_OUT.write_text(render_variation(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} and {VARIATION_OUT.relative_to(ROOT)} ({len(acc['ids'])} IDs accounted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
