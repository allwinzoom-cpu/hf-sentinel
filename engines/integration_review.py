"""LSCAN-005 integration-inventory validator. Enforces the acceptance contract on `engines/integration_candidates.json`:
every candidate records the required evidence; `documentation-only`/`rejected` candidates are never treated as
integrated; and every integrated engine owns a capability (preserving one-owner-per-capability with capabilities.json).
Pure + offline; `check()` returns the list of contract violations (empty = OK)."""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATES = HERE / "integration_candidates.json"

REQUIRED = ("status", "unique_value", "installed_version_proof", "fallback", "egress", "scorecard")
INTEGRATED = "integrated-engine"
NOT_INTEGRATED = ("documentation-only", "rejected")


def load() -> dict:
    return json.loads(CANDIDATES.read_text(encoding="utf-8"))


def check(data: dict | None = None) -> list[str]:
    data = data or load()
    valid = set(data["statuses"])
    bad: list[str] = []
    for name, c in data["candidates"].items():
        for f in REQUIRED:
            if not c.get(f):
                bad.append(f"{name}: missing required field '{f}'")
        if c.get("status") not in valid:
            bad.append(f"{name}: invalid status {c.get('status')!r}")
        # documentation-only / rejected must not claim a capability owner (i.e. must not be treated as integrated)
        if c.get("status") in NOT_INTEGRATED and c.get("owner_capability"):
            bad.append(f"{name}: {c['status']} candidate must not own a capability (not integrated)")
        # an integrated engine must own a capability (one-owner-per-capability: it earns its place)
        if c.get("status") == INTEGRATED and not c.get("owner_capability"):
            bad.append(f"{name}: integrated engine must own a capability")
    return bad
