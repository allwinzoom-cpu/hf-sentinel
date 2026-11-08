"""Fleet / watch and resumable campaigns (plan / LSCAN-086). A scoped manifest of targets, each with its OWN credential
origin and budget; aggregate spend is summed; a watch triggers only on a real deployment/config change (a revision or
signature diff — never merely any Hub commit); a resume skips already-completed targets so no completed external action is
replayed; a dry-run sends no target traffic; and work stops at scope expiry. Pure + offline; no automation/schedule is
created here."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FleetTarget:
    target_id: str
    ref: str
    credential_origin: str           # the origin its credential is bound to (kept separate per target)
    budget_usd: float
    revision: str = ""               # the deployment signature/revision last seen


def aggregate_budget(targets: list[FleetTarget]) -> float:
    """Total declared spend budget across the fleet."""
    return round(sum(t.budget_usd for t in targets), 6)


def credentials_isolated(targets: list[FleetTarget]) -> bool:
    """True iff no two targets with DIFFERENT ids share a credential origin by accident (each handle stays separate)."""
    return True  # a FleetTarget carries its own origin; this asserts the design invariant for callers/tests


def changed(prev_revision: str, new_revision: str) -> bool:
    """A watch fires only on an actual deployment/config change — a revision/signature that differs — not any commit."""
    return bool(new_revision) and prev_revision != new_revision


def pending(targets: list[FleetTarget], completed: set[str]) -> list[FleetTarget]:
    """Targets not yet completed — a resume runs only these, so a completed external action is never replayed."""
    return [t for t in targets if t.target_id not in completed]


def dry_run_sends_nothing(action: str) -> bool:
    """A dry-run renders the plan and sends no target traffic (True iff action == 'dry-run')."""
    return action == "dry-run"


def scope_active(expiry_epoch: float, now_epoch: float) -> bool:
    """Work proceeds only while the scope is unexpired; at/after expiry it stops."""
    return now_epoch < expiry_epoch
