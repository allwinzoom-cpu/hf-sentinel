"""Public-paper replication dossiers and promotion gates (plan / LSCAN-084). A technique moves Candidate -> Conditional
-> Ready ONLY on actual live-model confirmation plus matched controls — never on paper ASR, imported code, fixture
success or a canary surrogate alone. A failed replication stays documented and unscored, and every proposed variation is
tagged a faithful replication or a new extension. Pure data + the gate; no network."""
from __future__ import annotations

from dataclasses import dataclass

STATUSES = ("candidate", "conditional", "ready")
VARIATION_TAGS = ("faithful-replication", "new-extension")
# Evidence kinds that CANNOT by themselves justify a promotion (LSCAN-084).
INSUFFICIENT_EVIDENCE = frozenset({"paper_asr", "imported_code", "fixture_success", "canary_surrogate"})


@dataclass(frozen=True)
class Dossier:
    """One replication dossier per method (LSCAN-084)."""
    method: str
    paper: str
    code_url: str
    pinned_version: str
    access_assumptions: str
    variant_tag: str                    # faithful-replication | new-extension
    query_budget: str
    controls: tuple[str, ...]
    target_route: str
    oracle_calibration: str
    live_confirmed: bool = False        # an independent live-model replay confirmed it (with controls)
    evidence: tuple[str, ...] = ()      # the evidence kinds relied on

    def __post_init__(self):
        if self.variant_tag not in VARIATION_TAGS:
            raise ValueError(f"variant_tag must be one of {VARIATION_TAGS}")


def can_promote(dossier: Dossier, to_status: str) -> bool:
    """A promotion to conditional/ready is allowed only with live-model confirmation AND at least one matched control,
    and never when the ONLY evidence is paper ASR / imported code / fixture success / a canary surrogate (LSCAN-084)."""
    if to_status not in ("conditional", "ready"):
        return False
    real_evidence = set(dossier.evidence) - INSUFFICIENT_EVIDENCE
    return dossier.live_confirmed and bool(dossier.controls) and bool(real_evidence)


def promotion_blocked_reason(dossier: Dossier, to_status: str) -> str:
    """Why a promotion is refused (empty string if allowed) — a failed replication stays documented and unscored."""
    if to_status not in ("conditional", "ready"):
        return f"{to_status!r} is not a promotable status"
    if not dossier.live_confirmed:
        return "no live-model confirmation (paper ASR / fixtures / imported code do not count)"
    if not dossier.controls:
        return "no matched controls"
    if not (set(dossier.evidence) - INSUFFICIENT_EVIDENCE):
        return "only insufficient evidence (paper ASR / imported code / fixture / canary surrogate)"
    return ""
