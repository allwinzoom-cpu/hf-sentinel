"""Reproducibility-compatible evidence retention (plan / LSCAN-033, depends on LSCAN-024/025 + D-015). Decides the minimal
artifacts to persist for a finding so it can be replayed without hoarding sensitive content: a canonical request hash and
a redacted excerpt are always safe; a full transcript is kept only for a CONFIRMED finding AND only with the operator's
explicit (encrypted) opt-in. Unconfirmed findings persist nothing sensitive, and no raw credential or unconfirmed harmful
response is ever stored by default. The supported replay level (payload-only / full-script / exact-transcript) is derived
from what was actually retained, and an absent exact transcript is an explicit reproducibility limitation, not silence."""
from __future__ import annotations

from dataclasses import dataclass

REPLAY_LEVELS = ("payload-only", "full-script", "exact-transcript")


@dataclass(frozen=True)
class Retained:
    request_hash: str                 # canonical hash of the request (always safe to keep)
    redacted_excerpt: str = ""        # short redacted evidence (D-015)
    mutator_chain: tuple[str, ...] = ()   # the ordered script (LSCAN-025), enables full-script replay
    transcript_encrypted: bool = False    # a full transcript kept only under operator-controlled encryption


def plan_retention(*, confirmed: bool, transcript_opt_in: bool, request_hash: str, excerpt: str,
                   mutator_chain: tuple[str, ...]) -> Retained:
    """What to persist (LSCAN-033/D-015). An unconfirmed finding keeps only the request hash (no sensitive content). A
    confirmed finding keeps a redacted excerpt and the replay script; a full (encrypted) transcript is kept only on an
    explicit opt-in. A raw credential or unconfirmed harmful response is never persisted."""
    if not confirmed:
        return Retained(request_hash=request_hash)
    return Retained(request_hash=request_hash, redacted_excerpt=excerpt[:200], mutator_chain=tuple(mutator_chain),
                    transcript_encrypted=bool(transcript_opt_in))


def replay_level(retained: Retained) -> str:
    """The strongest replay level the retained artifacts support (LSCAN-033). An absent transcript/script caps the level
    — never claimed beyond what was kept."""
    if retained.transcript_encrypted:
        return "exact-transcript"
    if retained.mutator_chain:
        return "full-script"
    return "payload-only"


def reproducibility_limitation(retained: Retained) -> str:
    """The explicit limitation when exact replay is not available (empty if exact-transcript is retained)."""
    lvl = replay_level(retained)
    return "" if lvl == "exact-transcript" else f"exact-transcript replay unavailable (retained: {lvl})"


def redaction_preserves_attack(original_request_hash: str, retained: Retained) -> bool:
    """Redaction must not silently change the replayed attack: the retained request hash must still match the original
    (LSCAN-033). Redaction touches only the displayed excerpt, never the canonical request."""
    return retained.request_hash == original_request_hash
