"""Gateway, cache and concurrency isolation checks (plan / LSCAN-076).

A model gateway can leak one caller's content to another through response/session crossover, a shared cache keyed too
loosely, or cancel/retry races. We test this with PAIRED SYNTHETIC IDENTITIES: each identity plants a FRESH canary in its
own request; a confidentiality impact is confirmed ONLY when one identity's canary surfaces in another's response. Two
rules keep it honest:

  * A fresh-canary crossover is the ONLY confirmation of a leak (deterministic, unforgeable). Same-content coincidences
    cannot forge it.
  * A latency/timing difference is NEVER by itself a cache side-channel finding — ordinary timing noise is not evidence.
    A timing signal stays EXPERIMENTAL unless a canary crossover independently confirms the leak.

Runs at LOW concurrency within a declared quota. This is a scoped application/gateway concern — a raw model endpoint with
no shared cache/session layer is simply N/A. Offline deterministic core; the live paired run is gated.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    """One synthetic caller: a distinct session token and a fresh unforgeable canary planted in its request."""
    id: str
    session_token: str
    canary: str


def crossover(response: str, foreign_canary: str) -> bool:
    """True iff a response carries another identity's fresh canary — an unforgeable confidentiality leak (LSCAN-076)."""
    return bool(foreign_canary) and foreign_canary in (response or "")


def session_crossover(responses: dict[str, str], identities: list[Identity]) -> list[tuple[str, str]]:
    """Every (source_identity, leaked_into_identity) pair where one caller's canary surfaced in another's response
    (LSCAN-076). Self-matches (an identity seeing its own canary) are expected and never reported."""
    by_id = {ident.id: ident for ident in identities}
    leaks: list[tuple[str, str]] = []
    for recv_id, text in responses.items():
        for src in identities:
            if src.id != recv_id and src.id in by_id and crossover(text, src.canary):
                leaks.append((src.id, recv_id))
    return leaks


def cancel_retry_leak(cancelled_canary: str, later_response: str) -> bool:
    """True iff a cancelled request's fresh canary reappears in a later (retry or other-caller) response — a cancel/retry
    race leak (LSCAN-076)."""
    return crossover(later_response, cancelled_canary)


def cache_key_isolated(a: Identity, b: Identity, a_response: str, b_response: str) -> bool:
    """Gateway cache-key isolation (LSCAN-076): two identities issuing the SAME prompt must not receive each other's
    cached content. Isolated iff neither response carries the other's canary."""
    return not (crossover(b_response, a.canary) or crossover(a_response, b.canary))


def timing_verdict(*, canary_confirmed: bool, latency_delta_ms: float, noise_floor_ms: float) -> str:
    """How to read a cache/timing signal (LSCAN-076). A canary crossover confirms the leak outright. Absent that, a
    latency gap — even a large one — is only ever EXPERIMENTAL; ordinary timing noise is not a side-channel finding."""
    if canary_confirmed:
        return "confirmed: canary crossover (cache/session leak) — timing is corroborating, not the basis"
    if latency_delta_ms > noise_floor_ms:
        return (f"experimental: timing-only signal ({latency_delta_ms:.0f}ms > {noise_floor_ms:.0f}ms floor) — "
                "NOT a confirmed cache side-channel without a canary crossover")
    return "no signal: within timing noise"


def within_quota(concurrency: int, *, max_concurrency: int) -> bool:
    """Keep paired checks at low concurrency within the operator-declared quota (LSCAN-076)."""
    return 0 < concurrency <= max_concurrency
