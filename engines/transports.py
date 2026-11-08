"""Persistent and non-HTTP application transport contracts (plan / LSCAN-019).

This is an ARCHITECTURAL EXTENSION PROPOSAL, not a claim that the tool already speaks every protocol. It defines the
contract a persistent transport (SSE, WebSocket, RPC) must satisfy so that session boundaries and tool actions line up
with the actual application: session create/reset/cancel, message correlation by id (so out-of-order events and duplicate
callbacks resolve correctly), and explicit observation hooks. Two guard rails:

  * A DROPPED connection yields INCONCLUSIVE evidence — never a fabricated completion. Losing the channel is the absence
    of evidence, not evidence of success.
  * An HTTP chat adapter CANNOT claim browser/persistent coverage. A browser-only app needs an operator-provided test
    bridge or a separately scoped UI harness; this module refuses to let an HTTP adapter assert it covered that surface.

Offline deterministic core; the live bridges are a gated, operator-provided extension. See [[strictly-llm-only-no-agentic]].
"""
from __future__ import annotations

from dataclasses import dataclass

TRANSPORTS = ("http", "sse", "websocket", "rpc")
PERSISTENT = ("sse", "websocket", "rpc")                 # transports that carry a browser/persistent surface
SESSION_STATES = ("open", "reset", "cancelled", "dropped")


@dataclass(frozen=True)
class TransportContract:
    name: str
    supports_sessions: bool
    supports_cancel: bool

    def __post_init__(self) -> None:
        if self.name not in TRANSPORTS:
            raise ValueError(f"unknown transport {self.name!r}; expected one of {TRANSPORTS}")

    @property
    def is_persistent(self) -> bool:
        return self.name in PERSISTENT


@dataclass(frozen=True)
class Event:
    correlation_id: str      # ties a response back to its request (resolves out-of-order delivery)
    seq: int                 # per-correlation sequence number (resolves duplicate callbacks)
    payload: str


def correlate(events: list[Event], correlation_id: str) -> list[Event]:
    """All events for one request, ordered by their sequence number (LSCAN-019). Out-of-order arrival is normalized by
    `seq`, so correlation never depends on wire order."""
    matched = [e for e in events if e.correlation_id == correlation_id]
    return sorted(matched, key=lambda e: e.seq)


def dedupe(events: list[Event]) -> list[Event]:
    """Collapse duplicate callbacks (LSCAN-019): keep the first event per (correlation_id, seq), preserving order."""
    seen: set[tuple[str, int]] = set()
    out: list[Event] = []
    for e in events:
        key = (e.correlation_id, e.seq)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def is_stale(session_epoch: int, current_epoch: int) -> bool:
    """A session is stale once a reset/reconnect has advanced the epoch past the one it was opened in (LSCAN-019)."""
    return session_epoch < current_epoch


def completion_evidence(session_state: str, *, observed_effect: bool) -> str:
    """Grade a tool action's completion (LSCAN-019). A dropped connection is INCONCLUSIVE regardless of what was observed
    before the drop — never a fabricated completion. A completion requires a clean session AND an explicitly observed
    effect."""
    if session_state not in SESSION_STATES:
        raise ValueError(f"unknown session state {session_state!r}; expected one of {SESSION_STATES}")
    if session_state == "dropped":
        return "inconclusive: connection dropped — no completion can be asserted"
    if session_state in ("reset", "cancelled"):
        return f"no completion: session {session_state} before the effect was observed"
    return "completed: observed effect on an open session" if observed_effect else "no completion: no observed effect"


def coverage_claim(contract: TransportContract, *, surface: str, has_operator_bridge: bool) -> str:
    """What coverage a transport may honestly claim (LSCAN-019). An HTTP adapter cannot claim a browser/persistent
    surface; such a surface needs an operator-provided test bridge or a separately scoped UI harness."""
    if surface == "browser" and not contract.is_persistent and not has_operator_bridge:
        return ("N/A: an HTTP chat adapter cannot claim browser coverage — needs an operator-provided test bridge or a "
                "separately scoped UI harness")
    if surface == "browser" and not has_operator_bridge:
        return "inconclusive: persistent transport declared but no operator test bridge provided"
    return f"covered: {contract.name} over {surface}"
