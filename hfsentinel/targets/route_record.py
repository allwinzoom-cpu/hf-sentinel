"""Route record + drift evidence (plan LSCAN-009). Captures the serving path actually used for a target — requested vs
resolved provider/model, the served identity if the endpoint exposed one, a timestamp, and the serving **revision**.

Two honesty rules from the task:
  * The revision is the one the *serving path* exposed. If the endpoint did not expose a revision it is recorded as
    `"unknown"` — it is **never** inferred from the Hub repository SHA (a repo SHA is not the served build).
  * Replay must not silently treat a changed provider/model/served-identity as the same serving path: `route_changed`
    compares two records and returns True on any such difference, so a replay against a drifted route is flagged.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass

UNKNOWN_REVISION = "unknown"


@dataclass(frozen=True)
class RouteRecord:
    kind: str                       # hf-provider | hf-endpoint | hf-space | openai | hf-job
    requested_model: str | None     # what the operator asked for (may be an alias)
    requested_provider: str | None  # explicit @provider, or None for auto
    resolved_model: str | None      # canonical model pinned by resolution
    resolved_provider: str | None   # provider actually pinned (None for a non-router route)
    base_url: str                   # the endpoint the request goes to
    served_model: str | None = None  # the identity the endpoint reported, if any (else None — not assumed)
    revision: str = UNKNOWN_REVISION  # the SERVED revision only; "unknown" if the path exposed none (never a Hub SHA)
    resolved_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def build_route_record(resolved, *, served_model: str | None = None, served_revision: str | None = None) -> RouteRecord:
    """Build a RouteRecord from a ResolvedTarget plus whatever the live serving path exposed. `served_revision` is taken
    ONLY from the served identity; absent, the revision is `"unknown"` — a Hub repo SHA is deliberately not accepted
    here as a substitute (LSCAN-009)."""
    return RouteRecord(
        kind=getattr(resolved, "kind", ""),
        requested_model=getattr(resolved, "model", None),
        requested_provider=getattr(resolved, "provider", None),
        resolved_model=getattr(resolved, "model", None),
        resolved_provider=getattr(resolved, "provider", None),
        base_url=getattr(resolved, "base_url", "") or "",
        served_model=served_model,
        revision=served_revision if served_revision else UNKNOWN_REVISION,
        resolved_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    )


def route_changed(a: RouteRecord, b: RouteRecord) -> bool:
    """True iff the serving path differs between two records — so a replay can never silently treat a changed provider,
    model, served identity, endpoint, or served revision as the same path. `resolved_at` is ignored (timing, not route)."""
    keys = ("kind", "resolved_provider", "resolved_model", "base_url", "served_model", "revision")
    return any(getattr(a, k) != getattr(b, k) for k in keys)
