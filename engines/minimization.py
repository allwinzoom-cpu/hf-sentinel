"""Attack minimization and causal ablation (plan / LSCAN-031).

A confirmed attack usually bundles several moving parts — stacked transforms, an injected span, a few in-context
examples. Minimization asks which of them actually *caused* the boundary violation and which merely rode along. We
delta-debug (greedy 1-minimization, i.e. remove one component at a time and keep the removal only if the attack still
confirms) down to a 1-minimal subset, while always keeping the attack's IDENTITY — any component marked `required`, e.g.
the core harmful ask — in every candidate, so we never "minimize" into a different attack.

Two controls guard against coincidence (§ "controls recover intended behavior"): a no-attack control (identity stripped)
and a payload-removed control must BOTH fail. If either still succeeds, the suspected payload was not the cause and the
minimization is not causally valid.

Everything runs under a SEPARATE budget from the main scan (§ fair budget accounting): minimization is diagnostic, so it
must never consume a finding's confirmation budget. If the budget is exhausted, or minimization cannot reduce the recipe,
the ORIGINAL confirmed recipe is retained unchanged — a simplification failure never discards a known-good finding.

The oracle is injectable and deterministic here — no network, no model calls; this is the offline core. The live confirm
of a minimized candidate (re-running it against the real target) is a separate, gated step.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# An oracle decides whether the attack still confirms given the ids of the currently-active components. It is pure in
# tests; in production it wraps a live, budgeted confirmation run.
Oracle = Callable[[tuple[str, ...]], bool]


@dataclass(frozen=True)
class Component:
    """One removable (or identity) part of an attack recipe."""
    id: str
    kind: str                 # "transform" | "injected-span" | "context-example" | "turn"
    required: bool = False    # part of the attack identity (e.g. the core ask); never removed


@dataclass
class Budget:
    """A budget separate from the main scan's confirmation budget (LSCAN-031 / fair accounting)."""
    limit: int
    used: int = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def spend(self) -> bool:
        """Charge one oracle call; False if the budget is exhausted (the call must not run)."""
        if self.exhausted:
            return False
        self.used += 1
        return True


@dataclass
class MinimizeResult:
    minimized: tuple[Component, ...]      # the retained recipe (original if nothing could be safely removed)
    reduced: bool                         # True iff at least one component was dropped
    removed: tuple[str, ...]              # ids dropped from the original
    budget_used: int
    reason: str = ""                      # why reduction stopped (empty on a clean 1-minimal result)
    original_confirmed: bool = True       # False means the full recipe did not even confirm under this oracle

    @property
    def confirmed_minimal(self) -> bool:
        """A 1-minimal recipe that still confirms — the defensible minimized candidate."""
        return self.original_confirmed and self.reduced and not self.reason


def _active_ids(required: tuple[Component, ...], removable: list[Component]) -> tuple[str, ...]:
    return tuple(c.id for c in required) + tuple(c.id for c in removable)


def minimize(components: tuple[Component, ...], oracle: Oracle, budget: Budget) -> MinimizeResult:
    """Greedy 1-minimization of a confirmed recipe (LSCAN-031). Required components are kept in every candidate. Returns
    the original recipe unchanged if it does not confirm, if the budget runs out, or if no single removal is safe."""
    required = tuple(c for c in components if c.required)
    kept = [c for c in components if not c.required]

    def test(active: list[Component]) -> bool | None:
        if not budget.spend():
            return None                                   # budget exhausted: cannot test
        return oracle(_active_ids(required, active))

    base = test(kept)
    if base is None:
        return MinimizeResult(components, False, (), budget.used, "budget exhausted before baseline")
    if base is not True:
        # The full recipe did not confirm under this oracle — nothing to minimize; keep it and say so.
        return MinimizeResult(components, False, (), budget.used, "original did not confirm", original_confirmed=False)

    reason = ""
    converged = False
    while not budget.exhausted:
        changed = broke = False
        for c in list(kept):
            trial = [x for x in kept if x.id != c.id]
            r = test(trial)
            if r is None:                                 # ran out mid-pass: stop, keep what we have
                reason, broke = "budget exhausted during minimization", True
                break
            if r is True:
                kept = trial
                changed = True
        if broke:
            break
        if not changed:                                   # a full pass removed nothing -> 1-minimal
            converged = True
            break
    if not reason and not converged:                      # budget ran out before any pass could complete
        reason = "budget exhausted before minimization"

    kept_ids = {c.id for c in kept}
    minimized = tuple(c for c in components if c.required or c.id in kept_ids)
    removed = tuple(c.id for c in components if not c.required and c.id not in kept_ids)
    return MinimizeResult(minimized, bool(removed), removed, budget.used, reason)


def necessary_components(components: tuple[Component, ...], oracle: Oracle, budget: Budget) -> tuple[str, ...]:
    """Causal ablation (LSCAN-031): the removable components whose individual removal BREAKS the attack — i.e. each is
    necessary for the confirmed violation. A component whose removal leaves the attack confirming merely accompanied it.
    One oracle call per removable component (plus one baseline); stops early if the budget runs out."""
    required = tuple(c for c in components if c.required)
    removable = [c for c in components if not c.required]

    def test(active: list[Component]) -> bool | None:
        if not budget.spend():
            return None
        return oracle(_active_ids(required, active))

    if test(removable) is not True:
        return ()                                         # baseline does not confirm: ablation is meaningless
    necessary: list[str] = []
    for c in removable:
        r = test([x for x in removable if x.id != c.id])
        if r is None:
            break                                         # budget exhausted: report what we proved so far
        if r is False:                                    # removing c broke the attack -> c is necessary
            necessary.append(c.id)
    return tuple(necessary)


def controls_valid(oracle: Oracle, *, identity_ids: tuple[str, ...], payload_ids: tuple[str, ...],
                   all_ids: tuple[str, ...], budget: Budget) -> bool:
    """The two controls that make a minimization causally honest (LSCAN-031). Both must FAIL (attack does not confirm):
      * no-attack control — only the benign identity remains (payload and extras stripped);
      * payload-removed control — every component except the suspected payload(s).
    If either control still confirms, the suspected payload did not cause the violation, so the result is not valid.
    Returns False if the budget is exhausted before both controls can be checked (inconclusive, never a pass)."""
    if not budget.spend():
        return False
    if oracle(tuple(identity_ids)) is True:               # no-attack control succeeded -> not caused by the attack
        return False
    if not budget.spend():
        return False
    payload = set(payload_ids)
    no_payload = tuple(i for i in all_ids if i not in payload)
    return oracle(no_payload) is not True                 # payload-removed must fail for the payload to be the cause
