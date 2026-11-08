"""Replay a confirmed finding from its recipe (plan 16.17 done-when: "every confirmed finding replays from its
recipe"). The report persists only aggregates + a redacted excerpt for non-confirmed trials; a confirmed finding
instead carries a `Repro` recipe (catalog id, seed, trials, temperature, mutator chain) + the target pin, which is
everything needed to regenerate the exact trials deterministically and re-fire the native oracle.

    run = replay(finding.repro, target)          # re-runs the seeded sweep for this one technique
    assert run.hits >= 1                          # the oracle fires again → the finding reproduces

No raw transcript is needed to reproduce: the seed regenerates the same trial payloads, and the oracle (canary / E-rule)
scores the fresh output. `--save-transcripts` keeps the full exchange for confirmed findings only, for the operators
who want it; replay does not depend on it.
"""
from __future__ import annotations

from hfsentinel.attacks.canary import CanaryRun
from hfsentinel.engines.sweep import TechniqueRun, run_technique
from hfsentinel.report.schema import Repro


def replay(repro: Repro, target, *, gov=None, max_tokens: int = 256, concurrency: int = 1,
           sink_host: str | None = None) -> TechniqueRun:
    """Re-run the single technique described by `repro` against `target`, deterministically (same seed → same trials).
    Runs every recipe trial (no early stop) so the recipe is reproduced in full; the returned run's `hits`/`proven`
    show whether the native oracle fires again. `gov` is a Governor; a budget-free one is used when omitted."""
    if gov is None:
        from hfsentinel.engines.governor import Governor, Ledger
        # A generous meter covering the recipe's trials (+ temp-0 attempt and headroom); replay is a one-off re-run.
        gov = Governor(Ledger(max_requests=repro.trials * 4 + 8, budget_usd=10.0), concurrency=max(1, concurrency))
    canaries = CanaryRun(repro.seed, **({"sink_host": sink_host} if sink_host else {}))
    mutator = repro.mutator_chain[0] if repro.mutator_chain else None
    # Replay at the manifest's exact generation settings (LSCAN-024); fall back to the arg only for an older recipe that
    # predates the captured max_tokens.
    return run_technique(target, gov, repro.catalog_id, trials=repro.trials, temperature=repro.temperature,
                         max_tokens=repro.max_tokens or max_tokens, concurrency=concurrency, canaries=canaries,
                         seed=repro.seed, adaptive=False, mutator=mutator)
