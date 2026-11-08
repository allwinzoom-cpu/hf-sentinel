"""Repeated-run and serving-path stability matrix (plan / LSCAN-032). Repeats a confirmed candidate across seeds,
temperatures, sessions, time windows and explicitly-selected provider/runtime routes, and reports reliability with
UNCERTAINTY (Wilson intervals). It separates attack-GENERATION determinism (does the same seed regenerate identical
attack bytes?) from stochastic TARGET reliability (how often the target actually complies), records route/alias drift and
exposed quantization/template metadata as observed-or-unknown (no weight inspection), and NEVER equates a successful
replay on one serving route with all deployments of the named model. Pure + offline."""
from __future__ import annotations

from dataclasses import dataclass

from hfsentinel.scoring.stats import wilson


@dataclass(frozen=True)
class StabilityCell:
    dimension: str          # e.g. "seed=1", "temp=0.7", "route=deepinfra"
    hits: int
    trials: int

    @property
    def rate(self) -> float | None:
        return round(self.hits / self.trials, 4) if self.trials else None

    @property
    def ci95(self) -> tuple[float, float] | None:
        return wilson(self.hits, self.trials) if self.trials else None


def stability_matrix(cells: list[StabilityCell]) -> list[dict]:
    """Per-cell reliability with a 95% interval — uncertainty is always displayed, never a bare point estimate."""
    return [{"dimension": c.dimension, "rate": c.rate, "ci95": c.ci95, "trials": c.trials} for c in cells]


def generation_vs_target(*, same_seed_regenerates_identical_bytes: bool, target_cell: StabilityCell) -> dict:
    """Separate the two reliabilities (LSCAN-032): attack-generation determinism is a yes/no property of the harness;
    target reliability is a stochastic rate with an interval. They are never conflated."""
    return {"attack_generation_deterministic": bool(same_seed_regenerates_identical_bytes),
            "target_reliability": {"rate": target_cell.rate, "ci95": target_cell.ci95}}


def route_coverage_claim(routes_tested: list[str]) -> str:
    """The honest generalization bound (LSCAN-032): a replay confirmed on the tested route(s) is never claimed for all
    deployments of the named model."""
    n = len({r for r in routes_tested if r})
    return (f"confirmed on {n} serving route(s): {sorted(set(routes_tested))}; not generalizable to all deployments of "
            "the named model")
