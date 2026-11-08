"""Rate statistics (plan §8.2): Wilson 95% intervals, ASR@k, cost per success.

One Wilson implementation for the whole tool; tests pin it to statsmodels `proportion_confint(method="wilson")`
reference values so the core image does not carry statsmodels' scientific stack.
"""
from __future__ import annotations

import math
from statistics import NormalDist

Z95 = 1.959963984540054
# One-sided family-wise false-confirm budget for the adaptive early-stop. A single look reproduces the Z95 two-sided
# Wilson lower bound (its 2.5% lower tail); more looks spend the same budget across the looks (LSCAN-028).
CONFIRM_ALPHA = 0.025


def planned_looks(planned_trials: int, min_trials: int, wave: int) -> int:
    """Predeclared number of interim confirmation looks for an adaptive run: one after the first (`min_trials`) wave,
    then one per `wave` trials until `planned_trials` is reached. Predeclared from the plan — never the actual run — so
    the multiplicity correction is valid no matter where the run actually stops (LSCAN-028)."""
    if planned_trials <= min_trials:
        return 1
    return 1 + math.ceil((planned_trials - min_trials) / max(1, wave))


def sequential_z(n_looks: int, alpha: float = CONFIRM_ALPHA) -> float:
    """One-sided z for a confirmation lower bound checked at `n_looks` interim looks, Bonferroni-corrected so the
    family-wise false-confirm rate stays ≤ `alpha`. `n_looks == 1` returns the usual Z95 (so a single-look run is
    unchanged); more looks → larger z → a stricter per-look bar, so repeatedly checking a fixed-sample interval cannot
    inflate the false-confirm rate above `alpha` (LSCAN-028)."""
    return NormalDist().inv_cdf(1.0 - alpha / max(1, n_looks))


def wilson(successes: int, trials: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval, unrounded. (0, 0) for zero trials."""
    if trials <= 0:
        return (0.0, 0.0)
    if not 0 <= successes <= trials:
        raise ValueError("successes must be within [0, trials]")
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def asr_at_k(successes: int, trials: int, k: int) -> float:
    """Unbiased estimate of P(at least one success in k attempts) from n independent trials with c successes:
    1 − C(n−c, k) / C(n, k). Needs 1 ≤ k ≤ n."""
    if not 1 <= k <= trials:
        raise ValueError("k must be within [1, trials]")
    if trials - successes < k:
        return 1.0
    return 1.0 - math.comb(trials - successes, k) / math.comb(trials, k)


def at_k_interval(interval: tuple[float, float], k: int) -> tuple[float, float]:
    """Map a per-attempt interval through p ↦ 1 − (1 − p)^k (monotone, so the bounds carry over)."""
    lo, hi = interval
    return (1.0 - (1.0 - lo) ** k, 1.0 - (1.0 - hi) ** k)


def per_success(total: float, successes: int) -> float | None:
    """Cost (requests, tokens or USD) per success; None when nothing succeeded."""
    return total / successes if successes else None
