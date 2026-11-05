"""Rate statistics (plan §8.2): Wilson 95% intervals, ASR@k, cost per success.

One Wilson implementation for the whole tool; tests pin it to statsmodels `proportion_confint(method="wilson")`
reference values so the core image does not carry statsmodels' scientific stack.
"""
from __future__ import annotations

import math

Z95 = 1.959963984540054


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
