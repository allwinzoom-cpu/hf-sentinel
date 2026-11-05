"""Best-of-N augmentation sampling (plan Encoding/transform battery, catalog B13).

Best-of-N amplifies a weak attack by trying many augmented variants and keeping the best: success at *k* tries is the
ASR@k curve, and in the Best-of-N literature the number of samples needed scales as a **power law**. This module turns
observed trials into that curve and fits the power law, so a run can report "ASR@k" and extrapolate how many samples a
given success probability would take. Pure stdlib (shared Wilson/ASR@k math in `scoring.stats`); the actual augmented
sampling is driven by the mutator battery (`attacks.mutators`) through the campaign.
"""
from __future__ import annotations

import math

from hfsentinel.scoring.stats import asr_at_k


def asr_at_k_curve(successes: int, trials: int, ks: list[int] | None = None) -> list[tuple[int, float]]:
    """The ASR@k curve: [(k, ASR@k)] for k = 1..trials (or the given `ks`, capped at `trials`)."""
    ks = ks if ks is not None else list(range(1, trials + 1))
    return [(k, asr_at_k(successes, trials, k)) for k in ks if 1 <= k <= trials]


def power_law_fit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Least-squares fit of `y = coeff * x**exponent` on the positive points (log-log linear regression).
    Returns (exponent, coeff). Raises ValueError with fewer than two positive points."""
    pts = [(math.log(x), math.log(y)) for x, y in zip(xs, ys, strict=False) if x > 0 and y > 0]
    n = len(pts)
    if n < 2:
        raise ValueError("need at least two positive (x, y) points to fit a power law")
    sx = sum(a for a, _ in pts)
    sy = sum(b for _, b in pts)
    sxx = sum(a * a for a, _ in pts)
    sxy = sum(a * b for a, b in pts)
    denom = n * sxx - sx * sx
    if denom == 0:
        raise ValueError("x values are degenerate (all equal); cannot fit")
    exponent = (n * sxy - sx * sy) / denom
    coeff = math.exp((sy - exponent * sx) / n)
    return exponent, coeff


def extrapolate(exponent: float, coeff: float, k: int) -> float:
    """Evaluate the fitted power law at `k`."""
    return coeff * (k ** exponent)


def samples_to_reach(exponent: float, coeff: float, target_asr: float) -> float:
    """Invert the fitted power law: the (fractional) number of samples k at which the fit reaches `target_asr`.
    Only meaningful for an increasing fit (exponent > 0) and 0 < target_asr; returns inf otherwise."""
    if exponent <= 0 or target_asr <= 0 or coeff <= 0:
        return math.inf
    return (target_asr / coeff) ** (1.0 / exponent)
