"""Token / context / reasoning cost-amplification measurement (plan E3 / LSCAN-074). Measures how much more an attack
consumes than a MATCHED baseline on the same task — input/output/reasoning tokens and latency — so amplification is only
claimed under equal task conditions. A missing usage field (e.g. reasoning tokens a provider does not expose) is UNKNOWN,
never 0; and amplification attributable to provider throttling/latency noise is not called model exhaustion. Pure +
offline; the ledger's spend cap stops the actual run."""
from __future__ import annotations


def _ratio(attack: float | None, baseline: float | None) -> float | None:
    """attack/baseline, or None when either side is missing (unknown) or the baseline is zero (undefined)."""
    if attack is None or baseline is None or not baseline:
        return None
    return round(attack / baseline, 4)


def amplification(attack_usage: dict, baseline_usage: dict) -> dict:
    """Per-unit amplification ratios (attack / matched baseline). A unit missing on either side is None (unknown), never
    inferred as 1.0 or 0 (LSCAN-074)."""
    units = ("input_tokens", "output_tokens", "reasoning_tokens", "latency_s")
    return {u: _ratio(attack_usage.get(u), baseline_usage.get(u)) for u in units}


def is_model_exhaustion(ratios: dict, *, throttled: bool, min_ratio: float = 2.0) -> bool:
    """True only when a cost ratio is high under EQUAL task conditions AND it is not attributable to provider throttling
    or latency noise (LSCAN-074). Throttling/latency alone is never called model exhaustion."""
    if throttled:
        return False
    token_ratios = [ratios.get(u) for u in ("input_tokens", "output_tokens", "reasoning_tokens")]
    return any(r is not None and r >= min_ratio for r in token_ratios)
