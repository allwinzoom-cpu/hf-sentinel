"""Cost-amplification measurement (plan E3 / LSCAN-074): ratios vs a matched baseline, missing usage is unknown, and
throttling/latency noise is not model exhaustion."""
from hfsentinel.attacks import amplification as amp


def test_ratios_and_missing_usage_is_unknown():
    r = amp.amplification({"input_tokens": 400, "output_tokens": 800, "latency_s": 6.0},
                          {"input_tokens": 100, "output_tokens": 200, "latency_s": 3.0})
    assert r["input_tokens"] == 4.0 and r["output_tokens"] == 4.0 and r["latency_s"] == 2.0
    assert r["reasoning_tokens"] is None                      # not exposed on either side -> unknown, not 0


def test_zero_baseline_is_undefined_not_infinite():
    assert amp.amplification({"output_tokens": 5}, {"output_tokens": 0})["output_tokens"] is None


def test_exhaustion_requires_high_ratio_and_not_throttling():
    ratios = {"output_tokens": 5.0, "input_tokens": 1.1, "reasoning_tokens": None}
    assert amp.is_model_exhaustion(ratios, throttled=False) is True
    assert amp.is_model_exhaustion(ratios, throttled=True) is False       # throttling is not model exhaustion
    assert amp.is_model_exhaustion({"output_tokens": 1.2}, throttled=False) is False  # below the amplification bar
