"""Hallucination Score (plan): Σ induced_rate × gain_weight × cross-session reproducibility multiplier. Done-when:
the score rises for a stable (repeated) hallucination vs. a one-off."""
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.scoring.halluc_score import (
    MAX_MULT,
    MIN_MULT,
    HallucResult,
    gain_weights,
    halluc_score,
    reproducibility_multiplier,
)
from hfsentinel.scoring.severity import POINTS


def test_reproducibility_multiplier_bounds_and_monotonic():
    assert reproducibility_multiplier(0, 5) == MIN_MULT          # never reproduced → one-off floor
    assert reproducibility_multiplier(5, 5) == MAX_MULT          # every fresh session → stable ceiling
    assert reproducibility_multiplier(0, 0) == MIN_MULT          # no cross-session data → treated as one-off
    mults = [reproducibility_multiplier(k, 10) for k in range(11)]
    assert mults == sorted(mults) and mults[0] == MIN_MULT and mults[-1] == MAX_MULT


def test_score_rises_for_a_stable_hallucination_vs_a_one_off():
    one_off = HallucResult("H1", induced_rate=0.5, gain_weight=100.0, sessions=5, reproduced=1)
    stable = HallucResult("H1", induced_rate=0.5, gain_weight=100.0, sessions=5, reproduced=5)
    assert halluc_score([stable]) > halluc_score([one_off])      # the done-when
    # same induced_rate + gain, only reproducibility differs
    assert stable.induced_rate == one_off.induced_rate and stable.gain_weight == one_off.gain_weight


def test_score_sums_contributions_and_weights_by_gain():
    low = HallucResult("H3", induced_rate=0.8, gain_weight=15.0, sessions=1, reproduced=1)
    high = HallucResult("H1", induced_rate=0.8, gain_weight=100.0, sessions=1, reproduced=1)
    assert high.contribution > low.contribution                  # higher gain weight → larger contribution
    assert halluc_score([low, high]) == round(low.contribution + high.contribution, 4)
    assert halluc_score([]) == 0.0


def test_gain_weights_come_from_the_severity_table():
    weights = gain_weights(load_catalog())
    assert set(weights) == {f"H{i}" for i in range(1, 8)}         # every hallucination technique
    assert weights["H1"] == POINTS["Critical"]                   # H1 package-hallucination is a §8.3 override → Critical
    assert all(w in POINTS.values() for w in weights.values())   # weights are the severity points, one source of truth
