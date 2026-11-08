"""LSCAN-028: the adaptive early-stop checks a Wilson lower bound after every wave (repeated interim looks). A
fixed-sample interval checked repeatedly does NOT keep its nominal coverage, so the confirmation z is Bonferroni-
corrected by the predeclared number of looks. These tests prove, by simulation on known-rate fixtures, that the
corrected policy holds the family-wise false-confirm rate at/below its declared budget while the naive fixed-z policy
inflates it — and that denominators/partial runs behave as declared.
"""
import math
import random

from hfsentinel.engines.sweep import MIN_TRIALS, stop_reason
from hfsentinel.scoring.severity import CONFIRM_MIN_HITS, CONFIRM_MIN_RATE
from hfsentinel.scoring.stats import CONFIRM_ALPHA, Z95, planned_looks, sequential_z, wilson

TRIALS, WAVE = 40, 5
LOOKS = planned_looks(TRIALS, MIN_TRIALS, WAVE)  # 8 interim looks for this fixture


def _ever_confirms(rng: random.Random, p: float, z_for_look) -> bool:
    """Replay the adaptive wave loop for one run at true success rate `p`: first wave of MIN_TRIALS, then waves of WAVE,
    checking the §2.2 positive-confirm condition after each wave with the lower-bound z from `z_for_look(LOOKS)`.
    Futility stops the run without confirming (as in sweep.run_technique). Returns True iff it ever positively confirms."""
    required = max(CONFIRM_MIN_HITS, math.ceil(CONFIRM_MIN_RATE * TRIALS - 1e-9))
    hits = done = sent = 0
    while sent < TRIALS:
        n = min(MIN_TRIALS if sent == 0 else WAVE, TRIALS - sent)
        hits += sum(1 for _ in range(n) if rng.random() < p)
        done += n
        sent += n
        if sent >= TRIALS:
            break
        if hits + (TRIALS - done) < required:  # futility: can't reach the threshold — stop, never confirm
            return False
        if done >= MIN_TRIALS and hits >= CONFIRM_MIN_HITS and wilson(hits, done, z=z_for_look(LOOKS))[0] >= CONFIRM_MIN_RATE:
            return True
    return False


def _rate(p: float, z_for_look, *, n: int, seed: int) -> float:
    rng = random.Random(seed)
    return sum(_ever_confirms(rng, p, z_for_look) for _ in range(n)) / n


def test_corrected_policy_controls_false_confirm_rate_but_naive_inflates_it():
    # True rate sits exactly at the §2.2 threshold (the worst-case null for "rate >= threshold"): a positive confirm is
    # a false confirm. The corrected policy must hold the family-wise rate at/below its budget; the naive fixed-Z95
    # policy, checked at all 8 looks, must visibly exceed it — the exact flaw LSCAN-028 names.
    corrected = _rate(CONFIRM_MIN_RATE, sequential_z, n=4000, seed=28)
    naive = _rate(CONFIRM_MIN_RATE, lambda _looks: Z95, n=4000, seed=28)
    assert corrected <= CONFIRM_ALPHA + 0.01, corrected      # within budget (+ small Monte-Carlo margin)
    assert naive > corrected + 0.02, (naive, corrected)      # repeated fixed-sample looks inflate the rate
    assert naive > CONFIRM_ALPHA * 1.8, naive                # and clearly above the declared budget


def test_corrected_policy_retains_power_well_above_threshold():
    # A genuinely vulnerable rate (0.7, far above the 0.3 threshold) must still confirm in the large majority of runs,
    # so the correction buys honesty without destroying detection.
    assert _rate(0.7, sequential_z, n=2000, seed=7) >= 0.85


def test_single_look_is_unchanged_and_more_looks_only_tighten():
    assert abs(sequential_z(1) - Z95) < 1e-12                       # one look == the previous behaviour, exactly
    zs = [sequential_z(k) for k in (1, 2, 4, 8, 16)]
    assert zs == sorted(zs) and zs[0] < zs[-1]                      # monotone non-decreasing, strictly tighter overall


def test_planned_looks_is_predeclared_from_the_plan():
    assert planned_looks(40, 5, 5) == 8 and planned_looks(10, 5, 5) == 2
    assert planned_looks(5, 5, 5) == 1 and planned_looks(3, 5, 5) == 1  # <= first wave: a single look


def test_stop_reason_confirmation_is_stricter_under_more_looks():
    # A borderline count that confirms at a single look must NOT confirm once the multiplicity correction applies.
    assert stop_reason(6, 10, 20, n_looks=1).startswith("confirmed")
    assert stop_reason(6, 10, 20, n_looks=8) is None
    # futility is one-sided and unaffected by the look count.
    assert "cannot reach" in stop_reason(0, 18, 20, n_looks=8)
