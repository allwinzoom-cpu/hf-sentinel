"""Conditional membership-inference lane (plan / LSCAN-053): separate method lanes, threshold calibrated to a prespecified
FPR on nonmembers, TPR with a Wilson interval vs a chance baseline, and no ground truth => inconclusive (never a claim)."""
import pytest

from engines import membership as mi


def test_threshold_calibrates_to_the_prespecified_fpr_on_nonmembers():
    nonmembers = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]   # n=10
    thr = mi.threshold_at_fpr(nonmembers, 0.2)                         # admit at most 2 nonmembers
    admitted = sum(1 for s in nonmembers if s >= thr)
    assert admitted <= 2
    assert mi.threshold_at_fpr(nonmembers, 0.05) > max(nonmembers)     # fpr too small to admit any -> above the top
    with pytest.raises(ValueError, match="fpr"):
        mi.threshold_at_fpr(nonmembers, 1.5)


def test_a_separating_method_reads_above_chance_with_uncertainty():
    scored = [mi.Scored(0.9, True)] * 20 + [mi.Scored(0.1, False)] * 20   # cleanly separable
    res = mi.evaluate("logprob", scored, fpr_target=0.1, holdout_split="80/20 temporal")
    assert res.conclusive and res.tpr == 1.0
    assert res.baseline_tpr == 0.1 and res.beats_chance        # TPR lower bound clears chance
    assert "above chance" in res.verdict and res.lane == "logprob"


def test_a_chance_method_does_not_beat_baseline():
    # members and nonmembers interleaved over the same range -> no real separation
    scored = [mi.Scored(float(v), True) for v in range(0, 40, 2)] + \
             [mi.Scored(float(v), False) for v in range(1, 40, 2)]
    res = mi.evaluate("text-sampling", scored, fpr_target=0.1)
    assert res.conclusive and not res.beats_chance        # TPR lower bound does not clear chance
    assert "not above chance" in res.verdict


def test_missing_ground_truth_is_inconclusive_never_a_finding():
    res = mi.evaluate("logprob", [mi.Scored(0.9, True), mi.Scored(0.8, True)])   # no nonmembers
    assert not res.conclusive and not res.beats_chance
    assert "inconclusive" in res.verdict and "not an individual-membership finding" in res.verdict


def test_unknown_lane_is_rejected():
    with pytest.raises(ValueError, match="unknown lane"):
        mi.evaluate("weights", [mi.Scored(0.9, True), mi.Scored(0.1, False)])
