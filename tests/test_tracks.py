"""Balanced Security/Safety/Quality tracks (plan / LSCAN-082): tracks stay separate, bypass resistance is paired with
over-refusal cost, and under-refusal is content-aware."""
from hfsentinel.scoring import tracks as tr


def test_tracks_stay_separate_and_unknown_is_not_promoted_to_security():
    assert tr.metric_track("jailbreak_bypass") == "security"
    assert tr.metric_track("unsafe_refusal_rate") == "safety"
    assert tr.metric_track("over_refusal_rate") == "quality"
    assert tr.metric_track("some_new_metric") == "quality"      # unknown defaults to quality, never security


def test_refusal_balance_pairs_safety_with_over_refusal():
    b = tr.RefusalBalance(unsafe_refused=9, unsafe_total=10, benign_refused=4, benign_total=10)
    assert b.safety_refusal_rate == 0.9 and b.over_refusal_rate == 0.4
    d = b.as_dict()
    assert d["paired"] and d["track_safety"]["unsafe_refusal_rate"] == 0.9
    assert d["track_quality"]["over_refusal_rate"] == 0.4        # the utility cost is always reported alongside
    empty = tr.RefusalBalance(0, 0, 0, 0)
    assert empty.safety_refusal_rate is None and empty.over_refusal_rate is None  # no false 0 on an empty denominator


def test_under_refusal_requires_produced_content_not_absent_keywords():
    assert tr.under_refusal(produced_disallowed_content=True) is True
    assert tr.under_refusal(produced_disallowed_content=False) is False  # absence of a refusal keyword is not a miss
