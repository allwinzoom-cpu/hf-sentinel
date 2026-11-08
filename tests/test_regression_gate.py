"""Regression corpus + differential release gate (plan / LSCAN-085): drift is separated from model regression, deltas
carry confidence bounds, and roots deduplicate."""
import pytest

from hfsentinel.engines import regression as rg


def test_corpus_entry_validates_kind_and_roots_dedupe():
    with pytest.raises(ValueError, match="kind must be"):
        rg.CorpusEntry("bogus", "A1")
    entries = [rg.CorpusEntry("attack-recipe", "A1", root="injection"),
               rg.CorpusEntry("attack-recipe", "A6", root="injection"),   # same root
               rg.CorpusEntry("negative-control", "neg-1")]
    assert rg.dedupe_roots(entries) == ["injection", "neg-1"]             # repeated root collapses to one


def test_drift_is_inconclusive_not_model_regression():
    g = rg.differential_gate(9, 10, 2, 10, route_drifted=True)
    assert g.verdict == "inconclusive-drift" and "not attributable to model regression" in g.note
    g2 = rg.differential_gate(9, 10, 2, 10, judge_changed=True)
    assert g2.verdict == "inconclusive-drift"


def test_significant_rise_is_behavioural_regression_with_bounds_not_a_mechanism_claim():
    g = rg.differential_gate(19, 20, 1, 20)        # clearly more attackable
    assert g.verdict == "model-regression" and g.delta > 0
    assert g.current_ci[0] > g.baseline_ci[1] and "not an alignment-removal mechanism" in g.note


def test_overlapping_intervals_are_no_change():
    g = rg.differential_gate(6, 10, 5, 10)         # small delta, intervals overlap
    assert g.verdict == "no-change" and "within the confidence bounds" in g.note
