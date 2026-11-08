"""Retrieval poisoning / ranked exposure (plan LSCAN-062): a poisoned doc counts only if search surfaced it within the
consumed top-k and the model consumed it; harness-forced or below-cutoff docs do not."""
from hfsentinel.attacks import retrieval as rt


def test_exposed_requires_rank_within_topk():
    assert rt.exposed(2, top_k=3) and not rt.exposed(5, top_k=3) and not rt.exposed(None, top_k=3)


def test_poisoning_counts_only_when_search_surfaced_and_model_consumed():
    assert rt.poisoning_counts(retrieved_by_search=True, poisoned_rank=1, top_k=3, consumed_by_model=True)
    assert not rt.poisoning_counts(retrieved_by_search=False, poisoned_rank=1, top_k=3, consumed_by_model=True)  # harness-forced
    assert not rt.poisoning_counts(retrieved_by_search=True, poisoned_rank=9, top_k=3, consumed_by_model=True)   # below cutoff
    assert not rt.poisoning_counts(retrieved_by_search=True, poisoned_rank=1, top_k=3, consumed_by_model=False)  # not consumed


def test_exposure_outcome_is_honest():
    assert rt.exposure_outcome(retrieved_by_search=True, poisoned_rank=1, top_k=3) == "exposed"
    assert rt.exposure_outcome(retrieved_by_search=True, poisoned_rank=8, top_k=3) == "ranked-below-cutoff"
    assert rt.exposure_outcome(retrieved_by_search=False, poisoned_rank=None, top_k=3) == "not-retrieved"
