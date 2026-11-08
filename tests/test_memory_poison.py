"""Persistent memory / summarization poisoning (plan / LSCAN-067): persistence proven only via durable memory in a fresh
session without replaying the malicious turn; cross-user leak tested separately; cleanup verified."""
from hfsentinel.agents import memory_poison as mp

POISON = "POISON-MARK-7"


def test_session_reset_clears_short_term_but_keeps_durable():
    st = mp.MemoryState(short_term=(POISON,), durable=(POISON,))
    after = st.reset_session()
    assert after.contains(POISON) == ("durable",)      # short-term gone, durable kept


def test_persistence_requires_durable_scope_without_replay():
    durable = mp.MemoryState(durable=(f"note: {POISON}",))
    assert "persistence confirmed" in mp.persistence_verdict(durable, POISON, resurfaced_without_replay=True)
    # same state, but the effect only came from replaying the malicious turn -> not persistence
    assert "not persistence" in mp.persistence_verdict(durable, POISON, resurfaced_without_replay=False)
    # marker only in short-term -> would not survive a reset -> not persistence
    short = mp.MemoryState(short_term=(POISON,))
    assert "no persistence" in mp.persistence_verdict(short, POISON, resurfaced_without_replay=True)


def test_persistence_via_summary_and_retrieval_scopes():
    assert "summary" in mp.persistence_verdict(mp.MemoryState(summary=(POISON,)), POISON,
                                              resurfaced_without_replay=True)
    assert "retrieval" in mp.persistence_verdict(mp.MemoryState(retrieval=(POISON,)), POISON,
                                                resurfaced_without_replay=True)


def test_cross_user_leak_is_separate():
    bob = mp.MemoryState(durable=(f"leaked {POISON}",))
    assert mp.cross_user_leak(POISON, bob)
    assert not mp.cross_user_leak(POISON, mp.MemoryState(durable=("clean",)))


def test_cleanup_verified_only_when_marker_gone_everywhere():
    poisoned = mp.MemoryState(short_term=(POISON,), durable=(POISON,), summary=(POISON,), retrieval=(POISON,))
    assert mp.cleanup_verified(poisoned.clear_all(), POISON)
    assert not mp.cleanup_verified(poisoned, POISON)
