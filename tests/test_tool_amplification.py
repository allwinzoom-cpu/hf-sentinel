"""Tool-loop / fan-out / retry amplification (plan / LSCAN-075): effective cost counts all descendants, the per-run cap
propagates, cancellation stops scheduling, and scanner retries are distinguished from model-initiated loops.

Distinct from LSCAN-074's cost/token amplification (`hfsentinel/attacks/amplification.py`, tested in
`tests/test_amplification.py`) — this covers the agentic call-tree surface in `hfsentinel/agents/amplification.py`."""
from hfsentinel.agents import amplification as amp


def _tree():
    # one initiating call that fans out to 2 children, one of which recurses into 2 more -> 5 total
    leaf = amp.CallNode("query_db")
    mid = amp.CallNode("http_get", children=(leaf, amp.CallNode("http_get")))
    return amp.CallNode("plan", children=(mid, amp.CallNode("send_email")))


def test_effective_cost_counts_every_descendant():
    root = _tree()
    assert amp.total_calls(root) == 5
    assert amp.effective_cost([root]) == 5
    assert amp.amplification_factor([root]) == 5.0           # 1 initiating call -> 5 total
    assert amp.amplification_factor([amp.CallNode("x")]) == 1.0
    assert amp.amplification_factor([]) == 0.0


def test_cap_propagates_across_the_tree():
    root = _tree()
    assert not amp.within_cap([root], cap=4)                 # total 5 exceeds cap even though direct calls are few
    assert amp.within_cap([root], cap=5)


def test_cancellation_must_stop_scheduling():
    assert amp.cancellation_effective(scheduled_after_cancel=0)
    assert not amp.cancellation_effective(scheduled_after_cancel=3)


def test_loop_attribution_separates_scanner_retries_from_model_loops():
    assert "scanner-retry" in amp.loop_attribution(model_initiated=False, scanner_retry=True)
    assert "model-initiated loop" in amp.loop_attribution(model_initiated=True, scanner_retry=False)
    # a model loop that also triggered scanner retries is still attributed to the model
    assert "model-initiated loop" in amp.loop_attribution(model_initiated=True, scanner_retry=True)
    assert amp.loop_attribution(model_initiated=False, scanner_retry=False) == "no loop"
