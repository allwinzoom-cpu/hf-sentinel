"""Session fixture lifecycle (plan / LSCAN-026): clean reset, contamination caught before scoring, resume only a proven
state."""
from engines import session_fixture as sf


def test_reset_clears_canaries_and_task_state_but_keeps_config():
    s = sf.SessionFixture("s1", "tenant-A", planted_canaries=frozenset({"CAN-1"}),
                          tool_inventory=("search",), task_state="mid-attack")
    r = s.reset(new_session_id="s2")
    assert r.session_id == "s2" and r.identity == "tenant-A" and r.tool_inventory == ("search",)
    assert r.planted_canaries == frozenset() and r.task_state == "initial"   # no carried attack state


def test_contamination_is_detected_and_invalidates_a_control():
    prior = frozenset({"CAN-AAAA", "CAN-BBBB"})
    assert sf.contaminated("a clean benign answer", prior) == []
    assert sf.contaminated("leaked CAN-AAAA here", prior) == ["CAN-AAAA"]
    assert sf.control_is_valid("clean", prior) and not sf.control_is_valid("has CAN-BBBB", prior)


def test_resume_only_a_proven_state():
    assert sf.safe_to_resume(state_proven=True) == "resume"
    assert sf.safe_to_resume(state_proven=False) == "restart-clean"
