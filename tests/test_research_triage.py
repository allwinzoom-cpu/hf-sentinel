"""Research refresh triage (plan / LSCAN-088): dispositions and the production gate — unverified names/ASR claims never
auto-enter production; agentic is out of scope."""
from engines import research_triage as rt


def _item(**kw):
    return rt.ResearchItem(**{"name": "NewAttack", **kw})


def test_fully_specified_item_is_runnable_and_can_enter_production():
    it = _item(source="arxiv:x", date="2026-01", preconditions="chat target", replication_task="N trials",
               oracle="canary")
    assert rt.triage(it) == "runnable-task" and rt.can_enter_production(it)


def test_bare_name_or_asr_claim_cannot_enter_production():
    bare = _item()                                  # just a name
    assert rt.triage(bare) == "experimental-candidate" and not rt.can_enter_production(bare)
    partial = _item(source="arxiv:x", date="2026-01", preconditions="chat")   # no task/oracle
    assert rt.triage(partial) == "conditional-extension" and not rt.can_enter_production(partial)


def test_agentic_is_out_of_scope_and_duplicates_collapse():
    assert rt.triage(_item(agentic=True, source="s", date="d", preconditions="p", replication_task="t",
                           oracle="o")) == "out-of-scope"
    assert not rt.can_enter_production(_item(agentic=True, source="s", date="d", preconditions="p",
                                             replication_task="t", oracle="o"))
    assert rt.triage(_item(duplicate_of="B1")) == "duplicate"
    assert rt.triage(_item(duplicate_of="B1", preconditions="variant")) == "existing-family-variant"
