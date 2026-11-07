"""HF-job lifecycle contract (LSCAN-012): a dry-run submits nothing, and a non-terminal job is cleaned up on abort so
no orphan compute keeps billing."""
from hfsentinel.targets.job_lifecycle import cleanup_targets, dry_run_submits_nothing, is_terminal, needs_cleanup


def test_dry_run_submits_nothing():
    assert dry_run_submits_nothing("dry-run")
    assert not dry_run_submits_nothing("run")


def test_non_terminal_stages_need_cleanup():
    for s in ("submitted", "scheduling", "running"):
        assert needs_cleanup(s)
    for s in ("report-uploaded", "terminal"):
        assert not needs_cleanup(s) and is_terminal(s)


def test_cleanup_targets_selects_only_live_jobs():
    jobs = {"j1": "running", "j2": "terminal", "j3": "scheduling", "j4": "report-uploaded"}
    assert sorted(cleanup_targets(jobs)) == ["j1", "j3"]  # only the still-live jobs need a cancel
