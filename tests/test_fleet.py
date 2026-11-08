"""Fleet/watch + resumable campaigns (plan / LSCAN-086): change-triggered watch, resume skips completed, dry-run sends
nothing, scope expiry stops work, per-target budgets aggregate."""
from engines import fleet as fl

TARGETS = [fl.FleetTarget("t1", "hf-provider://a/b@p", "https://router.hf.co:443", 5.0, revision="r1"),
           fl.FleetTarget("t2", "hf-endpoint://x", "https://x.endpoints.hf.cloud:443", 3.0, revision="r1")]


def test_budget_aggregates_and_credentials_stay_separate():
    assert fl.aggregate_budget(TARGETS) == 8.0 and fl.credentials_isolated(TARGETS)


def test_watch_fires_only_on_a_real_revision_change():
    assert fl.changed("r1", "r2") is True
    assert fl.changed("r1", "r1") is False        # same revision (e.g. an unrelated commit) -> no trigger
    assert fl.changed("r1", "") is False          # unknown new revision -> do not fire


def test_resume_skips_completed_targets():
    assert [t.target_id for t in fl.pending(TARGETS, completed={"t1"})] == ["t2"]  # t1 not replayed
    assert fl.pending(TARGETS, completed={"t1", "t2"}) == []


def test_dry_run_sends_nothing_and_scope_expiry_stops_work():
    assert fl.dry_run_sends_nothing("dry-run") and not fl.dry_run_sends_nothing("run")
    assert fl.scope_active(100.0, 50.0) and not fl.scope_active(100.0, 100.0)
