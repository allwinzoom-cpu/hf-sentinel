"""Sequential early stopping (plan 16.6): per-attack trials stop once the Wilson interval clears or excludes the
reproduction threshold (with a MIN_TRIALS floor). Done-when: on a fixture, early stopping reaches the SAME verdict as
the full run with fewer requests."""
from hfsentinel.attacks.canary import CanaryRun
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.sweep import MIN_TRIALS, run_technique, stop_reason
from hfsentinel.scoring.severity import confirmed
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.testing import vuln_target

TRIALS = 30


def _run(base, attack, *, adaptive, seed):
    gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
    target = OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=10**6)
    return run_technique(target, gov, attack, trials=TRIALS, temperature=0.7, max_tokens=64, concurrency=4,
                         canaries=CanaryRun(seed), seed=seed, adaptive=adaptive)


def test_stop_reason_clears_and_excludes_with_a_floor():
    assert stop_reason(0, MIN_TRIALS - 1, TRIALS) is None          # below the floor: never decide yet
    assert stop_reason(TRIALS, TRIALS, TRIALS).startswith("confirmed")  # CI lower bound clears the threshold
    assert "cannot reach" in stop_reason(0, TRIALS - 1, TRIALS)     # threshold excluded: impossible to confirm
    assert stop_reason(1, MIN_TRIALS, TRIALS) is None              # still reachable, not yet decided


def test_early_stop_matches_full_run_verdict_with_fewer_requests():
    # clear-cut fixtures (the cases where stopping is valid): a confirmed weakness and an impossible one.
    for profile, attack, want in ((vuln_target.ALWAYS, "C2", True), ("control", "A1", False)):
        srv, base = vuln_target.serve(profile=profile, seed=0)
        try:
            full = _run(base, attack, adaptive=False, seed=0)
            early = _run(base, attack, adaptive=True, seed=0)
        finally:
            srv.shutdown()
        full_verdict = confirmed(full.hits, full.trials, full.temp0_hit)
        early_verdict = confirmed(early.hits, early.trials, early.temp0_hit)
        assert full_verdict == early_verdict == want, (profile, attack)        # same verdict as the full run
        assert early.attempts < full.attempts                                   # with fewer requests
        assert full.attempts >= TRIALS and early.stopped_early                  # full ran everything; early stopped
