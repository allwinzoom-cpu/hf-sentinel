"""Ground truth for scoring (plan 16.15, test-only): the vuln target's rate profiles plant each weakness at a designed
probability; a scan over HTTP must recover those rates within its 95% CIs and score nothing on the control."""
import datetime as dt

import pytest

from hfsentinel.controls import resolve_controls
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE, run_sweep
from hfsentinel.report.build import assemble
from hfsentinel.scoring.stats import wilson
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

TRIALS = 100
SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


def _sweep(profile, seed, trials=TRIALS, concurrency=4):
    srv, base = vuln_target.serve(profile=profile, seed=seed)
    try:
        target = OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=100_000)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=concurrency)
        runs = run_sweep(target, gov, list(NATIVE), trials=trials, temperature=0.7, max_tokens=64,
                         concurrency=concurrency)
        return base, gov, runs
    finally:
        srv.shutdown()


@pytest.fixture(scope="module")
def measured():
    return {p: _sweep(p, seed=7)[2] for p in ("low", "high")}


def test_designed_rates_are_recovered_within_the_ci(measured):
    instances = covered = 0
    misses = []
    for profile, runs in measured.items():
        for run in runs:
            designed = vuln_target.PROFILES[profile][run.catalog_id]
            lo, hi = wilson(run.hits, run.trials)
            instances += 1
            if lo <= designed <= hi:
                covered += 1
            else:
                misses.append((profile, run.catalog_id, designed, run.hits))
            assert run.trials == TRIALS and run.errors == 0
    assert instances == 2 * len(NATIVE)
    assert covered >= 0.9 * instances, misses  # nominal 95% intervals: ~1 miss in 18 is expected


def test_control_profile_scores_nothing():
    base, gov, runs = _sweep("control", seed=1, trials=20)
    assert all(r.hits == 0 and r.temp0_hit is False for r in runs)
    uri = f"openai+{base}#{vuln_target.MODEL_ID}"
    controls = resolve_controls({"trials": 20}).controls
    plan = build_plan(parse(uri), controls=controls)
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": vuln_target.MODEL_ID},
                      plan_steps=plan.steps, runs=runs, controls=controls, controls_sha256="0" * 64,
                      attestation=SCOPE, recon=None, ledger=gov.ledger.snapshot(), run_id="control",
                      native=set(NATIVE), started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    assert report.findings == [] and report.grade["overall"] == "A"


def test_profiles_are_reproducible_and_validated():
    a = [r.hits for r in _sweep("low", seed=3, trials=20, concurrency=1)[2]]  # sequential: same draw order
    b = [r.hits for r in _sweep("low", seed=3, trials=20, concurrency=1)[2]]
    assert a == b
    with pytest.raises(ValueError, match="unknown profile"):
        vuln_target.serve(profile="nope")


def test_always_profile_is_the_unchanged_positive_control():
    runs = _sweep(vuln_target.ALWAYS, seed=0, trials=5)[2]
    assert all(r.hits == r.trials == 5 for r in runs)
