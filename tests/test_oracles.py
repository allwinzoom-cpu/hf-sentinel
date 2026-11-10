"""Section 4.0 oracle coverage (plan task 601): every Ready/Conditional technique has a working success oracle, and
every Candidate runs experimental (never scored). Done-when: each Ready/Conditional catalog row resolves to an
importable, callable oracle; the registry and catalog never drift; candidates are flagged experimental."""
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.attacks.oracles import ORACLES, SCORED_STATUSES, oracle_for, requires_oracle, resolve
from hfsentinel.engines.planner import build_plan
from hfsentinel.targets.resolve import parse

CATALOG = load_catalog()
KINDS = {"deterministic", "judge", "signature", "call-log", "registry", "nli", "reference"}


def test_registry_and_catalog_do_not_drift():
    cat_ids = {a.id for a in CATALOG.attacks}
    assert set(ORACLES) == cat_ids                 # every technique registered, no stale/extra entries


def test_every_ready_or_conditional_technique_has_a_working_oracle():
    missing, broken = [], []
    for a in CATALOG.attacks:
        if not requires_oracle(a):
            continue
        oracle = oracle_for(a)
        if oracle.experimental or oracle.kind not in KINDS:
            missing.append(a.id)
            continue
        try:
            fn = resolve(oracle.impl)                # the scorer must still import…
            if not callable(fn):                     # …and be callable
                broken.append(a.id)
        except (ImportError, AttributeError):
            broken.append(a.id)
    assert not missing, f"Ready/Conditional techniques without a scored oracle: {missing}"
    assert not broken, f"oracles pointing at a missing/uncallable impl: {broken}"


def test_candidates_are_flagged_experimental_in_the_registry():
    for a in CATALOG.attacks:
        if a.status == "candidate":
            assert oracle_for(a).experimental, f"{a.id} is a candidate but not flagged experimental"
        else:
            assert not oracle_for(a).experimental, f"{a.id} is {a.status} but flagged experimental"


def test_planner_runs_candidates_experimental_and_never_scores_them():
    # the triage planner is the enforcement point: a candidate is never 'run' — it is 'experimental' when its
    # requirements are met, otherwise held (blocked/n-a/unverified) just like any other technique.
    target = parse("openai+http://127.0.0.1:1/v1#m")
    plan = build_plan(target, CATALOG)
    by_id = {s.catalog_id: s for s in plan.steps}
    experimental_seen = False
    for a in CATALOG.attacks:
        if a.status != "candidate":
            continue
        step = by_id[a.id]
        assert step.disposition != "run", f"{a.id} candidate must never be scored (got 'run')"
        assert step.disposition in ("experimental", "blocked", "n/a", "unverified"), \
            f"{a.id} unexpected disposition {step.disposition}"
        experimental_seen = experimental_seen or step.disposition == "experimental"
    assert experimental_seen, "no candidate reached the experimental path — enforcement untested"


def test_scored_statuses_are_exactly_ready_and_conditional():
    assert set(SCORED_STATUSES) == {"ready", "conditional"}


def test_best_of_n_native_oracle_is_deterministic_and_held_out():
    oracle = ORACLES["B13"]
    assert oracle.kind == "deterministic"
    assert oracle.impl == "hfsentinel.attacks.canary:find_canary"
    assert "fresh-canary confirmation" in oracle.note
