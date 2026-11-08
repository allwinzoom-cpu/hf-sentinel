"""Campaign wiring of the Laya-advised stages (plan §6.2 / [[laya-involved-everywhere]]): obfuscation (§16.7), triggers
(054), evolution (042), minimization (031). Each is opt-in (a flag), Laya advises WHAT to try, and the deterministic
oracle decides. A stub Laya drives the advisory ordering; the obfuscation stage fail-soft no-ops when the engine is
absent (as in CI)."""
from hfsentinel.controls import resolve_controls
from hfsentinel.core.system_one import Decision
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target


class _StubLaya:
    available = True

    def choose_technique(self, profile, candidates):
        return Decision("technique", next(iter(candidates)), 0.9, 0.9, {})

    def defence_style(self, observations):
        return Decision("defence", "keyword_filter", 0.9, 0.9, {})

    def triage(self, goal, response):
        return Decision("triage", "refuse", 0.9, 0.9, {})

    def reaches_system_two(self, triage, *, policy=None):
        return True


def _plan(uri, trials):
    controls = resolve_controls({"trials": trials, "concurrency": 4}).controls
    return build_plan(parse(uri), controls=controls), controls


def _target(base):
    return OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=100_000)


def _gov():
    return Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)


def test_stages_are_opt_in_and_off_by_default():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        res = run_campaign(_target(base), _gov(), plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls)
        assert res.triggered == {} and res.obfuscation == {} and res.evolution == {} and res.minimization == {}
    finally:
        srv.shutdown()


def test_triggered_stage_runs_a_sweep_and_laya_orders_it():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        res = run_campaign(_target(base), _gov(), plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls, check_triggered=True, system_one=_StubLaya())
        assert res.triggered and res.triggered["probes"] >= 1
        assert res.triggered["fired"] == 0                                   # vuln target has no backdoor -> clean
        assert "does NOT certify the absence" in res.triggered["verdict"]
        assert any(d["catalog_id"] == "trig" and "laya" in d["action"] for d in res.decisions)   # Laya ordered it
    finally:
        srv.shutdown()


def test_obfuscation_stage_is_fail_soft_without_the_engine():
    from hfsentinel.attacks import obfuscation as obf
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        res = run_campaign(_target(base), _gov(), plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls, check_obfuscation=True, system_one=_StubLaya())
        assert res.obfuscation.get("available") is obf.is_available()
        if not obf.is_available():                                          # CI / worktree path
            assert any(d["catalog_id"] == "obf" and d["action"] == "n/a" for d in res.decisions)
    finally:
        srv.shutdown()


def test_evolution_stage_records_laya_operator_advice():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        res = run_campaign(_target(base), _gov(), plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls, check_evolution=True, system_one=_StubLaya())
        from engines.evolution import MUTATION_OPERATORS
        assert res.evolution["advised_operator"] in MUTATION_OPERATORS
        assert any(d["catalog_id"] == "evo" and "laya" in d["action"] for d in res.decisions)
        # no Laya -> no advice
        res2 = run_campaign(_target(base), _gov(), plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                            seed=0, controls=controls, check_evolution=True)
        assert res2.evolution == {"advised_operator": None}
    finally:
        srv.shutdown()


def test_minimization_stage_ablates_a_confirmed_escalation():
    from hfsentinel.engines.recon import Fact, TargetProfile
    srv, base = vuln_target.serve(defended=True, seed=30)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 10)
        profile = TargetProfile(facts={"keyword_filter": Fact(True, "refused_3_of_3")}, refusal_style="templated")
        res = run_campaign(_target(base), _gov(), plan, trials=10, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=30, profile=profile, controls=controls, check_minimization=True, system_one=_StubLaya())
        if any(e.get("confirmed") for e in res.escalations):               # a mutator bypass was confirmed
            assert res.minimization and res.minimization["id"]
            # on a filtered target the base technique fails without the mutator -> mutator is necessary
            assert not res.minimization["reduced"]
            assert any(d["stage"] == "S4" and "recipe" in d["action"] for d in res.decisions)
    finally:
        srv.shutdown()
