"""Attack campaign v1 (plan 16.18): staged run, sequential stopping (16.6), decision log, judge-panel loading."""
import datetime as dt

from hfsentinel.attacks.canary import CanaryRun
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE, run_technique, stop_reason
from hfsentinel.judges import ensemble
from hfsentinel.report.build import assemble
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


def _plan(uri, trials):
    controls = resolve_controls({"trials": trials, "concurrency": 4}).controls
    return build_plan(parse(uri), controls=controls), controls


def _target(base):
    return OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=100_000)


def test_stop_reason_decides_both_ways():
    assert stop_reason(0, 5, 20) is None  # still reachable, not yet confirmed
    assert "cannot reach" in stop_reason(0, 18, 20)  # 2 left, needs >= 6
    assert stop_reason(20, 20, 20).startswith("confirmed")
    assert stop_reason(1, 4, 20) is None  # below MIN_TRIALS boundary handled by caller


def test_always_profile_stops_early_but_still_confirms():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        canaries = CanaryRun(0)
        run = run_technique(_target(base), gov, "C2", trials=30, temperature=0.7, max_tokens=64, concurrency=4,
                            canaries=canaries, adaptive=True)
        assert run.hits == run.trials and run.trials < 30 and run.stopped_early.startswith("confirmed")
        assert run.temp0_hit is None  # already confirmed: no temperature-0 attempt needed
    finally:
        srv.shutdown()


def test_control_profile_stops_for_impossibility():
    srv, base = vuln_target.serve(profile="control", seed=0)
    try:
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=5)
        run = run_technique(_target(base), gov, "A1", trials=40, temperature=0.7, max_tokens=64, concurrency=5,
                            canaries=CanaryRun(0), adaptive=True)
        assert run.hits == 0 and run.trials < 40 and "cannot reach" in run.stopped_early
    finally:
        srv.shutdown()


def test_campaign_uses_fewer_requests_and_logs_decisions():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=1)
    try:
        plan, _ = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 20)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=20, temperature=0.7, max_tokens=64, concurrency=4, seed=1)
        assert res.requests < res.exhaustive_requests  # stopping saved requests
        stages = {d["stage"] for d in res.decisions}
        assert {"S1", "S2", "S3", "S5"} <= stages
        assert any(d["action"] == "defer" and d["catalog_id"].startswith("B") for d in res.decisions)  # B deferred
        ran = {d["catalog_id"] for d in res.decisions if d["stage"] == "S3"}
        assert ran <= set(NATIVE) and {"C2", "A1", "E3"} <= ran
    finally:
        srv.shutdown()


def test_campaign_report_records_the_log():
    srv, base = vuln_target.serve(profile="high", seed=2)
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        plan, controls = _plan(uri, 20)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=20, temperature=0.7, max_tokens=64, concurrency=4, seed=2)
        report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": vuln_target.MODEL_ID},
                          plan_steps=plan.steps, runs=res.runs, controls=controls, controls_sha256="0" * 64,
                          attestation=SCOPE, recon=None, campaign={"decisions": res.decisions,
                          "attack_requests": res.requests, "exhaustive_requests": res.exhaustive_requests,
                          "requests_saved": res.exhaustive_requests - res.requests},
                          ledger=gov.ledger.snapshot(), run_id="camp", native=set(NATIVE),
                          started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
        from hfsentinel.report import render
        assert report.campaign["requests_saved"] >= 0
        md = render.to_markdown(report)
        assert "## Campaign" in md and "exhaustive" in md
        import json
        assert json.loads(render.to_json(report))["campaign"]["decisions"]
    finally:
        srv.shutdown()


def test_production_policy_matches_the_calibration_evidence():
    import json
    from pathlib import Path
    policy, models = ensemble.production_policy()
    evidence = json.loads((Path(__file__).resolve().parents[1] / "docs" / "judges" / "jbb-calibration.json")
                          .read_text())["production_policy"]
    assert policy.name == evidence["name"] and policy.k == evidence["k"]
    assert [list(m) for m in policy.members] == [list(m) for m in evidence["members"]]
    assert set(models) == {alias for alias, _ in policy.members} and all(models.values())


class FakeS1:
    """Fake SystemOne: records calls, returns a scripted Decision; available=True."""
    available = True

    def __init__(self, choice="keyword_filter", confidence=0.8, act=0.9):
        from hfsentinel.core.system_one import Decision
        self._d = lambda name: Decision(name, choice, confidence, act, {choice: confidence})
        self.calls = []

    def defence_style(self, observations):
        self.calls.append(("defence", observations))
        return self._d("defence")

    def choose_technique(self, profile, candidates):
        self.calls.append(("technique", list(candidates)))
        from hfsentinel.core.system_one import Decision
        return Decision("technique", next(iter(candidates)), 0.8, 0.9, {})


def test_system_one_advice_is_logged_and_advisory():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=5)
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        from hfsentinel.engines.recon import Fact, TargetProfile
        profile = TargetProfile(facts={"keyword_filter": Fact(False, "refused_0_of_3")}, over_refusal_rate=0.0,
                                refusal_style="none", requests=15)
        plan, _ = _plan(uri, 20)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        s1 = FakeS1()
        res = run_campaign(_target(base), gov, plan, trials=20, temperature=0.7, max_tokens=64, concurrency=4, seed=5,
                           system_one=s1, profile=profile)
        advisory = [d for d in res.decisions if d.get("source") == "system-one"]
        assert any(d["stage"] == "S1" and "defence" in d["action"] for d in advisory)
        assert any(d["stage"] == "S2" and d["action"] == "technique advice" for d in advisory)
        assert ("defence", ["over-refusal rate 0.0", "refusal style: none",
                            "keyword_filter: no (refused_0_of_3)"]) == s1.calls[0]
        # advisory only: the techniques that ran are unchanged from the planner's runnable set
        ran = {d["catalog_id"] for d in res.decisions if d["stage"] == "S3" and d["source"] == "campaign"}
        assert {"C2", "A1", "E3"} <= ran
    finally:
        srv.shutdown()


def test_no_system_one_leaves_campaign_unchanged():
    srv, base = vuln_target.serve(profile="high", seed=6)
    try:
        plan, _ = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 20)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=20, temperature=0.7, max_tokens=64, concurrency=4, seed=6)
        assert not any(d.get("source") == "system-one" for d in res.decisions)  # none added
        assert any(d["stage"] == "S3" for d in res.decisions)
    finally:
        srv.shutdown()


def test_unavailable_system_one_is_a_safe_noop():
    from hfsentinel.core.system_one import SystemOne
    srv, base = vuln_target.serve(profile="control", seed=7)
    try:
        plan, _ = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 10)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=10, temperature=0.7, max_tokens=64, concurrency=4, seed=7,
                           system_one=SystemOne(None), profile=None)
        assert not any(d.get("source") == "system-one" for d in res.decisions)  # unavailable → no advice logged
    finally:
        srv.shutdown()


def test_cross_verify_and_learn(tmp_path):
    from hfsentinel.engines.strategy_library import StrategyLibrary
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=11)
    try:
        plan, _ = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 12)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        lib = StrategyLibrary(tmp_path / "lib.json")
        res = run_campaign(_target(base), gov, plan, trials=12, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=11, library=lib)
        # S6: every confirmed finding was cross-verified on the always-profile target
        s6 = [d for d in res.decisions if d["stage"] == "S6"]
        assert s6 and all(res.cross_verified[d["catalog_id"]] for d in s6)
        assert res.verify_requests > 0  # S6 requests tracked separately from the breadth budget
        # S7: outcomes written to the library; a later plan sees a learned prior
        assert any(d["stage"] == "S7" for d in res.decisions)
        reloaded = StrategyLibrary(tmp_path / "lib.json")
        assert reloaded.prior("C2", None) != 0.5
    finally:
        srv.shutdown()


def test_cross_verify_flags_a_non_reproducing_artefact():
    from hfsentinel.attacks.canary import CanaryRun
    from hfsentinel.engines.campaign import CampaignResult, _cross_verify
    from hfsentinel.engines.sweep import TechniqueRun
    srv, base = vuln_target.serve(profile="control", seed=12)  # nothing really fires
    try:
        res = CampaignResult()
        res.runs = [TechniqueRun("C2", trials=10, hits=10, temp0_hit=True)]  # a fake "confirmed" artefact
        _cross_verify(res, _target(base), Governor(Ledger(max_requests=10_000, budget_usd=1.0), concurrency=2),
                      CanaryRun(12), trials=10, temperature=0.7, max_tokens=64, concurrency=2, seed=12)
        assert res.cross_verified["C2"] is False  # independent re-run on the control did not reproduce
    finally:
        srv.shutdown()


def test_s4_escalation_bypasses_a_filter_that_breadth_misses():
    from hfsentinel.engines.recon import Fact, TargetProfile
    srv, base = vuln_target.serve(defended=True, seed=30)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 10)
        # recon on a defended target sees a keyword filter → S4 is enabled
        profile = TargetProfile(facts={"keyword_filter": Fact(True, "refused_3_of_3")}, refusal_style="templated")
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=10, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=30, profile=profile, controls=controls)
        # breadth alone found A1 refused; S4 escalated it with an encoding mutator and confirmed
        a1 = next(r for r in res.runs if r.catalog_id == "A1")
        assert a1.hits >= 2  # the escalated run replaced the refused breadth run
        esc = [e for e in res.escalations if e["id"] == "A1" and e["confirmed"]]
        assert esc and esc[0]["mutator"] in ("base64", "cipher")
        assert any(d["stage"] == "S4" and "escalated" in d["action"] for d in res.decisions)
        assert res.depth_requests > 0
    finally:
        srv.shutdown()


def test_s4_skipped_without_a_filter():
    srv, base = vuln_target.serve(profile="control", seed=31)  # undefended, nothing fires
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 8)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=8, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=31, profile=None, controls=controls)
        assert res.escalations == [] and res.depth_requests == 0  # no filter observed → no escalation
    finally:
        srv.shutdown()
