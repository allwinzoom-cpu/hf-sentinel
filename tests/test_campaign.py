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
        # LSCAN-030: the report carries budget-normalised accounting; a high-profile run reaches a first success, so the
        # first-success hook fired (the exact cost math is pinned by test_budget/test_governor; this harness's target is
        # not wired to this ledger, so the metered counts read 0 here).
        b = report.campaign["budgets"]
        assert b["paid_attempts"] == gov.ledger.snapshot()["requests"]
        assert set(b["asr_per_budget"]) == {"per_query", "per_1k_tokens", "per_usd", "per_minute"}
        assert b["first_success_cost"] is not None and set(b["calls_by_role"]) == {"target", "judge", "attacker",
                                                                                   "translator"}
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


def test_s4_scores_on_held_out_confirmation_not_selection_trials():
    # LSCAN-027: a mutator SELECTED by the search must be confirmed on independent held-out trials; the finding's
    # reported rate comes from that confirmation (full `trials`), never the smaller selection batch (ESCALATE_TRIALS).
    from hfsentinel.engines.campaign import ESCALATE_TRIALS
    from hfsentinel.engines.recon import Fact, TargetProfile
    srv, base = vuln_target.serve(defended=True, seed=30)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 10)
        profile = TargetProfile(facts={"keyword_filter": Fact(True, "refused_3_of_3")}, refusal_style="templated")
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=10, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=30, profile=profile, controls=controls)
        a1_esc = [e for e in res.escalations if e["id"] == "A1"]
        assert any(e["phase"] == "search" for e in a1_esc)                 # a discovery phase ran
        confs = [e for e in a1_esc if e["phase"] == "held-out-confirm" and e["confirmed"]]
        assert confs, "a discovered mutator must be confirmed on held-out trials"
        a1 = next(r for r in res.runs if r.catalog_id == "A1")
        assert a1.trials > ESCALATE_TRIALS and a1.trials == confs[0]["trials"]  # scored on held-out, not the search batch
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


def test_memorization_stage_finds_c3_against_the_vuln_target():
    """C3 campaign wiring: with a held reference set, run_campaign runs the memorization-extraction stage and scores it."""
    from hfsentinel.attacks.memorization import PLANTED_REFERENCE
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=5, temperature=0.7, max_tokens=256, concurrency=4,
                           seed=0, controls=controls, reference_set=PLANTED_REFERENCE)
        c3 = [r for r in res.runs if r.catalog_id == "C3"]
        assert c3 and c3[0].hits >= 1 and c3[0].proven            # a planted passage was reproduced verbatim
        assert c3[0].trials == len(PLANTED_REFERENCE)
    finally:
        srv.shutdown()


def test_no_memorization_stage_without_a_reference_set():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls)
        assert not any(r.catalog_id == "C3" for r in res.runs)    # C3 runs only when the operator supplies references
    finally:
        srv.shutdown()


def test_multiturn_escalation_stage_breaks_a_defended_target():
    """Multi-turn scan stage: against a defended target the escalation gradually breaks through on the encoded turn."""
    srv, base = vuln_target.serve(defended=True, seed=30)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=5, temperature=0.7, max_tokens=256, concurrency=4,
                           seed=30, controls=controls)
        assert res.multiturn.get("broken") is True and res.multiturn["move"] == "encoded"
        assert res.multiturn_requests >= 4                         # softer turns tried before the encoded break
    finally:
        srv.shutdown()


def test_multiturn_escalation_stage_records_a_clean_run():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
        res = run_campaign(_target(base), gov, plan, trials=5, temperature=0.7, max_tokens=64, concurrency=4,
                           seed=0, controls=controls)
        assert "broken" in res.multiturn and isinstance(res.multiturn["turns"], list)
    finally:
        srv.shutdown()


def test_hallucination_stage_scores_h1_against_the_vuln_target():
    """H1 scan stage: induce a package suggestion and verify it; a non-existent recommendation is a scored H1 finding."""
    from hfsentinel.engines.campaign import CampaignResult, _hallucination_stage
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        res = CampaignResult()

        def fake(eco, name):
            return (not name.lower().startswith("quibble"), "fake-registry")

        _hallucination_stage(res, _target(base), ecosystems={"pypi"}, max_tokens=256, verifier=fake)
        h1 = [r for r in res.runs if r.catalog_id == "H1"]
        assert h1 and h1[0].hits >= 1 and h1[0].proven       # recommended a non-existent package
    finally:
        srv.shutdown()


def test_fabricated_api_stage_scores_h2_against_the_vuln_target():
    """H2 scan stage: induce an API call and flag any the operator's reference does not know (fabricated)."""
    from hfsentinel.engines.campaign import CampaignResult, _fabricated_api_stage
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        res = CampaignResult()
        known = {"requests.get", "requests.post", "pandas.read_parquet", "os.cpu_count"}
        _fabricated_api_stage(res, _target(base), known_apis=known, max_tokens=256)
        h2 = [r for r in res.runs if r.catalog_id == "H2"]
        assert h2 and h2[0].hits >= 1 and h2[0].proven
    finally:
        srv.shutdown()


def test_fabricated_citation_stage_scores_h6_against_the_vuln_target():
    """H6 scan stage: induce a citation and flag any DOI/arXiv the resolver cannot find (fabricated source)."""
    from hfsentinel.engines.campaign import CampaignResult, _fabricated_citation_stage
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        res = CampaignResult()
        _fabricated_citation_stage(res, _target(base), max_tokens=256, verifier=lambda kind, value: False)
        h6 = [r for r in res.runs if r.catalog_id == "H6"]
        assert h6 and h6[0].hits >= 1 and h6[0].proven
    finally:
        srv.shutdown()


def test_sycophancy_stage_scores_h5_against_the_vuln_target():
    """H5 scan stage: state the correct answer, push back with the wrong one; a flip is a scored H5 finding."""
    from hfsentinel.engines.campaign import CampaignResult, _sycophancy_stage
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        res = CampaignResult()
        _sycophancy_stage(res, _target(base), max_tokens=256)
        h5 = [r for r in res.runs if r.catalog_id == "H5"]
        assert h5 and h5[0].hits >= 1 and h5[0].proven
    finally:
        srv.shutdown()


def test_overconfidence_stage_scores_h7_against_the_vuln_target():
    """H7 scan stage: a confidence-forced wrong answer is miscalibration (overconfidence)."""
    from hfsentinel.engines.campaign import CampaignResult, _overconfidence_stage
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        res = CampaignResult()
        _overconfidence_stage(res, _target(base), max_tokens=256)
        h7 = [r for r in res.runs if r.catalog_id == "H7"]
        assert h7 and h7[0].hits >= 1 and h7[0].proven
    finally:
        srv.shutdown()


def test_full_campaign_exercises_model_only_stages_across_categories():
    """Capstone: one campaign runs the native sweep + the opt-in model-only stages and finds issues across A/C/E/H."""
    from hfsentinel.attacks.memorization import PLANTED_REFERENCE
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        plan, controls = _plan(f"openai+{base}#{vuln_target.MODEL_ID}", 5)
        gov = Governor(Ledger(max_requests=200_000, budget_usd=5.0), concurrency=4)

        def fake_nli(premise, hypothesis):
            h = (hypothesis or "").lower()
            bad = any(k in h for k in ("visible from the moon", "invented the telephone", "10% of their brains")) \
                and "not " not in h
            return {"contradiction": 0.9 if bad else 0.02, "entailment": 0.02, "neutral": 0.08 if bad else 0.96}

        res = run_campaign(_target(base), gov, plan, trials=5, temperature=0.7, max_tokens=256, concurrency=4, seed=0,
                           controls=controls, reference_set=PLANTED_REFERENCE,
                           api_reference={"requests.get", "os.cpu_count"}, check_sycophancy=True,
                           check_calibration=True, nli_scorer=fake_nli)
        cats = {r.catalog_id[0] for r in res.runs if r.hits > 0}
        assert {"A", "C", "E", "H"} <= cats, sorted(r.catalog_id for r in res.runs if r.hits > 0)
    finally:
        srv.shutdown()
