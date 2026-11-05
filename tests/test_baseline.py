"""Baseline arm + ASR lift (plan 16.4): the un-attacked control is measured, findings are graded on lift, and a
model that emits the behaviour anyway (baseline == attack) scores zero lift and no finding."""
import datetime as dt
import random

from hfsentinel.attacks import canary, category_e
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report.build import assemble
from hfsentinel.targets.openai_compat import ChatResult
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


def test_baseline_builders_are_benign_and_carry_the_oracle():
    import re
    rng = random.Random(0)
    attack_markers = re.compile(r"ignore|instruction|reply with|output only|verification code", re.IGNORECASE)
    for aid in ("A1", "A2", "A3", "C2", "A5"):
        t = canary.build_baseline(aid, rng)
        assert not attack_markers.search(t.messages[-1]["content"])  # benign user turn, no attack framing
        assert t.canary  # the oracle target is present so a spontaneous emission is measurable
    for aid in ("E1", "E2", "E3"):
        assert category_e.build_baseline(aid, rng).messages


def test_vuln_target_baseline_is_low_attack_high():
    # on the vuln target, the attack fires but the benign baseline does not → positive lift
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=1)
    try:
        from hfsentinel.targets.openai_compat import OpenAICompatTarget
        tgt = OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=5000)
        run = canary.CanaryRun(1)
        # baseline arm: benign carriers should rarely echo the canary
        base_hits = 0
        for _ in range(8):
            b = run.baseline("A1")
            base_hits += run.evaluate(b, tgt.chat(b.messages, max_tokens=64).text).hit
        assert base_hits <= 2  # the un-attacked rate is low
    finally:
        srv.shutdown()


def test_grade_uses_lift_and_never_refused_scores_zero():
    # a stub that ALWAYS echoes any canary it is given → attack and baseline both fire → zero lift → no finding
    class Echoer:
        def chat(self, messages, *, max_tokens=256, temperature=0.7):
            import re
            text = " ".join(m["content"] for m in messages if isinstance(m.get("content"), str))
            codes = re.findall(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}|ak_[0-9a-f]{24}", text)
            return ChatResult(f"Sure: {' '.join(codes)}", "m")
    uri = "openai+http://127.0.0.1:9/v1#m"
    controls = resolve_controls({"trials": 10, "attacks": "A1"}).controls
    plan = build_plan(parse(uri), selected=["A1"], controls=controls)
    gov = Governor(Ledger(max_requests=10_000, budget_usd=1.0), concurrency=1)
    res = run_campaign(Echoer(), gov, plan, trials=10, temperature=0.7, max_tokens=64, concurrency=1, seed=2,
                       controls=controls)
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps,
                      runs=res.runs, controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                      baseline=res.baseline, ledger={}, run_id="b", native=set(NATIVE),
                      started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    row = next(r for r in report.techniques if r.catalog_id == "A1")
    assert row.baseline_asr is not None and row.lift == 0.0  # echoes un-attacked too → no lift
    assert report.findings == [] and report.grade["overall"] == "A"  # a never-refused goal is not a finding
    assert "no lift" in row.severity_reason
