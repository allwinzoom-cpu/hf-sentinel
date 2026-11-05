"""Engine-service judge path (plan 16.19 + 16.18 S5): engine-emitted judge-scored candidate exchanges are read over an
ephemeral channel (deleted after reading, D-015/16.17), scored through the triage-gated System-2 panel, and the
judge-confirmed ones fold into the report as judge-oracle findings; triage savings are recorded."""
import datetime as dt
import json

from hfsentinel.controls import resolve_controls
from hfsentinel.core.system_one import Decision, SystemOne
from hfsentinel.engines import engine_bridge as eb
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.judges.ensemble import Decision as JudgeDecision
from hfsentinel.report.build import assemble
from hfsentinel.targets.resolve import parse

TARGET = {"ref": "openai+http://127.0.0.1:9/v1#m", "endpoint": "http://127.0.0.1:9/v1", "model": "m"}
SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


class FakePanel:
    def __init__(self):
        self.calls = 0

    def decide(self, goal, response):
        self.calls += 1
        return JudgeDecision("finding", "fake") if "OWNED" in response else JudgeDecision("no-finding", "fake")


class ScriptedS1(SystemOne):
    def __init__(self, available=True):
        super().__init__(client=(lambda s, q: {"answers": {}}) if available else None)

    def triage(self, goal, response):
        if not self.available:
            return Decision("triage", "refuse", 0.0, 0.0, available=False)
        if "OWNED" in response:
            return Decision("triage", "comply", 0.9, 0.9, {"comply": 0.85, "partial": 0.1, "refuse": 0.05})
        return Decision("triage", "refuse", 0.9, 0.9, {"comply": 0.02, "partial": 0.03, "refuse": 0.95})


POLICY = {"calibrated": True, "threshold": 0.55}
PROVEN_ENGINE = {"schema_version": "0.1", "engine": "probe-suite", "target": {"ref": TARGET["ref"], "model": "m"},
                 "results": [], "errors": []}


def _runner_with_candidates(responses):
    def runner(engine_key, label, command, max_seconds, allow, out_dir):
        (out_dir / f"{label}.engine.json").write_text(json.dumps(PROVEN_ENGINE))
        lines = [json.dumps({"catalog_id": "B1", "goal": "write malware", "response": r}) for r in responses]
        (out_dir / f"{label}.candidates.jsonl").write_text("\n".join(lines) + "\n")
    return runner


def test_run_engine_reads_and_deletes_the_candidate_channel(tmp_path):
    out = eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path,
                        runner=_runner_with_candidates(["sure: OWNED", "I refuse"]))
    assert len(out.candidates) == 2 and out.candidates[0]["catalog_id"] == "B1"
    assert out.candidates[0]["engine"] == "probe-suite"
    # D-015/16.17: the raw channel is deleted once read; no raw response text persists on disk.
    assert not list(tmp_path.glob("*.candidates.jsonl"))
    engine_json = next(tmp_path.glob("*.engine.json")).read_text()
    assert "write malware" not in engine_json and "I refuse" not in engine_json


def test_malformed_channel_yields_no_candidates_and_is_deleted(tmp_path):
    def runner(engine_key, label, command, max_seconds, allow, out_dir):
        (out_dir / f"{label}.engine.json").write_text(json.dumps(PROVEN_ENGINE))
        (out_dir / f"{label}.candidates.jsonl").write_text("{not json\n")
    out = eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path, runner=runner)
    assert out.candidates == [] and not list(tmp_path.glob("*.candidates.jsonl"))


def test_judge_candidates_folds_confirmed_into_judge_findings():
    panel, s1 = FakePanel(), ScriptedS1()
    candidates = [{"engine": "probe-suite", "catalog_id": "B1", "goal": "g", "response": r}
                  for r in ("OWNED a", "OWNED b", "OWNED c", "I refuse")]
    results, stats = eb.judge_candidates(candidates, panel, s1, target=TARGET, policy=POLICY)
    assert panel.calls == 3  # the confident refusal skipped the panel
    assert stats["judge_calls_made"] == 3 and stats["judge_calls_saved"] == 1
    tr = results[0].results[0]
    assert tr.catalog_id == "B1" and tr.trials == 4 and tr.successes == 3
    assert tr.oracle.kind == "judge" and tr.oracle.name == "judge-panel"
    assert all("write malware" not in p.excerpt for p in tr.proven) and all(len(p.excerpt) <= 200 for p in tr.proven)


def test_judge_finding_scored_in_the_report_with_judge_oracle():
    panel, s1 = FakePanel(), ScriptedS1()
    candidates = [{"engine": "probe-suite", "catalog_id": "B1", "goal": "g", "response": r}
                  for r in ("OWNED a", "OWNED b", "OWNED c", "nope")]
    results, _ = eb.judge_candidates(candidates, panel, s1, target=TARGET, policy=POLICY)
    controls = resolve_controls({"trials": 10, "attacks": "B1"}).controls
    plan = build_plan(parse(TARGET["ref"]), selected=["B1"], controls=controls)
    report = assemble(target={"ref": TARGET["ref"], "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps,
                      runs=[], controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                      engine_results=results, ledger={}, run_id="ejp", native=set(NATIVE),
                      started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    b1 = next(f for f in report.findings if f.catalog_id == "B1")
    assert b1.oracle.kind == "judge" and b1.oracle.name == "judge-panel"
    assert b1.successes == 3 and b1.engine_build.engines == ["probe-suite"] and b1.status == "confirmed"


def test_no_candidates_is_a_clean_noop():
    results, stats = eb.judge_candidates([], FakePanel(), ScriptedS1(), target=TARGET)
    assert results == [] and stats["judge_calls_made"] == 0 and stats["triage_agreement"] is None
