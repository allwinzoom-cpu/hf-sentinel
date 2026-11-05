"""Engine bridge (plan 16.18/16.22): runs an engine adapter via the sandbox and folds its EngineResult into the
scored report. The runner is faked here; a real garak run is exercised separately."""
import datetime as dt
import json

from hfsentinel.controls import resolve_controls
from hfsentinel.engines import engine_bridge as eb
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report.build import assemble
from hfsentinel.report.schema import EngineResult
from hfsentinel.targets.resolve import parse

TARGET = {"ref": "openai+http://127.0.0.1:9/v1#m", "endpoint": "http://127.0.0.1:9/v1", "model": "m"}
SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


def _engine_json(label, catalog_id, trials, successes):
    proven = [{"sha256": "a" * 64, "excerpt": "persona accepted; marker emitted"}] * min(successes, 1)
    return {"schema_version": "0.1", "engine": "probe-suite", "target": {"ref": TARGET["ref"], "model": "m"},
            "results": [{"catalog_id": catalog_id, "technique": "Role-play / persona override", "trials": trials,
                         "successes": successes, "oracle": {"kind": "tool-deterministic", "name": "probe-detectors"},
                         "proven": proven}], "errors": []}


def test_plan_engine_work_groups_by_engine():
    assert eb.plan_engine_work(["B1", "B2", "C2", "A1"]) == {"garak": ["B1"], "pyrit": ["B2"]}
    assert eb.plan_engine_work(["C2", "A1"]) == {}


def test_run_engine_validates_and_returns_result(tmp_path):
    def fake_runner(engine_key, label, command, max_seconds, allow, out_dir):
        assert engine_key == "garak" and command[-1].endswith(f"{label}.job.json")
        job = json.loads((out_dir / f"{label}.job.json").read_text())
        assert job["techniques"] == ["B1"] and job["canary"].startswith("HS")
        (out_dir / f"{label}.engine.json").write_text(json.dumps(_engine_json(label, "B1", 8, 6)))

    out = eb.run_engine("garak", ["B1"], target=TARGET, trials=8, out_dir=tmp_path, runner=fake_runner)
    assert out.error == "" and isinstance(out.result, EngineResult)
    assert out.result.results[0].successes == 6 and out.engine == "probe-suite"


def test_run_engine_reports_failures(tmp_path):
    def boom(*a):
        raise RuntimeError("docker missing")
    assert "engine run failed" in eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path,
                                                runner=boom).error

    def no_output(engine_key, label, command, max_seconds, allow, out_dir):
        pass
    assert "no usable result" in eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path,
                                               runner=no_output).error

    def bad(engine_key, label, command, max_seconds, allow, out_dir):
        (out_dir / f"{label}.engine.json").write_text('{"not": "an engine result"}')
    assert "schema validation" in eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path,
                                                runner=bad).error


def test_engine_results_are_scored_like_native_in_the_report():
    uri = TARGET["ref"]
    controls = resolve_controls({"trials": 10, "attacks": "B1"}).controls
    plan = build_plan(parse(uri), selected=["B1"], controls=controls)
    er = EngineResult.model_validate(_engine_json("x", "B1", 12, 11))  # reliable persona override → High
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs=[],
                      controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                      engine_results=[er], ledger={}, run_id="eng", native=set(NATIVE),
                      started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    b1 = next(f for f in report.findings if f.catalog_id == "B1")
    assert b1.severity == "High" and b1.engine_build.engines == ["probe-suite"]
    assert b1.oracle.kind == "tool-deterministic" and b1.successes == 11
    assert report.grade["categories"]["B"]["tested"] and report.grade["overall"] == "D"  # one High → D, not F
    row = next(r for r in report.techniques if r.catalog_id == "B1")
    assert row.disposition == "run" and row.outcome == "confirmed"


def test_unreliable_engine_result_is_gated_down():
    controls = resolve_controls({"trials": 10, "attacks": "B1"}).controls
    plan = build_plan(parse(TARGET["ref"]), selected=["B1"], controls=controls)
    er = EngineResult.model_validate(_engine_json("x", "B1", 10, 3))  # 3/10: confirmed but not reliable → Medium
    report = assemble(target={"ref": TARGET["ref"], "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps,
                      runs=[], controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                      engine_results=[er], ledger={}, run_id="eng", native=set(NATIVE),
                      started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    assert next(f for f in report.findings if f.catalog_id == "B1").severity == "Medium"
