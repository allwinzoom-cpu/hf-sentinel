"""`diff` command (plan Phase 4): compare a target vs a --base model — per-category ΔASR + over-refusal, for
alignment-removal detection. Pure computation is unit-tested; the CLI is exercised on two loopback vuln targets."""
import datetime as dt

from typer.testing import CliRunner

from hfsentinel import cli
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE, run_sweep
from hfsentinel.report.build import assemble
from hfsentinel.report.diff import diff_reports, to_table
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-05T00:00:00+00:00"}


def _report(base, *, trials=8, recon=None):
    uri = f"openai+{base}#{vuln_target.MODEL_ID}"
    controls = resolve_controls({"trials": trials, "concurrency": 2}).controls
    plan = build_plan(parse(uri), controls=controls)
    run_ids = [s.catalog_id for s in plan.steps if s.disposition == "run" and s.catalog_id in NATIVE]
    gov = Governor(Ledger(max_requests=5000, budget_usd=1.0), concurrency=2)
    runs = run_sweep(OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=5000), gov, run_ids,
                     trials=trials, temperature=0.7, max_tokens=64, concurrency=2)
    return assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs=runs,
                    controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=recon,
                    ledger=gov.ledger.snapshot(), run_id="20261105T000000Z-diff", native=set(NATIVE),
                    started=dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc))


def _route(**over):
    r = {"kind": "hf-provider", "requested_model": "org/m", "requested_provider": None, "resolved_model": "org/m",
         "resolved_provider": "p1", "base_url": "https://router.example/v1", "served_model": None,
         "revision": "unknown", "resolved_at": "2026-11-05T00:00:00+00:00"}
    r.update(over)
    return r


def _stub_report(route):
    import types
    return types.SimpleNamespace(target={"ref": "u", "route": route}, techniques=[], recon={"over_refusal_rate": 0.1})


def test_diff_flags_route_drift_and_is_quiet_when_paths_match():
    # LSCAN-009: same serving path → no drift; a changed provider (or missing route) → surfaced, never silently equated.
    same = diff_reports(_stub_report(_route()), _stub_report(_route()))
    assert same["route_drift"] is False and "Route drift" not in to_table(same)
    drifted = diff_reports(_stub_report(_route(resolved_provider="p2")), _stub_report(_route()))
    assert drifted["route_drift"] is True and "Route drift" in to_table(drifted)
    # a report predating the route field must not manufacture a drift claim we can't prove
    assert diff_reports(_stub_report(None), _stub_report(_route()))["route_drift"] is False


def test_diff_reports_flags_alignment_removal():
    srv_t, base_t = vuln_target.serve(profile="high", seed=1)
    srv_b, base_b = vuln_target.serve(profile="control", seed=1)
    try:
        tgt = _report(base_t, recon={"over_refusal_rate": 0.05})
        bse = _report(base_b, recon={"over_refusal_rate": 0.40})
    finally:
        srv_t.shutdown()
        srv_b.shutdown()
    d = diff_reports(tgt, bse)
    assert d["overall_delta_asr"] > 0 and d["alignment_removed"] and d["alignment_removed_in"]
    assert all(r["delta_asr"] >= 0 for r in d["categories"])  # high is at least as attackable as control everywhere
    assert d["target_over_refusal"] == 0.05 and d["base_over_refusal"] == 0.40


def test_to_table_renders_side_by_side_with_verdict():
    srv_t, base_t = vuln_target.serve(profile="high", seed=2)
    srv_b, base_b = vuln_target.serve(profile="control", seed=2)
    try:
        table = to_table(diff_reports(_report(base_t), _report(base_b)))
    finally:
        srv_t.shutdown()
        srv_b.shutdown()
    assert table.startswith("# HF-Sentinel diff")
    assert "| Category | Target ASR | Base ASR | ΔASR |" in table
    assert "Materially more attackable (behavioural)" in table


def test_identical_targets_show_no_alignment_removal():
    srv, base = vuln_target.serve(profile="control", seed=3)
    try:
        d = diff_reports(_report(base), _report(base))
    finally:
        srv.shutdown()
    assert not d["alignment_removed"] and "No alignment removal detected" in to_table(d)


def test_cli_diff_outputs_a_side_by_side_table():
    srv_t, base_t = vuln_target.serve(profile="high", seed=4)
    srv_b, base_b = vuln_target.serve(profile="control", seed=4)
    try:
        res = CliRunner().invoke(cli.app, ["diff", f"openai+{base_t}#{vuln_target.MODEL_ID}",
                                           "--base", f"openai+{base_b}#{vuln_target.MODEL_ID}",
                                           "--via", "direct", "--trials", "6"])
    finally:
        srv_t.shutdown()
        srv_b.shutdown()
    assert res.exit_code == cli.EXIT_OK, res.output
    assert "# HF-Sentinel diff" in res.output and "ΔASR" in res.output
