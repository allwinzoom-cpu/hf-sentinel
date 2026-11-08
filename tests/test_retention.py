"""Evidence retention — proven findings only (plan 16.17, D-015).

Done-when: after a full run the output directory holds no request/response text and no tool-call record for any
non-confirmed trial (aggregates only), and every confirmed finding replays from its recipe. `--save-transcripts` keeps
full transcripts for confirmed findings only.
"""
import datetime as dt
import json
from pathlib import Path

from hfsentinel.controls import resolve_controls
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.replay import replay
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report import render
from hfsentinel.report.build import assemble
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}


def _target(base):
    return OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=100_000)


def _run(base, seed, *, keep_transcripts=False, trials=16):
    uri = f"openai+{base}#{vuln_target.MODEL_ID}"
    controls = resolve_controls({"trials": trials, "concurrency": 4}).controls
    plan = build_plan(parse(uri), controls=controls)
    gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=4)
    res = run_campaign(_target(base), gov, plan, trials=trials, temperature=0.7, max_tokens=64, concurrency=4,
                       seed=seed, keep_transcripts=keep_transcripts)
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": vuln_target.MODEL_ID},
                      plan_steps=plan.steps, runs=res.runs, controls=controls, controls_sha256="0" * 64,
                      attestation=SCOPE, recon=None, baseline=res.baseline,
                      campaign={"decisions": res.decisions, "attack_requests": res.requests,
                                "exhaustive_requests": res.exhaustive_requests},
                      ledger=gov.ledger.snapshot(), run_id=f"ret{seed}", native=set(NATIVE),
                      started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))
    return res, report, uri


def test_full_run_persists_only_aggregates_for_non_confirmed(tmp_path):
    srv, base = vuln_target.serve(profile="high", seed=7)
    try:
        _, report, _ = _run(base, 7)
        assert report.findings  # the vulnerable target yields confirmed findings
        paths = render.write(report, tmp_path, ["json", "sarif", "md"])
        # 1) No transcripts file is written without --save-transcripts.
        assert not list(tmp_path.glob("*.transcripts.json"))
        # 2) Every confirmed finding has an evidence hash + repro recipe; every non-confirmed technique carries neither
        #    a per-trial record nor an excerpt in the report — only aggregate counts.
        doc = json.loads(render.to_json(report))
        confirmed = {f["catalog_id"] for f in doc["findings"]}
        for f in doc["findings"]:
            assert f["evidence"]["hash"] and f["repro"] and f["repro"]["catalog_id"] == f["catalog_id"]
        for row in doc["techniques"]:
            if row["catalog_id"] not in confirmed:
                # aggregates only: counts/rates, never raw request or response text
                assert set(row) >= {"trials", "hits"}
                assert "transcript" not in row and "messages" not in row and "response" not in row
        # 3) No rendered file carries a full transcript — no request/response structure, and the proven excerpt is
        #    capped at 200 chars.
        for p in paths:
            text = Path(p).read_text(encoding="utf-8")
            assert '"messages"' not in text and '"output"' not in text
        for f in report.findings:
            assert len(f.evidence.redacted_excerpt) <= 200
    finally:
        srv.shutdown()


def test_confirmed_finding_replays_from_its_recipe():
    srv, base = vuln_target.serve(profile="high", seed=8)
    try:
        _, report, _ = _run(base, 8)
        finding = next(f for f in report.findings if f.repro is not None)
        # LSCAN-024: the recipe is a complete versioned manifest — exact generation settings + dependency pins.
        repro = finding.repro
        assert repro.max_tokens >= 1 and repro.replayable == "exact"
        assert repro.system_instruction_owner == "harness"
        assert {"catalog_version", "schema", "tool_build"} <= set(repro.versions)
        from hfsentinel.report.schema import replay_compatibility
        assert replay_compatibility(repro, dict(repro.versions)) == []            # same env -> exact replay valid
        assert replay_compatibility(repro, {**repro.versions, "schema": "9.9"}) == ["schema"]  # drift is flagged
        # Re-run the single technique from its recipe against the same target; the native oracle must fire again.
        run = replay(repro, _target(base))
        assert run.catalog_id == finding.catalog_id
        assert run.hits >= 1, f"{finding.catalog_id} did not reproduce from its recipe"
    finally:
        srv.shutdown()


def test_save_transcripts_keeps_confirmed_only(tmp_path):
    srv, base = vuln_target.serve(profile="high", seed=9)
    try:
        res, report, _ = _run(base, 9, keep_transcripts=True)
        confirmed_ids = {f.catalog_id for f in report.findings}
        assert confirmed_ids
        # The cli writes transcripts only for confirmed findings' techniques.
        tx = {r.catalog_id: r.transcripts for r in res.runs if r.catalog_id in confirmed_ids and r.transcripts}
        path = render.write_transcripts(tmp_path, "ret9", tx)
        assert path is not None
        saved = json.loads(Path(path).read_text(encoding="utf-8"))["transcripts"]
        assert set(saved) <= confirmed_ids and set(saved)  # only confirmed techniques, and at least one
        # Each saved transcript is a full exchange (messages + output) — this is the opt-in retention.
        some = next(iter(saved.values()))[0]
        assert "messages" in some and "output" in some
        # The file is 0600.
        assert (path.stat().st_mode & 0o777) == 0o600
    finally:
        srv.shutdown()


def test_no_transcripts_file_when_nothing_confirmed(tmp_path):
    assert render.write_transcripts(tmp_path, "empty", {"A1": []}) is None
    assert render.write_transcripts(tmp_path, "empty", {}) is None
    assert not list(tmp_path.glob("*.transcripts.json"))
