"""Scan-event store (stdlib sqlite): a scan records a summary row, one coverage row per technique (ran/not-run + why),
and one row per confirmed finding; writes are idempotent on run_id; and the CLI `scan --db` captures a real scan."""
import sqlite3

import pytest
from typer.testing import CliRunner

from hfsentinel import api, cli, sdk, store
from hfsentinel.testing import vuln_target

REPORT = {
    "run": {"run_id": "20260101T000000Z-abcd", "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:01:00+00:00"},
    "target": {"ref": "openai+http://x#m", "kind": "openai", "provider": None, "resolved_model": "m"},
    "grade": {"overall": "F", "reason": "confirmed Critical finding"},
    "ledger": {"requests": 42, "errors": 0, "cost_priced_usd": 0.0012},
    "scope": {"source": "loopback", "reference": "ref-1"},
    "report_sha256": "sha256:deadbeef",
    "techniques": [
        {"catalog_id": "C2", "category": "C", "disposition": "run", "outcome": "confirmed", "reason": "",
         "trials": 5, "hits": 5, "asr": 1.0, "asr_ci95": [0.57, 1.0], "errors": 0, "severity": "Critical"},
        {"catalog_id": "A1", "category": "A", "disposition": "run", "outcome": "no-hit", "reason": "",
         "trials": 5, "hits": 0, "asr": 0.0, "asr_ci95": [0.0, 0.43], "errors": 0, "severity": "Medium"},
        {"catalog_id": "B1", "category": "B", "disposition": "not-run", "outcome": None,
         "reason": "needs a judge stage not in this build", "trials": 0, "hits": 0, "asr": None,
         "asr_ci95": None, "errors": 0, "severity": None},
    ],
    "findings": [
        {"finding_id": "F-1", "catalog_id": "C2", "severity": "Critical", "asr": 1.0, "asr_ci95": [0.57, 1.0],
         "technique": "Secret leakage from context", "evidence_level": "confirmed", "reproducible": True,
         "baseline_asr": 0.0, "lift": 1.0, "oracle": {"name": "canary-match"},
         "owasp": ["LLM06"], "atlas": ["AML.T0051"],
         "evidence": {"hash": "a" * 64, "redacted_excerpt": "system canary <REDACTED> reproduced verbatim"}},
    ],
}


def test_record_scan_captures_summary_coverage_and_findings(tmp_path):
    db = tmp_path / "scans.db"
    rid = store.record_scan(db, REPORT)
    assert rid == "20260101T000000Z-abcd"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    s = conn.execute("SELECT * FROM scans WHERE run_id=?", (rid,)).fetchone()
    assert s["target_ref"] == "openai+http://x#m" and s["grade"] == "F"
    assert (s["techniques_total"], s["techniques_run"], s["techniques_not_run"]) == (3, 2, 1)
    assert s["confirmed"] == 1 and s["requests"] == 42 and abs(s["cost_usd"] - 0.0012) < 1e-9
    # coverage is a per-technique event, including the not-run reason
    assert store.coverage_counts(db, rid) == {"run": 2, "not-run": 1}
    b1 = conn.execute("SELECT * FROM coverage WHERE run_id=? AND catalog_id='B1'", (rid,)).fetchone()
    assert b1["disposition"] == "not-run" and "judge" in b1["reason"]
    # confirmed finding is stored in full, with its CI split out
    f = conn.execute("SELECT * FROM findings WHERE run_id=?", (rid,)).fetchone()
    assert f["catalog_id"] == "C2" and f["severity"] == "Critical" and (f["ci_low"], f["ci_high"]) == (0.57, 1.0)
    # the proof the console drill-down renders is persisted too (D-015: redacted excerpt, never raw traffic)
    assert f["evidence_excerpt"] == "system canary <REDACTED> reproduced verbatim"
    assert (f["baseline_asr"], f["lift"]) == (0.0, 1.0) and f["oracle"] == "canary-match"
    assert f["owasp"] == "LLM06" and f["atlas"] == "AML.T0051"


def test_scan_detail_returns_finding_proof_for_the_drilldown(tmp_path):
    # scan_detail is what GET /history/{run_id} serves the console; it must carry the proof + precision, taxonomy as lists
    db = tmp_path / "scans.db"
    store.record_scan(db, REPORT)
    detail = store.scan_detail(db, "20260101T000000Z-abcd")
    assert detail is not None
    f = next(x for x in detail["findings"] if x["catalog_id"] == "C2")
    assert f["evidence_excerpt"] == "system canary <REDACTED> reproduced verbatim"
    assert f["baseline_asr"] == 0.0 and f["lift"] == 1.0 and f["oracle"] == "canary-match"
    assert f["owasp"] == ["LLM06"] and f["atlas"] == ["AML.T0051"]      # comma-joined storage back to lists
    assert f["reproducible"] is True and f["evidence_level"] == "confirmed"


def test_connect_migrates_an_older_findings_table(tmp_path):
    # a store written by a build before the proof columns existed must gain them on connect (ADD COLUMN, non-destructive)
    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    old.executescript(store.SCHEMA)          # full current schema for scans/coverage (those tables are unchanged) …
    old.execute("DROP TABLE findings")       # … but simulate the OLD findings table: no proof columns yet
    old.execute(
        "CREATE TABLE findings (run_id TEXT, finding_id TEXT, catalog_id TEXT, severity TEXT, asr REAL, "
        "ci_low REAL, ci_high REAL, technique TEXT, evidence_level TEXT, reproducible INTEGER, "
        "PRIMARY KEY (run_id, finding_id))")
    old.commit()
    old.close()
    conn = store.connect(db)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    conn.close()
    assert {"evidence_excerpt", "baseline_asr", "lift", "oracle", "owasp", "atlas"} <= cols
    # and a scan now records + reads back the proof against the migrated table
    store.record_scan(db, REPORT)
    f = next(x for x in store.scan_detail(db, "20260101T000000Z-abcd")["findings"] if x["catalog_id"] == "C2")
    assert f["evidence_excerpt"] == "system canary <REDACTED> reproduced verbatim"


def test_history_lists_recent_scans(tmp_path):
    db = tmp_path / "scans.db"
    store.record_scan(db, REPORT)
    res = CliRunner().invoke(cli.app, ["history", "--db", str(db)])
    assert res.exit_code == 0, res.output
    assert "scan history" in res.output and "openai+http://x#m" in res.output and " F " in res.output


def test_history_run_detail_shows_coverage_and_findings(tmp_path):
    db = tmp_path / "scans.db"
    store.record_scan(db, REPORT)
    res = CliRunner().invoke(cli.app, ["history", "--db", str(db), "--run", "20260101T000000Z-abcd"])
    assert res.exit_code == 0, res.output
    assert "B1   not-run" in res.output and "judge" in res.output        # the not-run coverage + reason
    assert "C2   run" in res.output                                      # a technique that ran
    assert "finding   C2" in res.output and "Critical" in res.output     # the confirmed finding


def test_history_requires_a_store(tmp_path, monkeypatch):
    monkeypatch.delenv("HFSENTINEL_DB", raising=False)
    res = CliRunner().invoke(cli.app, ["history"])
    assert res.exit_code == cli.EXIT_USAGE and "no scan store" in res.output
    res2 = CliRunner().invoke(cli.app, ["history", "--db", str(tmp_path / "missing.db")])
    assert res2.exit_code == cli.EXIT_INPUT and "not found" in res2.output


def test_cli_prune_command(tmp_path):
    import copy
    db = tmp_path / "scans.db"
    for i in range(4):
        r = copy.deepcopy(REPORT)
        r["run"]["run_id"] = f"run-{i}"
        r["run"]["started_at"] = f"2026-01-0{i + 1}T00:00:00+00:00"
        store.record_scan(db, r)
    res = CliRunner().invoke(cli.app, ["prune", "--db", str(db), "--keep", "1"])
    assert res.exit_code == 0, res.output
    assert "3 scan(s) removed" in res.output
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    # guards: no store configured, missing file
    import os as _os
    monkey = {k: _os.environ.pop(k) for k in ["HFSENTINEL_DB"] if k in _os.environ}
    try:
        assert CliRunner().invoke(cli.app, ["prune"]).exit_code == cli.EXIT_USAGE
    finally:
        _os.environ.update(monkey)
    assert CliRunner().invoke(cli.app, ["prune", "--db", str(tmp_path / "nope.db")]).exit_code == cli.EXIT_INPUT


def test_prune_keeps_the_most_recent_and_cascades(tmp_path):
    import copy
    db = tmp_path / "scans.db"
    for i in range(5):
        r = copy.deepcopy(REPORT)
        r["run"]["run_id"] = f"run-{i}"
        r["run"]["started_at"] = f"2026-01-0{i + 1}T00:00:00+00:00"   # run-4 is the most recent
        store.record_scan(db, r)
    removed = store.prune(db, keep=2)
    assert removed == 3
    conn = sqlite3.connect(db)
    kept = {row[0] for row in conn.execute("SELECT run_id FROM scans").fetchall()}
    assert kept == {"run-3", "run-4"}                                  # the two most recent by started
    # coverage + findings of pruned runs are gone; the kept ones remain
    assert conn.execute("SELECT COUNT(*) FROM coverage WHERE run_id='run-0'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE run_id='run-0'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM coverage WHERE run_id='run-4'").fetchone()[0] == 3
    assert store.prune(db, keep=2) == 0                                # idempotent once at/under the cap


def test_record_scan_is_idempotent(tmp_path):
    db = tmp_path / "scans.db"
    store.record_scan(db, REPORT)
    store.record_scan(db, REPORT)  # re-recording the same run must replace, not duplicate
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM coverage").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_cli_scan_records_every_scan_to_the_db(tmp_path):
    srv, base = vuln_target.serve(profile="high", seed=2)
    db = tmp_path / "scans.db"
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        res = CliRunner().invoke(cli.app, ["scan", uri, "--via", "direct", "--trials", "3",
                                           "--out", str(tmp_path / "rep"), "--db", str(db)])
    finally:
        srv.shutdown()
    assert res.exit_code in (0, cli.EXIT_FINDINGS), res.output
    assert "store     recorded scan" in res.output
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    scan = conn.execute("SELECT * FROM scans").fetchone()
    assert scan is not None and scan["target_ref"] == uri and scan["techniques_run"] > 0
    # coverage rows exist for every technique the report listed
    cov = conn.execute("SELECT COUNT(*) FROM coverage WHERE run_id=?", (scan["run_id"],)).fetchone()[0]
    assert cov == scan["techniques_total"] > 0


def test_regression_delta_helper_needs_a_baseline():
    # None whenever there is nothing to compare against; the overall ΔASR once a prior scan exists
    assert cli._regression_delta(None) is None
    assert cli._regression_delta({"target_ref": "t", "base": None}) is None          # first scan of the target
    assert cli._regression_delta({"base": {"run_id": "b"}, "overall_delta_asr": 0.2}) == 0.2
    d = cli._regression_delta({"base": {"run_id": "b"}, "overall_delta_asr": 0.2})
    assert d >= 0.1 and not d >= 0.3                                                  # fires at 0.1, not at 0.3


def test_cli_scan_regression_gate(tmp_path):
    # the CI regression gate: the first scan of a target has no baseline (gate skipped, never EXIT_REGRESSION); a second
    # scan of the same target reports the observed behavioural ΔASR vs. the first. A high threshold keeps the two
    # same-target runs from firing on noise, so this stays deterministic.
    srv, base = vuln_target.serve(profile="high", seed=5)
    db = tmp_path / "scans.db"
    uri = f"openai+{base}#{vuln_target.MODEL_ID}"
    out = str(tmp_path / "rep")
    try:
        args = ["scan", uri, "--via", "direct", "--trials", "3", "--out", out, "--db", str(db),
                "--fail-on-regression", "0.5"]
        r1 = CliRunner().invoke(cli.app, args)
        r2 = CliRunner().invoke(cli.app, args)
    finally:
        srv.shutdown()
    assert "no earlier scan of this target" in r1.output, r1.output   # first scan: nothing to compare against
    assert r1.exit_code != cli.EXIT_REGRESSION and r1.exit_code != cli.EXIT_USAGE, r1.output
    assert "regression  overall attack-success" in r2.output, r2.output  # second scan: behavioural delta reported
    assert "serving path not verified identical" in r2.output           # LSCAN-009 framing preserved on the gate
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2


def test_cli_scan_regression_gate_needs_a_store(tmp_path):
    # --fail-on-regression without --db cannot assess regression: it is skipped, never a hard failure
    srv, base = vuln_target.serve(profile="high", seed=6)
    uri = f"openai+{base}#{vuln_target.MODEL_ID}"
    try:
        res = CliRunner().invoke(cli.app, ["scan", uri, "--via", "direct", "--trials", "2",
                                           "--out", str(tmp_path / "rep"), "--fail-on-regression", "0.1"])
    finally:
        srv.shutdown()
    assert "needs a scan store" in res.output and res.exit_code != cli.EXIT_REGRESSION, res.output


def test_sdk_scan_records_to_db(tmp_path):
    # the SDK path records every scan when db_path is set (the service reuses this)
    srv, url = vuln_target.serve(profile="high", seed=3)
    db = tmp_path / "scans.db"
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1, db_path=str(db))
    finally:
        srv.shutdown()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    scan = conn.execute("SELECT * FROM scans WHERE run_id=?", (result.run_id,)).fetchone()
    assert scan is not None and scan["target_ref"] == uri
    assert conn.execute("SELECT COUNT(*) FROM coverage WHERE run_id=?", (result.run_id,)).fetchone()[0] > 0


def test_sdk_store_error_never_sinks_the_scan(tmp_path):
    # a store failure must not fail a completed scan: point db at an un-creatable path, scan still returns
    srv, url = vuln_target.serve(seed=4)
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        bad_db = tmp_path / "nope.db" / "scans.db"  # parent is a file-less path under a non-dir; mkdir may still work...
        (tmp_path / "nope.db").write_text("i am a file, not a directory")  # ...so force the parent to be a FILE
        result = sdk.scan(uri, profile="quick", trials=2, max_tokens=32, seed=1, db_path=str(bad_db))
    finally:
        srv.shutdown()
    assert result.run_id and result.report is not None  # scan completed despite the store write failing


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_service_forwards_db_path_to_every_scan(monkeypatch, tmp_path):
    # the service records every scan server-side: create_app(db_path=...) must forward it into sdk.scan
    from fastapi.testclient import TestClient
    seen = {}

    def fake_scan(target, **kwargs):
        seen["db_path"] = kwargs.get("db_path")

        class _R:
            def to_dict(self):
                return {"run_id": "x", "grade": {}, "findings": []}
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    db = str(tmp_path / "service.db")
    client = TestClient(api.create_app(api_keys=["secret"], db_path=db))
    h = {"X-API-Key": "secret"}
    job = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=h).json()["job_id"]
    for _ in range(50):
        if client.get(f"/scans/{job}", headers=h).json()["status"] in ("completed", "failed"):
            break
    assert seen["db_path"] == db  # a client never sets this; the server configures it


def _cmp_report(run_id, started, grade, coverage, findings):
    return {
        "run": {"run_id": run_id, "started_at": started, "finished_at": started},
        "target": {"ref": "openai+http://x#m", "kind": "openai", "provider": None, "resolved_model": "m"},
        "grade": {"overall": grade, "reason": ""},
        "ledger": {"requests": 5, "errors": 0, "cost_priced_usd": 0.01},
        "scope": {"source": "loopback", "reference": "r"},
        "techniques": coverage, "findings": findings,
    }


def test_scan_comparison_is_a_behavioural_delta_vs_the_previous_scan(tmp_path):
    db = tmp_path / "scans.db"
    base = _cmp_report(
        "R-base", "2026-11-01T00:00:00+00:00", "C",
        [{"catalog_id": "A1", "category": "A", "disposition": "run", "outcome": "no-hit", "trials": 5, "hits": 1,
          "asr": 0.2, "asr_ci95": [0.0, 0.5], "errors": 0, "severity": "Low"},
         {"catalog_id": "E2", "category": "E", "disposition": "run", "outcome": "confirmed", "trials": 5, "hits": 3,
          "asr": 0.6, "asr_ci95": [0.2, 0.9], "errors": 0, "severity": "High"}],
        [{"finding_id": "b1", "catalog_id": "E2", "severity": "High", "asr": 0.6, "asr_ci95": [0.2, 0.9],
          "technique": "command injection", "evidence_level": "confirmed", "reproducible": True}])
    tgt = _cmp_report(
        "R-tgt", "2026-11-10T00:00:00+00:00", "F",
        [{"catalog_id": "A1", "category": "A", "disposition": "run", "outcome": "hit", "trials": 5, "hits": 3,
          "asr": 0.5, "asr_ci95": [0.1, 0.9], "errors": 0, "severity": "Medium"},
         {"catalog_id": "E2", "category": "E", "disposition": "run", "outcome": "no-hit", "trials": 5, "hits": 0,
          "asr": 0.0, "asr_ci95": [0.0, 0.4], "errors": 0, "severity": None},
         {"catalog_id": "C2", "category": "C", "disposition": "run", "outcome": "confirmed", "trials": 5, "hits": 5,
          "asr": 1.0, "asr_ci95": [0.5, 1.0], "errors": 0, "severity": "Critical"}],
        [{"finding_id": "t1", "catalog_id": "C2", "severity": "Critical", "asr": 1.0, "asr_ci95": [0.5, 1.0],
          "technique": "secret leakage", "evidence_level": "confirmed", "reproducible": True}])
    store.record_scan(db, base)
    store.record_scan(db, tgt)

    c = store.scan_comparison(db, "R-tgt")
    assert c is not None and c["base"]["run_id"] == "R-base"           # picks the most recent earlier scan of the target
    assert c["base"]["grade"] == "C" and c["target"]["grade"] == "F"
    deltas = {r["category"]: r["delta_asr"] for r in c["categories"]}
    assert deltas["A"] == 0.3 and deltas["E"] == -0.6 and deltas["C"] == 1.0   # per-category ΔASR from stored coverage
    assert [f["catalog_id"] for f in c["findings_new"]] == ["C2"]      # appeared in the target run
    assert [f["catalog_id"] for f in c["findings_resolved"]] == ["E2"]  # present before, gone now
    assert c["findings_persistent"] == []
    assert "not an alignment-removal claim" in c["behavioural_note"]   # agnostic/LSCAN-003 framing preserved


def test_scan_comparison_edge_cases(tmp_path):
    db = tmp_path / "scans.db"
    store.record_scan(db, _cmp_report("R-only", "2026-11-01T00:00:00+00:00", "A", [], []))
    # the earliest scan of a target has nothing earlier to compare to
    assert store.scan_comparison(db, "R-only") == {"target_ref": "openai+http://x#m", "base": None}
    # an unknown run id is None (distinct from "no base")
    assert store.scan_comparison(db, "nope") is None


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_history_compare_endpoint(tmp_path):
    from fastapi.testclient import TestClient
    db = str(tmp_path / "scans.db")
    store.record_scan(db, _cmp_report("R-base", "2026-11-01T00:00:00+00:00", "C",
        [{"catalog_id": "A1", "category": "A", "disposition": "run", "asr": 0.2, "trials": 5, "hits": 1,
          "asr_ci95": [0.0, 0.5], "errors": 0, "severity": "Low"}], []))
    store.record_scan(db, _cmp_report("R-tgt", "2026-11-10T00:00:00+00:00", "F",
        [{"catalog_id": "A1", "category": "A", "disposition": "run", "asr": 0.7, "trials": 5, "hits": 4,
          "asr_ci95": [0.3, 0.9], "errors": 0, "severity": "High"}], []))
    client = TestClient(api.create_app(api_keys=["secret"], db_path=db))
    h = {"X-API-Key": "secret"}
    r = client.get("/history/R-tgt/compare", headers=h)
    assert r.status_code == 200 and r.json()["base"]["run_id"] == "R-base"
    assert client.get("/history/R-base/compare", headers=h).json()["base"] is None   # earliest scan: no base
    assert client.get("/history/nope/compare", headers=h).status_code == 404
    assert client.get("/history/R-tgt/compare").status_code == 401                   # auth required


def test_scan_report_round_trips_the_full_report(tmp_path):
    # the store keeps the full assembled report so a past scan is re-exportable; unknown run → None
    db = tmp_path / "scans.db"
    store.record_scan(db, REPORT)
    got = store.scan_report(db, "20260101T000000Z-abcd")
    assert got is not None and got["run"]["run_id"] == "20260101T000000Z-abcd"
    assert got["findings"][0]["catalog_id"] == "C2"           # the full report, not the slim detail
    assert store.scan_report(db, "no-such-run") is None


def test_scan_report_absent_for_pre_capture_store(tmp_path):
    # an older store has the scan rows but no report blob (connect() adds the empty reports table) → None, not an error
    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    old.executescript(store.SCHEMA)
    old.execute("DROP TABLE reports")                         # simulate a build before report capture existed
    old.commit()
    old.close()
    store.record_scan(db, REPORT)                             # re-records summary/coverage/findings …
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM reports WHERE run_id='20260101T000000Z-abcd'")   # … but drop the blob to mimic old data
    conn.commit()
    conn.close()
    assert store.scan_report(db, "20260101T000000Z-abcd") is None
    assert store.scan_detail(db, "20260101T000000Z-abcd") is not None          # slim detail still available


def test_prune_also_removes_stored_reports(tmp_path):
    import copy
    db = tmp_path / "scans.db"
    for i in range(3):
        r = copy.deepcopy(REPORT)
        r["run"]["run_id"] = f"run-{i}"
        r["run"]["started_at"] = f"2026-01-0{i + 1}T00:00:00+00:00"
        store.record_scan(db, r)
    store.prune(db, keep=1)
    assert store.scan_report(db, "run-0") is None and store.scan_report(db, "run-1") is None
    assert store.scan_report(db, "run-2") is not None        # the kept scan still has its report
