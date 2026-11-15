"""Scan-event store (stdlib sqlite): a scan records a summary row, one coverage row per technique (ran/not-run + why),
and one row per confirmed finding; writes are idempotent on run_id; and the CLI `scan --db` captures a real scan."""
import sqlite3

from typer.testing import CliRunner

from hfsentinel import cli, store
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
         "technique": "Secret leakage from context", "evidence_level": "confirmed", "reproducible": True},
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
