"""Durable scan-event store (stdlib ``sqlite3`` only — no new dependency).

Records, for every scan, three layers:
  * ``scans``     — one summary row (target, grade, counts, cost, scope attestation ref);
  * ``coverage``  — one row per catalog technique: whether it ran or not and why, plus hits/trials/ASR — so the coverage
                    of each scan is itself a queryable event;
  * ``findings``  — one row per CONFIRMED finding, in full.

Aggregates are kept for every technique; full per-request traffic is never dumped here — it is retained (as transcripts)
only for confirmed findings elsewhere (D-015). Writes are idempotent on ``run_id`` (re-recording a run replaces it), so
a retried scan never double-counts. Opt-in via a configured DB path: once a deployment sets one, every scan is captured.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    run_id TEXT PRIMARY KEY,
    started TEXT, finished TEXT, recorded_at TEXT,
    target_ref TEXT, kind TEXT, provider TEXT, resolved_model TEXT,
    grade TEXT, grade_reason TEXT,
    confirmed INTEGER, techniques_total INTEGER, techniques_run INTEGER, techniques_not_run INTEGER,
    requests INTEGER, errors INTEGER, cost_usd REAL,
    scope_source TEXT, scope_ref TEXT, report_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS coverage (
    run_id TEXT, catalog_id TEXT, category TEXT,
    disposition TEXT, outcome TEXT, reason TEXT,
    trials INTEGER, hits INTEGER, asr REAL, ci_low REAL, ci_high REAL, errors INTEGER, severity TEXT,
    PRIMARY KEY (run_id, catalog_id),
    FOREIGN KEY (run_id) REFERENCES scans(run_id)
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT, finding_id TEXT, catalog_id TEXT, severity TEXT,
    asr REAL, ci_low REAL, ci_high REAL, technique TEXT, evidence_level TEXT, reproducible INTEGER,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id) REFERENCES scans(run_id)
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_ref);
CREATE INDEX IF NOT EXISTS idx_coverage_tech ON coverage(catalog_id);
CREATE INDEX IF NOT EXISTS idx_findings_tech ON findings(catalog_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) the scan store at `db_path` with the schema ensured. WAL mode lets a reader run while a
    scan writes. The parent directory is created if missing."""
    path = Path(db_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def _as_dict(report: Any) -> dict:
    if hasattr(report, "model_dump"):
        return report.model_dump(mode="json")
    return dict(report)


def _ci(row: dict, key: str) -> tuple[Any, Any]:
    ci = row.get(key) or (None, None)
    return (ci[0], ci[1]) if isinstance(ci, (list, tuple)) and len(ci) == 2 else (None, None)


def record_scan(db_path: str | Path, report: Any, *, recorded_at: str | None = None) -> str:
    """Persist one scan (summary + per-technique coverage + confirmed findings) to the store. Idempotent on ``run_id``.
    Accepts the assembled Report model or a plain report dict. Returns the ``run_id``."""
    import datetime as dt

    r = _as_dict(report)
    run = r.get("run", {}) or {}
    target = r.get("target", {}) or {}
    grade = r.get("grade", {}) or {}
    ledger = r.get("ledger", {}) or {}
    scope = r.get("scope", {}) or {}
    techniques = r.get("techniques", []) or []
    findings = r.get("findings", []) or []
    run_id = run.get("run_id") or ""
    if not run_id:
        raise ValueError("report has no run_id; cannot record")

    ran = [t for t in techniques if t.get("disposition") == "run"]
    cost = ledger.get("cost_priced_usd") or ledger.get("cost_reported_usd") or ledger.get("cost_estimated_usd") or 0.0
    conn = connect(db_path)
    try:
        with conn:  # one transaction; rolls back on any error
            conn.execute("DELETE FROM coverage WHERE run_id=?", (run_id,))
            conn.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (:run_id,:started,:finished,:recorded_at,:target_ref,:kind,"
                ":provider,:resolved_model,:grade,:grade_reason,:confirmed,:techniques_total,:techniques_run,"
                ":techniques_not_run,:requests,:errors,:cost_usd,:scope_source,:scope_ref,:report_sha256)",
                {"run_id": run_id, "started": run.get("started_at"), "finished": run.get("finished_at"),
                 "recorded_at": recorded_at or dt.datetime.now(dt.timezone.utc).isoformat(),
                 "target_ref": target.get("ref"), "kind": target.get("kind"), "provider": target.get("provider"),
                 "resolved_model": target.get("resolved_model"), "grade": grade.get("overall"),
                 "grade_reason": grade.get("reason"), "confirmed": len(findings), "techniques_total": len(techniques),
                 "techniques_run": len(ran), "techniques_not_run": len(techniques) - len(ran),
                 "requests": ledger.get("requests"), "errors": ledger.get("errors"), "cost_usd": cost,
                 "scope_source": scope.get("source"), "scope_ref": scope.get("reference"),
                 "report_sha256": r.get("report_sha256")})
            for t in techniques:
                lo, hi = _ci(t, "asr_ci95")
                conn.execute(
                    "INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, t.get("catalog_id"), t.get("category"), t.get("disposition"), t.get("outcome"),
                     t.get("reason"), t.get("trials"), t.get("hits"), t.get("asr"), lo, hi, t.get("errors"),
                     t.get("severity")))
            for f in findings:
                lo, hi = _ci(f, "asr_ci95")
                conn.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (run_id, f.get("finding_id"), f.get("catalog_id"), f.get("severity"), f.get("asr"), lo, hi,
                     f.get("technique"), f.get("evidence_level"), int(bool(f.get("reproducible")))))
        return run_id
    finally:
        conn.close()


def coverage_counts(db_path: str | Path, run_id: str) -> dict[str, int]:
    """{disposition: count} for one scan — a quick read-back of recorded coverage."""
    conn = connect(db_path)
    try:
        rows = conn.execute("SELECT disposition, COUNT(*) n FROM coverage WHERE run_id=? GROUP BY disposition",
                            (run_id,)).fetchall()
        return {row["disposition"]: row["n"] for row in rows}
    finally:
        conn.close()
