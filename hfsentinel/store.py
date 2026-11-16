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

import json
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
    evidence_excerpt TEXT, baseline_asr REAL, lift REAL, oracle TEXT, owasp TEXT, atlas TEXT,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id) REFERENCES scans(run_id)
);
CREATE TABLE IF NOT EXISTS reports (
    run_id TEXT PRIMARY KEY, report_json TEXT,
    FOREIGN KEY (run_id) REFERENCES scans(run_id)
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_ref);
CREATE INDEX IF NOT EXISTS idx_coverage_tech ON coverage(catalog_id);
CREATE INDEX IF NOT EXISTS idx_findings_tech ON findings(catalog_id);
"""

# Columns added after the first release. A store created by an older build has the findings table but not these; SQLite's
# CREATE TABLE IF NOT EXISTS never alters an existing table, so we add any missing one on connect (ADD COLUMN only, so an
# older reader still works). Each carries the proof the console drill-down shows: the redacted evidence excerpt (D-015 —
# already ≤200 chars, never raw traffic), the precision story (baseline ASR + lift), the oracle, and the taxonomy.
_FINDINGS_ADDED_COLUMNS = {
    "evidence_excerpt": "TEXT", "baseline_asr": "REAL", "lift": "REAL",
    "oracle": "TEXT", "owasp": "TEXT", "atlas": "TEXT",
}


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
    _migrate_findings_columns(conn)
    return conn


def _migrate_findings_columns(conn: sqlite3.Connection) -> None:
    """Add any findings column introduced after the store was first created (ADD COLUMN is non-destructive)."""
    have = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col, decl in _FINDINGS_ADDED_COLUMNS.items():
        if col not in have:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")  # col/decl are our own literals, not input


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
            # The full assembled report (after the scans row, which it references), kept so a past scan is re-exportable
            # (SARIF/MD/HTML/JSON) from the console long after the in-memory job is gone. Same alias-only, aggregate-only
            # artifact the service already hands out, evidence already redacted to ≤200-char excerpts (D-015).
            conn.execute("INSERT OR REPLACE INTO reports VALUES (?,?)", (run_id, json.dumps(r)))
            for t in techniques:
                lo, hi = _ci(t, "asr_ci95")
                conn.execute(
                    "INSERT INTO coverage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, t.get("catalog_id"), t.get("category"), t.get("disposition"), t.get("outcome"),
                     t.get("reason"), t.get("trials"), t.get("hits"), t.get("asr"), lo, hi, t.get("errors"),
                     t.get("severity")))
            for f in findings:
                lo, hi = _ci(f, "asr_ci95")
                ev = f.get("evidence") or {}
                oracle = f.get("oracle") or {}
                conn.execute(
                    "INSERT INTO findings (run_id, finding_id, catalog_id, severity, asr, ci_low, ci_high, technique, "
                    "evidence_level, reproducible, evidence_excerpt, baseline_asr, lift, oracle, owasp, atlas) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, f.get("finding_id"), f.get("catalog_id"), f.get("severity"), f.get("asr"), lo, hi,
                     f.get("technique"), f.get("evidence_level"), int(bool(f.get("reproducible"))),
                     ev.get("redacted_excerpt") or None, f.get("baseline_asr"), f.get("lift"),
                     oracle.get("name"), ",".join(f.get("owasp") or []) or None,
                     ",".join(f.get("atlas") or []) or None))
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


def recent_scans(db_path: str | Path, *, limit: int = 20, target: str | None = None) -> list[dict]:
    """The most recent scans (optionally filtered to one target), newest first — for `hfsentinel history`."""
    conn = connect(db_path)
    try:
        sql = ("SELECT run_id, started, target_ref, grade, confirmed, techniques_run, techniques_total, "
               "techniques_not_run, requests, cost_usd FROM scans")
        params: tuple = ()
        if target:
            sql += " WHERE target_ref = ?"
            params = (target,)
        sql += " ORDER BY started DESC LIMIT ?"
        return [dict(r) for r in conn.execute(sql, (*params, limit)).fetchall()]
    finally:
        conn.close()


def _finding_row(r: sqlite3.Row) -> dict:
    """A stored finding as the API/console consume it: taxonomy back to lists, reproducible back to bool, with the proof
    excerpt + precision stats (baseline ASR, lift) so the drill-down shows WHY it was confirmed, not just that it was."""
    d = dict(r)
    d["owasp"] = d["owasp"].split(",") if d.get("owasp") else []
    d["atlas"] = d["atlas"].split(",") if d.get("atlas") else []
    if "reproducible" in d and d["reproducible"] is not None:
        d["reproducible"] = bool(d["reproducible"])
    return d


def scan_detail(db_path: str | Path, run_id: str) -> dict | None:
    """One scan with its per-technique coverage and confirmed findings, or None if the run_id is unknown."""
    conn = connect(db_path)
    try:
        scan = conn.execute("SELECT * FROM scans WHERE run_id=?", (run_id,)).fetchone()
        if scan is None:
            return None
        coverage = [dict(r) for r in conn.execute(
            "SELECT catalog_id, category, disposition, outcome, reason, hits, trials, asr, severity "
            "FROM coverage WHERE run_id=? ORDER BY catalog_id", (run_id,)).fetchall()]
        findings = [_finding_row(r) for r in conn.execute(
            "SELECT catalog_id, severity, asr, ci_low, ci_high, technique, evidence_level, reproducible, "
            "evidence_excerpt, baseline_asr, lift, oracle, owasp, atlas FROM findings WHERE run_id=? "
            "ORDER BY asr DESC", (run_id,)).fetchall()]
        return {"scan": dict(scan), "coverage": coverage, "findings": findings}
    finally:
        conn.close()


def scan_report(db_path: str | Path, run_id: str) -> dict | None:
    """The full assembled report dict for a past scan, or None if the run is unknown OR predates report capture (an
    older store recorded the summary/coverage/findings but no report blob). Lets the console re-export a historical scan
    (SARIF for GitHub code scanning, Markdown/HTML to share) without re-running it."""
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT report_json FROM reports WHERE run_id=?", (run_id,)).fetchone()
        if row is None or row["report_json"] is None:
            return None
        return json.loads(row["report_json"])
    finally:
        conn.close()


def _category_asr(coverage: list[dict]) -> dict[str, float]:
    """Mean ASR across the run (scored) techniques in each category — the same per-category signal diff_reports uses,
    computed here from the stored coverage rows so no full report is needed to compare two scans."""
    sums: dict[str, float] = {}
    counts: dict[str, int] = {}
    for c in coverage:
        if c.get("disposition") == "run" and c.get("asr") is not None:
            cat = c.get("category") or (c.get("catalog_id") or " ")[0]
            sums[cat] = sums.get(cat, 0.0) + float(c["asr"])
            counts[cat] = counts.get(cat, 0) + 1
    return {cat: sums[cat] / counts[cat] for cat in counts}


def scan_comparison(db_path: str | Path, run_id: str) -> dict | None:
    """Compare a scan against the most recent EARLIER scan of the same target: per-category ΔASR, overall ΔASR, the
    grade change, and which confirmed findings are new / resolved / still present (keyed by catalog_id). This is an
    *observed behavioural* attackability delta (LSCAN-003) — never an alignment-removal or training-history claim, and
    the store does not record the serving path per technique, so it is not asserted that both runs hit the same route
    (LSCAN-009). Returns None if the run is unknown, or ``{"base": None}`` if there is no earlier scan to compare to."""
    conn = connect(db_path)
    try:
        cur = conn.execute("SELECT run_id, started, target_ref, grade, confirmed FROM scans WHERE run_id=?",
                           (run_id,)).fetchone()
        if cur is None:
            return None
        base = conn.execute(
            "SELECT run_id, started, grade, confirmed FROM scans WHERE target_ref=? AND started < ? AND run_id != ? "
            "ORDER BY started DESC LIMIT 1", (cur["target_ref"], cur["started"], run_id)).fetchone()
        if base is None:
            return {"target_ref": cur["target_ref"], "base": None}

        def _cov(rid: str) -> list[dict]:
            return [dict(r) for r in conn.execute(
                "SELECT catalog_id, category, disposition, asr FROM coverage WHERE run_id=?", (rid,)).fetchall()]

        def _finds(rid: str) -> dict[str, dict]:
            return {r["catalog_id"]: dict(r) for r in conn.execute(
                "SELECT catalog_id, severity, technique, asr FROM findings WHERE run_id=?", (rid,)).fetchall()}

        tgt_cat, bse_cat = _category_asr(_cov(run_id)), _category_asr(_cov(base["run_id"]))
        rows = [{"category": c, "target_asr": round(tgt_cat.get(c, 0.0), 4), "base_asr": round(bse_cat.get(c, 0.0), 4),
                 "delta_asr": round(tgt_cat.get(c, 0.0) - bse_cat.get(c, 0.0), 4)}
                for c in sorted(set(tgt_cat) | set(bse_cat))]
        tf, bf = _finds(run_id), _finds(base["run_id"])
        new = [tf[k] for k in tf if k not in bf]
        resolved = [bf[k] for k in bf if k not in tf]
        persistent = [tf[k] for k in tf if k in bf]
        return {
            "target_ref": cur["target_ref"],
            "target": {"run_id": cur["run_id"], "started": cur["started"], "grade": cur["grade"],
                       "confirmed": cur["confirmed"]},
            "base": {"run_id": base["run_id"], "started": base["started"], "grade": base["grade"],
                     "confirmed": base["confirmed"]},
            "categories": rows,
            "overall_delta_asr": round(sum(r["delta_asr"] for r in rows) / len(rows), 4) if rows else 0.0,
            "findings_new": new, "findings_resolved": resolved, "findings_persistent": persistent,
            # behavioural only; same serving path is not verified from the store (LSCAN-009)
            "behavioural_note": "Observed attack-success delta between two scans of this target reference; not an "
                                "alignment-removal claim, and the serving path is not verified identical.",
        }
    finally:
        conn.close()


def scan_trend(db_path: str | Path, target: str, *, limit: int = 20) -> dict:
    """A target's per-category and overall ASR across its recent scans, ordered oldest→newest for a regression-trend
    view. Each point carries the scan's run_id/time/grade/confirmed count plus ``category_asr`` and ``overall_asr``
    computed from the stored coverage rows (the same signal :func:`scan_comparison` diffs pairwise), so the console can
    chart whether a target is drifting more or less attackable over time without re-running anything.

    This is an *observed behavioural* signal (LSCAN-003): a rising line means later scans elicited more successful
    attacks on this target reference, never an alignment-removal or training-history claim; and the store does not
    record the serving path per technique, so points are not asserted to have hit the same route (LSCAN-009). Returns
    ``{"target_ref", "points": [...], "behavioural_note"}`` with ``points`` empty when the target has no scans."""
    conn = connect(db_path)
    try:
        scans = conn.execute(
            "SELECT run_id, started, grade, confirmed FROM scans WHERE target_ref=? ORDER BY started DESC LIMIT ?",
            (target, max(1, limit))).fetchall()
        points = []
        for s in reversed(scans):  # oldest→newest so the chart reads left-to-right in time
            cov = [dict(r) for r in conn.execute(
                "SELECT catalog_id, category, disposition, asr FROM coverage WHERE run_id=?",
                (s["run_id"],)).fetchall()]
            scored = [float(c["asr"]) for c in cov if c.get("disposition") == "run" and c.get("asr") is not None]
            points.append({
                "run_id": s["run_id"], "started": s["started"], "grade": s["grade"], "confirmed": s["confirmed"],
                "category_asr": {k: round(v, 4) for k, v in sorted(_category_asr(cov).items())},
                "overall_asr": round(sum(scored) / len(scored), 4) if scored else 0.0,
            })
        return {
            "target_ref": target, "points": points,
            # behavioural only; same serving path is not verified from the store (LSCAN-009)
            "behavioural_note": "Observed per-scan attack-success rates for this target reference; a trend is an "
                                "observed behavioural signal, not an alignment or training-history claim, and the "
                                "serving path is not verified identical across scans.",
        }
    finally:
        conn.close()


def prune(db_path: str | Path, *, keep: int = 1000) -> int:
    """Retention: keep only the ``keep`` most recent scans (by ``started``); delete older scans and their coverage +
    findings. Returns how many scans were removed. A long-running service records every scan, so a deployment runs this
    (e.g. on a schedule) to bound the store. ``keep`` is floored at 0; one transaction, so it is all-or-nothing."""
    conn = connect(db_path)
    try:
        with conn:  # single transaction
            stale = [r["run_id"] for r in conn.execute(
                "SELECT run_id FROM scans ORDER BY started DESC LIMIT -1 OFFSET ?", (max(0, keep),)).fetchall()]
            for run_id in stale:
                conn.execute("DELETE FROM coverage WHERE run_id=?", (run_id,))
                conn.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
                conn.execute("DELETE FROM reports WHERE run_id=?", (run_id,))
                conn.execute("DELETE FROM scans WHERE run_id=?", (run_id,))
        return len(stale)
    finally:
        conn.close()
