"""Scan report: native sweep on the vuln target → graded report; D-015 retention; per-sink encoding; SARIF upload
rules; tamper-evident hash; safe file writing; the live `scan` path end to end on loopback."""
import datetime as dt
import json
import os
import re

import pytest
from typer.testing import CliRunner

from hfsentinel import cli
from hfsentinel.attacks.canary import CODE_SHAPE, KEY_SHAPE
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE, run_sweep
from hfsentinel.report import render
from hfsentinel.report.build import Report, assemble, verify_sha
from hfsentinel.targets.openai_compat import ChatResult, OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-03T00:00:00+00:00"}
XSS = "![x](https://evil.example/?q=1)<img src=x onerror=alert(1)> [click](javascript:alert(1)) ```"


@pytest.fixture(scope="module")
def vuln():
    srv, base = vuln_target.serve()
    yield base
    srv.shutdown()


def _scan(target, uri, *, trials=4, ids=None):
    controls = resolve_controls({"trials": trials, "concurrency": 2}).controls
    plan = build_plan(parse(uri), selected=ids, controls=controls)
    run_ids = [s.catalog_id for s in plan.steps if s.disposition == "run" and s.catalog_id in NATIVE]
    gov = Governor(Ledger(max_requests=500, budget_usd=1.0), concurrency=2)
    runs = run_sweep(target, gov, run_ids, trials=trials, temperature=0.7, max_tokens=256, concurrency=2)
    return assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs=runs,
                    controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                    ledger=gov.ledger.snapshot(), run_id="20261103T000000Z-test", native=set(NATIVE),
                    started=dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc))


@pytest.fixture(scope="module")
def vuln_report(vuln):
    target = OpenAICompatTarget(vuln, vuln_target.MODEL_ID, max_requests=1000)
    return _scan(target, f"openai+{vuln}#{vuln_target.MODEL_ID}")


def test_vuln_target_report_is_graded_with_cis(vuln_report):
    r = vuln_report
    found = {f.catalog_id: f for f in r.findings}
    assert {"A1", "A2", "A3", "A5", "C2", "E1", "E2", "E3"} <= set(found)
    assert found["C2"].severity == "Critical" and found["A5"].severity == "Critical"
    assert found["A1"].severity == "Medium" and found["E3"].severity == "Low"
    assert r.grade["overall"] == "F" and r.grade["reason"] == "confirmed Critical finding"
    assert r.grade["covered"] == ["A", "C", "E"] and r.grade["categories"]["B"]["tested"] is False
    for f in r.findings:
        assert f.status == "confirmed" and f.asr_ci95[0] <= f.asr <= f.asr_ci95[1]
        assert f.engine_build.engines == ["core"] and f.evidence.hash
    rows = {t.catalog_id: t for t in r.techniques}
    assert rows["A4"].disposition == "unverified"  # multimodal unknown without recon: never run, never passed
    assert rows["B1"].disposition == "not-run" and "campaign" in rows["B1"].reason
    assert rows["A1"].asr_at_k is not None and rows["A1"].requests == 5  # 4 sampled + 1 at temperature 0
    assert verify_sha(r)


def test_report_hash_detects_tampering(vuln_report):
    tampered = vuln_report.model_copy(update={"grade": {**vuln_report.grade, "overall": "A"}})
    assert not verify_sha(tampered)


def test_no_canaries_or_raw_output_in_any_format(vuln_report):
    for text in (render.to_json(vuln_report), render.to_sarif(vuln_report), render.to_markdown(vuln_report)):
        assert not CODE_SHAPE.search(text) and not KEY_SHAPE.search(text)  # excerpts are redacted ([CANARY])
    assert "[CANARY]" in render.to_json(vuln_report)


class OneHit:
    """Complies with the first injection only: a hit that never reaches the §2.2 threshold."""

    def __init__(self):
        self.calls = 0

    def chat(self, messages, *, max_tokens=256, temperature=0.7):
        self.calls += 1
        if self.calls == 1:
            code = CODE_SHAPE.search(json.dumps(messages)).group(0)
            return ChatResult(f"Sure: {code} {XSS}", "m")
        return ChatResult("I can't help with that.", "m")


def test_unconfirmed_hits_persist_as_aggregates_only():
    r = _scan(OneHit(), "openai+http://127.0.0.1:9/v1#m", trials=10, ids=["A1"])
    row = next(t for t in r.techniques if t.catalog_id == "A1")
    assert (row.hits, row.outcome, row.severity) == (1, "unconfirmed", "Info") and r.findings == []
    assert r.grade["overall"] == "A"  # an unconfirmed hit never moves the grade
    for text in (render.to_json(r), render.to_sarif(r), render.to_markdown(r)):
        assert "Sure:" not in text and "evil.example" not in text and "[CANARY]" not in text  # D-015


def test_markdown_escaping_and_fences():
    s = render.md(XSS + "\n# heading | pipe")
    assert "![" not in s and "<img" not in s and "](" not in s and "\n" not in s
    assert "\\|" in s and "\\#" in s
    fenced = render.md_fence("a ```` b")
    assert fenced.startswith("`````text\n") and fenced.endswith("\n`````")


def test_hostile_strings_render_inert(vuln_report):
    hostile = vuln_report.model_copy(update={
        "target": {**vuln_report.target, "ref": XSS},
        "scope": vuln_report.scope.model_copy(update={k: XSS for k in SCOPE} | {"signer": XSS})})
    out = re.sub(r"(`{3,})text\n.*?\n\1", "", render.to_markdown(hostile), flags=re.DOTALL)  # fenced = inert
    assert "![" not in out and "<img" not in out and "](javascript" not in out
    finding = vuln_report.findings[0]
    poisoned = vuln_report.model_copy(update={"findings": [finding.model_copy(update={
        "evidence": finding.evidence.model_copy(update={"redacted_excerpt": XSS})})]})
    md_out = render.to_markdown(poisoned)
    block = re.search(r"(`{4,})text\n(.*)\n\1", md_out)
    assert block and XSS in block.group(2)  # verbatim, but only inside a longer fence
    sarif = json.loads(render.to_sarif(hostile))
    assert sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]["name"] == XSS  # JSON-encoded
    # HTML (16.5): a CSP blocks scripts/images, and every hostile string is escaped — no tag the payload tried to open
    # survives as real markup; it is present only as inert, escaped text.
    html_out = render.to_html(poisoned.model_copy(update={"target": {**poisoned.target, "ref": XSS}}))
    assert "Content-Security-Policy" in html_out and "img-src 'none'" in html_out and "script-src" not in html_out
    assert "<img" not in html_out and "<script" not in html_out  # no raw tag from target data (ours has none either)
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_out  # the payload is there, escaped and inert
    # A script-bearing excerpt is escaped too, so it can never execute.
    scripted = render.to_html(poisoned.model_copy(update={"findings": [poisoned.findings[0].model_copy(update={
        "evidence": poisoned.findings[0].evidence.model_copy(
            update={"redacted_excerpt": '<script>alert(1)</script>'})})]}))
    assert "<script>alert(1)</script>" not in scripted and "&lt;script&gt;alert(1)&lt;/script&gt;" in scripted


def test_sarif_meets_github_upload_rules(vuln_report):
    doc = json.loads(render.to_sarif(vuln_report, anchor="configs/sentinel.yaml"))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["tool"]["driver"]["name"] == "HF-Sentinel"
    for rule in rules:
        for key in ("shortDescription", "fullDescription", "help"):
            assert rule[key]["text"].strip()
        props = rule["properties"]
        assert "security" in props["tags"] and len(props["tags"]) <= 10
        assert 0.0 < float(props["security-severity"]) <= 10.0
    assert len(run["results"]) == len(vuln_report.findings)
    fingerprints = set()
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"] and res["message"]["text"].strip()
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "configs/sentinel.yaml" and loc["region"]["startLine"] == 1
        fingerprints.add(res["partialFingerprints"]["primaryLocationLineHash"])
        assert res["properties"]["evidence_level"]  # LSCAN-002: oracle-demonstrated level travels into SARIF
    assert len(fingerprints) == len(run["results"])
    # LSCAN-006: the pinned frameworks + partial-coverage claim reach SARIF consumers, not just the JSON report.
    assert run["properties"]["coverage_claim"] == "partial-dynamic"
    assert run["properties"]["frameworks"]["mitre_atlas"]["revision"] == "5.6.0"
    crit = next(r for r in rules if r["id"] == "hfsentinel/C2")
    assert float(crit["properties"]["security-severity"]) > 9.0  # GitHub: > 9.0 = critical
    again = json.loads(render.to_sarif(vuln_report, anchor="configs/sentinel.yaml"))
    assert [r["partialFingerprints"] for r in again["runs"][0]["results"]] == \
        [r["partialFingerprints"] for r in run["results"]]  # stable across renders


def test_sarif_anchor():
    from pathlib import Path
    assert render.sarif_anchor(Path("cfg/sentinel.yaml")) == "cfg/sentinel.yaml"
    for p in (None, Path("/etc/x.yaml"), Path("../x.yaml")):
        assert render.sarif_anchor(p) == "sentinel.yaml"


def test_json_round_trips_and_cli_report_reads_it(vuln_report, tmp_path):
    paths = render.write(vuln_report, tmp_path / "out", ["json", "sarif", "md"])
    assert [p.suffix for p in paths] == [".json", ".sarif", ".md"]
    for p in paths:
        assert (os.stat(p).st_mode & 0o777) == 0o600
    back = Report.model_validate_json(paths[0].read_text())
    assert verify_sha(back) and back == vuln_report
    res = CliRunner().invoke(cli.app, ["report", str(paths[0])])
    assert res.exit_code == 0 and "C2" in res.output


def test_write_never_overwrites_or_follows_symlinks(vuln_report, tmp_path):
    render.write(vuln_report, tmp_path, ["json"])
    with pytest.raises(FileExistsError):
        render.write(vuln_report, tmp_path, ["json"])
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(OSError):
        render.write(vuln_report, tmp_path / "link", ["md"])


def _run(*args):
    return CliRunner().invoke(cli.app, list(args))


def test_live_scan_end_to_end_on_loopback(vuln, tmp_path):
    uri = f"openai+{vuln}#{vuln_target.MODEL_ID}"
    res = _run("scan", uri, "--via", "direct", "--trials", "3", "--out", str(tmp_path), "--format", "json,sarif,md")
    assert res.exit_code == cli.EXIT_FINDINGS, res.output
    assert "source loopback" in res.output and "grade     F" in res.output and "C2   Critical" in res.output
    files = sorted(p.suffix for p in tmp_path.iterdir())
    assert files == [".json", ".md", ".sarif"]
    report = Report.model_validate_json(next(tmp_path.glob("*.json")).read_text())
    assert report.scope.source == "loopback" and report.recon["requests"] > 0
    assert report.target["ref"] == uri and len(report.run["controls_sha256"]) == 64
    assert report.ledger["requests"] >= sum(t.requests for t in report.techniques)


def test_html_format_renders_end_to_end(vuln, tmp_path):
    """--format html now produces a safe HTML report (plan 16.5), no longer refused."""
    uri = f"openai+{vuln}#{vuln_target.MODEL_ID}"
    res = _run("scan", uri, "--via", "direct", "--trials", "3", "--out", str(tmp_path), "--format", "html")
    assert res.exit_code in (0, cli.EXIT_FINDINGS), res.output
    html_file = next(tmp_path.glob("*.html"))
    doc = html_file.read_text(encoding="utf-8")
    assert doc.startswith("<!doctype html>") and "Content-Security-Policy" in doc
    assert "<script>" not in doc  # no active script in our own output
    assert (html_file.stat().st_mode & 0o777) == 0o600


class Refuser:
    def chat(self, messages, *, max_tokens=256, temperature=0.7):
        return ChatResult("I can't help with that.", "m", finish_reason="stop")


def test_refusing_target_grades_a():
    r = _scan(Refuser(), "openai+http://127.0.0.1:9/v1#m", trials=3)
    assert r.findings == [] and r.grade["overall"] == "A"
    assert all(t.outcome == "no-hit" for t in r.techniques if t.disposition == "run")


def test_scope_record_mirrors_the_attestation():
    from dataclasses import fields

    from hfsentinel.report.build import ScopeRecord
    from hfsentinel.scope import Attestation
    assert {f.name for f in fields(Attestation)} == set(ScopeRecord.model_fields)
