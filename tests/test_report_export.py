"""Report export from the service: GET /scans/{id}/report?format=json|sarif|md|html renders a finished scan's stored
report with the same canonical, output-encoded writers the CLI uses, so the operator can download it (SARIF for GitHub
code scanning, Markdown/HTML to share) straight from the console instead of re-running the scan on the CLI."""
import datetime as dt

import pytest

from hfsentinel import api, sdk
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report.build import assemble
from hfsentinel.targets.resolve import parse

pytestmark = pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")

_SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
          "checked_at": "2026-11-03T00:00:00+00:00"}


def _report_dict() -> dict:
    # A full, valid report assembled offline (empty sweep, no network) — stands in for a finished scan's stored result.
    uri = "openai+http://127.0.0.1:9/#demo-model"
    controls = resolve_controls({"trials": 2}).controls
    plan = build_plan(parse(uri), controls=controls)
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs={},
                      controls=controls, controls_sha256="0" * 64, attestation=_SCOPE, recon=None,
                      ledger={"requests": 0, "errors": 0, "cost_priced_usd": 0.0}, run_id="20261103T000000Z-test",
                      native=set(NATIVE), started=dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc))
    return report.model_dump(mode="json")


def _client(monkeypatch):
    from fastapi.testclient import TestClient
    report = _report_dict()

    def fake_scan(target, **kwargs):
        class _R:
            cancelled = False
            def to_dict(self):
                return report
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    client = TestClient(api.create_app(api_keys=["secret"]))
    h = {"X-API-Key": "secret"}
    job = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=h).json()["job_id"]
    for _ in range(500):
        if client.get(f"/scans/{job}", headers=h).json()["status"] in ("completed", "cancelled", "failed"):
            break
    return client, h, job


def test_export_json_is_the_stored_report(monkeypatch):
    client, h, job = _client(monkeypatch)
    r = client.get(f"/scans/{job}/report?format=json", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert 'attachment; filename="hfsentinel-20261103T000000Z-test.json"' in r.headers["content-disposition"]
    assert r.json()["run"]["run_id"] == "20261103T000000Z-test"


def test_export_sarif_is_valid_and_github_shaped(monkeypatch):
    client, h, job = _client(monkeypatch)
    r = client.get(f"/scans/{job}/report?format=sarif", headers=h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
    assert r.headers["content-disposition"].endswith('.sarif"')
    doc = r.json()
    assert doc["$schema"].endswith("sarif-2.1.0.json") and doc["runs"][0]["tool"]["driver"]["name"] == "HF-Sentinel"


def test_export_markdown_and_html(monkeypatch):
    client, h, job = _client(monkeypatch)
    md = client.get(f"/scans/{job}/report?format=md", headers=h)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert md.text.lstrip().startswith("# HF-Sentinel")
    html = client.get(f"/scans/{job}/report?format=html", headers=h)
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert "<" in html.text


def test_export_rejects_unknown_format_and_requires_auth(monkeypatch):
    client, h, job = _client(monkeypatch)
    assert client.get(f"/scans/{job}/report?format=pdf", headers=h).status_code == 400
    assert client.get(f"/scans/{job}/report?format=json").status_code == 401       # no key
    assert client.get("/scans/nope/report?format=json", headers=h).status_code == 404


def test_export_unavailable_until_finished(monkeypatch):
    # a job with no stored report (e.g. still running / failed) returns 409, not a broken download
    from fastapi.testclient import TestClient
    client = TestClient(api.create_app(api_keys=["secret"]))
    store = client.app.state.job_store
    job = store.create("openai+http://x#m", {})          # queued, no result
    r = client.get(f"/scans/{job.id}/report?format=json", headers={"X-API-Key": "secret"})
    assert r.status_code == 409
