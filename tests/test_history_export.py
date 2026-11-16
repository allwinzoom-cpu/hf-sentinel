"""Re-export a PAST scan from the store: GET /history/{run_id}/report?format=json|sarif|md|html renders a recorded
scan's full report with the same canonical writers the live download uses, so an operator can pull last week's SARIF for
GitHub code scanning or re-share the HTML without re-running the scan. The store now keeps the full assembled report
(alias-only, aggregate-only, evidence already redacted — D-015) alongside the slim summary/coverage/findings."""
import datetime as dt
import sqlite3

import pytest

from hfsentinel import api, store
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report.build import assemble
from hfsentinel.targets.resolve import parse

pytestmark = pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")

_SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
          "checked_at": "2026-11-16T00:00:00+00:00"}
_RID = "20261116T000000Z-hx"


def _recorded_db(tmp_path) -> str:
    uri = "openai+http://127.0.0.1:9/#m"
    controls = resolve_controls({"trials": 2}).controls
    plan = build_plan(parse(uri), controls=controls)
    report = assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs={},
                      controls=controls, controls_sha256="0" * 64, attestation=_SCOPE, recon=None,
                      ledger={"requests": 0, "errors": 0, "cost_priced_usd": 0.0}, run_id=_RID,
                      native=set(NATIVE), started=dt.datetime(2026, 11, 16, tzinfo=dt.timezone.utc))
    db = str(tmp_path / "scans.db")
    store.record_scan(db, report.model_dump(mode="json"))
    return db


def _client(db):
    from fastapi.testclient import TestClient
    return TestClient(api.create_app(api_keys=["secret"], db_path=db)), {"X-API-Key": "secret"}


def test_history_export_every_format(tmp_path):
    client, h = _client(_recorded_db(tmp_path))
    j = client.get(f"/history/{_RID}/report?format=json", headers=h)
    assert j.status_code == 200 and j.headers["content-type"].startswith("application/json")
    assert j.json()["run"]["run_id"] == _RID
    assert f'filename="hfsentinel-{_RID}.json"' in j.headers["content-disposition"]

    s = client.get(f"/history/{_RID}/report?format=sarif", headers=h)
    assert s.status_code == 200 and s.headers["content-type"].startswith("application/sarif+json")
    assert s.json()["$schema"].endswith("sarif-2.1.0.json")
    assert s.json()["runs"][0]["tool"]["driver"]["name"] == "HF-Sentinel"

    md = client.get(f"/history/{_RID}/report?format=md", headers=h)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert md.text.lstrip().startswith("# HF-Sentinel")
    html = client.get(f"/history/{_RID}/report?format=html", headers=h)
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html") and "<" in html.text


def test_history_export_errors(tmp_path):
    client, h = _client(_recorded_db(tmp_path))
    assert client.get(f"/history/{_RID}/report?format=pdf", headers=h).status_code == 400   # unknown format
    assert client.get("/history/nope/report?format=json", headers=h).status_code == 404     # unknown run
    assert client.get(f"/history/{_RID}/report?format=json").status_code == 401             # auth required


def test_history_export_409_when_report_predates_capture(tmp_path):
    # a scan recorded by an older build has summary/coverage/findings but no stored report blob → 409, not a broken file
    db = _recorded_db(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM reports WHERE run_id=?", (_RID,))   # simulate the pre-capture store
    conn.commit()
    conn.close()
    client, h = _client(db)
    r = client.get(f"/history/{_RID}/report?format=sarif", headers=h)
    assert r.status_code == 409
    assert client.get(f"/history/{_RID}", headers=h).status_code == 200   # the slim detail is still served


def test_history_export_requires_a_store():
    from fastapi.testclient import TestClient
    client = TestClient(api.create_app(api_keys=["secret"]))      # no db_path configured
    assert client.get(f"/history/{_RID}/report?format=json", headers={"X-API-Key": "secret"}).status_code == 503
