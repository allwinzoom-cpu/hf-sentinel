"""API layer for the UI: /catalog (selectable options), /history + /history/{run_id} (store-backed reads), and the SSE
/scans/{id}/events stream authenticated by a per-job stream token (never the API key)."""
import pytest

from hfsentinel import api, sdk, store

pytestmark = pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")

HDR = {"X-API-Key": "secret"}


def _client(**kw):
    from fastapi.testclient import TestClient
    return TestClient(api.create_app(api_keys=["secret"], **kw))


def _fake_scan(target, **kwargs):
    prog = kwargs.get("progress")
    if prog:
        prog({"type": "scan_started", "run_id": "x", "total": 2})
        prog({"type": "technique_done", "catalog_id": "A1", "category": "A", "outcome": "no-hit", "asr": 0.0})
        prog({"type": "scan_completed", "run_id": "x", "grade": "A", "confirmed": 0})

    class _R:
        run_id = "x"
        def to_dict(self):
            return {"run_id": "x", "grade": {"overall": "A"}, "findings": []}
    return _R()


def test_catalog_exposes_profiles_categories_techniques_and_packs():
    c = _client()
    assert c.get("/catalog").status_code == 401                      # deny-by-default: key required
    body = c.get("/catalog", headers=HDR).json()
    assert "quick" in body["profiles"] and "deep" in body["profiles"]
    cat_ids = {c["id"] for c in body["categories"]}
    assert {"A", "C", "E"} <= cat_ids and all(c["name"] for c in body["categories"])
    ids = {t["id"] for t in body["techniques"]}
    assert "A1" in ids and len(body["techniques"]) > 10
    packs = {p["id"] for p in body["rule_packs"]}
    assert {"owasp", "full"} <= packs


def test_history_requires_store_then_returns_rows(tmp_path):
    db = str(tmp_path / "scans.db")
    store.record_scan(db, {
        "run": {"run_id": "r1", "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:01:00+00:00"},
        "target": {"ref": "openai+http://x#m", "kind": "openai", "provider": None, "resolved_model": "m"},
        "grade": {"overall": "F", "reason": "x"}, "ledger": {"requests": 5, "errors": 0, "cost_priced_usd": 0.01},
        "scope": {"source": "loopback", "reference": "ref"}, "report_sha256": "sha256:x",
        "techniques": [{"catalog_id": "C2", "category": "C", "disposition": "run", "outcome": "confirmed",
                        "trials": 5, "hits": 5, "asr": 1.0, "asr_ci95": [0.5, 1.0], "errors": 0, "severity": "Critical"}],
        "findings": [{"finding_id": "F1", "catalog_id": "C2", "severity": "Critical", "asr": 1.0,
                      "asr_ci95": [0.5, 1.0], "technique": "Secret leakage", "evidence_level": "confirmed",
                      "reproducible": True}]})
    assert _client().get("/history", headers=HDR).status_code == 503       # no store configured on this app
    c = _client(db_path=db)
    rows = c.get("/history", headers=HDR).json()["scans"]
    assert rows and rows[0]["run_id"] == "r1" and rows[0]["grade"] == "F"
    detail = c.get("/history/r1", headers=HDR).json()
    assert detail["scan"]["run_id"] == "r1" and detail["findings"][0]["catalog_id"] == "C2"
    assert c.get("/history/nope", headers=HDR).status_code == 404


def test_submit_returns_stream_token_and_sse_streams_events(monkeypatch):
    monkeypatch.setattr(sdk, "scan", _fake_scan)
    c = _client()
    r = c.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=HDR)
    assert r.status_code == 202
    body = r.json()
    assert body["stream_token"] and body["events"].endswith(body["stream_token"])
    # the SSE endpoint is token-authenticated, not key-authenticated: a wrong token is rejected, the API key is not used
    assert c.get(f"/scans/{body['job_id']}/events?token=wrong").status_code == 401
    text = c.get(body["events"]).text
    for marker in ("stream_open", "scan_started", "technique_done", "scan_completed", "scan_closed"):
        assert marker in text, (marker, text[:400])


def test_events_unknown_job_is_404():
    assert _client().get("/scans/nope/events?token=x").status_code == 404


def test_api_key_auth_accepts_any_configured_key_and_rejects_others():
    # keys are compared in constant time; every configured key is accepted, anything else is 401
    from fastapi.testclient import TestClient
    c = TestClient(api.create_app(api_keys=["alpha-key", "beta-key"]))
    assert c.get("/catalog", headers={"X-API-Key": "alpha-key"}).status_code == 200
    assert c.get("/catalog", headers={"X-API-Key": "beta-key"}).status_code == 200
    assert c.get("/catalog", headers={"X-API-Key": "alpha-ke"}).status_code == 401   # prefix of a real key is rejected
    assert c.get("/catalog", headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.get("/catalog").status_code == 401                                      # no key


def test_security_headers_on_every_response():
    # the browser-facing service hardens responses against sniffing, clickjacking and referrer leakage
    c = _client()
    for path in ("/", "/healthz"):
        h = c.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in h["content-security-policy"]


def test_console_is_served_at_root():
    # the operator console is served same-origin (no auth to fetch the page; its own API calls carry the key)
    r = _client().get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Sentinel Console" in r.text and "/catalog" in r.text and "EventSource" in r.text
