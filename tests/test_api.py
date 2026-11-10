"""FastAPI layer: stdlib components (job store, rate limiter, request model, key loading) always run; the full app
(auth, async job lifecycle, error mapping) runs under the TestClient when the optional ``api`` extra is installed, with
``sdk.scan`` monkeypatched so the tests are fast and never make a real request."""
from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from hfsentinel.api import app as api


# ---- stdlib components (no FastAPI needed) ----
def test_job_store_lifecycle_and_eviction():
    store = api.JobStore(max_jobs=2)
    a = store.create("t-a", {"target": "t-a"})
    b = store.create("t-b", {"target": "t-b"})
    store.update(a.id, status="completed", result={"ok": True}, finished="t")
    assert store.get(a.id).public()["result"] == {"ok": True}
    store.create("t-c", {"target": "t-c"})            # evicts the oldest (a)
    assert store.get(a.id) is None and store.get(b.id) is not None


def test_rate_limiter_blocks_over_limit():
    rl = api.RateLimiter(per_min=2)
    assert rl.allow("k") and rl.allow("k") and not rl.allow("k")
    assert rl.allow("other")                          # per-key, independent


def test_load_api_keys_from_list_and_env(monkeypatch):
    assert api.load_api_keys(["a", "b ", " "]) == {"a", "b"}
    monkeypatch.setenv("HFSENTINEL_API_KEYS", "x, y ,")
    assert api.load_api_keys() == {"x", "y"}
    monkeypatch.delenv("HFSENTINEL_API_KEYS", raising=False)
    assert api.load_api_keys() == set()               # none configured => deny-all


def test_scan_request_curates_and_bounds():
    r = api.ScanRequest(target="openai+http://127.0.0.1:1/v1#m", profile="quick", trials=3,
                        extended=True, check_triggered=False)
    assert r.scan_kwargs() == {"profile": "quick", "trials": 3, "extended": True}  # False/None omitted
    with pytest.raises(ValidationError):
        api.ScanRequest(target="x", trials=0)         # out of bounds (ge=1)
    with pytest.raises(ValidationError):
        api.ScanRequest(target="x", profile="bogus")  # not an allowed profile


def test_failed_job_public_view_redacts_internal():
    store = api.JobStore()
    j = store.create("t", {"target": "t"})
    store.update(j.id, status="failed", error="KeyError", error_kind="internal", finished="t")
    pub = store.get(j.id).public()
    assert pub["status"] == "failed" and pub["error_kind"] == "internal" and "result" not in pub


# ---- full app under the TestClient (requires the optional `api` extra) ----
pytestmark_client = pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")


def _client(monkeypatch, *, result=None, exc=None):
    """A TestClient over an app whose sdk.scan is replaced by a fast fake (returns `result` or raises `exc`)."""
    from fastapi.testclient import TestClient

    class _FakeResult:
        def to_dict(self):
            return result or {"grade": {"overall": None}, "findings": []}

    def fake_scan(target, **kwargs):
        if exc is not None:
            raise exc
        return _FakeResult()

    monkeypatch.setattr(api.sdk, "scan", fake_scan)
    app = api.create_app(api_keys=["secret"], rate_per_min=100, max_concurrent=2)
    return TestClient(app)


def _poll(client, job_id, *, headers, tries=50):
    for _ in range(tries):
        body = client.get(f"/scans/{job_id}", headers=headers).json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError("job did not finish")


@pytestmark_client
def test_healthz_is_open():
    client = _client_noauth()
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def _client_noauth():
    from fastapi.testclient import TestClient
    return TestClient(api.create_app(api_keys=["secret"]))


@pytestmark_client
def test_auth_required_and_rate_limited(monkeypatch):
    client = _client(monkeypatch)
    assert client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}).status_code == 401
    ok = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"},
                     headers={"X-API-Key": "secret"})
    assert ok.status_code == 202 and "job_id" in ok.json()
    bad = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"},
                      headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401


@pytestmark_client
def test_no_keys_configured_denies(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.delenv("HFSENTINEL_API_KEYS", raising=False)
    client = TestClient(api.create_app(api_keys=[]))
    r = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers={"X-API-Key": "x"})
    assert r.status_code == 503


@pytestmark_client
def test_scan_job_completes_and_returns_result(monkeypatch):
    client = _client(monkeypatch, result={"grade": {"overall": "A"}, "findings": []})
    headers = {"X-API-Key": "secret"}
    sub = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m", "profile": "quick"},
                      headers=headers)
    assert sub.status_code == 202
    body = _poll(client, sub.json()["job_id"], headers=headers)
    assert body["status"] == "completed" and body["result"]["grade"]["overall"] == "A"


@pytestmark_client
def test_scope_denied_scan_fails_with_scope_kind(monkeypatch):
    from hfsentinel.scope import ScopeError
    client = _client(monkeypatch, exc=ScopeError("refused: target is not in scope"))
    headers = {"X-API-Key": "secret"}
    sub = client.post("/scans", json={"target": "hf-provider://org/m@p"}, headers=headers)
    body = _poll(client, sub.json()["job_id"], headers=headers)
    assert body["status"] == "failed" and body["error_kind"] == "scope"


@pytestmark_client
def test_unknown_job_404(monkeypatch):
    client = _client(monkeypatch)
    assert client.get("/scans/nope", headers={"X-API-Key": "secret"}).status_code == 404
