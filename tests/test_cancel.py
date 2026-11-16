"""Cooperative scan cancellation: the SDK threads a `cancel` predicate into the campaign, which stops at the next
technique/stage boundary and finalizes a *partial* report (never an abort). The API exposes this as DELETE /scans/{id},
settling the job to `cancelled` while still returning the partial report. A real scan proves the engine honours cancel;
the API test proves the DELETE → cancel-event → status plumbing without depending on scan timing."""
import threading
import time

import pytest

from hfsentinel import api, sdk
from hfsentinel.testing import vuln_target


def test_sdk_cancel_finalizes_a_partial_report():
    # cancel() true from the start: the campaign must stop before running techniques and still return a report.
    srv, url = vuln_target.serve(profile="high", seed=7)
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1, cancel=lambda: True)
    finally:
        srv.shutdown()
    assert result.cancelled is True            # the result flags the partial run
    assert result.report is not None           # a report is always finalized, never an abort
    # a cancelled-before-sweep scan confirms nothing (it never attacked), which is a valid, honest outcome
    assert result.findings == []


def test_sdk_no_cancel_runs_normally():
    # the default path (cancel=None) is unaffected: a normal scan is not marked cancelled.
    srv, url = vuln_target.serve(profile="high", seed=8)
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1)
    finally:
        srv.shutdown()
    assert result.cancelled is False
    assert result.report is not None


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_delete_cancels_a_running_scan(monkeypatch):
    # DELETE /scans/{id} must set the job's cancel event; _run maps a cancelled result to status "cancelled" and still
    # returns the partial report. A fake scan that waits on the predicate makes this deterministic (no scan-timing race).
    from fastapi.testclient import TestClient

    started = threading.Event()

    def fake_scan(target, **kwargs):
        cancel = kwargs.get("cancel")
        started.set()
        for _ in range(500):                       # wait until the DELETE sets the cancel event
            if cancel and cancel():
                break
            time.sleep(0.01)
        was_cancelled = bool(cancel and cancel())

        class _R:
            cancelled = was_cancelled
            def to_dict(self):
                return {"run": {"run_id": "x"}, "grade": {"overall": "A"}, "findings": []}
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    client = TestClient(api.create_app(api_keys=["secret"]))
    h = {"X-API-Key": "secret"}
    job = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=h).json()["job_id"]
    assert started.wait(timeout=5)                 # the scan thread is running and polling the predicate

    cancel = client.delete(f"/scans/{job}", headers=h)
    assert cancel.status_code == 200 and cancel.json()["status"] == "cancelling"

    body = {}
    for _ in range(500):
        body = client.get(f"/scans/{job}", headers=h).json()
        if body["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.01)
    assert body["status"] == "cancelled"           # settled to cancelled, not completed
    assert "result" in body                        # the partial report is still returned


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_delete_unknown_and_terminal_jobs(monkeypatch):
    # unknown id → 404; a DELETE on an already-terminal job is idempotent and returns its terminal status unchanged.
    from fastapi.testclient import TestClient

    def fake_scan(target, **kwargs):
        class _R:
            cancelled = False
            def to_dict(self):
                return {"run": {"run_id": "x"}, "grade": {"overall": "A"}, "findings": []}
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    client = TestClient(api.create_app(api_keys=["secret"]))
    h = {"X-API-Key": "secret"}
    assert client.delete("/scans/nope", headers=h).status_code == 404

    job = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=h).json()["job_id"]
    for _ in range(500):
        if client.get(f"/scans/{job}", headers=h).json()["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.01)
    done = client.delete(f"/scans/{job}", headers=h)     # already terminal
    assert done.status_code == 200 and done.json()["status"] == "completed"


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_delete_requires_auth():
    from fastapi.testclient import TestClient
    client = TestClient(api.create_app(api_keys=["secret"]))
    assert client.delete("/scans/anything").status_code == 401
