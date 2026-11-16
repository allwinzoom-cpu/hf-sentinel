"""Admission control + job-lifecycle accounting. Scans are long and the worker pool is small, so the service bounds
queued+running work and sheds load with 429 + Retry-After instead of queuing unbounded traffic to targets. The active
counter (not the record count) is the bound; evicting a record never stops a running scan, so eviction skips live jobs."""
import threading
import time

import pytest

from hfsentinel import api, sdk
from hfsentinel.api.app import JobStore  # plain stdlib/pydantic; importable without the fastapi extra


def test_active_counts_queued_running_and_decrements_once_on_terminal():
    store = JobStore(max_jobs=100)
    j = store.create("openai+http://x#m", {})
    assert store.active() == 1                       # a fresh job is queued/active
    store.update(j.id, status="running")
    assert store.active() == 1                       # running is still active
    store.update(j.id, status="completed", result={})
    assert store.active() == 0                       # settles to terminal: counted down
    store.update(j.id, status="completed")           # a redundant terminal update must not double-decrement
    assert store.active() == 0


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_every_terminal_state_releases_a_slot(terminal):
    store = JobStore(max_jobs=100)
    j = store.create("openai+http://x#m", {})
    store.update(j.id, status=terminal)
    assert store.active() == 0


def test_eviction_never_drops_a_non_terminal_job():
    # max_jobs=2, but both jobs are still in flight → neither is evicted when a 3rd arrives (orphaning a live scan is worse
    # than keeping an extra record). The oldest FINISHED record is the one that gets dropped.
    store = JobStore(max_jobs=2)
    a = store.create("t", {})
    b = store.create("t", {})
    c = store.create("t", {})                        # over the record cap, but a and b are still queued
    assert {j is not None for j in (store.get(a.id), store.get(b.id), store.get(c.id))} == {True}
    store.update(a.id, status="completed")           # now a is terminal and the oldest finished record
    store.create("t", {})                            # a new record evicts a (the finished one), not b or c
    assert store.get(a.id) is None
    assert store.get(b.id) is not None and store.get(c.id) is not None


def test_create_app_default_backlog_scales_with_workers():
    if not api.FASTAPI_AVAILABLE:
        pytest.skip("FastAPI not installed (optional `api` extra)")
    app = api.create_app(api_keys=["k"], max_concurrent=4)
    assert app.state.max_active_jobs == 32           # max(8, 4*8)
    app2 = api.create_app(api_keys=["k"], max_concurrent=4, max_active_jobs=5)
    assert app2.state.max_active_jobs == 5           # explicit override wins


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_api_sheds_load_with_429_when_queue_is_full(monkeypatch):
    # Hold scans open so they stay active; a submission past the backlog bound must get 429 + Retry-After, and once a
    # slot frees the next submission is accepted again.
    from fastapi.testclient import TestClient

    release = threading.Event()

    def fake_scan(target, **kwargs):
        release.wait(timeout=10)                     # stay "running" until the test releases it

        class _R:
            cancelled = False
            def to_dict(self):
                return {"run": {"run_id": "x"}, "grade": {"overall": "A"}, "findings": []}
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    client = TestClient(api.create_app(api_keys=["secret"], max_concurrent=1, max_active_jobs=2))
    h = {"X-API-Key": "secret"}
    body = {"target": "openai+http://127.0.0.1:1/v1#m"}

    first = client.post("/scans", json=body, headers=h)
    second = client.post("/scans", json=body, headers=h)
    assert first.status_code == 202 and second.status_code == 202      # backlog of 2 accepted

    full = client.post("/scans", json=body, headers=h)
    assert full.status_code == 429                                     # at capacity: shed load
    assert full.headers.get("Retry-After") == "30"

    release.set()                                                      # let the running scans finish, freeing slots
    for _ in range(500):
        if client.app.state.job_store.active() < 2:
            break
        time.sleep(0.01)
    assert client.post("/scans", json=body, headers=h).status_code == 202   # accepted again once drained


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_graceful_shutdown_cancels_inflight_and_finalizes(monkeypatch):
    # On shutdown (TestClient context exit → lifespan shutdown) an in-flight scan must be signalled to stop and finalize
    # a partial report — not abandoned mid-request. The lifespan waits for the pool to drain, so after the `with` block
    # the job has settled to "cancelled".
    from fastapi.testclient import TestClient

    saw_cancel = threading.Event()

    def fake_scan(target, **kwargs):
        cancel = kwargs.get("cancel")
        for _ in range(2000):                        # run until shutdown signals cancellation
            if cancel and cancel():
                saw_cancel.set()
                break
            time.sleep(0.01)
        was_cancelled = bool(cancel and cancel())

        class _R:
            cancelled = was_cancelled
            def to_dict(self):
                return {"run": {"run_id": "x"}, "grade": {"overall": "A"}, "findings": []}
        return _R()

    monkeypatch.setattr(sdk, "scan", fake_scan)
    app = api.create_app(api_keys=["secret"], max_concurrent=1)
    h = {"X-API-Key": "secret"}
    with TestClient(app) as client:
        job = client.post("/scans", json={"target": "openai+http://127.0.0.1:1/v1#m"}, headers=h).json()["job_id"]
        for _ in range(500):                         # wait until the scan is actually running
            if client.get(f"/scans/{job}", headers=h).json()["status"] == "running":
                break
            time.sleep(0.01)
    # context exited → graceful drain ran
    assert saw_cancel.is_set()                       # the in-flight scan was told to stop
    settled = app.state.job_store.get(job)
    assert settled is not None and settled.status == "cancelled"   # finalized, not abandoned
