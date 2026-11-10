"""FastAPI application for HF-Sentinel: a secure, scalable async-job API over :mod:`hfsentinel.sdk`.

Design (per the operator's choices):
  * Async jobs. ``POST /scans`` validates + queues a scan and returns ``202`` with a ``job_id`` immediately; the scan runs
    on a bounded thread pool (scans are long and the SDK is synchronous). ``GET /scans/{id}`` polls status/result. This
    keeps the event loop free and lets many scans run without a worker blocking per request.
  * API-key bearer auth + per-key rate limiting. Every scan route requires a configured key (``Authorization: Bearer`` or
    ``X-API-Key``); with no keys configured the API refuses scan requests (deny-by-default). Keys never appear in URLs.
  * Curated surface. Only the "very-needed" scan knobs are settable over HTTP (:class:`ScanRequest`); every advanced
    control keeps its SDK default. The authorized SCOPE is configured server-side (``create_app(scope_file=...)``), never
    taken from a request body — so a client cannot point the scanner at an out-of-scope target or a traversal path.

The job store, rate limiter, auth helper and request model are plain stdlib/pydantic, so they unit-test without FastAPI;
only :func:`create_app` needs the optional ``api`` extra.
"""
from __future__ import annotations

import datetime as dt
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field  # pydantic is a core dependency

from hfsentinel import sdk
from hfsentinel.scope import ScopeError

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    FASTAPI_AVAILABLE = True
except Exception:                               # noqa: BLE001 - optional extra; core scanner must import without fastapi
    FASTAPI_AVAILABLE = False

DEFAULT_RATE_PER_MIN = 30
_PROFILE_RE = r"^(quick|standard|deep|agentic|hallucination|diff)$"
# Only these SDK knobs are forwarded from a request; nothing else is reachable over HTTP.
_SCAN_FIELDS = ("profile", "categories", "attacks", "exclude", "extended", "check_triggered", "check_obfuscation",
                "check_evolution", "check_minimization", "trials", "max_tokens", "budget_usd", "max_requests")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class ScanRequest(BaseModel):
    """The curated knobs a client may set. Bounded to safe ranges; scope/credentials are server-side only."""
    target: str = Field(..., min_length=1, max_length=2048)
    profile: str | None = Field(None, pattern=_PROFILE_RE)
    categories: list[str] | None = Field(None, max_length=32)
    attacks: list[str] | None = Field(None, max_length=128)
    exclude: list[str] | None = Field(None, max_length=128)
    extended: bool = False
    check_triggered: bool = False
    check_obfuscation: bool = False
    check_evolution: bool = False
    check_minimization: bool = False
    trials: int | None = Field(None, ge=1, le=100)
    max_tokens: int | None = Field(None, ge=1, le=8192)
    budget_usd: float | None = Field(None, ge=0, le=1000)
    max_requests: int | None = Field(None, ge=1, le=100000)

    def scan_kwargs(self) -> dict[str, Any]:
        """The subset forwarded to sdk.scan: optional values only when set; boolean flags only when True (False is the
        SDK default, so there is nothing to forward). `target` is passed separately."""
        bool_flags = {"extended", "check_triggered", "check_obfuscation", "check_evolution", "check_minimization"}
        data = self.model_dump()
        kwargs: dict[str, Any] = {}
        for key in _SCAN_FIELDS:
            value = data.get(key)
            if key in bool_flags:
                if value:
                    kwargs[key] = True
            elif value is not None:
                kwargs[key] = value
        return kwargs


@dataclass
class Job:
    id: str
    status: str                       # queued | running | completed | failed
    created: str
    target: str
    request: dict
    result: dict | None = None
    error: str | None = None
    error_kind: str | None = None  # scope | scan | internal
    finished: str | None = None

    def public(self) -> dict:
        """JSON-safe view. On failure, a redacted reason + kind; never an internal traceback."""
        out: dict[str, Any] = {"job_id": self.id, "status": self.status, "created": self.created,
                               "target": self.target}
        if self.status == "completed":
            out["result"] = self.result
        if self.status == "failed":
            out["error"] = self.error
            out["error_kind"] = self.error_kind
        if self.finished:
            out["finished"] = self.finished
        return out


class JobStore:
    """Thread-safe, in-memory job registry with FIFO eviction (one process; swap for a shared store to scale out)."""
    def __init__(self, max_jobs: int = 1000):
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._max = max_jobs

    def create(self, target: str, request: dict) -> Job:
        job = Job(id=uuid.uuid4().hex, status="queued", created=_now(), target=target, request=request)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self._max:
                self._jobs.pop(self._order.pop(0), None)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, value in fields.items():
                setattr(job, key, value)


class RateLimiter:
    """Per-key sliding-window limiter (requests/minute), in-memory and thread-safe."""
    def __init__(self, per_min: int = DEFAULT_RATE_PER_MIN):
        self.per_min = max(1, per_min)
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            window = [t for t in self._hits.get(key, []) if now - t < 60.0]
            if len(window) >= self.per_min:
                self._hits[key] = window
                return False
            window.append(now)
            self._hits[key] = window
            return True


def load_api_keys(explicit: list[str] | None = None) -> set[str]:
    """Configured API keys: explicit list, else comma-separated ``HFSENTINEL_API_KEYS``. Empty => deny all scan routes."""
    if explicit is not None:
        return {k.strip() for k in explicit if k.strip()}
    raw = os.environ.get("HFSENTINEL_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


def _present_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def create_app(*, api_keys: list[str] | None = None, scope_file: str | None = None,
               signers_file: str | None = None, rate_per_min: int = DEFAULT_RATE_PER_MIN,
               max_concurrent: int = 2, max_jobs: int = 1000):
    """Build the FastAPI app. `scope_file`/`signers_file` set the server-side authorized scope (deny-by-default without
    one); `api_keys` (or ``HFSENTINEL_API_KEYS``) are the accepted keys. Raises RuntimeError if FastAPI is not installed."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI is not installed; install the optional extra: pip install 'hfsentinel[api]'")
    keys = load_api_keys(api_keys)
    store = JobStore(max_jobs=max_jobs)
    limiter = RateLimiter(rate_per_min)
    pool = ThreadPoolExecutor(max_workers=max(1, max_concurrent), thread_name_prefix="hfs-scan")
    app = FastAPI(title="HF-Sentinel API", version="0.1.0",
                  description="Dynamic black-box LLM security scanner — async job API.")

    async def require_key(authorization: str | None = Header(default=None),
                          x_api_key: str | None = Header(default=None)) -> str:
        if not keys:
            raise HTTPException(status_code=503, detail="API keys are not configured on the server")
        presented = _present_key(authorization, x_api_key)
        if not presented or presented not in keys:
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        if not limiter.allow(presented):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return presented

    def _run(job_id: str, target: str, kwargs: dict) -> None:
        store.update(job_id, status="running")
        try:
            result = sdk.scan(target, scope_file=scope_file, signers_file=signers_file, **kwargs)
            store.update(job_id, status="completed", result=result.to_dict(), finished=_now())
        except ScopeError as e:
            store.update(job_id, status="failed", error=str(e), error_kind="scope", finished=_now())
        except sdk.ScanError as e:
            store.update(job_id, status="failed", error=str(e), error_kind="scan", finished=_now())
        except Exception as e:  # noqa: BLE001 - a scan crash must fail the job, never take down the server
            store.update(job_id, status="failed", error=f"{type(e).__name__}", error_kind="internal", finished=_now())

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "keys_configured": bool(keys)}

    @app.post("/scans", status_code=202)
    async def submit_scan(req: ScanRequest, _key: str = Depends(require_key)) -> dict:
        job = store.create(req.target, req.model_dump())
        pool.submit(_run, job.id, req.target, req.scan_kwargs())
        return {"job_id": job.id, "status": job.status, "poll": f"/scans/{job.id}"}

    @app.get("/scans/{job_id}")
    async def get_scan(job_id: str, _key: str = Depends(require_key)) -> dict:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job id")
        return job.public()

    app.state.job_store = store          # exposed for tests / introspection
    app.state.rate_limiter = limiter
    return app
