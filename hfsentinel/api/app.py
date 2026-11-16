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

import asyncio
import contextlib
import datetime as dt
import json
import os
import queue
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field  # pydantic is a core dependency

from hfsentinel import sdk
from hfsentinel import store as scanstore
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.controls import PROFILES
from hfsentinel.scope import ScopeError

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query
    from fastapi.responses import HTMLResponse, Response, StreamingResponse
    FASTAPI_AVAILABLE = True
except Exception:                               # noqa: BLE001 - optional extra; core scanner must import without fastapi
    FASTAPI_AVAILABLE = False

# Human-readable category names (A–E in scope; D agentic is out of scope, shown for completeness) and curated rule packs:
# named bundles of categories the UI offers as one click. Kept here so /catalog is the single source the UI renders from.
CATEGORY_NAMES = {"A": "Injection & exfiltration", "B": "Adaptive attacks", "C": "Secret leakage",
                  "D": "Agentic (out of scope)", "E": "Insecure output & code", "H": "Hallucination"}
RULE_PACKS = (
    {"id": "owasp", "name": "OWASP LLM Top-10", "description": "broad baseline sweep", "categories": ["A", "C", "E"]},
    {"id": "inject", "name": "Prompt injection", "description": "A-series injection & overrides", "categories": ["A"]},
    {"id": "exfil", "name": "Data exfiltration", "description": "canary-gated outbound channels",
     "categories": ["A", "C"]},
    {"id": "code", "name": "Insecure code (E2)", "description": "code-sink oracle", "categories": ["E"]},
    {"id": "full", "name": "Full kill-chain", "description": "every category + adaptive engines",
     "categories": ["A", "B", "C", "E"]},
)

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
    status: str                       # queued | running | completed | failed | cancelled
    created: str
    target: str
    request: dict
    result: dict | None = None
    error: str | None = None
    error_kind: str | None = None  # scope | scan | internal
    finished: str | None = None
    stream_token: str = ""                               # capability to read this job's event stream (not the API key)
    events: Any = field(default=None, repr=False)        # queue.Queue of progress events; drained by the SSE endpoint
    cancel_event: Any = field(default=None, repr=False)  # threading.Event; set by DELETE, polled by the campaign

    def public(self) -> dict:
        """JSON-safe view. On failure, a redacted reason + kind; never an internal traceback."""
        out: dict[str, Any] = {"job_id": self.id, "status": self.status, "created": self.created,
                               "target": self.target}
        if self.status in ("completed", "cancelled"):   # a cancelled scan still carries its partial report
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
        self._active = 0   # queued + running jobs (admission control); decremented once, on the terminal transition

    # Terminal states hold a finished report (or a failure reason); a job settles into exactly one of them.
    TERMINAL = ("completed", "failed", "cancelled")

    def create(self, target: str, request: dict) -> Job:
        job = Job(id=uuid.uuid4().hex, status="queued", created=_now(), target=target, request=request,
                  stream_token=secrets.token_urlsafe(24))
        job.events = queue.Queue(maxsize=10000)
        job.cancel_event = threading.Event()
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._active += 1
            # Evicting a record does not stop its thread, so never evict a non-terminal job: drop only the oldest
            # already-finished record. The active counter (not the record count) is what bounds in-flight work.
            while len(self._order) > self._max:
                victim = next((jid for jid in self._order
                               if (j := self._jobs.get(jid)) and j.status in self.TERMINAL), None)
                if victim is None:
                    break   # everything retained is still in flight; keep it rather than orphan a running scan
                self._order.remove(victim)
                self._jobs.pop(victim, None)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def nonterminal(self) -> list[Job]:
        """Snapshot of queued+running jobs (for graceful shutdown: signal each to stop at its next boundary)."""
        with self._lock:
            return [j for j in self._jobs.values() if j.status not in self.TERMINAL]

    def active(self) -> int:
        with self._lock:
            return self._active

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            was_terminal = job.status in self.TERMINAL
            for key, value in fields.items():
                setattr(job, key, value)
            if not was_terminal and job.status in self.TERMINAL:   # count each job down exactly once, on settling
                self._active = max(0, self._active - 1)


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
               max_concurrent: int = 2, max_jobs: int = 1000, max_active_jobs: int | None = None,
               db_path: str | None = None):
    """Build the FastAPI app. `scope_file`/`signers_file` set the server-side authorized scope (deny-by-default without
    one); `api_keys` (or ``HFSENTINEL_API_KEYS``) are the accepted keys. `db_path` (or ``HFSENTINEL_DB``) records every
    scan to a SQLite store, server-side only. `max_active_jobs` bounds queued+running scans (admission control): past it
    the service sheds load with 429 + Retry-After instead of queuing unbounded traffic to targets. Raises RuntimeError
    if FastAPI is not installed."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI is not installed; install the optional extra: pip install 'hfsentinel[api]'")
    keys = load_api_keys(api_keys)
    # Default backlog: a few waves of work over the worker pool, so a burst is absorbed but a client cannot queue
    # thousands of long scans that would all eventually reach out to targets.
    max_active = max_active_jobs if max_active_jobs is not None else max(8, max(1, max_concurrent) * 8)
    db_path = db_path or os.environ.get("HFSENTINEL_DB")  # server-configured; a client can never choose where we persist
    store = JobStore(max_jobs=max_jobs)
    limiter = RateLimiter(rate_per_min)
    pool = ThreadPoolExecutor(max_workers=max(1, max_concurrent), thread_name_prefix="hfs-scan")

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        yield
        # Graceful shutdown (SIGTERM / uvicorn stop): signal every in-flight scan to stop at its next technique/stage
        # boundary — each then finalizes and stores a *partial* report instead of being killed mid-request — drop any
        # queued-but-unstarted scans, and wait for the running ones to drain. Reuses the cooperative-cancel machinery.
        for job in store.nonterminal():
            if job.cancel_event is not None:
                job.cancel_event.set()
        await asyncio.to_thread(pool.shutdown, wait=True, cancel_futures=True)

    app = FastAPI(title="HF-Sentinel API", version="0.1.0", lifespan=_lifespan,
                  description="Dynamic black-box LLM security scanner — async job API.")

    @app.middleware("http")
    async def _security_headers(request, call_next):
        """Harden every response for the browser-facing console: block MIME sniffing, framing (clickjacking) and
        referrer leakage. No CSP beyond frame-ancestors, so the self-contained console's inline assets keep working."""
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        return response

    async def require_key(authorization: str | None = Header(default=None),
                          x_api_key: str | None = Header(default=None)) -> str:
        if not keys:
            raise HTTPException(status_code=503, detail="API keys are not configured on the server")
        presented = _present_key(authorization, x_api_key)
        # Constant-time comparison against every configured key (consistent with the stream-token check), so a response's
        # timing never leaks how much of a guessed key was correct. `any` only short-circuits once a key already matched.
        if not presented or not any(secrets.compare_digest(presented, k) for k in keys):
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        if not limiter.allow(presented):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return presented

    def _run(job_id: str, target: str, kwargs: dict) -> None:
        job = store.get(job_id)
        events = job.events if job else None
        cancel = job.cancel_event.is_set if job and job.cancel_event else None
        store.update(job_id, status="running")
        try:
            result = sdk.scan(target, scope_file=scope_file, signers_file=signers_file, db_path=db_path,
                              progress=(events.put if events else None), cancel=cancel, **kwargs)
            # A cancelled scan returns a partial report; mark it so the operator can tell it from a full run.
            status = "cancelled" if getattr(result, "cancelled", False) else "completed"
            store.update(job_id, status=status, result=result.to_dict(), finished=_now())
        except ScopeError as e:
            store.update(job_id, status="failed", error=str(e), error_kind="scope", finished=_now())
        except sdk.ScanError as e:
            store.update(job_id, status="failed", error=str(e), error_kind="scan", finished=_now())
        except Exception as e:  # noqa: BLE001 - a scan crash must fail the job, never take down the server
            store.update(job_id, status="failed", error=f"{type(e).__name__}", error_kind="internal", finished=_now())
        finally:
            if events is not None:
                try:
                    events.put_nowait({"type": "_end"})           # sentinel: tells the SSE generator the run is over
                except queue.Full:
                    pass

    @app.get("/", response_class=HTMLResponse)
    async def console() -> str:
        """Serve the operator console (static, same-origin). Its own API calls carry the key; serving the page needs none.
        Returns a minimal placeholder if the asset is missing, so the API still runs without the bundled UI."""
        from pathlib import Path
        page = Path(__file__).parent / "static" / "console.html"
        try:
            return page.read_text(encoding="utf-8")
        except OSError:
            return "<!doctype html><title>HF-Sentinel</title><p>Console asset not found. API is running at /healthz."

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "keys_configured": bool(keys)}

    @app.post("/scans", status_code=202)
    async def submit_scan(req: ScanRequest, _key: str = Depends(require_key)) -> dict:
        # Admission control: scans are long and the worker pool is small, so shed load past the backlog bound instead of
        # queuing unbounded work (each queued scan would otherwise eventually send traffic to a target). 429 + Retry-After.
        if store.active() >= max_active:
            raise HTTPException(status_code=429, detail="scan queue is full; retry shortly",
                                headers={"Retry-After": "30"})
        job = store.create(req.target, req.model_dump())
        pool.submit(_run, job.id, req.target, req.scan_kwargs())
        # The events URL carries a per-job stream token, not the API key: EventSource cannot send headers, and this keeps
        # the key out of URLs and access logs. The token is a capability scoped to this one job's stream.
        return {"job_id": job.id, "status": job.status, "poll": f"/scans/{job.id}",
                "stream_token": job.stream_token, "events": f"/scans/{job.id}/events?token={job.stream_token}"}

    @app.get("/scans/{job_id}")
    async def get_scan(job_id: str, _key: str = Depends(require_key)) -> dict:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job id")
        return job.public()

    # Render format → (content type, file extension). SARIF uploads to GitHub code-scanning as a `.sarif` file.
    _REPORT_FORMATS = {"json": ("application/json", "json"),
                       "sarif": ("application/sarif+json", "sarif"),
                       "md": ("text/markdown; charset=utf-8", "md"),
                       "html": ("text/html; charset=utf-8", "html")}

    @app.get("/scans/{job_id}/report")
    async def download_report(job_id: str, format: str = Query(default="json"),
                              _key: str = Depends(require_key)) -> Response:
        """Download a finished scan's report in a chosen format, rendered by the same canonical, output-encoded writers
        the CLI uses (JSON / SARIF 2.1.0 / Markdown / HTML). Available once the job is terminal (a cancelled scan's
        partial report downloads too)."""
        fmt = format.lower()
        if fmt not in _REPORT_FORMATS:
            raise HTTPException(status_code=400, detail=f"unknown format; choose one of {sorted(_REPORT_FORMATS)}")
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job id")
        if job.status not in ("completed", "cancelled") or not job.result:
            raise HTTPException(status_code=409, detail="report not available until the scan finishes")

        from hfsentinel.report import render
        from hfsentinel.report.build import Report
        if fmt == "json":
            body = json.dumps(job.result, indent=2)   # the stored report dict verbatim; no re-render needed
        else:
            try:
                report = Report.model_validate(job.result)
            except Exception as e:
                raise HTTPException(status_code=422, detail="stored report could not be rendered") from e
            body = {"sarif": render.to_sarif, "md": render.to_markdown, "html": render.to_html}[fmt](report)

        media_type, ext = _REPORT_FORMATS[fmt]
        run_id = (job.result.get("run") or {}).get("run_id") or job.id
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(run_id))[:80]   # filename is attacker-influenced; keep it inert
        return Response(content=body, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="hfsentinel-{safe}.{ext}"'})

    @app.delete("/scans/{job_id}")
    async def cancel_scan(job_id: str, _key: str = Depends(require_key)) -> dict:
        """Request cancellation of a queued or running scan. Cooperative: the campaign stops at its next technique/stage
        boundary and finalizes a partial report, so this returns ``cancelling`` and the job settles to ``cancelled``.
        Already-terminal jobs are returned unchanged (idempotent)."""
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job id")
        if job.status in ("completed", "failed", "cancelled"):
            return {"job_id": job.id, "status": job.status}       # terminal already: nothing to cancel
        if job.cancel_event is not None:
            job.cancel_event.set()
        return {"job_id": job.id, "status": "cancelling"}

    @app.get("/scans/{job_id}/events")
    async def scan_events(job_id: str, token: str = Query(default="")):
        """Server-Sent Events for a running scan. Authenticated by the per-job stream token (constant-time compared), so
        the API key never appears in a URL. Streams the SDK's progress events verbatim, then a final ``scan_closed``."""
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job id")
        if not token or not secrets.compare_digest(token, job.stream_token):
            raise HTTPException(status_code=401, detail="invalid or missing stream token")

        def sse(obj: dict) -> str:
            return f"data: {json.dumps(obj)}\n\n"

        async def generate():
            yield sse({"type": "stream_open", "job_id": job.id, "status": job.status})
            while True:
                try:
                    ev = await asyncio.to_thread(job.events.get, True, 15.0)   # block a worker thread up to 15s per wait
                except queue.Empty:
                    yield ": keep-alive\n\n"                                   # comment frame keeps the connection warm
                    if job.status in ("completed", "failed", "cancelled") and job.events.empty():
                        break
                    continue
                if ev.get("type") == "_end":
                    final = store.get(job_id)
                    yield sse({"type": "scan_closed", "status": final.status if final else "unknown"})
                    break
                yield sse(ev)

        return StreamingResponse(generate(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/catalog")
    async def catalog(_key: str = Depends(require_key)) -> dict:
        """What the UI renders selectable options from: profiles, categories (+names), every technique, and rule packs."""
        cat = load_catalog()
        attacks = list(cat.by_id().values())
        cats = sorted({a.category for a in attacks})
        return {"profiles": list(PROFILES),
                "categories": [{"id": c, "name": CATEGORY_NAMES.get(c, c)} for c in cats],
                "techniques": [{"id": a.id, "category": a.category, "name": a.name, "status": a.status}
                               for a in attacks],
                "rule_packs": list(RULE_PACKS)}

    @app.get("/history")
    async def history(limit: int = 20, target: str | None = None, _key: str = Depends(require_key)) -> dict:
        if not db_path:
            raise HTTPException(status_code=503, detail="no scan store configured on the server")
        return {"scans": scanstore.recent_scans(db_path, limit=max(1, min(limit, 200)), target=target)}

    @app.get("/history/{run_id}")
    async def history_detail(run_id: str, _key: str = Depends(require_key)) -> dict:
        if not db_path:
            raise HTTPException(status_code=503, detail="no scan store configured on the server")
        detail = scanstore.scan_detail(db_path, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="unknown run id")
        return detail

    @app.get("/history/{run_id}/compare")
    async def history_compare(run_id: str, _key: str = Depends(require_key)) -> dict:
        """Behavioural attackability delta vs. the most recent earlier scan of the same target (LSCAN-003/009)."""
        if not db_path:
            raise HTTPException(status_code=503, detail="no scan store configured on the server")
        cmp = scanstore.scan_comparison(db_path, run_id)
        if cmp is None:
            raise HTTPException(status_code=404, detail="unknown run id")
        return cmp

    app.state.job_store = store          # exposed for tests / introspection
    app.state.rate_limiter = limiter
    app.state.max_active_jobs = max_active
    return app
