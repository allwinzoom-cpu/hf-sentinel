"""Scan progress events — the normalized, JSON-safe stream the SDK emits during a run.

A caller passes ``progress=`` to :func:`hfsentinel.sdk.scan`; the SDK calls it with one dict per event. The FastAPI
service bridges that callback to a Server-Sent-Events stream, and the CLI can print it, so CLI, SDK, API and UI all read
the same event shape. Events are advisory: an emit must never change or fail a scan, so the SDK swallows callback errors.

Event types:
  * ``scan_started``    — ``run_id``, ``target``, ``profile``, ``total`` (techniques that will run);
  * ``technique_done``  — one native technique finished: ``catalog_id``, ``category``, ``outcome``
                          (confirmed|hit|no-hit), ``hits``, ``trials``, ``asr``, ``errors``, cumulative ``requests``
                          and ``cost_usd`` from the ledger;
  * ``scan_completed``  — ``run_id``, ``grade``, ``confirmed`` count, final ``requests`` and ``cost_usd``.
"""
from __future__ import annotations

import contextlib
import datetime as dt
from collections.abc import Callable
from typing import Any

ProgressCallback = Callable[[dict], None]


def scan_event(type: str, **fields: Any) -> dict:
    """Build one JSON-safe event dict with a UTC timestamp. ``None`` fields are dropped so the payload stays compact."""
    event = {"type": type, "ts": dt.datetime.now(dt.timezone.utc).isoformat()}
    event.update({k: v for k, v in fields.items() if v is not None})
    return event


def emit(progress: ProgressCallback | None, type: str, **fields: Any) -> None:
    """Call ``progress`` with one event, swallowing any error — progress reporting must never disturb a running scan."""
    if progress is None:
        return
    with contextlib.suppress(Exception):  # a bad subscriber must not fail the scan
        progress(scan_event(type, **fields))
