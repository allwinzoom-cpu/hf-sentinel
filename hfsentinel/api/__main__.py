"""Launch the HF-Sentinel HTTP API: ``python -m hfsentinel.api`` (requires the optional ``api`` extra).

Configuration via environment:
  HFSENTINEL_API_KEYS       comma-separated accepted API keys (required; empty => every scan request is denied)
  HFSENTINEL_API_SCOPE      path to a signed scope file (deny-by-default without one; only built-in safe targets pass)
  HFSENTINEL_API_SIGNERS    path to the allowed-signers file for the scope
  HFSENTINEL_API_HOST       bind host (default 127.0.0.1 — loopback; set 0.0.0.0 only behind an authenticated gateway)
  HFSENTINEL_API_PORT       bind port (default 8000)
  HFSENTINEL_API_RATE       per-key requests/minute (default 30)
  HFSENTINEL_API_CONCURRENCY  max concurrent scans (default 2)
"""
from __future__ import annotations

import os
import sys


def main() -> int:
    try:
        import uvicorn
    except Exception:  # noqa: BLE001 - optional extra
        sys.stderr.write("The API extra is not installed. Run: pip install 'hfsentinel[api]'\n")
        return 1
    from hfsentinel.api.app import create_app

    app = create_app(scope_file=os.environ.get("HFSENTINEL_API_SCOPE") or None,
                     signers_file=os.environ.get("HFSENTINEL_API_SIGNERS") or None,
                     rate_per_min=int(os.environ.get("HFSENTINEL_API_RATE", "30")),
                     max_concurrent=int(os.environ.get("HFSENTINEL_API_CONCURRENCY", "2")))
    host = os.environ.get("HFSENTINEL_API_HOST", "127.0.0.1")   # loopback by default; expose only behind a gateway
    port = int(os.environ.get("HFSENTINEL_API_PORT", "8000"))
    if not app.state.job_store or not os.environ.get("HFSENTINEL_API_KEYS"):
        sys.stderr.write("warning: HFSENTINEL_API_KEYS is not set — all scan requests will be denied (503).\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
