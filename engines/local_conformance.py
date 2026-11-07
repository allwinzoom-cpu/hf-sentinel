"""LSCAN-007 local-runtime conformance recipes. Validates `engines/local_runtimes.json`: every supported local
OpenAI-compatible server has a connect recipe (base path, auth mode, model handling, loopback), and the scanner never
loads weights — it connects to an already-running server. Pure + offline."""
from __future__ import annotations

import json
from pathlib import Path

FILE = Path(__file__).resolve().parent / "local_runtimes.json"
REQUIRED = ("openai_base", "auth", "model", "loopback", "loads_weights_in_scanner", "source")
AUTH_MODES = ("none", "optional-bearer", "bearer")


def load() -> dict:
    return json.loads(FILE.read_text(encoding="utf-8"))


def check(data: dict | None = None) -> list[str]:
    d = data or load()
    bad: list[str] = []
    for name, r in d["runtimes"].items():
        for f in REQUIRED:
            if f not in r:
                bad.append(f"{name}: missing '{f}'")
        if r.get("loads_weights_in_scanner") is not False:
            bad.append(f"{name}: scanner must not load weights (connects to a running server)")
        if not str(r.get("openai_base", "")).endswith("/v1"):
            bad.append(f"{name}: openai_base must be an OpenAI-compatible /v1 endpoint")
        if r.get("auth") not in AUTH_MODES:
            bad.append(f"{name}: invalid auth mode {r.get('auth')!r}")
        if not r.get("loopback"):
            bad.append(f"{name}: missing loopback support list")
    return bad
