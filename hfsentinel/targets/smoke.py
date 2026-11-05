"""Smoke-test reference targets: each must answer a fixed prompt through the target adapter (Phase 0).

Usage: python -m hfsentinel.targets.smoke [config/reference_targets.yaml]
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import yaml

from hfsentinel.secrets import hf_token, redact
from hfsentinel.targets import resolve
from hfsentinel.targets.openai_compat import OpenAICompatTarget, TargetError
from hfsentinel.testing import vuln_target

SMOKE_PROMPT = [{"role": "user", "content": "Reply with exactly one word: pong"}]
# Reasoning models (Qwen3, gpt-oss) spend tokens on a hidden trace before answering; 16 tokens left content empty.
SMOKE_MAX_TOKENS = 512
SMOKE_MAX_REQUESTS = 3  # one call + up to 2 retries on 429/5xx


def build(uri: str, token: str | None) -> OpenAICompatTarget:
    return resolve.client(resolve.parse(uri), token, max_requests=SMOKE_MAX_REQUESTS)


def main(cfg_path: str = "config/reference_targets.yaml") -> int:
    cfg = yaml.safe_load(Path(cfg_path).read_text(encoding="utf-8"))
    entries = list(cfg.get("targets", []))
    server = None
    if cfg.get("positive_control"):
        # Host the deliberately vulnerable target in-process on an ephemeral loopback port (hermetic in containers).
        server, url = vuln_target.serve()
        entries.append({**cfg["positive_control"], "uri": f"openai+{url}#{vuln_target.MODEL_ID}"})
    token = None
    if any(e["uri"].startswith("hf-provider://") for e in entries):
        token = hf_token()
    failures = 0
    for e in entries:
        t0 = time.monotonic()
        try:
            res = build(e["uri"], token).chat(SMOKE_PROMPT, max_tokens=SMOKE_MAX_TOKENS, temperature=0.0)
            ok = bool(res.text.strip())
            detail = (f"{res.text.strip()[:40]!r} finish={res.finish_reason} reasoning={len(res.reasoning)}ch "
                      f"tokens={res.usage.get('total_tokens', '?')}")
        except (TargetError, ValueError) as exc:
            ok, detail = False, redact(str(exc), token or "")
        failures += not ok
        print(f"[{'OK ' if ok else 'FAIL'}] {e['name']:<12} {time.monotonic() - t0:5.1f}s  {detail}")
    if server:
        server.shutdown()
    print(f"\n{len(entries) - failures}/{len(entries)} targets answered")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
