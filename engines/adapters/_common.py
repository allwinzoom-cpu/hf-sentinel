"""Shared engine-side adapter helpers (baked into every engine image; stdlib only).

Job spec (JSON file, argv[1]):
  {"label": str, "target": {"ref": str, "endpoint": str, "model": str}, "techniques": [str], "trials": int,
   "canary": str | null, "judge": {"endpoint": str, "model": str} | null}
Output: /out/<label>.engine.json — the EngineResult contract (hfsentinel/report/schema.py). Engines are named by alias
only (D-014); only proven cases carry evidence, as sha256 + short excerpt (D-015).
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

SCHEMA_VERSION = "0.1"
USER_AGENT = "hfsentinel/0.0.1"
EXCERPT = 160

# Toolchain non-disclosure (plan 16.16, D-014): adapters scrub upstream names from any free text they emit (error
# tails, display names) at write time. The core re-scrubs with the full term set; this is the image-side first pass.
# Stdlib-only (adapters cannot import the package), so the distinctive tokens are listed inline here.
_UPSTREAM = ("garak", "pyrit", "deepteam", "deepeval", "litellm", "semgrep", "osemgrep", "codeshield",
             "llamafirewall", "agentdojo", "promptmap", "strong_reject", "strongreject", "purplellama",
             "jailbreakbench", "nvidia", "microsoft", "meta-llama", "ethz-spylab", "confident-ai", "utkusen",
             "dsbowen")
_UPSTREAM_RE = re.compile("|".join(sorted((re.escape(t) for t in _UPSTREAM), key=len, reverse=True)), re.IGNORECASE)


def scrub(text: str) -> str:
    """Redact upstream tool names from a string, collapsing owner/name path runs into one placeholder."""
    if not text:
        return text
    return re.sub(r"(?:\[engine\][/\\.]*){2,}", "[engine]", _UPSTREAM_RE.sub("[engine]", text))


def load_job() -> dict:
    with open(sys.argv[1], encoding="utf-8") as fh:
        return json.load(fh)


def proven(blob: object, text: str) -> dict:
    raw = json.dumps(blob, sort_keys=True, default=str).encode()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "excerpt": " ".join(str(text).split())[:EXCERPT]}


def technique(catalog_id: str, name: str, trials: int, proofs: list, oracle_kind: str, oracle_name: str) -> dict:
    return {"catalog_id": catalog_id, "technique": scrub(name), "trials": trials, "successes": len(proofs),
            "oracle": {"kind": oracle_kind, "name": scrub(oracle_name)}, "proven": proofs}


def candidate(job: dict, catalog_id: str, goal: str, response: str) -> None:
    """Append one judge-scored candidate exchange (goal + raw response) to the ephemeral channel the core reads, judges
    through the triage-gated panel, then deletes (engine-service judge path, 16.19; raw text never persists, D-015).
    For techniques whose oracle is the judge panel (harmful-goal jailbreaks), not a deterministic detector."""
    with open(f"/out/{job['label']}.candidates.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"catalog_id": catalog_id, "goal": goal, "response": response}) + "\n")


def emit(job: dict, engine: str, results: list, errors: list | None = None) -> int:
    out = {"schema_version": SCHEMA_VERSION, "engine": engine,
           "target": {"ref": job["target"]["ref"], "model": job["target"]["model"]},
           "results": results, "errors": [scrub(e) for e in (errors or [])]}
    with open(f"/out/{job['label']}.engine.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"adapter={engine} techniques={len(results)} successes={sum(r['successes'] for r in results)} "
          f"errors={len(errors or [])}", flush=True)
    return 0 if not errors else 3


def chat(endpoint: str, model: str, messages: list, max_tokens: int = 400, temperature: float = 0.7) -> str:
    """Minimal OpenAI-compatible call with our neutral User-Agent (D-014); key only sent to HTTPS endpoints."""
    body = json.dumps({"model": model, "messages": messages, "max_tokens": max_tokens,
                       "temperature": temperature}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if endpoint.startswith("https://") and os.environ.get("OPENAI_API_KEY"):
        headers["Authorization"] = f"Bearer {os.environ['OPENAI_API_KEY']}"
    req = urllib.request.Request(f"{endpoint}/chat/completions", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp)["choices"][0]["message"].get("content") or ""
