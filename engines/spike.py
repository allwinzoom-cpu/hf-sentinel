"""Phase 1 integration spike (plan 16.22): every adopted adapter scans the same endpoint; outputs are normalized.

    python engines/spike.py [alias ...]

Runs each engine-side adapter in its sandboxed container, validates the EngineResult contract, converts to catalog-
mapped Findings, and writes docs/spike/<label>.findings.json. Raw adapter output and job files are deleted (D-015).
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sandbox

from hfsentinel.report.normalize import to_findings
from hfsentinel.report.schema import EngineResult

OUT = ROOT / "docs" / "spike"
ROUTER = "https://router.huggingface.co/v1"
COMMON = {"ref": "hf-provider://openai/gpt-oss-120b@deepinfra", "endpoint": ROUTER, "model": "openai/gpt-oss-120b:deepinfra"}
VULN = {"ref": "openai+http://vuln-target:8765/v1#hfsentinel/vuln-target-v0", "endpoint": "http://vuln-target:8765/v1",
        "model": "hfsentinel/vuln-target-v0"}
# alias -> (versions.json key, techniques, trials, runs on vuln target?)
ADAPTERS = {
    "probe-suite": ("garak", ["A1", "B1"], 5, True),
    "orchestrator": ("pyrit", ["A1", "B2"], 2, True),
    "extractor": ("promptmap", ["C1"], 5, True),
    "agent-bench": ("agentdojo", ["D1"], 2, False),  # needs a tool-calling target (Section 4.0 precondition)
    "guard-suite": ("purplellama", ["E2"], 3, True),
}


def run_one(alias: str, target_name: str, target: dict) -> dict:
    engine, techniques, trials, _ = ADAPTERS[alias]
    label = f"{alias}-{target_name}"
    job = {"label": label, "target": target, "techniques": techniques, "trials": trials,
           "canary": "SNTL-" + secrets.token_hex(6).upper()}
    (OUT / f"{label}.job.json").write_text(json.dumps(job), encoding="utf-8")
    ev = sandbox.run(engine, label, ["python", f"/opt/hfsentinel-adapters/{alias}.py", f"/out/{label}.job.json"],
                     1800, sandbox.DEFAULT_ALLOW, OUT.resolve(), None, r"^adapter=")
    raw = OUT / f"{label}.engine.json"
    summary = {"label": label, "exit_code": ev["exit_code"], "egress": ev["egress"], "target_view": ev.get("target_view")}
    if raw.is_file():
        result = EngineResult.model_validate_json(raw.read_text(encoding="utf-8"))
        findings = to_findings(result, "sha256:" + ev["image_id"].split(":")[-1][:12])
        (OUT / f"{label}.findings.json").write_text(
            json.dumps({"engine_result_summary": [{k: r[k] for k in ("catalog_id", "technique", "trials", "successes")}
                                                  for r in result.model_dump()["results"]],
                        "errors": result.errors, "findings": [f.model_dump() for f in findings]}, indent=2) + "\n",
            encoding="utf-8")
        summary["findings"] = len(findings)
        summary["results"] = [(r.catalog_id, r.technique, r.successes, r.trials) for r in result.results]
        raw.unlink()
    (OUT / f"{label}.job.json").unlink(missing_ok=True)
    return summary


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rc = 0
    for alias in argv or list(ADAPTERS):
        targets = [("common", COMMON)] + ([("vuln", VULN)] if ADAPTERS[alias][3] else [])
        for name, target in targets:
            s = run_one(alias, name, target)
            ok = s["exit_code"] == 0 and "results" in s
            rc |= not ok
            print(f"[{'OK ' if ok else 'FAIL'}] {s['label']:<26} results={s.get('results')} egress_denied="
                  f"{s['egress']['denied']} ua={(s.get('target_view') or {}).get('user_agents')}", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
