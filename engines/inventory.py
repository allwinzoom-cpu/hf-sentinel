"""Installed-version feature inventory (plan 16.21, Section 11: verify coverage on installed versions).

Host driver:  python3 engines/inventory.py            → runs itself inside each engine container (--network none)
In container: python /inv/inventory.py --inside <alias> → prints {"alias", "features": {kind: [names]}} as JSON
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _names(module, suffix: str) -> list[str]:
    return sorted(n for n in dir(module) if n.endswith(suffix) and not n.startswith("_"))


def inside(alias: str) -> dict:
    f: dict[str, list[str]] = {}
    if alias == "probe-suite":
        for kind, flag in (("probes", "--list_probes"), ("detectors", "--list_detectors")):
            out = subprocess.run([sys.executable, "-m", "garak", flag], capture_output=True, text=True, check=True).stdout
            f[kind] = sorted({m.group(1) for m in re.finditer(rf"{kind}: (\S+)", ANSI.sub("", out))})
    elif alias == "orchestrator":
        import pyrit.converter as conv
        import pyrit.executor.attack as att
        f["attacks"], f["converters"] = _names(att, "Attack"), _names(conv, "Converter")
    elif alias == "extractor":
        import yaml
        rules = Path("/opt/promptmap/rules")
        f["rule_types"] = sorted(p.name for p in rules.iterdir() if p.is_dir())
        f["rules"] = sorted(f"{p.parent.name}/{yaml.safe_load(p.read_text())['name']}" for p in rules.glob("*/*.yaml"))
    elif alias == "agent-bench":
        from agentdojo.attacks.attack_registry import ATTACKS
        from agentdojo.task_suite.load_suites import get_suites
        suites = get_suites("v1.2.2")
        f["suites"] = sorted(suites)
        f["attacks"] = sorted(ATTACKS)
        f["task_counts"] = sorted(f"{n}:{len(s.user_tasks)}x{len(s.injection_tasks)}" for n, s in suites.items())
    elif alias == "guard-suite":
        import llamafirewall
        f["scanner_types"] = sorted(t.name for t in llamafirewall.ScannerType)
        f["code_scanner"] = ["CodeShield.scan_code"]
    elif alias == "rubric-judge":
        import strong_reject.evaluate as ev
        f["evaluators"] = sorted(ev.registered_evaluators)
    else:
        raise SystemExit(f"no inventory for {alias}")
    return {"alias": alias, "features": f}


def host() -> int:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "engines" / "versions.json").read_text(encoding="utf-8"))
    out_dir = root / "engines" / "inventory"
    out_dir.mkdir(exist_ok=True)
    rc = 0
    for spec in manifest["engines"].values():
        alias = spec["alias"]
        if alias == "crosscheck":
            continue  # deferred to Phase 4 (owner decision)
        res = subprocess.run(["docker", "run", "--rm", "--platform", "linux/amd64", "--cpus", "2", "--memory", "4g",
                              "--read-only", "--tmpfs", "/tmp:exec", "--network", "none", "--cap-drop", "ALL",
                              "-e", "SEMGREP_SEND_METRICS=off", "-e", "LITELLM_LOCAL_MODEL_COST_MAP=True",
                              "-v", f"{Path(__file__).resolve().parent}:/inv:ro", f"hfsentinel-engine-{alias}:amd64",
                              "python", "-W", "ignore", "/inv/inventory.py", "--inside", alias],
                             capture_output=True, text=True, check=False)
        try:
            data = json.loads(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            print(f"[FAIL] {alias}: {(res.stderr.strip().splitlines() or ['no output'])[-1][:200]}")
            rc = 1
            continue
        data["version"] = spec.get("version") or spec["commit"]
        (out_dir / f"{alias}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"[OK ] {alias}: " + ", ".join(f"{k}={len(v)}" for k, v in data["features"].items()))
    return rc


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        print(json.dumps(inside(sys.argv[2])))
        sys.exit(0)
    sys.exit(host())
