"""Build, smoke-test and OSV-audit every engine image in Linux containers (plan 16.11, D-009, D-010).

The host only drives `docker`; all installs, smoke checks and audits run inside containers.

    python engines/build.py [--platform linux/amd64,linux/arm64] [--skip-audit] [engine ...]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "engines" / "versions.json").read_text(encoding="utf-8"))
TOOLS_IMAGE = "hfsentinel-tools"
WAIVERS = json.loads((ROOT / "engines" / "audit-waivers.json").read_text(encoding="utf-8"))["waivers"]
LIMITS = ["--cpus", os.environ.get("HFS_DOCKER_CPUS", "2"), "--memory", os.environ.get("HFS_DOCKER_MEMORY", "4g"),
          "--pids-limit", "512"]  # D-013: keep the operator machine light
HARDENED = [*LIMITS, "--read-only", "--tmpfs", "/tmp:exec,size=2g", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges"]


def _arch(platform: str) -> str:
    return platform.split("/")[1]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, **kw)  # callers inspect returncode


def build(name: str, spec: dict, platform: str) -> tuple[bool, str]:
    tag = f"hfsentinel-engine-{spec['alias']}:{_arch(platform)}"
    args = ["docker", "buildx", "build", "--platform", platform, "-f", "engines/Dockerfile", "--load", "-t", tag,
            "--build-arg", f"PY_IMAGE={MANIFEST['python_images'][spec['python']]}",
            "--build-arg", f"ENGINE={name}",
            "--build-arg", f"TORCH_CPU={1 if spec.get('torch') == 'cpu' else 0}",
            "--build-arg", f"SDIST_ALLOW={','.join(sorted(spec.get('sdist_allow', {})))}",
            "--build-arg", f"BUILD_WARMUP={spec.get('build_warmup', '')}"]
    if spec["source"] == "git":
        args += ["--build-arg", f"GIT_REPO={spec['repo']}", "--build-arg", f"GIT_COMMIT={spec['commit']}",
                 "--build-arg", f"GIT_SHA256={spec['sha256']}", "--build-arg", f"GIT_KIND={spec['kind']}"]
    res = run([*args, "."], cwd=ROOT)
    if res.returncode:
        return False, "build failed:\n" + "\n".join(res.stderr.splitlines()[-25:])
    return True, tag


def smoke(tag: str, spec: dict, platform: str) -> tuple[bool, str]:
    res = run(["docker", "run", "--rm", "--platform", platform, *HARDENED, "--network", "none", tag, *spec["smoke"]])
    out = (res.stdout + res.stderr).strip().splitlines()
    return res.returncode == 0, (out[-1] if out else "")[:160]


def audit(name: str) -> tuple[bool, str]:
    lock = f"engines/{name}/requirements.lock"
    res = run(["docker", "run", "--rm", "--platform", "linux/amd64", *HARDENED, "-v", f"{ROOT}/engines:/w/engines:ro",
               f"{TOOLS_IMAGE}:amd64", "pip-audit", "-r", lock, "--require-hashes", "--disable-pip", "--no-deps",
               "-s", "osv", "-f", "json", "--progress-spinner", "off"])
    try:
        data = json.loads(res.stdout)
    except ValueError:
        return False, "audit error: " + (res.stderr.strip().splitlines() or ["no output"])[-1][:200]
    vulns = [(d["name"], d["version"], v["id"]) for d in data.get("dependencies", []) for v in d.get("vulns", [])]
    today = dt.date.today().isoformat()
    waived = WAIVERS.get(name, {})
    live = [x for x in vulns if not (x[2] in waived and waived[x[2]]["package"] == x[0] and waived[x[2]]["expires"] >= today)]
    note = f" ({len(vulns) - len(live)} waived with reason, engines/audit-waivers.json)" if len(live) < len(vulns) else ""
    return not live, (f"{len(live)} unwaived finding(s): {live}" if live else "no unwaived vulns (OSV)" + note)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", default="linux/amd64,linux/arm64")
    ap.add_argument("--skip-audit", action="store_true")
    ap.add_argument("engines", nargs="*")
    a = ap.parse_args()
    names = a.engines or list(MANIFEST["engines"])
    ok_all = True
    for name in names:
        spec = MANIFEST["engines"][name]
        for platform in a.platform.split(","):
            if platform not in spec.get("platforms", [platform]):
                print(f"[SKIP] {name:<15} {platform:<12} {spec.get('platform_note', 'unsupported platform')}", flush=True)
                continue
            ok, tag = build(name, spec, platform)
            if ok:
                ok, detail = smoke(tag, spec, platform)
            else:
                detail = tag
            ok_all &= ok
            print(f"[{'OK ' if ok else 'FAIL'}] {name:<15} {platform:<12} {detail}", flush=True)
        if not a.skip_audit:
            ok, detail = audit(name)
            ok_all &= ok
            print(f"[{'OK ' if ok else 'FAIL'}] {name:<15} {'audit':<12} {detail}", flush=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
