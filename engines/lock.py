"""Compile hash-locked, Linux-universal lockfiles for every engine. Runs INSIDE the tools container (D-009).

    python engines/lock.py [engine ...]      # default: all engines in versions.json
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ENGINES_DIR = Path(__file__).resolve().parent


def lock(name: str, spec: dict) -> None:
    edir = ENGINES_DIR / name
    cmd = ["uv", "pip", "compile", "requirements.in", "--universal", "--python-version", spec["python"],
           "--generate-hashes", "--no-header", "--quiet", "--output-file", "requirements.lock"]
    cmd += ["--constraint", str(ENGINES_DIR / "security-floors.txt")]
    if spec.get("torch") == "cpu":
        cmd += ["--torch-backend", "cpu"]  # CPU-only torch wheels; scanners never need CUDA
    if spec.get("exclude_newer"):
        cmd += ["--exclude-newer", spec["exclude_newer"]]  # supply-chain age floor for every transitive artifact
    print(f"[lock] {name}: {' '.join(cmd[3:])}", flush=True)
    subprocess.run(cmd, cwd=edir, check=True)


def main(argv: list[str]) -> int:
    manifest = json.loads((ENGINES_DIR / "versions.json").read_text(encoding="utf-8"))
    engines = {**manifest["engines"], "tools": {"python": "3.12"},
               "localmodel": {"python": "3.12", "torch": "cpu", "exclude_newer": "2026-10-20"},  # plan 16.14
               "laya": {"python": "3.12", "torch": "cpu", "exclude_newer": "2026-10-20"}}  # plan 16.19
    names = argv or list(engines)
    unknown = [n for n in names if n not in engines]
    if unknown:
        print(f"unknown engines: {unknown}", file=sys.stderr)
        return 2
    failed = []
    for name in names:
        try:
            lock(name, engines[name])
        except subprocess.CalledProcessError:
            failed.append(name)
    if failed:
        print(f"[lock] FAILED: {failed}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
