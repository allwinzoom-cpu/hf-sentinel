"""Run one engine command in an egress-controlled sandbox and write machine evidence (plan 16.12; D-009/D-010).

Topology (per run, torn down afterwards):
    internal network (no route out) ── engine container ──► vuln-target (ground-truth positive control)
                                    └─► egress proxy (allow-list, JSON log) ──► internet (only allowed hosts)

    python engines/sandbox.py --engine garak --label garak-weak-small --max-seconds 900 -- <command ...>

The HF token is never placed on a command line, in an image, or in `docker inspect`: the .env file is mounted read-only
and read into the tool process environment (OPENAI_API_KEY / HF_TOKEN) by a tiny shell prologue.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hfsentinel.engines.nondisclosure import terms as _upstream_terms
from hfsentinel.secrets import hf_token, redact

MANIFEST = json.loads((ROOT / "engines" / "versions.json").read_text(encoding="utf-8"))
RUNTIME_IMAGE = "hfsentinel:runtime-amd64"
DEFAULT_ALLOW = "router.huggingface.co,huggingface.co"
LIMITS = ["--cpus", os.environ.get("HFS_DOCKER_CPUS", "2"), "--memory", os.environ.get("HFS_DOCKER_MEMORY", "4g"),
          "--pids-limit", "512"]  # D-013: keep the operator machine light
HARDENED = [*LIMITS, "--read-only", "--tmpfs", "/tmp:exec,size=2g", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
TELEMETRY_OFF = {"DEEPEVAL_TELEMETRY_OPT_OUT": "YES", "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
                 "ANONYMIZED_TELEMETRY": "False", "LITELLM_LOCAL_MODEL_COST_MAP": "True",
                 "SEMGREP_SEND_METRICS": "off"}
# Reads hf_tok / HF_TOKEN from the mounted dotenv into the tool's environment only.
PROLOGUE = ('t=$(sed -n -e "s/^HF_TOKEN=//p" -e "s/^hf_tok=//p" /run/secrets/hfsentinel.env | head -n1 | tr -d "\\"\'"); '
            '[ -n "$t" ] || { echo "sandbox: token missing" >&2; exit 97; }; '
            'export OPENAI_API_KEY="$t" HF_TOKEN="$t" OPENAICOMPATIBLE_API_KEY="$t"; unset t; exec "$@"')
ANSI = re.compile(r"\x1b\[[0-9;]*m")
EXCERPT_LINES = 12  # D-015: a short tail for evidence, not a transcript
# D-014/16.16: upstream names that must never be visible to a target. One source of truth with the report-side scrub.
FINGERPRINT_TERMS = sorted(_upstream_terms())


def fingerprint_leaks(user_agents: list[str], header_names: list[str]) -> list[str]:
    """Upstream tool tokens visible to the target owner in the captured User-Agents / header names (empty = clean)."""
    haystack = [v.lower() for v in (*user_agents, *header_names)]
    return sorted({n for n in FINGERPRINT_TERMS for v in haystack if n in v})


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, **kw)


def must(cmd: list[str]) -> str:
    res = sh(cmd)
    if res.returncode:
        raise RuntimeError(f"{cmd[:3]} failed: {res.stderr.strip()[-300:]}")
    return res.stdout.strip()


def excerpt(output: str, exit_code: int, keep: str | None) -> str:
    """D-015: on success keep only tool status lines (per-tool `keep` regex), never model responses; on failure add the error tail."""
    lines = [ANSI.sub("", ln) for ln in output.strip().splitlines()]
    status = [ln for ln in lines if re.search(keep, ln)] if keep else []
    if exit_code == 0:
        return "\n".join(status[-EXCERPT_LINES:])
    return "\n".join(status[-4:] + ["--- error tail ---"] + lines[-EXCERPT_LINES:])


def run(engine: str, label: str, command: list[str], max_seconds: int, allow: str, out_dir: Path,
        extra_env: dict[str, str] | None = None, excerpt_keep: str | None = None) -> dict:
    spec = MANIFEST["engines"][engine]
    image = f"hfsentinel-engine-{spec['alias']}:amd64"
    sid = pysecrets.token_hex(4)
    net, proxy, vt = f"hfs-sbx-{sid}", f"hfs-egress-{sid}", f"hfs-vt-{sid}"
    log_dir = out_dir / f"{label}.egress"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "egress.jsonl").write_text("")
    token = hf_token()
    started = dt.datetime.now(dt.timezone.utc)
    t0 = time.monotonic()
    try:
        must(["docker", "network", "create", "--internal", net])
        must(["docker", "run", "-d", "--platform", "linux/amd64", "--name", proxy, "--network", net, "--network-alias", "egress", *HARDENED,
              "-v", f"{log_dir}:/logs", "--user", f"{os.getuid()}:{os.getgid()}", RUNTIME_IMAGE,
              "hfsentinel.sandbox.egress_proxy", "--listen", "0.0.0.0:3128", "--allow", allow,
              "--log", "/logs/egress.jsonl"])
        must(["docker", "network", "connect", "bridge", proxy])
        must(["docker", "run", "-d", "--platform", "linux/amd64", "--name", vt, "--network", net, "--network-alias", "vuln-target", *HARDENED,
              RUNTIME_IMAGE, "hfsentinel.testing.vuln_target", "--host", "0.0.0.0", "--port", "8765"])
        envs = []
        for k, v in {**TELEMETRY_OFF, "HTTPS_PROXY": "http://egress:3128", "HTTP_PROXY": "http://egress:3128",
                     "https_proxy": "http://egress:3128", "http_proxy": "http://egress:3128",
                     "NO_PROXY": "vuln-target,localhost,127.0.0.1", "no_proxy": "vuln-target,localhost,127.0.0.1",
                     **(extra_env or {})}.items():
            envs += ["-e", f"{k}={v}"]
        time.sleep(1.0)  # let proxy + vuln target bind
        tool = sh(["docker", "run", "--rm", "--platform", "linux/amd64", "--name", f"hfs-tool-{sid}", "--network", net, *HARDENED, *envs,
                   "-v", f"{ROOT / '.env'}:/run/secrets/hfsentinel.env:ro", "-v", f"{out_dir}:/out",
                   "--user", f"{os.getuid()}:{os.getgid()}", "--entrypoint", "/bin/sh", image, "-c", PROLOGUE, "sandbox",
                   *command], timeout=max_seconds)
        exit_code, output = tool.returncode, tool.stdout + tool.stderr
    except subprocess.TimeoutExpired as e:
        sh(["docker", "rm", "-f", f"hfs-tool-{sid}"])
        exit_code, output = 124, f"{e.stdout or ''}{e.stderr or ''}\n[sandbox] killed after {max_seconds}s"
    finally:
        target_log = sh(["docker", "logs", vt]).stdout
        sh(["docker", "rm", "-f", proxy, vt])
        sh(["docker", "network", "rm", net])
    output = redact(output if isinstance(output, str) else output.decode(errors="replace"), token)
    egress = [json.loads(x) for x in (log_dir / "egress.jsonl").read_text().splitlines() if x.strip()]
    denied = sorted({f"{r.get('host', r.get('target', '?'))}:{r.get('reason')}" for r in egress if r["decision"] == "deny"})
    shutil.rmtree(log_dir, ignore_errors=True)  # D-015: keep the summary (denials are the signal), drop the raw log
    seen = [json.loads(x) for x in target_log.splitlines() if x.startswith('{"event": "request"')]
    user_agents = sorted({r["user_agent"] for r in seen})
    header_names = sorted({h for r in seen for h in r["header_names"]})
    leaks = fingerprint_leaks(user_agents, header_names)
    result = {
        "label": label, "engine": engine, "tool_version": spec.get("version") or spec.get("commit"),
        "repo": spec["repo"], "image": image, "image_id": must(["docker", "image", "inspect", "-f", "{{.Id}}", image]),
        "command": command, "env": extra_env or {}, "started_utc": started.isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - t0, 1), "exit_code": exit_code,
        "egress": {"allowed_connections": sum(r["decision"] == "allow" for r in egress), "denied": denied,
                   "allowlist": allow.split(",")},
        "target_view": {"requests": len(seen), "user_agents": user_agents, "header_names": header_names,
                        "tool_fingerprint_leaks": leaks},  # D-014: what the target owner can see
        "output_excerpt": excerpt(output, exit_code, excerpt_keep),
    }
    (out_dir / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True, choices=sorted(MANIFEST["engines"]))
    ap.add_argument("--label", required=True)
    ap.add_argument("--max-seconds", type=int, default=900)
    ap.add_argument("--allow", default=DEFAULT_ALLOW)
    ap.add_argument("--keep", metavar="REGEX", help="status-line pattern to keep in the evidence excerpt (D-015)")
    ap.add_argument("--env", action="append", default=[], metavar="K=V", help="non-secret env for the tool")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "scorecards" / "evidence")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        ap.error("missing command after --")
    a.out.mkdir(parents=True, exist_ok=True)
    extra = dict(kv.split("=", 1) for kv in a.env)
    if any(k.upper() in ("OPENAI_API_KEY", "HF_TOKEN") for k in extra):
        ap.error("secrets are injected by the sandbox; never pass them via --env")
    r = run(a.engine, a.label, cmd, a.max_seconds, a.allow, a.out.resolve(), extra, a.keep)
    print(json.dumps({k: r[k] for k in ("label", "exit_code", "duration_s", "egress")}, indent=2))
    print("--- output (tail) ---\n" + "\n".join(r["output_excerpt"].splitlines()[-15:]))
    return 0 if r["exit_code"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
