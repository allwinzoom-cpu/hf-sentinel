# Engine images — build / smoke / audit evidence (Phase 1 · Pin repos/versions, plan 16.11)

Run 2026-11-02 with `python3 engines/build.py` (host only drives docker; installs, smoke checks and OSV audits run in
Linux containers, D-009/D-010). Inputs: `engines/versions.json`, per-engine `requirements.lock` (uv `--universal
--generate-hashes`, `engines/security-floors.txt`), git tools as sha256-verified commit tarballs, CPU-only torch.

| Image (alias, D-014) | Upstream pin | linux/amd64 build+smoke | linux/arm64 build+smoke | OSV audit | Findings |
|---|---|---|---|---|---|
| `probe-suite` | garak 0.17.1 | ✅ | ✅ | ✅ | clean |
| `orchestrator` | pyrit 1.1.0 | ✅ | skip: base2048==0.1.3 (Rust ext) ships no linux/aarch64 cp312 whee… | ✅ | clean |
| `crosscheck` | deepteam 1.0.10 | ✅ | ✅ | ✅ | clean |
| `extractor` | promptmap 432e072ae654 | ✅ | ✅ | ✅ | clean |
| `rubric-judge` | strong_reject 7a551d5b440e | ✅ | ✅ | ✅ | clean |
| `agent-bench` | agentdojo 0.1.35 | ✅ | ✅ | ✅ | clean |
| `guard-suite` | purplellama 1.0.3 | ✅ | ✅ | ✅ | 5 waived (reasoned) |

**Found and fixed during this task:** filelock 13 CVEs (security floor ≥ 4.2.1, all locks); PyPI name confusion
(`promptmap` ≠ utkusen/promptmap → git pin); strong_reject undeclared package data (import from verified tree);
jailbreakbench pulled CUDA, then failed on a removed litellm module and carried 13 protobuf advisories → package dropped,
dataset pinned in `engines/datasets.json`; deepteam undeclared `sentry_sdk` import (declared + telemetry off);
litellm/semgrep remote calls at import (disabled by env); sdist-only packages limited to a reasoned allow-list;
purplellama: mcp/otel advisories unfixable while codeshield needs semgrep 1.183 (which pins mcp==1.29.0 and
opentelemetry-api<1.38) → 5 waivers with reachability reasons and 90-day expiry (`engines/audit-waivers.json`)
instead of a silent 100-release semgrep downgrade.

Core suite in containers after this task: ruff clean, 110/110 pytest, test_plan 17/17 on linux/amd64 and linux/arm64.
