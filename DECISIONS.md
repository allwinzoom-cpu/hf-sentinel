# HF-Sentinel — Decisions Log

Source of truth for scope: `hf-llm-security-scanner-project-plan.md` (v0.11). Each entry records a decision,
its status, and who signed off. Status values: **Proposed** (awaiting owner sign-off), **Accepted**, **Superseded**.

## D-001 — Llama components (plan header assumption 1)

**Status:** Superseded in part by D-016 (2026-11-02): "Laya" is `convaiinnovations/laya`, not Llama. The Llama
components below remain in use, HF-hosted only (D-011).

"Laya model" is read as Meta **Llama** protections plus a Llama instruct model. Components and their roles (plan §7):

| Component | Role | Not used for |
|---|---|---|
| Llama Guard 4 (`meta-llama` org; exact repo/size confirmed at build time) | Harm judge on outputs (B, A4) | Sole judge of injection success |
| Llama Prompt Guard 2 (86M / 22M) | Attack-prompt labelling, detectability metric, cheap pre-filter | Judging outputs |
| LlamaFirewall | Guardrail differential (S7, `--with-firewall`) | Being scored as the target |
| CyberSecEval / CodeShield | Category E2 | General jailbreak judging |
| Llama instruct (Llama 4 or 3.x) | Adaptive Attacker Agent + secondary rubric judge | Judging its own attacks without an independent second judge |

## D-002 — Interface: CLI-first (plan header assumption 2)

**Status:** Accepted (2026-11-02)

Primary interface is the Python CLI `hfsentinel` (Typer). The HF Space is a thin Gradio UI over the same engine and
adds no attack logic of its own. Python ≥ 3.10; all dependencies pinned.

## D-003 — Authorization policy (plan header assumption 3, §12)

**Status:** Accepted (2026-11-02)

- Only targets the operator owns, or has **written** permission to test, may be scanned.
- `hfsentinel scan` records the operator's authorization attestation in every report; scans of third-party
  endpoints require a scope reference.
- H1: hallucinated package names are reported to the deployer (and registry where appropriate), **never registered**,
  and never published as a usable list.
- Evidence is stored as hashes + redacted excerpts by default; full transcripts are opt-in and access-controlled.
- High-severity attack modules are not exposed in the public Space.
- Responsible disclosure: 90-day default for Critical/High.

## D-004 — HF compute plan (Phase 0)

**Status:** Accepted (2026-11-02) — HF Jobs path **deferred**. Use Inference Providers + Spaces (P1/P3/P0); `hf-job://` and P2 stay unimplemented until a payment method is approved.

## D-005 — Live-call budget

**Status:** Accepted (2026-11-02) — **$20 hard cap** on HF Inference Provider spend through Phase 2. Scanner aborts
cleanly at the cap; raising it requires owner approval.

## D-006 — HF uploads

**Status:** Accepted (2026-11-02) — agent may create **private** HF repos/Spaces under the owner's account (via
`hf_tok` in `.env`) for test targets such as the deliberately vulnerable reference target. Nothing public without
explicit approval.

## D-007 — Reference endpoints

**Status:** Accepted (2026-11-02) — agent selects and verifies 5 provider-served targets (varied size, one weak small
instruct, one guardrailed path) plus the deliberately vulnerable target as a positive control; recorded in
`config/reference_targets.yaml`.

## D-008 — GitHub remote

**Status:** Accepted (2026-11-02) — no remote for now; CI is simulated locally (clean venv + pre-commit). "CI green"
task stays open until a remote exists.

## D-009 — Linux containers only

**Status:** Accepted (2026-11-02) — every build, test, scan and prod deployment runs in **Linux containers** (OCI
images, `linux/amd64` primary + `linux/arm64`). Host (macOS/Windows) runs are never evidence: a task's *Done when* is met
only when demonstrated inside the container. Images: digest-pinned base, hash-locked dependencies (`uv pip compile
--universal --generate-hashes`), non-root user, read-only root filesystem where possible, no secrets in image layers
(tokens mounted at runtime as files). Heavy engines (garak, PyRIT, …) get their own images to isolate conflicting
dependency trees.

## D-010 — No GPUs for the local dynamic scanner

**Status:** Accepted (2026-11-02) — scanner, engine and judge containers run CPU-only. Torch is locked to CPU wheels
(`uv --torch-backend cpu`); no CUDA/cuDNN/NCCL/triton packages may appear in any lock (enforced by
`tests/test_engines.py`). Large models (Llama Guard 4, attacker/rubric LLMs, targets) are consumed through
inference APIs (HF Inference Providers / OpenAI-compatible endpoints); only small CPU-friendly classifiers (e.g.
Prompt Guard 2 86M/22M, an NLI model) may run in-container. GPU work, if ever needed, happens behind a remote endpoint.

## D-011 — Llama components consumed via APIs

**Status:** Accepted (2026-11-02, under D-001/D-010) — Llama Guard 4 (`:deepinfra`), Prompt Guard 2 86M
(`hf-inference`) and Llama attacker/rubric models are called through HF Inference Providers; verified live. The
owner's HF account has **no access to gated `meta-llama/*` weights** (HTTP 403), so no local Llama weights are used.
Update 2026-11-02 (owner): no local Llama weights — all Llama components stay HF-hosted; the earlier gated-access
request is withdrawn.

## D-012 — Model placement and own test models

**Status:** Accepted (2026-11-02) — large models (≳ 8B) are used via HF-hosted APIs; light models (≲ 1.5B, classifiers)
may be downloaded at a pinned revision (file sha256 recorded) and run CPU-only in containers (D-010, limits in D-013). We build our own
small deliberately vulnerable models (plan 16.15) with planted, rate-calibrated behaviours, published as **private**
HF repos (D-006). They emit benign markers only; H1-style behaviour uses a reserved `hfsentinel-canary-*` namespace.

## D-013 — Keep the operator's machine light; heavy compute on HF (PRO)

**Status:** Accepted (2026-11-02) — the owner pays for HF PRO so heavy work runs on HF, not the laptop. Locally:
only classifiers and instruct models ≤ 0.5B, CPU-only; every container started by our tooling is capped
(`--cpus 2 --memory 4g` by default, `HFS_DOCKER_CPUS` / `HFS_DOCKER_MEMORY` to change); builds run sequentially; no
local training. Training/serving of our own models (16.15) uses a private ZeroGPU Space under PRO (HF Jobs only if
billing is approved, D-004). All large targets/judges/attackers stay on Inference Providers.

## D-014 — Upstream tool names never leave the CLI

**Status:** Accepted (2026-11-02; confirmed by owner: "for end users it is HF Sentinel") — one unified product
experience. Upstream engine/tool names
(e.g. the probe, orchestration, extraction and judge libraries we wrap) must not appear in traffic to targets
(User-Agent, headers, payload markers), in user-facing CLI output, reports, SARIF, model-card snippets or the Space UI,
or in published HF artifacts. Engines are referred to by neutral aliases with an opaque build hash; the alias→upstream
mapping stays internal (`engines/versions.json`). Engine stdout/stderr, banners and tracebacks are captured and never
shown raw — users see HF-Sentinel progress/errors only; raw engine logs go to an internal 0600 debug file. Container
images are named by alias (`hfsentinel-engine-<alias>`). Plan 16.16.

## D-015 — Persist only proven findings

**Status:** Accepted (2026-11-02; owner instruction) — fuzzed requests/responses are not stored unless they belong to a
confirmed finding. Confirmed findings keep a minimal repro recipe + sha256 + short redacted excerpt; everything else is
aggregate statistics. The same holds for tool calls (mock-tool call logs, engine invocations, egress logs): persisted
only when part of a confirmed finding or a security signal (e.g. denied egress), otherwise counts. Raw engine result
dumps are summarized, then deleted. Plan 16.17.

## D-016 — Laya is the local System-1 decision model

**Status:** Accepted (2026-11-02; owner: "Laya is System One and can be used to take some decisions… a good model
locally") — `convaiinnovations/laya` (Apache-2.0, ungated, 421M English `typed-decisions` / 322M `multilingual`) runs
locally CPU-only in a Linux container at revision `7b928d828b7b0e022f929d9bd2e44165aa270148`, offline, using its
reviewed `rl_agent_api.py` (code reviewed 2026-11-02: no network/subprocess/pickle; weights loaded strictly from the
pinned files). It makes fast advisory decisions (triage, defence style, next technique, act-vs-escalate); it never
confirms a finding — System-2 (deterministic oracles + HF judges) does. Plan 16.19.

## D-017 — Frontier models as judges

**Status:** Accepted (2026-11-02; owner direction "use Codex or Claude Code to be the judge") — Claude via the Anthropic
Messages API as primary rubric judge (tool-less, structured output, refusal = escalate) **and** an OpenAI model as an
independent second frontier judge; agent CLIs only as offline System-3 adjudicators with tools disabled. Judge spend
cap **$25** (separate from the $20 HF cap, D-005), hard-stopped by the budget ledger; plan includes comparing Claude
Opus 5.5 vs Sonnet 5.5 as judge on the 300 pinned human-labelled items. **Owner action:** add `ANTHROPIC_API_KEY=` and
`OPENAI_API_KEY=` to `.env` (mounted read-only into judge containers only, never logged). Plan 16.20.

**Amendment (2026-11-02, owner):** default judge path is **Claude Code (`claude -p`) and Codex (`codex exec`) as
subprocesses** using the owner's existing logins instead of API keys: run inside a Linux judge container with no tools
(empty tool list, no MCP; Codex in its most restricted sandbox, empty working dir), structured output
(`--json-schema` / `--output-schema`), no project files mounted, egress limited to the vendor endpoints, auth via mounted
`claude setup-token` token and Codex `auth.json`. Used only for System-2 confirmation and calibration. A planted
tool-injection test must prove the lockout before any verdict counts. API keys remain an optional fallback. Owner to
confirm their plan terms allow automated use.

## D-018 — Engines as internal services; no Docker socket in the CLI

**Status:** Accepted (2026-11-02, builder decision under D-009) — in production each engine runs as a long-lived
container exposing a small job API on an internal network (with the egress proxy as the only way out); the CLI/Space
container submits jobs over HTTP and never mounts the Docker socket (that would grant host-root). Locally, the one-shot
sandbox (`engines/sandbox.py`) is used for development and evaluation. Plan 16.22.

## D-019 — Target adapters are stdlib clients, not vendor SDKs

**Status:** Accepted (2026-11-03, builder decision under D-014/16.16) — the plan named the `openai` SDK and
`gradio_client` for target adapters. Header capture against a loopback server (openai 3.35.1, gradio_client 2.7.2)
showed both fingerprint the client to the target: `User-Agent: OpenAI/Python 3.35.1` plus nine `x-stainless-*`
headers (package version, OS, arch, runtime) that remain even when the User-Agent is overridden, and
`User-Agent: gradio_client/2.7.2; hf_hub/…; python/…`; together they add ~72 MB / 25 packages. HF-Sentinel keeps its
stdlib OpenAI-compatible adapter (Providers, Endpoints, OpenAI-compatible URLs and Spaces) and adds a stdlib client for
Gradio's documented REST API (`/config` → `{api_prefix}/info` → `/call/{api}` → SSE), verified live on Gradio 6.30/6.31.
Both send no tool-identifying headers, refuse redirects, cap sizes and never download Space file outputs. Revisit if a
needed capability exists only in an SDK.

## D-020 — Zoo sequencing and ZeroGPU spend cap

**Status:** Accepted (2026-11-03, owner) — the vulnerable model zoo (16.15) is built **after** the scanner pieces its
done-when is verified with (rate governor, recon/planner, scope enforcement, canary harness, per-trial canaries,
judges, scoring) and before the campaign/Laya tasks that use it; GPU quota is spent once, on recipes the real oracles can
check. ZeroGPU use by our tooling is capped at **30 GPU-min/day**, metered from each call's requested duration, and
never spills into pre-paid credits (PRO includes 40 min/day; overage auto-bills credits at $1 per 10 min and the
account can pay). The HF token (fine-grained, incl. `job.write` and `inference.endpoints.write`) is never stored as a
Space secret; Hub operations run from local containers.

## D-021 — Judge-injection target is decision-level; no spotlighting

**Status:** Accepted (2026-11-03, owner) — live evidence (10 unanimous-unsafe items × 4 injection fixtures): individual
rubric judges were flipped to "safe" 19 times unhardened and 21 times with random-boundary spotlighting (no gain);
Llama Guard 4 never flipped; and at the ensemble decision level no injected response ever became "no-finding" — every
flip landed in "review". Spotlighting also coincided with a calibration miss (held-out 0.83 vs 0.889). Therefore: 16.3's
done-when is judged at the decision level (injected text can never turn a finding into "no-finding"), a deterministic
grader-injection detector forces "review" and records the attempt, judges use the unhardened prompts with the
final-`#scores` parser, and judge precision is re-verified with a 2-fold check (select on each half, test on the
other, pooled). Individual rubric judges remain injectable; that is stated, not hidden.

## D-022 — Pooled transport for target adapters: urllib3

**Status:** Accepted (2026-11-03, builder decision; evaluation requested by the owner) — measured in a throwaway
container: 30 sequential HTTPS requests to a Hub endpoint took 5.0 s with the stdlib client (median 164 ms; a new TLS
connection per request), 3.1 s with urllib3 2.8.0 (median 99 ms) and 3.0 s with httpx2 2.15.1 (median 98 ms). urllib3
sends exactly the headers we set (plus `Accept-Encoding: identity`); httpx2 adds `Accept: */*` and asks for gzip by
default (a decompression-bomb surface); both return redirects unfollowed when told to. `httpx` itself has not released
since 2024-12. urllib3 has no required dependencies and fits the synchronous, thread-pooled adapters, so the two target
adapters use a urllib3 pool (redirects and retries off, connect/read timeouts, bounded reads, identity encoding); Hub
metadata and model downloads stay on the stdlib. httpx2 is the path if the adapters ever go async.

## D-023 — Zoo = rate-profiled test target (owner)

**Status:** Accepted (2026-11-04, owner: "build something simple and effective … it's for testing only") — the model
zoo (16.15) is a test fixture, not product: instead of LoRA models trained and served on ZeroGPU, the loopback vuln
target gains seeded rate profiles (`low`, `high`, `control`) that plant each weakness at a designed probability. This
supersedes D-020's ZeroGPU use for the zoo (no Space, no GPU quota, no Hub writes). Kept from the dropped design: the
Gradio adapter passes a system message and sampling settings to chatbot-template Spaces.

## D-024 — Laya variant, offline load, and triage-until-calibrated (builder, within D-013)

**Status:** Proposed (2026-11-04, builder; owner review) — Laya (`convaiinnovations/laya`, Apache-2.0, 421M) is the
`typed-decisions` variant: a ModernBERT-large encoder + a from-scratch RL decision head that answers typed questions
(choice / score / noul) with calibrated probabilities and an act-vs-escalate head. Reviewed its inference code
(`rl_agent_api.py`, `rl_common.py`): no remote code, no exec/network/pickle; vendored + sha256-pinned, encoder built
from the local config (`AutoModel.from_config`, strict weight load), run offline on CPU (D-013). **Measured:** it loads
under `--network none` and ranks response triage correctly in direction (refusal -> "refused", compliance -> "complied")
and reproduces the model card's billing example, but its calibrated confidence on our triage question is modest
(top ~0.5 over four options). Therefore triage runs **advisory and safe-bypass**: SystemOne escalates every response to
System-2 until a triage threshold is calibrated on a labelled set (recall >= 0.95, plan done-when) — no judge-call
savings are claimed yet. Laya never confirms a finding or sets severity.

## Sign-off

| Decision | Owner | Date |
|---|---|---|
| D-001 | afernandez@cricut.com | 2026-11-02 |
| D-002 | afernandez@cricut.com | 2026-11-02 |
| D-003 | afernandez@cricut.com | 2026-11-02 |
| D-004 | afernandez@cricut.com | 2026-11-02 |
| D-005 | afernandez@cricut.com | 2026-11-02 |
| D-006 | afernandez@cricut.com | 2026-11-02 |
| D-007 | afernandez@cricut.com | 2026-11-02 |
| D-008 | afernandez@cricut.com | 2026-11-02 |
| D-009 | afernandez@cricut.com | 2026-11-02 |
| D-010 | afernandez@cricut.com | 2026-11-02 |
| D-011 | afernandez@cricut.com | 2026-11-02 |
| D-012 | afernandez@cricut.com | 2026-11-02 |
| D-013 | afernandez@cricut.com | 2026-11-02 |
| D-014 | afernandez@cricut.com | 2026-11-02 |
| D-015 | afernandez@cricut.com | 2026-11-02 |
| D-016 | afernandez@cricut.com | 2026-11-02 |
| D-017 | afernandez@cricut.com | 2026-11-02 |
| D-018 | builder (pending owner review) | 2026-11-02 |
| D-019 | builder (pending owner review) | 2026-11-03 |
| D-020 | afernandez@cricut.com | 2026-11-03 |
| D-021 | afernandez@cricut.com | 2026-11-03 |
| D-022 | builder (owner-requested evaluation) | 2026-11-03 |
| D-023 | afernandez@cricut.com | 2026-11-04 |
| D-024 | builder (proposed; owner review) | 2026-11-04 |
