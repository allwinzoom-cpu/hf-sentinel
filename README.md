# HF-Sentinel

Dynamic, black-box LLM attack & scoring tool (`hfsentinel` CLI). **Authorized testing only** — see `SECURITY.md`.

Plan: `hf-llm-security-scanner-project-plan.md` · Status: `STATUS.md` · Decisions: `DECISIONS.md`

Everything builds, tests and runs in **Linux containers only** (DECISIONS D-009) and needs **no GPU** (D-010).

## Running in containers

```bash
# Core: lint + unit tests + plan harness (hardened, no network), per architecture
docker buildx build --platform linux/amd64 --target test -t hfsentinel:test --load .
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none hfsentinel:test

# Live smoke against config/reference_targets.yaml — token mounted as a read-only file, never baked in
docker buildx build --platform linux/amd64 --target runtime -t hfsentinel:runtime --load .
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/.env:/run/secrets/hfsentinel.env:ro" -e HFSENTINEL_ENV_FILE=/run/secrets/hfsentinel.env \
  --entrypoint python hfsentinel:runtime -m hfsentinel.targets.smoke

# CLI (image entrypoint): resolve/--dry-run send nothing to the target; scan refuses without a verified scope file.
# --via auto (default) pins the target from read-only Hub metadata; --via direct makes no Hub calls (needs @provider).
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none \
  hfsentinel:runtime resolve --via direct hf-provider://Qwen/Qwen3-32B@deepinfra
# Targets: hf-provider://org/model[@provider] · hf-endpoint://<host>.endpoints.huggingface.cloud[#model] ·
#          hf-space://owner/space[@api|#model] · openai+https://host/v1#model · hf-job://org/model[@flavor] (deferred, D-004)
# Scope (plan 16.1, D-003): anything that sends target traffic (scan, --recon) needs authorization — a signed scope
# file, or a built-in source (loopback host; D-007 reference endpoints). Out-of-scope targets are refused (exit 3)
# before any network call, including Hub lookups. Sign with your SSH key; trust signers in allowed_signers:
#   ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n hfsentinel-scope scope.yaml        # writes scope.yaml.sig
#   echo "you@example.com $(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub)" >> ~/.config/hfsentinel/allowed_signers
#   hfsentinel scan <target> --scope scope.yaml [--signers FILE] --dry-run      # prints the attestation
# scope.yaml: version: 1 · authorization {reference, authorized_by, statement, granted, expires (<= 366 days)} ·
#             targets: [{uri, note}] — hf-provider without @provider authorizes every provider for that model.
# Controls: --profile quick|standard|deep|agentic|hallucination|diff|custom, every knob as a flag or in sentinel.yaml;
# precedence flag → config → profile → default. --dry-run shows each value's source; --print-config emits a
# sentinel.yaml that reproduces the run. Budget ceilings: --budget-usd ≤ 20 (D-005), --budget-judge-usd ≤ 25 (D-017).
#   hfsentinel scan --config sentinel.yaml --rounds 50 --asr-k 50 --dry-run
# --user-agent / target_io.user_agent sets the User-Agent sent to targets (default hfsentinel/<version>;
#   printable ASCII, <= 200 chars, CR/LF refused).
# Live scan (authorized targets): staged campaign (scope → recon → plan → breadth → confirm → report) over the
# native deterministic-oracle techniques (A1–A5, C2, E1–E3), with sequential stopping to cut requests; judge-scored
# jailbreaks (B) run via the engine images with --engines (host-only, needs Docker). Wilson-CI scoring, §8.3 severity, A–F grade → reports in --out
# (json, sarif, md; files 0600, never overwritten). Only confirmed findings keep a hash + redacted excerpt (D-015).
#   hfsentinel scan hf-provider://google/gemma-3-27b-it@deepinfra --categories A,C,E --trials 10 \
#     --out reports --format json,sarif,md --fail-on high
# SARIF meets GitHub code-scanning upload rules; results anchor to the --config file (else sentinel.yaml).
# Exit codes: 0 ok · 1 internal error · 2 usage · 3 refused by scope · 4 invalid input · 5 not supported yet ·
#             6 Hugging Face Hub unavailable · 10 a confirmed finding meets --fail-on

# Local helper models (plan 16.14, D-013): only ungated models <= 0.5B params, pinned in config/local_models.json
# (commit + per-file sha256). Fetch with network into $HFS_MODELS_DIR, then serve offline; any mismatch fails closed.
M="${HFS_MODELS_DIR:-$HOME/.cache/hfsentinel/models}"; mkdir -p "$M"
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges -v "$M:/models" \
  -e HFS_MODELS_DIR=/models --entrypoint python hfsentinel:runtime -m hfsentinel.targets.local_hf fetch
docker buildx build --platform linux/arm64 -f engines/localmodel/Dockerfile -t hfsentinel-localmodel:arm64 --load .
docker run --rm --network none --cpus 2 --memory 4g --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges -v "$M:/models:ro" hfsentinel-localmodel:arm64 --selftest
# Pin another model (refuses gated / > 0.5B):  python -m hfsentinel.targets.local_hf pin <repo> <alias> chat|nli

# Laya System-1 decision layer (plan 16.19, D-013): local calibrated act-vs-escalate model (convaiinnovations/laya,
# ModernBERT-large + RL head, 421M, CPU, offline). Fetch + sha256-verify the pinned weights, then self-test offline:
L="${HFS_LAYA_DIR:-$HOME/.cache/hfsentinel/laya}"; mkdir -p "$L"
python -m hfsentinel.engines.laya_fetch                       # verifies every file against config/laya_model.json
docker buildx build --platform linux/arm64 -f engines/laya/Dockerfile -t hfsentinel-laya:arm64 --load .
docker run --rm --network none --cpus 2 --memory 4g --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges -v "$L:/models/laya:ro" hfsentinel-laya:arm64 --selftest
# --serve exposes POST /system_one {state, questions}; SystemOne (hfsentinel/core/system_one.py) is the client.
# Advisory only: low confidence / escalate / likely-success always go to System-2 (judges); Laya never confirms.

# Engines (garak, PyRIT, …): relock inside the tools container, then build + smoke + OSV-audit every image
docker buildx build --platform linux/amd64 -f engines/tools/Dockerfile -t hfsentinel-tools:amd64 --load .
docker run --rm -v "$PWD/engines:/w/engines" hfsentinel-tools:amd64 python engines/lock.py
python3 engines/build.py            # host only drives docker; all work happens in containers
```
