# GitHub Action — PR security gate

`action.yml` (at the repo root) wraps the `hfsentinel` CLI as a composite action: it runs a scan against an
**authorized** LLM target, uploads the SARIF report to GitHub code scanning, and fails the job when a confirmed
finding is at or above a chosen severity.

The scan is **fail-closed**. It sends no traffic without a scope file that authorizes the target and is signed with an
OpenSSH Ed25519 key; the signature is verified (against your `allowed_signers`) before the scope YAML is parsed. So the
`scope` and `signers` inputs are required. See [`docs/methodology.md`](methodology.md) for the scope format.

## Inputs

| input | required | default | meaning |
|-------|----------|---------|---------|
| `target` | yes | — | target URI, e.g. `openai+https://host/v1#model` or `hf-provider://org/model` |
| `scope` | yes | — | path to the signed `scope.yaml` (its `.sig` beside it) authorizing the target |
| `signers` | yes | — | OpenSSH `allowed_signers` trusted to have signed the scope |
| `fail-on` | no | `high` | fail on a confirmed finding at or above `critical \| high \| medium` |
| `budget-usd` | no | `20` | target spend cap (the CLI enforces ≤ 20) |
| `budget-judge-usd` | no | `0` | judge spend cap (≤ 25); `0` disables judge-scored engine candidates |
| `max-minutes` / `max-requests` | no | — | optional wall-clock / request caps |
| `config` | no | — | optional sentinel config file (inputs above override it) |
| `output-dir` | no | `hfsentinel-report` | directory for the SARIF/Markdown/JSON reports |
| `upload-sarif` | no | `true` | upload SARIF to code scanning (needs `security-events: write`) |
| `hf-token` | no | — | optional HF token (pass a secret) for Hub-resolved targets; used only as `HF_TOKEN`, never printed |

The SARIF is uploaded **before** the gate is enforced, so findings always reach code scanning even when the job fails.

## Usage — scan on a schedule, gate on Critical

```yaml
name: llm-security-scan
on:
  schedule: [{ cron: "0 6 * * 1" }]   # weekly; or workflow_dispatch / pull_request
  workflow_dispatch:
permissions:
  contents: read
  security-events: write              # required to upload SARIF to code scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: allwinzoom-cpu/hf-sentinel@v1
        with:
          target: openai+https://your-endpoint/v1#your-model
          scope: .hfsentinel/scope.yaml
          signers: .hfsentinel/allowed_signers
          fail-on: critical
          hf-token: ${{ secrets.HF_TOKEN }}
```

A confirmed finding at or above `fail-on` makes the step exit non-zero, so the workflow (and a PR gate that requires it)
fails; the SARIF still appears under **Security → Code scanning**.

## Hosted / heavy-compute variant (HF Jobs)

For targets that need GPU or a large local model, run the scan as a Hugging Face Job rather than on the GitHub runner,
with [`huggingface/hf-jobs-action`](https://github.com/huggingface/hf-jobs). That path is gated on the HF Jobs runner
(`targets/job_target.py`, plan task 617 / D-004) and an HF token with `job.write`; it is **not yet wired** here. Until
then this action runs the CLI directly on the runner, which is the right fit for hosted-API targets (the common case).

## Verification

`tests/test_github_action.py` checks the action is a well-formed composite with the required fail-closed inputs, its
third-party steps are pinned to full commit SHAs, and it wraps the CLI / uploads SARIF / enforces `--fail-on`; then it
runs the exact scan invocation the action makes against the loopback vulnerable target and asserts the gate trips
(exit 10) with a Critical result in the written SARIF — the task's done-when.
