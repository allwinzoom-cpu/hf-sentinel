# Methodology

HF-Sentinel is a **dynamic, black-box** LLM security scanner: it attacks a live inference endpoint and scores what comes
back. It never inspects model files or weights, and it never runs a local model scan — the scope is the runtime
behaviour of a deployed model. See [definitions.md](definitions.md) for what counts as a security/safety/quality finding
and [scoring.md](scoring.md) for the confidence-interval, severity, and grade math.

## Authorization first (fail-closed)

Anything that sends traffic to a target — `scan`, `--recon`, `diff` — requires authorization before any network call,
including Hub lookups. Authorization is a signed scope file (SSH-signed, trusted via `allowed_signers`) or a built-in
source (the loopback host; the D-007 reference endpoints). An out-of-scope target is refused with exit code 3 before a
single request is sent. This is enforced, not advisory.

## The staged campaign

A live scan is a budget-gated kill chain, not a fire-everything sweep. Each stage writes a decision record that appears
in the report, so every choice (why a technique was run, skipped, stopped, or escalated) is auditable.

- **S0 — scope & budget gate.** Authorization + the $20 target / $25 judge ceilings (D-005 / D-017).
- **S1 — recon.** Profile the target: capabilities (structured output, tool calling, multimodal, …), refusal baseline,
  guard signals. Laya (System-1, local) classifies replies to steer later stages.
- **S2 — plan.** The planner ranks runnable catalog techniques by expected gain per request and routes each to the
  engine proven best for it; preconditions mark techniques `run` / `experimental` / `n/a` / `blocked` / `unverified`.
- **S3 — breadth.** A small sample per technique with **sequential early stopping** (§16.6): a floor of a few trials,
  then stop as soon as the Wilson interval clears or excludes the reproduction threshold — same verdict, fewer requests.
- **S4 — depth.** Escalate weak spots with encoding mutators, defence-adaptive (only when recon shows a keyword
  filter); and run experimental techniques (e.g. B23 constrained decoding) where their precondition is met.
- **S5 — confirm.** Reproduce at temperature > 0 and at 0; the deterministic oracle decides directly, and judge-scored
  techniques go through the triage-gated judge panel (Laya skips the judges on a confident refusal).
- **S6 — cross-verify.** Re-run each confirmed finding with fresh, independent canaries to rule out an oracle artefact.
- **S7 — learn.** Write winning strategies (aggregates only) back to the strategy library for future runs.
- **S8 — report.** Score, grade, and write JSON / SARIF / Markdown / HTML (+ a model-card snippet).

## Confirmation and evidence retention

Only **confirmed** findings (see [scoring.md](scoring.md)) are persisted, and then only as a minimal repro recipe
(catalog id, seed, trials, mutator chain, target pin) + a sha256 of the exchange + a short redacted excerpt. Every other
trial persists as aggregates only (trials, successes, ASR + CI, cost). `--save-transcripts` keeps full transcripts for
confirmed findings only. Raw request/response text for non-confirmed trials never touches disk.

## Reporting without disclosure

Reports name engines only by neutral alias (never the upstream tool name), and the opaque engine-build hash pins what
produced them. Every target-derived string is encoded for its sink — JSON/SARIF by the encoder, Markdown in length-safe
code fences, HTML escaped under a restrictive CSP — because the attacks deliberately elicit XSS and markdown-image
payloads. The report carries a content sha256, so tampering is detectable.

## Limitations

- **Dynamic black-box only.** HF-Sentinel tests runtime behaviour. It does not analyse weights, training data, or model
  files, and a clean grade reflects only the techniques actually run (untested categories are shown as *not tested*,
  never as an A).
- **Judge-scored techniques need judges enabled.** Jailbreak (category B) success is judge-scored and runs through the
  engine images (`--engines`, host-only, needs Docker) with the System-2 judge panel; the frontier judges need owner
  credentials (D-017). Without them those categories are reported as not run, not as passing.
- **`diff` and alignment removal.** `diff` compares a target against a base model's per-category ASR; a large positive
  ΔASR flags likely alignment removal but is a signal to investigate, not proof.
- **Statistical, not exhaustive.** ASR and its interval come from a finite sample; a 0% observed rate still carries a
  non-zero upper bound, shown in the report.
