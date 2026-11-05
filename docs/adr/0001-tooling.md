# ADR 0001 — Tooling: adopt / borrow / reject

**Status:** accepted · **Date:** 2026-11-05 · relates to plan §4.6, §16.21 (capability ownership), §16.22 (adapters),
DECISIONS D-009 (containers), D-014 (non-disclosure), D-018 (engines as services).

## Context

HF-Sentinel reuses existing red-team tooling rather than re-implementing attacks. Several tools overlap, so a per-tool
verdict is needed. The rule is **capability ownership (§16.21): each capability has exactly one owning engine**, chosen
on Phase 1 evidence; no two engines run the same attack for the same catalog ID in a campaign (the campaign routes each
technique to its owner). A tool that owns no unique capability is reduced to *Borrow* (take only its corpus/rubric) or
*Reject*. Verdicts: **Adopt as engine** / **Adopt for categories** / **Borrow** / **Reject**.

Each adopted engine is a hash-locked, non-root Linux image (D-009) addressed by a neutral alias (D-014) and run as an
internal service (D-018). Pins live in `engines/versions.json`; datasets in `engines/datasets.json`.

## Verdicts

| Tool | Verdict | Alias / use | Owned capability | Rationale |
|---|---|---|---|---|
| **garak** (NVIDIA) | Adopt as engine | `probe-suite` | Static injection/probe breadth + deterministic detectors (A1, B1) | Largest maintained probe library; deterministic detectors need no judge. |
| **PyRIT** (Microsoft) | Adopt as engine | `orchestrator` | Composable encoding/obfuscation converters (B2) + adaptive attacker-LLM (PAIR/TAP/Crescendo) | Only tool with composable converter stacks and multi-turn search. |
| **promptmap** (`utkusen/promptmap`) | Adopt as engine | `extractor` | Prompt-extraction payload corpus (C1), scored by our canary oracle | Distinct extraction corpus; pinned as a commit tarball (not the unrelated PyPI `promptmap`). |
| **strong_reject** (`dsbowen/strong_reject`) | Adopt for categories | `rubric-judge` | Jailbreak rubric scoring (A/B) | A **judge**, not an attacker; continuous rubric penalises empty/vague jailbreaks. Rubric template vendored verbatim (MIT). |
| **PurpleLlama** (Meta) | Adopt for categories | `guard-suite` | Insecure-code detection (E2, CodeShield) + guardrail differential (LlamaFirewall) | Owns the E2 code-sink capability (∪ our dedicated sink rules). |
| **AgentDojo** (ETH) | Adopt as engine | `agent-bench` | Stateful agent environments with deterministic oracles (Category D) | Only tool with tool-enabled agent environments; **Phase 4**. |
| **DeepTeam** (Confident AI) | Borrow (deferred) | `crosscheck` | — (OWASP/NIST mapping, multi-turn GOAT) | Owns no unique capability today; its agent-specific test classes are **deferred to Phase 4** by owner decision. |
| **HarmBench** | Borrow | — (dataset only) | — | Classifier judge is **not served by any provider** and is the weakest reference (0.65 vs humans), so **not a runtime judge**; its standardized behaviours are borrowed as a pinned seed dataset. |
| **JailbreakBench** | Reject (package); Borrow (data) | — | — | The `jailbreakbench` **package is rejected** (unmaintained since 2024-06, imports a removed litellm module); its JBB-Behaviors + judge-comparison data are pinned by revision + sha256 in `engines/datasets.json`. |
| **AdvBench / CyberSecEval** | Borrow | — (seed datasets) | — | Seed corpora only, pinned by commit + sha256. |

## Consequences

- Every adopted engine owns ≥ 1 capability no other engine owns; overlaps are fallbacks, not duplicate runs
  (enforced by the capability matrix, §16.21 / Coverage-matrix task).
- Judges (strong_reject rubric, guard-suite) are scorers, never attackers.
- Borrowed tools contribute data/rubrics but run no attacks; rejected packages contribute nothing executable.
- Deferred tools (DeepTeam/crosscheck, AgentDojo/agent-bench beyond groundwork) land in Phase 4.
