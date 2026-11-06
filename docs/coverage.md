# Capability coverage matrix

Generated from `engines/capabilities.json` by `engines/coverage_matrix.py` (plan 16.21 / task 599). Each capability has exactly one owner; every catalog ID is accounted for below.

## Capabilities (one owner each)

| Capability | Owner | Catalog IDs | Fallbacks |
|---|---|---|---|
| deterministic-canary-injection-oracles | `built-by-us` | A1, A2, A3, A4, A5, A6, C2 | probe-suite |
| active-content-and-resource-oracles | `built-by-us` | E1, E3, E5 | probe-suite |
| insecure-code-scanner | `guard-suite` | E2 | built-by-us |
| extraction-and-memorization-oracles | `built-by-us` | C1, C3, C4 | extractor, probe-suite |
| glitch-anomaly-oracle | `built-by-us` | B22 | probe-suite |
| hallucination-oracles | `built-by-us` | H1, H2, H3, H4, H5, H6, H7 | probe-suite |
| agentic-tool-abuse-oracles | `built-by-us` | D1, D2, D3, D4, D5, D6, D7, E4 | agent-bench |
| static-jailbreak-probe-breadth | `probe-suite` | B1, B3, B5, B6, B9, B12, B15, B16, B17, B18, B19, B21 | orchestrator |
| adaptive-multi-turn-and-converters | `orchestrator` | B2, B4, B7, B8, B10, B11, B13, B14, B20 | probe-suite |
| constrained-decoding-oracle | `built-by-us` | B23 | — |
| stateful-agent-benchmark-environments | `agent-bench` | — | — |
| framework-mapping-and-generated-agentic-tests | `crosscheck` | — | — |
| prompt-extraction-payload-corpus | `extractor` | — | — |
| jailbreak-rubric-scoring-template | `rubric-judge` | — | — |
| composable-mutation-encoding-transforms | `built-by-us` | — | orchestrator |
| adaptive-system-1-decision-layer | `built-by-us` | — | — |
| scoring-grading-and-confirmation | `built-by-us` | — | — |

## Catalog accounting

All 52 catalog IDs accounted for · conditional: 11 · deferred: 11 · engine-wired: 2 · experimental: 9 · oracle-only: 11 · wired: 8

| ID | Owner | Capability | Status | Note |
|---|---|---|---|---|
| A1 | `built-by-us` | deterministic-canary-injection-oracles | wired |  |
| A2 | `built-by-us` | deterministic-canary-injection-oracles | wired |  |
| A3 | `built-by-us` | deterministic-canary-injection-oracles | wired |  |
| A4 | `built-by-us` | deterministic-canary-injection-oracles | conditional | conditional: multimodal input accepted |
| A5 | `built-by-us` | deterministic-canary-injection-oracles | wired |  |
| A6 | `built-by-us` | deterministic-canary-injection-oracles | conditional | native breadth sweep; runs when recon detects special_token_parsing (chat-template injection) |
| B1 | `probe-suite` | static-jailbreak-probe-breadth | engine-wired |  |
| B2 | `orchestrator` | adaptive-multi-turn-and-converters | engine-wired |  |
| B3 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth / templated battery (641) wiring pending |
| B4 | `orchestrator` | adaptive-multi-turn-and-converters | deferred | PyRIT multi-turn (Crescendo) wiring pending (643) |
| B5 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth wiring pending |
| B6 | `probe-suite` | static-jailbreak-probe-breadth | experimental | candidate; experimental, reproduce in 646 |
| B7 | `orchestrator` | adaptive-multi-turn-and-converters | deferred | PyRIT multi-turn (PAIR/TAP) wiring pending (643) |
| B8 | `orchestrator` | adaptive-multi-turn-and-converters | experimental | candidate; experimental, reproduce in 646 |
| B9 | `probe-suite` | static-jailbreak-probe-breadth | experimental | candidate; experimental, reproduce in 646 |
| B10 | `orchestrator` | adaptive-multi-turn-and-converters | experimental | candidate; experimental, reproduce in 646 |
| B11 | `orchestrator` | adaptive-multi-turn-and-converters | experimental | candidate; experimental, reproduce in 646 |
| B12 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth wiring pending |
| B13 | `orchestrator` | adaptive-multi-turn-and-converters | deferred | PyRIT search (best-of-N) wiring pending |
| B14 | `orchestrator` | adaptive-multi-turn-and-converters | experimental | candidate; experimental, reproduce in 646 |
| B15 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth / templated battery (641) wiring pending |
| B16 | `probe-suite` | static-jailbreak-probe-breadth | experimental | candidate; experimental, reproduce in 646 |
| B17 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth / templated battery (641) wiring pending |
| B18 | `probe-suite` | static-jailbreak-probe-breadth | experimental | candidate; experimental, reproduce in 646 |
| B19 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak static-breadth / templated battery (641) wiring pending |
| B20 | `orchestrator` | adaptive-multi-turn-and-converters | deferred | PyRIT strategy-discovery wiring pending |
| B21 | `probe-suite` | static-jailbreak-probe-breadth | deferred | garak phrasing.PastTense / templated battery (641) wiring pending |
| B22 | `built-by-us` | glitch-anomaly-oracle | oracle-only | native glitch oracle built + tested; attack generation not in breadth sweep |
| B23 | `built-by-us` | constrained-decoding-oracle | experimental | candidate; experimental, never scored (constrained decoding) |
| C1 | `built-by-us` | extraction-and-memorization-oracles | oracle-only | native canary oracle built + tested; payload corpus via extractor, not in breadth sweep |
| C2 | `built-by-us` | deterministic-canary-injection-oracles | wired |  |
| C3 | `built-by-us` | extraction-and-memorization-oracles | conditional | scan stage via --memorization-refs (operator-held reference set) |
| C4 | `built-by-us` | extraction-and-memorization-oracles | conditional | conditional: target has cross-session memory |
| D1 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool-enabled target or mock-tool env (oracle tested via fixtures) |
| D2 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool-enabled target or mock-tool env (oracle tested via fixtures) |
| D3 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool-enabled target or mock-tool env (oracle tested via fixtures) |
| D4 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool-enabled target or mock-tool env (oracle tested via fixtures) |
| D5 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool-enabled target or mock-tool env (oracle tested via fixtures) |
| D6 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: multi-agent target or mock-tool env (oracle tested via fixtures) |
| D7 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: browse/HTTP tool + controlled sink (oracle tested via fixtures) |
| E1 | `built-by-us` | active-content-and-resource-oracles | wired |  |
| E2 | `guard-suite` | insecure-code-scanner | wired |  |
| E3 | `built-by-us` | active-content-and-resource-oracles | wired |  |
| E4 | `built-by-us` | agentic-tool-abuse-oracles | oracle-only | runtime: tool loop possible (native loop-cap oracle tested via fixtures) |
| E5 | `built-by-us` | active-content-and-resource-oracles | oracle-only | native active-content oracle built + tested; not in breadth sweep |
| H1 | `built-by-us` | hallucination-oracles | conditional | scan stage via --halluc-registries (live registry check) |
| H2 | `built-by-us` | hallucination-oracles | conditional | scan stage via --api-reference (operator known-API set) |
| H3 | `built-by-us` | hallucination-oracles | conditional | scan stage via --nli-url (operator NLI service) |
| H4 | `built-by-us` | hallucination-oracles | conditional | scan stage via --nli-url (shares the NLI false-premise oracle) |
| H5 | `built-by-us` | hallucination-oracles | conditional | scan stage via --check-sycophancy (two-turn answer-flip) |
| H6 | `built-by-us` | hallucination-oracles | conditional | scan stage via --check-citations (DOI/arXiv resolver, SSRF-safe) |
| H7 | `built-by-us` | hallucination-oracles | conditional | scan stage via --check-calibration (confidence vs correctness) |

## Gaps — no reliable coverage yet (task 600)

20 technique(s) not reliably runnable today; each maps to a Phase-3/4 ticket (its reason).

| ID | Owner | Status | Ticket / reason |
|---|---|---|---|
| B3 | `probe-suite` | deferred | garak static-breadth / templated battery (641) wiring pending |
| B4 | `orchestrator` | deferred | PyRIT multi-turn (Crescendo) wiring pending (643) |
| B5 | `probe-suite` | deferred | garak static-breadth wiring pending |
| B6 | `probe-suite` | experimental | candidate; experimental, reproduce in 646 |
| B7 | `orchestrator` | deferred | PyRIT multi-turn (PAIR/TAP) wiring pending (643) |
| B8 | `orchestrator` | experimental | candidate; experimental, reproduce in 646 |
| B9 | `probe-suite` | experimental | candidate; experimental, reproduce in 646 |
| B10 | `orchestrator` | experimental | candidate; experimental, reproduce in 646 |
| B11 | `orchestrator` | experimental | candidate; experimental, reproduce in 646 |
| B12 | `probe-suite` | deferred | garak static-breadth wiring pending |
| B13 | `orchestrator` | deferred | PyRIT search (best-of-N) wiring pending |
| B14 | `orchestrator` | experimental | candidate; experimental, reproduce in 646 |
| B15 | `probe-suite` | deferred | garak static-breadth / templated battery (641) wiring pending |
| B16 | `probe-suite` | experimental | candidate; experimental, reproduce in 646 |
| B17 | `probe-suite` | deferred | garak static-breadth / templated battery (641) wiring pending |
| B18 | `probe-suite` | experimental | candidate; experimental, reproduce in 646 |
| B19 | `probe-suite` | deferred | garak static-breadth / templated battery (641) wiring pending |
| B20 | `orchestrator` | deferred | PyRIT strategy-discovery wiring pending |
| B21 | `probe-suite` | deferred | garak phrasing.PastTense / templated battery (641) wiring pending |
| B23 | `built-by-us` | experimental | candidate; experimental, never scored (constrained decoding) |
