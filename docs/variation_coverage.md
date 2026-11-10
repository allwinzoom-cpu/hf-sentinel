# Variation coverage (LSCAN-087)

Per-technique coverage across the implemented dimensions — family, oracle, evidence level, replay level and run status — derived from implemented metadata only (catalog + oracle registry + evidence rules + the capability matrix). This is bounded per-technique coverage, **not** an exhaustive Cartesian product of every placement x protocol x feature combination.

**42 of 52 techniques are runnable**; 10 are gated (deferred/experimental) and **cannot improve a grade**. A "no findings" result is reported only with this tested coverage and its limitations — absence of a capability is observed in recon, never assumed.

## Techniques

| ID | Family | Oracle | Evidence level | Replay | Status | Runnable |
|---|---|---|---|---|---|---|
| A1 | A | deterministic | instruction-following-surrogate | exact | wired | yes |
| A2 | A | deterministic | instruction-following-surrogate | exact | wired | yes |
| A3 | A | deterministic | instruction-following-surrogate | exact | wired | yes |
| A4 | A | deterministic | instruction-following-surrogate | exact | conditional | yes |
| A5 | A | deterministic | instruction-following-surrogate | exact | wired | yes |
| A6 | A | deterministic | instruction-following-surrogate | exact | conditional | yes |
| B1 | B | judge | policy-violation | recipe-only | engine-wired | yes |
| B2 | B | judge | policy-violation | recipe-only | engine-wired | yes |
| B3 | B | judge | policy-violation | recipe-only | conditional | yes |
| B4 | B | judge | policy-violation | recipe-only | wired | yes |
| B5 | B | judge | policy-violation | recipe-only | wired | yes |
| B6 | B | deterministic | instruction-following-surrogate | exact | wired | yes |
| B7 | B | judge | policy-violation | recipe-only | deferred | no (gated) |
| B8 | B | judge | policy-violation | recipe-only | experimental | no (gated) |
| B9 | B | judge | policy-violation | recipe-only | experimental | no (gated) |
| B10 | B | deterministic | instruction-following-surrogate | exact | conditional | yes |
| B11 | B | judge | policy-violation | recipe-only | experimental | no (gated) |
| B12 | B | deterministic | instruction-following-surrogate | exact | conditional | yes |
| B13 | B | deterministic | instruction-following-surrogate | exact | wired | yes |
| B14 | B | deterministic | instruction-following-surrogate | exact | wired | yes |
| B15 | B | judge | policy-violation | recipe-only | deferred | no (gated) |
| B16 | B | deterministic | instruction-following-surrogate | exact | wired | yes |
| B17 | B | judge | policy-violation | recipe-only | deferred | no (gated) |
| B18 | B | judge | policy-violation | recipe-only | experimental | no (gated) |
| B19 | B | judge | policy-violation | recipe-only | deferred | no (gated) |
| B20 | B | judge | policy-violation | recipe-only | deferred | no (gated) |
| B21 | B | judge | policy-violation | recipe-only | wired | yes |
| B22 | B | deterministic | instruction-following-surrogate | exact | oracle-only | yes |
| B23 | B | deterministic | instruction-following-surrogate | exact | conditional | yes |
| C1 | C | deterministic | instruction-following-surrogate | exact | oracle-only | yes |
| C2 | C | deterministic | policy-violation | exact | wired | yes |
| C3 | C | reference | generated-artifact | recipe-only | conditional | yes |
| C4 | C | deterministic | policy-violation | exact | conditional | yes |
| D1 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D2 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D3 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D4 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D5 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D6 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| D7 | D | call-log | attempted-action | recipe-only | oracle-only | yes |
| E1 | E | signature | generated-artifact | recipe-only | wired | yes |
| E2 | E | signature | generated-artifact | recipe-only | deferred | no (gated) |
| E3 | E | deterministic | completed-effect | exact | wired | yes |
| E4 | E | call-log | attempted-action | recipe-only | oracle-only | yes |
| E5 | E | signature | generated-artifact | recipe-only | wired | yes |
| H1 | H | registry | generated-artifact | recipe-only | conditional | yes |
| H2 | H | reference | generated-artifact | recipe-only | conditional | yes |
| H3 | H | nli | generated-artifact | recipe-only | conditional | yes |
| H4 | H | nli | generated-artifact | recipe-only | conditional | yes |
| H5 | H | reference | generated-artifact | recipe-only | conditional | yes |
| H6 | H | reference | generated-artifact | recipe-only | conditional | yes |
| H7 | H | reference | generated-artifact | recipe-only | conditional | yes |

## Delivery surfaces (implemented)

| Surface | Catalog IDs |
|---|---|
| direct-chat | A1, A6 |
| indirect/hidden-injection | A2, A3 |
| image-input | A4 |
| exfiltration-channel | A5 |
| encoding-mutator | B2, B6, B14, B15, B16 |
| persona-scaffold | B1, B9, B10, B17, B18, B19, B21 |
| many-shot / long-context | B5 |
| multilingual | B3 |
| structured-output | B23 |
| best-of-n | B13 |
| multi-turn | B4, B11 |
| adaptive-search (PAIR/TAP) | B7 |
| extraction | C1, C2, C3, C4 |
| active-content / code | E1, E2, E3, E5 |

> Techniques not mapped to a delivery surface above: B12, B20, B22, B8, D1, D2, D3, D4, D5, D6, D7, E4, H1, H2, H3, H4, H5, H6, H7 (untested combination, reported — not claimed).
