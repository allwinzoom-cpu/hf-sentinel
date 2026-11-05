### Tool: rubric-judge (strong_reject @7a551d5)  ·  Version: 7a551d5b440ec7b75d4f6f5bb7c1719965b76b47  ·  Repo: dsbowen/strong_reject  ·  Evaluated: 2026-11-02

| Criterion | Score (0–3) | Evidence |
|---|---|---|
| Catalog coverage (IDs) | 1 | Judge for B-category success; not an attacker in our use |
| Target reach (provider/endpoint/space/openai) | 2 | Judge calls routed to HF router via litellm kwargs |
| Dynamic / adaptive | 0 | Scoring only |
| Multi-turn | 0 | Single response scoring |
| Agent/tool observation | 0 | No tool-call observation |
| Scoring quality (precision on 50 labelled) | 1 | With Llama-3.3-70B as judge: precision 0.55, recall 1.0 on 12 human-labelled items; no threshold fixed it |
| Extensibility (hours to add 1 attack) | 2 | New evaluator = registered function |
| Output format | 2 | Dict scores per item |
| Sandbox fit | 2 | Bare except returns NaN on parse failure (we treat as error); heavy torch deps for unused fine-tuned judge |
| Health (license, release, activity) | 2 | Last commit 2025-07-07 |

**Decision:** Borrow: keep only the rubric template; run it with a frontier judge that passes the human-label gate

**Notes & gaps:**
- Judge-model choice dominates quality; measure every judge on >=50 labelled items first.
- Vuln-target run N/A: this is a judge; evaluated against pinned human labels instead.

#### Run evidence (machine-generated, sandboxed)

- `strong_reject-human-agreement` — exit 0, 90.0s, image `sha256:80cb6b5614af`, egress allowed 4, denied none
  - Command: `python -W ignore /out/rubric-judge_agreement.py strong_reject-human-agreement /out/judge-comparison.csv meta-llama/Llama-3.3-70B-Instruct:novita 6`
  - Results (aggregate only, D-015): `{"n": 12, "judge_errors": 0, "tp": 6, "fp": 5, "fn": 0, "tn": 1, "agreement": 0.583, "precision": 0.545, "recall": 1.0, "reference_same_items": {"harmbench": {"agreement": 0.833, "precision": 0.75}, "llamaguard2": {"agreement": 0.917, "precision": 0.857}}}`

  ```text
  done {"n": 12, "judge_errors": 0, "tp": 6, "fp": 5, "fn": 0, "tn": 1, "agreement": 0.583, "precision": 0.545, "recall": 1.0, "reference_same_items": {"harmbench": {"agreement": 0.833, "precision": 0.75}, "llamaguard2": {"agreement": 0.917, "precision": 0.857}}}
  ```

