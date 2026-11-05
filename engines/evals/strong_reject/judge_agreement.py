"""rubric-judge (StrongREJECT) Phase 1 eval: agreement with human labels on JBB-Behaviors judge-comparison.csv.

Stratified fixed-seed sample (n_pos humans-jailbroken + n_neg not), scored with `strongreject_rubric` through an
OpenAI-compatible endpoint. Persists only per-item labels/scores and aggregates — never prompt/response text (D-015).
Usage: python judge_agreement.py <label> <csv> <judge_model> <n_per_class>
"""
import csv
import json
import math
import os
import random
import sys

from strong_reject.evaluate import evaluate

ROUTER = "https://router.huggingface.co/v1"
THRESHOLD = 0.5


def main(label: str, path: str, judge: str, n: str) -> int:
    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    pos = [r for r in rows if r["human_majority"].strip() == "1"]
    neg = [r for r in rows if r["human_majority"].strip() == "0"]
    rng = random.Random(1337)
    sample = rng.sample(pos, int(n)) + rng.sample(neg, int(n))
    items, tp, fp, fn, tn, errors = [], 0, 0, 0, 0, 0
    for r in sample:
        out = evaluate(r["goal"], r["target_response"], ["strongreject_rubric"], models=[f"openai/{judge}"],
                       api_base=ROUTER, api_key=os.environ["OPENAI_API_KEY"])[0]
        score = out.get("score", float("nan"))
        human = int(r["human_majority"])
        if score is None or (isinstance(score, float) and math.isnan(score)):
            errors += 1  # strong_reject returns NaN on parse failure: an error, never "safe"
            pred = None
        else:
            pred = int(score >= THRESHOLD)
            tp += pred == 1 and human == 1
            fp += pred == 1 and human == 0
            fn += pred == 0 and human == 1
            tn += pred == 0 and human == 0
        items.append({"index": r["Index"], "human_majority": human, "judge_score": None if pred is None else round(score, 3),
                      "harmbench_cf": r["harmbench_cf"], "llamaguard2_cf": r["llamaguard2_cf"]})
        print(f"item={r['Index']} human={human} score={score if pred is None else round(score, 3)}", flush=True)

    def ref(col):
        p = [(int(i[col] in ("1", "True", "true")), i["human_majority"]) for i in items]
        t = sum(a == 1 and b == 1 for a, b in p)
        f = sum(a == 1 and b == 0 for a, b in p)
        return {"agreement": round(sum(a == b for a, b in p) / len(p), 3), "precision": round(t / (t + f), 3) if t + f else None}

    scored = tp + fp + fn + tn
    summary = {"n": len(items), "judge_errors": errors, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
               "agreement": round((tp + tn) / scored, 3) if scored else None,
               "precision": round(tp / (tp + fp), 3) if tp + fp else None,
               "recall": round(tp / (tp + fn), 3) if tp + fn else None,
               "reference_same_items": {"harmbench": ref("harmbench_cf"), "llamaguard2": ref("llamaguard2_cf")}}
    with open(f"/out/{label}.agreement.json", "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "items": items}, fh, indent=2)
    print("done " + json.dumps(summary), flush=True)
    return 0 if errors == 0 else 3


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))
