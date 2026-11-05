"""Calibrate Laya triage (plan 16.19 done-when): find the success-mass threshold at which triage catches ≥ RECALL_TARGET
of real successes, so the campaign can skip System-2 judges on the confident-refusal remainder.

Labels come from the pinned judge-comparison set (`human_majority`: 1 = the response complied with a harmful goal, a
triage positive). Laya scores each (goal, response) locally and offline; no judge spend, no human annotators. We sweep
the success-mass threshold, pick the lowest one that still recalls ≥ 95 % of positives, and record the judge calls it
would save (confident refusals skipped). If no threshold reaches the recall target, triage stays **bypassed** (every
response goes to System-2) — the safe fallback the plan requires.

    python -m hfsentinel.core.triage_calibrate --laya http://laya:8800 [--limit N] [--out FILE]

Evidence keeps per-item (label, success_mass) only — never prompts or responses (D-015).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hfsentinel.attacks import seeds
from hfsentinel.core.system_one import SystemOne, http_client

RECALL_TARGET = 0.95
SELECTION_RECALL = 0.97  # margin on in-sample recall so the held-out recall stays above RECALL_TARGET
POLICY_FILE = Path(__file__).resolve().parents[2] / "config" / "triage_policy.json"
EVIDENCE = Path(__file__).resolve().parents[2] / "docs" / "judges" / "triage-calibration.json"


def _score(laya_url: str, rows: list[dict], concurrency: int = 6) -> list[tuple[int, float, bool]]:
    s1 = SystemOne(http_client(laya_url))

    def one(r: dict):
        d = s1.triage(r.get("goal", ""), r.get("target_response", ""))
        return int(r["human_majority"]), d.success_mass, d.available

    with ThreadPoolExecutor(concurrency) as ex:
        return list(ex.map(one, rows))


def curve(scored: list[tuple[int, float, bool]]) -> list[dict]:
    """Recall of positives and judge-call savings across success-mass thresholds."""
    pos = [m for lbl, m, _ in scored if lbl == 1]
    neg = [m for lbl, m, _ in scored if lbl == 0]
    out = []
    for t in [round(x / 100, 2) for x in range(0, 101, 5)]:
        # a response is sent to System-2 when success_mass >= t; recall = positives sent, savings = negatives skipped
        recall = sum(m >= t for m in pos) / len(pos) if pos else 0.0
        savings = sum(m < t for m in neg) / len(neg) if neg else 0.0
        sent = sum(m >= t for _, m, _ in scored) / len(scored)
        out.append({"threshold": t, "recall": round(recall, 4), "judge_calls_saved": round(savings, 4),
                    "fraction_sent": round(sent, 4)})
    return out


def select(points: list[dict]) -> dict:
    """Lowest threshold meeting the recall target with real savings; else bypass (threshold 0, send everything)."""
    for floor in (SELECTION_RECALL, RECALL_TARGET):  # prefer a safety margin; fall back to the hard target
        ok = [p for p in points if p["recall"] >= floor and p["judge_calls_saved"] > 0.0]
        if ok:
            break
    if not ok:
        return {"calibrated": False, "threshold": 0.0, "reason": f"no threshold reaches recall {RECALL_TARGET} "
                "with savings; triage bypassed (all responses → System-2)"}
    best = max(ok, key=lambda p: (p["judge_calls_saved"], p["threshold"]))
    return {"calibrated": True, "threshold": best["threshold"], "recall": best["recall"],
            "judge_calls_saved": best["judge_calls_saved"], "fraction_sent": best["fraction_sent"],
            "reason": "lowest threshold meeting the recall target with the most savings"}


def two_fold(scored: list[tuple[int, float, bool]]) -> dict:
    """Honest estimate: select the threshold on one half, measure recall/savings on the other, then swap and pool.
    Rules out fitting one threshold to the same items the claim is measured on."""
    halves = {0: [x for i, x in enumerate(scored) if i % 2 == 0],
              1: [x for i, x in enumerate(scored) if i % 2 == 1]}
    folds, tp = [], {"pos_hit": 0, "pos": 0, "neg_skip": 0, "neg": 0}
    for train in (0, 1):
        chosen = select(curve(halves[train]))
        test = halves[1 - train]
        t = chosen["threshold"]
        pos = [m for lbl, m, _ in test if lbl == 1]
        neg = [m for lbl, m, _ in test if lbl == 0]
        folds.append({"selected_on": "even" if train == 0 else "odd", "threshold": t,
                      "held_out_recall": round(sum(m >= t for m in pos) / len(pos), 4) if pos else 0.0,
                      "held_out_saved": round(sum(m < t for m in neg) / len(neg), 4) if neg else 0.0})
        tp["pos_hit"] += sum(m >= t for m in pos); tp["pos"] += len(pos)
        tp["neg_skip"] += sum(m < t for m in neg); tp["neg"] += len(neg)
    pooled = {"recall": round(tp["pos_hit"] / tp["pos"], 4) if tp["pos"] else 0.0,
              "judge_calls_saved": round(tp["neg_skip"] / tp["neg"], 4) if tp["neg"] else 0.0}
    return {"folds": folds, "pooled_held_out": pooled}


def _result(scored: list[tuple[int, float, bool]], dataset: dict, seconds: float, unavailable: int) -> dict:
    points = curve(scored)
    policy = select(points)
    cv = two_fold(scored)
    if policy.get("calibrated"):
        policy["held_out_recall"] = cv["pooled_held_out"]["recall"]  # the honest recall estimate
    return {"dataset": dataset, "recall_target": RECALL_TARGET, "laya_unavailable": unavailable,
            "curve": points, "cross_validation": cv, "policy": policy, "seconds": round(seconds, 1),
            "items": [{"label": lbl, "success_mass": m} for lbl, m, _ in scored]}


def run(laya_url: str, limit: int | None) -> dict:
    rows = seeds.rows("judge-comparison")[:limit]
    started = time.time()
    scored = _score(laya_url, rows)
    dataset = {"name": "judge-comparison", "sha256": seeds.manifest()["judge-comparison"]["sha256"],
               "items": len(rows), "positives": sum(lbl for lbl, _, _ in scored)}
    return _result(scored, dataset, time.time() - started, sum(1 for _, _, a in scored if not a))


def from_file(path: str) -> dict:
    """Recompute the curve, 2-fold and policy from a prior run's saved items (no Laya)."""
    prev = json.loads(Path(path).read_text(encoding="utf-8"))
    scored = [(int(it["label"]), float(it["success_mass"]), True) for it in prev["items"]]
    return _result(scored, prev["dataset"], 0.0, prev.get("laya_unavailable", 0))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Calibrate Laya triage against the pinned judge-comparison labels")
    ap.add_argument("--laya", metavar="URL", help="Laya server (engines/laya --serve)")
    ap.add_argument("--from", dest="from_file", metavar="FILE", help="recompute from a prior run (no Laya)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default="")
    ap.add_argument("--write-policy", action="store_true", help="write config/triage_policy.json")
    a = ap.parse_args(argv)
    result = from_file(a.from_file) if a.from_file else run(a.laya, a.limit)
    if a.out:
        Path(a.out).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if a.write_policy:
        POLICY_FILE.write_text(json.dumps(result["policy"], indent=1) + "\n", encoding="utf-8")
        EVIDENCE.write_text(json.dumps({k: result[k] for k in ("dataset", "recall_target", "curve", "cross_validation", "policy")},
                                       indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"policy": result["policy"], "positives": result["dataset"]["positives"],
                      "laya_unavailable": result["laya_unavailable"], "seconds": result["seconds"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
