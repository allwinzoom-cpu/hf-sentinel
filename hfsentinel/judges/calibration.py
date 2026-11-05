"""Judge calibration set: label schema, loader, and inter-annotator agreement (plan §8.1, Phase 0).

Files: calibration/<category>.jsonl, one JSON object per line (see `Label`). Each item must be labelled
independently by two annotators. Usage: python -m hfsentinel.judges.calibration [calibration_dir]
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

MIN_ITEMS_PER_CATEGORY = 50
MIN_KAPPA = 0.6
CATEGORIES = ("A", "B", "C", "D", "E", "H")


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str = Field(min_length=1, max_length=64)
    catalog_id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    annotator: str = Field(min_length=1, max_length=64)
    label: Literal["success", "fail"]
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")  # evidence hash, not the raw harmful output
    redacted_excerpt: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=500)


def cohens_kappa(a: list[str], b: list[str]) -> float:
    """Cohen's kappa for two raters over the same items. Returns 1.0 when both raters are constant and agree."""
    if len(a) != len(b) or not a:
        raise ValueError("raters must label the same non-empty item list")
    n = len(a)
    p_o = sum(x == y for x, y in zip(a, b)) / n
    cats = set(a) | set(b)
    p_e = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    if p_e == 1.0:
        return 1.0 if p_o == 1.0 else 0.0
    return (p_o - p_e) / (1 - p_e)


def load_labels(directory: Path) -> list[Label]:
    labels: list[Label] = []
    for path in sorted(directory.glob("*.jsonl")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                labels.append(Label.model_validate(json.loads(line)))
            except (ValueError, ValidationError) as e:
                raise ValueError(f"{path.name}:{n}: invalid label ({type(e).__name__})") from None
    return labels


def agreement_report(labels: list[Label]) -> dict[str, dict]:
    """Per category: item count, annotator pair, kappa, and whether the Phase 0 gate passes."""
    by_cat: dict[str, dict[str, dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    for lb in labels:
        item = by_cat[lb.catalog_id[0]][lb.item_id]
        if lb.annotator in item:
            raise ValueError(f"duplicate label: item {lb.item_id} by {lb.annotator}")
        item[lb.annotator] = lb.label
    report: dict[str, dict] = {}
    for cat in CATEGORIES:
        items = by_cat.get(cat, {})
        annotators = sorted({a for v in items.values() for a in v})
        both = [v for v in items.values() if len(v) == 2] if len(annotators) == 2 else []
        kappa = cohens_kappa([v[annotators[0]] for v in both], [v[annotators[1]] for v in both]) if both else None
        report[cat] = {"items": len(both), "annotators": annotators, "kappa": kappa,
                       "pass": len(both) >= MIN_ITEMS_PER_CATEGORY and kappa is not None and kappa >= MIN_KAPPA}
    return report


def main(directory: str = "calibration") -> int:
    report = agreement_report(load_labels(Path(directory)))
    for cat, r in report.items():
        k = "n/a" if r["kappa"] is None else f"{r['kappa']:.3f}"
        print(f"[{'PASS' if r['pass'] else 'FAIL'}] {cat}: items={r['items']:<4} kappa={k:<6} annotators={r['annotators']}")
    return 0 if all(r["pass"] for r in report.values()) else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
