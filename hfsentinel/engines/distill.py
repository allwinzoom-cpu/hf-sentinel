"""Laya distillation loop (plan 16.19 / task 616, D-006/D-013/D-015).

System-2-confirmed verdicts — deterministic-oracle hits, agreeing judge panels, human calibration labels — are the
ground truth Laya's advisory System-1 decisions are graded against. This module turns those verdicts into a training set
and gates whether a distilled checkpoint may replace the current one.

**D-015 (retention):** a distillation example stores only a *redacted feature vector* (the Laya encoder embedding — a
list of floats, never the raw response text) plus the confirmed decision label and its source. Raw text is embedded and
dropped; it never lands in the dataset. `build_dataset` takes an injected `embed` callable so this module stays
torch-free and testable; the real encoder embedding is computed HF-side in `engines/laya/train.py`.

**D-006/D-013:** training runs on HF (never locally), on CPU within the cap. A distilled checkpoint replaces the current
one only if `should_promote` passes: it must beat the current checkpoint on the held-out set **without lowering triage
recall** (missing a real jailbreak is the one error triage must never get worse at — Section 8.3 / 16.19).
"""
from __future__ import annotations

import json
import math
import random
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DECISIONS = ("triage", "defence", "technique", "act")  # the four System-1 decisions (system_one.py)
SOURCES = ("oracle", "judge", "human")                 # how the label was System-2-confirmed
LIKELY_SUCCESS = ("comply", "partial")                 # triage labels that mean a real jailbreak (recall target)
SCHEMA_VERSION = 1


class DistillError(ValueError):
    pass


@dataclass(frozen=True)
class ConfirmedVerdict:
    """A transient System-2 result to learn from. `text` (goal+response) is embedded then dropped — never persisted."""
    decision: str
    label: str
    text: str
    source: str
    weight: float = 1.0


@dataclass(frozen=True)
class DistillExample:
    """One D-015-safe training row: a redacted embedding + the confirmed label. No raw text."""
    decision: str
    label: str
    features: tuple[float, ...]
    source: str
    weight: float = 1.0

    def to_dict(self) -> dict:
        return {"decision": self.decision, "label": self.label, "features": list(self.features),
                "source": self.source, "weight": self.weight}

    @staticmethod
    def from_dict(d: dict) -> DistillExample:
        return DistillExample(d["decision"], d["label"], tuple(float(x) for x in d["features"]),
                              d.get("source", "oracle"), float(d.get("weight", 1.0)))


def validate_example(ex: DistillExample) -> None:
    """Fail closed on a malformed or non-redacted example (D-015: features must be finite floats, no raw text)."""
    if ex.decision not in DECISIONS:
        raise DistillError(f"unknown decision: {ex.decision}")
    if ex.source not in SOURCES:
        raise DistillError(f"unknown source: {ex.source}")
    if not ex.label or not isinstance(ex.label, str) or len(ex.label) > 64:
        raise DistillError("label must be a short non-empty string")
    if not ex.features or not all(isinstance(f, float) and math.isfinite(f) for f in ex.features):
        raise DistillError("features must be a non-empty vector of finite floats")
    if not 0.0 <= ex.weight <= 1000.0:
        raise DistillError("weight out of range")


def build_dataset(verdicts: Iterable[ConfirmedVerdict], embed: Callable[[list[str]], list[Sequence[float]]]) \
        -> list[DistillExample]:
    """Redact verdicts into training rows: embed each `text` to a float vector (the only feature kept), attach the
    confirmed label + source, and drop the text. `embed` maps a batch of texts to equal-length float vectors."""
    verdicts = list(verdicts)
    for v in verdicts:
        if v.decision not in DECISIONS:
            raise DistillError(f"unknown decision: {v.decision}")
        if v.source not in SOURCES:
            raise DistillError(f"unknown source: {v.source}")
    vecs = embed([v.text for v in verdicts]) if verdicts else []
    if len(vecs) != len(verdicts):
        raise DistillError("embed returned the wrong number of vectors")
    out: list[DistillExample] = []
    for v, vec in zip(verdicts, vecs, strict=True):
        ex = DistillExample(v.decision, v.label, tuple(float(x) for x in vec), v.source, v.weight)
        validate_example(ex)
        out.append(ex)
    return out


def write_dataset(examples: Sequence[DistillExample], path: Path) -> None:
    """Write the dataset (D-015-safe: embeddings + labels only) as JSON lines with a schema header."""
    for ex in examples:
        validate_example(ex)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({"_schema": SCHEMA_VERSION, "_count": len(examples)})]
    lines += [json.dumps(ex.to_dict(), separators=(",", ":")) for ex in examples]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_dataset(path: Path) -> list[DistillExample]:
    rows = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not rows:
        return []
    header = json.loads(rows[0])
    if header.get("_schema") != SCHEMA_VERSION:
        raise DistillError(f"unsupported dataset schema: {header.get('_schema')}")
    out = [DistillExample.from_dict(json.loads(ln)) for ln in rows[1:]]
    for ex in out:
        validate_example(ex)
    return out


def held_out_split(examples: Sequence[DistillExample], frac: float = 0.2, *, seed: int = 0) \
        -> tuple[list[DistillExample], list[DistillExample]]:
    """Deterministic (train, held_out) split. Held-out is the gate's yardstick; the split must be reproducible so a
    promotion decision is auditable."""
    if not 0.0 < frac < 1.0:
        raise DistillError("frac must be in (0, 1)")
    idx = list(range(len(examples)))
    random.Random(seed).shuffle(idx)
    cut = max(1, round(len(examples) * frac)) if examples else 0
    held = {idx[i] for i in range(cut)}
    return [examples[i] for i in range(len(examples)) if i not in held], \
           [examples[i] for i in range(len(examples)) if i in held]


@dataclass(frozen=True)
class Metrics:
    accuracy: float
    triage_recall: float | None  # recall on the likely-success class (comply/partial); None if no such labels
    n: int
    per_decision: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"accuracy": self.accuracy, "triage_recall": self.triage_recall, "n": self.n,
                "per_decision": self.per_decision}


def evaluate(predict: Callable[[DistillExample], str], examples: Sequence[DistillExample]) -> Metrics:
    """Score a checkpoint's predictions over the held-out set. `predict(ex) -> label`. Triage recall is the fraction of
    true likely-success (comply/partial) triage items the checkpoint also calls likely-success — the safety metric."""
    if not examples:
        raise DistillError("cannot evaluate on an empty set")
    correct = 0
    by_dec: dict[str, list[int]] = {}
    pos_total = pos_hit = 0
    for ex in examples:
        pred = predict(ex)
        ok = int(pred == ex.label)
        correct += ok
        by_dec.setdefault(ex.decision, []).append(ok)
        if ex.decision == "triage" and ex.label in LIKELY_SUCCESS:
            pos_total += 1
            pos_hit += int(pred in LIKELY_SUCCESS)
    per = {d: round(sum(v) / len(v), 4) for d, v in by_dec.items()}
    recall = round(pos_hit / pos_total, 4) if pos_total else None
    return Metrics(round(correct / len(examples), 4), recall, len(examples), per)


def should_promote(candidate: Metrics, current: Metrics, *, min_accuracy_gain: float = 0.0) \
        -> tuple[bool, str]:
    """Gate: promote the distilled checkpoint only if it beats the current one on accuracy AND does not lower triage
    recall (16.19: a distilled checkpoint replaces the current one only if it beats it without lowering triage recall).
    A candidate that drops recall is rejected even if overall accuracy rose — missing a jailbreak is the costly error."""
    if candidate.n == 0 or current.n == 0:
        return False, "no held-out evaluation"
    if candidate.accuracy <= current.accuracy + min_accuracy_gain:
        return False, (f"accuracy not improved ({candidate.accuracy:.4f} ≤ "
                       f"{current.accuracy + min_accuracy_gain:.4f})")
    cand_r, cur_r = candidate.triage_recall, current.triage_recall
    if cur_r is not None and cand_r is not None and cand_r < cur_r:
        return False, f"triage recall dropped ({cand_r:.4f} < {cur_r:.4f})"
    if cur_r is not None and cand_r is None:
        return False, "candidate has no triage recall to compare (would hide a regression)"
    return True, f"accuracy {current.accuracy:.4f}→{candidate.accuracy:.4f}, triage recall {cur_r}→{cand_r}"
