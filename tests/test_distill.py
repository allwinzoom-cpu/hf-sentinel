"""Laya distillation loop (plan 16.19 / task 616): dataset redaction (D-015), held-out split, evaluation, and the
promotion gate. No torch and no model: the training itself is HF-side (`engines/laya/train.py --train`), but the data
redaction, the gate, and the trainer's `--dry-run` validation are all deterministic and tested here.

The gate is the safety-critical piece: a distilled checkpoint replaces the current one only if it beats it on held-out
accuracy **without lowering triage recall** (missing a real jailbreak is the error triage must never get worse at)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from hfsentinel.engines import distill
from hfsentinel.engines.distill import ConfirmedVerdict, DistillExample, Metrics

ROOT = Path(__file__).resolve().parents[1]


def _fake_embed(dim: int = 4):
    # deterministic, text-derived vector so build_dataset is exercised without a model
    return lambda texts: [[float((len(t) + i) % 7) + 0.5 for i in range(dim)] for t in texts]


# ---- redaction / dataset ----
def test_build_dataset_keeps_only_embeddings_and_labels():
    verdicts = [ConfirmedVerdict("triage", "comply", "secret response text", "judge"),
                ConfirmedVerdict("defence", "keyword_filter", "another raw reply", "oracle")]
    examples = distill.build_dataset(verdicts, _fake_embed())
    assert [e.label for e in examples] == ["comply", "keyword_filter"]
    assert all(len(e.features) == 4 and all(isinstance(f, float) for f in e.features) for e in examples)
    # D-015: no raw text survives anywhere in a serialized example
    blob = json.dumps([e.to_dict() for e in examples])
    assert "secret response text" not in blob and "another raw reply" not in blob
    assert not any(hasattr(e, "text") for e in examples)


def test_build_dataset_rejects_unknown_fields_and_bad_embed():
    with pytest.raises(distill.DistillError, match="unknown decision"):
        distill.build_dataset([ConfirmedVerdict("nope", "x", "t", "judge")], _fake_embed())
    with pytest.raises(distill.DistillError, match="unknown source"):
        distill.build_dataset([ConfirmedVerdict("triage", "comply", "t", "guess")], _fake_embed())
    with pytest.raises(distill.DistillError, match="wrong number of vectors"):
        distill.build_dataset([ConfirmedVerdict("triage", "comply", "t", "judge")], lambda texts: [])


def test_validate_example_fails_closed():
    good = DistillExample("triage", "comply", (0.1, 0.2), "judge")
    distill.validate_example(good)
    with pytest.raises(distill.DistillError):
        distill.validate_example(DistillExample("triage", "comply", (float("nan"),), "judge"))
    with pytest.raises(distill.DistillError):
        distill.validate_example(DistillExample("triage", "comply", (), "judge"))
    with pytest.raises(distill.DistillError):
        distill.validate_example(DistillExample("triage", "x" * 100, (0.1,), "judge"))
    with pytest.raises(distill.DistillError):
        distill.validate_example(DistillExample("triage", "comply", (0.1,), "nope"))


def test_dataset_round_trips(tmp_path):
    examples = distill.build_dataset(
        [ConfirmedVerdict("triage", "refuse", "r", "oracle"),
         ConfirmedVerdict("triage", "comply", "c", "judge")], _fake_embed())
    p = tmp_path / "d.jsonl"
    distill.write_dataset(examples, p)
    back = distill.read_dataset(p)
    assert [e.to_dict() for e in back] == [e.to_dict() for e in examples]
    # a bad schema header is refused
    p.write_text(json.dumps({"_schema": 999}) + "\n", encoding="utf-8")
    with pytest.raises(distill.DistillError, match="schema"):
        distill.read_dataset(p)


# ---- split / evaluate / gate ----
def test_held_out_split_is_deterministic_and_disjoint():
    ex = [DistillExample("triage", "comply", (float(i),), "judge") for i in range(10)]
    tr1, ho1 = distill.held_out_split(ex, 0.3, seed=1)
    _tr2, ho2 = distill.held_out_split(ex, 0.3, seed=1)
    assert [e.to_dict() for e in ho1] == [e.to_dict() for e in ho2]
    assert len(ho1) == 3 and len(tr1) == 7
    feats = {e.features for e in tr1} | {e.features for e in ho1}
    assert len(feats) == 10  # disjoint, union covers all


def test_evaluate_accuracy_and_triage_recall():
    ex = [DistillExample("triage", "comply", (1.0,), "judge"),   # positive (likely-success)
          DistillExample("triage", "partial", (2.0,), "judge"),  # positive
          DistillExample("triage", "refuse", (3.0,), "oracle")]  # negative
    # predictor: gets comply right, calls the partial a refuse (misses a positive), refuse right
    preds = {(1.0,): "comply", (2.0,): "refuse", (3.0,): "refuse"}
    m = distill.evaluate(lambda e: preds[e.features], ex)
    assert m.accuracy == round(2 / 3, 4)
    assert m.triage_recall == round(1 / 2, 4)  # caught 1 of 2 positives


def test_should_promote_requires_better_accuracy_without_losing_recall():
    cur = Metrics(0.80, 0.90, 50)
    assert distill.should_promote(Metrics(0.85, 0.90, 50), cur)[0]      # better acc, recall held
    assert distill.should_promote(Metrics(0.85, 0.95, 50), cur)[0]      # better acc, recall up
    assert not distill.should_promote(Metrics(0.85, 0.80, 50), cur)[0]  # recall dropped -> reject
    assert not distill.should_promote(Metrics(0.80, 0.95, 50), cur)[0]  # acc not improved -> reject
    assert not distill.should_promote(Metrics(0.90, None, 50), cur)[0]  # no recall to compare -> reject
    assert not distill.should_promote(Metrics(0.90, 0.95, 0), cur)[0]   # no held-out eval -> reject
    ok, why = distill.should_promote(Metrics(0.85, 0.90, 50), cur)
    assert ok and "triage recall" in why


# ---- trainer --dry-run (no torch) ----
def _load_train():
    spec = importlib.util.spec_from_file_location("laya_train", ROOT / "engines" / "laya" / "train.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_trainer_dry_run_validates_dataset_without_torch(tmp_path, capsys):
    train = _load_train()
    examples = distill.build_dataset(
        [ConfirmedVerdict("triage", "comply", "a", "judge"),
         ConfirmedVerdict("triage", "refuse", "b", "oracle")], _fake_embed())
    p = tmp_path / "d.jsonl"
    distill.write_dataset(examples, p)
    assert train.main(["--dry-run", "--data", str(p)]) == 0
    report = json.loads(capsys.readouterr().out.splitlines()[0])
    assert report["count"] == 2 and report["feature_dim"] == 4
    assert report["class_balance"]["triage"] == {"comply": 1, "refuse": 1}


def test_trainer_dry_run_empty_dataset_fails(tmp_path):
    train = _load_train()
    p = tmp_path / "empty.jsonl"
    distill.write_dataset([], p)
    assert train.main(["--dry-run", "--data", str(p)]) == 1
