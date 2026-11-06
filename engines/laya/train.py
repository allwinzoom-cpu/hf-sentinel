"""Laya distillation trainer (plan 16.19 / task 616, D-006/D-013/D-015) — runs in the laya image on HF PRO, never
locally. It closes the loop: redact System-2-confirmed verdicts into a D-015 dataset (encoder embeddings + labels, no
raw text), then distil a candidate decision head on those labels. Promotion is gated by `distill.should_promote`
(beats the current checkpoint on held-out accuracy without lowering triage recall).

    python train.py --embed   --verdicts V.jsonl --model-dir /models/laya --out data.jsonl   # redact -> D-015 dataset
    python train.py --dry-run --data data.jsonl                                              # validate + class balance
    python train.py --train   --data data.jsonl --out /tmp/candidate [--epochs N]            # distil a candidate head
    python train.py --gate    --data data.jsonl --candidate /tmp/candidate --model-dir /models/laya  # promote?  (gate)

torch / transformers are imported lazily inside `--embed`/`--train`/`--gate`, so `--dry-run` (dataset validation) needs
neither and is exercised by the core test suite. `--embed` reads a transient verdicts file ({decision,label,text,source}
— the only place raw text appears) and writes only embeddings; delete the verdicts file after (D-015).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
try:  # core/test image: the package is installed
    from hfsentinel.engines import distill
except ImportError:  # laya image: distill.py is vendored next to this script (stdlib-only; loads standalone)
    sys.path.insert(0, str(HERE))
    import distill


def _read_verdicts(path: Path) -> list[distill.ConfirmedVerdict]:
    out = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        d = json.loads(ln)
        out.append(distill.ConfirmedVerdict(d["decision"], d["label"], d["text"],
                                            d.get("source", "oracle"), float(d.get("weight", 1.0))))
    return out


def _load_encoder(model_dir: Path):
    """Load the pinned Laya encoder offline (strict weight load, no remote code) for embedding. HF-side only."""
    import torch  # noqa: F401
    from transformers import AutoModel, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(str(model_dir / "tokenizer"), local_files_only=True)
    enc = AutoModel.from_pretrained(str(model_dir / "encoder"), local_files_only=True)
    enc.eval()
    return tok, enc


def _embed_texts(tok, enc, texts: list[str], batch: int = 16) -> list[list[float]]:
    import torch
    out: list[list[float]] = []
    with torch.no_grad():
        for i in range(0, len(texts), batch):
            chunk = texts[i:i + batch]
            t = tok(chunk, return_tensors="pt", padding=True, truncation=True, max_length=512)
            h = enc(**t).last_hidden_state
            mask = t["attention_mask"].unsqueeze(-1).float()
            pooled = (h * mask).sum(1) / mask.sum(1).clamp(min=1.0)  # mean-pool over real tokens
            out.extend(pooled.cpu().tolist())
    return out


def cmd_embed(a) -> int:
    verdicts = _read_verdicts(Path(a.verdicts))
    tok, enc = _load_encoder(Path(a.model_dir))
    examples = distill.build_dataset(verdicts, lambda texts: _embed_texts(tok, enc, texts))
    distill.write_dataset(examples, Path(a.out))
    print(f"embedded {len(examples)} verdicts -> {a.out} (D-015: embeddings + labels only)")
    return 0


def cmd_dry_run(a) -> int:
    examples = distill.read_dataset(Path(a.data))
    if not examples:
        print("dry-run: dataset is empty", file=sys.stderr)
        return 1
    bal: dict[str, dict[str, int]] = {}
    for ex in examples:
        bal.setdefault(ex.decision, {}).setdefault(ex.label, 0)
        bal[ex.decision][ex.label] += 1
    dim = len(examples[0].features)
    if any(len(ex.features) != dim for ex in examples):
        print("dry-run: inconsistent feature dimensions", file=sys.stderr)
        return 1
    print(json.dumps({"count": len(examples), "feature_dim": dim, "class_balance": bal}))
    print("dry-run: ok")
    return 0


def _train_head(examples, dim: int, labels_by_decision: dict, epochs: int, out_dir: Path):
    """Distil one linear decision head per decision over the frozen encoder embeddings (standard head-distillation)."""
    import torch
    from torch import nn
    heads = {}
    for decision, labels in labels_by_decision.items():
        rows = [ex for ex in examples if ex.decision == decision]
        x = torch.tensor([list(ex.features) for ex in rows], dtype=torch.float32)
        y = torch.tensor([labels.index(ex.label) for ex in rows], dtype=torch.long)
        w = torch.tensor([ex.weight for ex in rows], dtype=torch.float32)
        head = nn.Linear(dim, len(labels))
        opt = torch.optim.Adam(head.parameters(), lr=1e-3)
        lossf = nn.CrossEntropyLoss(reduction="none")
        for _ in range(epochs):
            opt.zero_grad()
            loss = (lossf(head(x), y) * w).mean()
            loss.backward()
            opt.step()
        heads[decision] = head.state_dict()
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.save({"heads": heads, "labels": labels_by_decision, "dim": dim}, out_dir / "decision_heads.pt")
    (out_dir / "labels.json").write_text(json.dumps(labels_by_decision), encoding="utf-8")


def cmd_train(a) -> int:
    examples = distill.read_dataset(Path(a.data))
    if not examples:
        print("train: empty dataset", file=sys.stderr)
        return 1
    labels_by_decision: dict[str, list[str]] = {}
    for ex in examples:
        labels_by_decision.setdefault(ex.decision, [])
        if ex.label not in labels_by_decision[ex.decision]:
            labels_by_decision[ex.decision].append(ex.label)
    _train_head(examples, len(examples[0].features), labels_by_decision, a.epochs, Path(a.out))
    print(f"trained candidate decision heads -> {a.out}  ({len(examples)} examples, {a.epochs} epochs)")
    return 0


def cmd_gate(a) -> int:
    """Evaluate the candidate heads vs the current ones on a held-out split and apply the promotion gate."""
    import torch
    examples = distill.read_dataset(Path(a.data))
    _, held = distill.held_out_split(examples, a.held_out_frac, seed=a.seed)
    cand = torch.load(Path(a.candidate) / "decision_heads.pt", weights_only=True)

    def predictor(bundle):
        from torch import nn

        def predict(ex):
            labels = bundle["labels"].get(ex.decision)
            if not labels:
                return ""
            head = nn.Linear(bundle["dim"], len(labels))
            head.load_state_dict(bundle["heads"][ex.decision])
            x = torch.tensor([list(ex.features)], dtype=torch.float32)
            return labels[int(head(x).argmax(1).item())]
        return predict

    cand_m = distill.evaluate(predictor(cand), held)
    # The "current" baseline is the majority-class predictor when no prior candidate is pinned (first distillation).
    cur_path = Path(a.current) / "decision_heads.pt" if a.current else None
    if cur_path and cur_path.is_file():
        cur_m = distill.evaluate(predictor(torch.load(cur_path, weights_only=True)), held)
    else:
        from collections import Counter
        majority = {d: Counter(ex.label for ex in held if ex.decision == d).most_common(1)[0][0]
                    for d in {e.decision for e in held}}
        cur_m = distill.evaluate(lambda ex: majority.get(ex.decision, ""), held)
    ok, reason = distill.should_promote(cand_m, cur_m)
    print(json.dumps({"promote": ok, "reason": reason, "candidate": cand_m.to_dict(), "current": cur_m.to_dict()}))
    return 0 if ok else 2


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--embed", action="store_true")
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--train", action="store_true")
    g.add_argument("--gate", action="store_true")
    ap.add_argument("--verdicts")
    ap.add_argument("--data")
    ap.add_argument("--model-dir", default="/models/laya")
    ap.add_argument("--out")
    ap.add_argument("--candidate")
    ap.add_argument("--current", default=None)
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--held-out-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    try:
        if a.embed:
            return cmd_embed(a)
        if a.dry_run:
            return cmd_dry_run(a)
        if a.train:
            return cmd_train(a)
        return cmd_gate(a)
    except (distill.DistillError, OSError, KeyError, ValueError) as e:
        print(f"train: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
