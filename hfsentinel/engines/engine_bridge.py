"""Bridge from the campaign to the engine images (plan 16.18/16.22, D-018): run an engine-owned technique inside its
hardened engine container and fold the result into the scored report.

Attack content for catalog B lives in the engines (garak personas → B1, PyRIT converter stacks → B2); HF-Sentinel
authors none. Each engine runs through the existing egress-controlled sandbox (`engines/sandbox.py`), reads a job spec,
and writes the `EngineResult` contract (`hfsentinel/report/schema.py`); this bridge validates it and converts it with
the normal `report/normalize.py` path, so engine findings are scored exactly like native ones.

This is the operator-side path: it needs Docker and the built engine images, so it runs only when `scan --engines` is
passed outside the hardened scan container. The always-on engine service (a network job API, no Docker socket in the
CLI container, D-018) is the later engine-service task; the job-spec and result contract here are already its shape.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from hfsentinel.engines.nondisclosure import scrub
from hfsentinel.report.schema import EngineResult, EngineTarget, Oracle, ProvenCase, TechniqueResult

MAX_CANDIDATES = 2000  # cap the in-memory judge-scored stream per run (D-005/D-017 budget safety)

# Engine-owned catalog techniques this bridge can run today (adapter alias + the upstream engine key, 16.21).
ENGINE_TECHNIQUES: dict[str, tuple[str, str]] = {
    "B1": ("probe-suite", "garak"),   # persona-override probes + deterministic detectors
    "B2": ("orchestrator", "pyrit"),  # encoding/obfuscation converter stacks + substring scorer
}
ADAPTER_DIR = "/opt/hfsentinel-adapters"
ENGINE_ALIAS = {key: alias for alias, key in ENGINE_TECHNIQUES.values()}
MAX_RESULT_BYTES = 4_000_000


@dataclass
class EngineOutcome:
    engine: str
    techniques: list[str]
    result: EngineResult | None = field(default=None, repr=False)
    error: str = ""
    # Judge-scored candidate exchanges (goal + raw response) for techniques whose oracle is the judge panel, not a
    # deterministic detector. Held in memory only; the ephemeral channel file is deleted once read (D-015/16.17).
    candidates: list[dict] = field(default_factory=list, repr=False)


def plan_engine_work(technique_ids: list[str]) -> dict[str, list[str]]:
    """Group requested engine-owned techniques by engine key; unknown IDs are ignored (recorded by the caller)."""
    work: dict[str, list[str]] = {}
    for cid in technique_ids:
        if cid in ENGINE_TECHNIQUES:
            work.setdefault(ENGINE_TECHNIQUES[cid][1], []).append(cid)
    return work


def _job_spec(label: str, techniques: list[str], target: dict, trials: int, canary: str,
              judge: dict | None) -> dict:
    return {"label": label, "target": target, "techniques": sorted(techniques), "trials": trials,
            "canary": canary, "judge": judge}


def run_engine(engine_key: str, techniques: list[str], *, target: dict, trials: int, out_dir: Path,
               runner: Callable, max_seconds: int = 900, allow: str = "",
               label: str | None = None) -> EngineOutcome:
    """Run one engine over its techniques and return the validated EngineResult. `runner` is `sandbox.run` in
    production and a fake in tests; `target` is {ref, endpoint, model}."""
    alias = ENGINE_ALIAS[engine_key]
    label = label or f"{alias}-{secrets.token_hex(3)}"
    canary = "HS" + secrets.token_hex(8).upper()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{label}.job.json").write_text(json.dumps(
        _job_spec(label, techniques, target, trials, canary, None)), encoding="utf-8")
    command = ["python", "-W", "ignore", f"{ADAPTER_DIR}/{alias}.py", f"/out/{label}.job.json"]
    try:
        runner(engine_key, label, command, max_seconds, allow, out_dir)
    except Exception as e:  # noqa: BLE001 — surface any sandbox failure as a recorded engine error, never a crash
        return EngineOutcome(alias, techniques, error=f"engine run failed: {type(e).__name__}")
    path = out_dir / f"{label}.engine.json"
    if not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
        return EngineOutcome(alias, techniques, error="engine produced no usable result")
    try:
        result = EngineResult.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return EngineOutcome(alias, techniques, error="engine result failed schema validation")
    return EngineOutcome(alias, techniques, result=_sanitize(result),
                         candidates=_read_candidates(out_dir / f"{label}.candidates.jsonl", alias))


def _read_candidates(path: Path, engine: str) -> list[dict]:
    """Read the ephemeral judge-scored candidate channel (one JSON exchange per line) and delete it — the raw responses
    are judged in memory and never persisted (D-015/16.17 'raw engine dumps are summarized then deleted')."""
    if not path.is_file():
        return []
    out = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or len(out) >= MAX_CANDIDATES:
                continue
            rec = json.loads(line)
            cid, goal, response = rec.get("catalog_id"), rec.get("goal"), rec.get("response")
            if cid in ENGINE_TECHNIQUES and isinstance(goal, str) and isinstance(response, str):
                out.append({"engine": engine, "catalog_id": cid, "goal": goal, "response": response})
    except ValueError:
        out = []  # a malformed channel yields no candidates rather than a crash
    finally:
        path.unlink(missing_ok=True)  # delete the raw channel whether or not it parsed
    return out


def judge_candidates(candidates: list[dict], panel, system_one, *, target: dict, policy=None):
    """Engine-service judge path (plan 16.19 + 16.18 S5): run engine-emitted judge-scored candidate exchanges through
    the triage-gated judge panel and fold the judge-confirmed ones into the report as findings.

    Laya triage gates each judge call (`judges.ensemble.TriagedPanel`): a confident refusal skips the panel (a saved
    call); everything else is judged. Returns `(engine_results, stats)` — synthetic `EngineResult`s (oracle kind
    `judge`, grouped by engine alias + catalog id) carrying only judge-confirmed cases as proven, scored by the normal
    engine-folding path, plus the triage savings (`judge_calls_made`/`saved`/`triage_agreement`). Raw responses are
    judged in memory; only confirmed cases keep a short redacted excerpt (D-015)."""
    if not candidates:
        return [], {"judge_calls_made": 0, "judge_calls_saved": 0, "judge_calls_saved_fraction": 0.0,
                    "triage_agreement": None}
    from hfsentinel.judges.ensemble import TriagedPanel
    tp = TriagedPanel(panel, system_one, policy=policy)
    confirmed: dict[tuple[str, str], list[ProvenCase]] = {}
    trials: dict[tuple[str, str], int] = {}
    for c in candidates:
        key = (c["engine"], c["catalog_id"])
        trials[key] = trials.get(key, 0) + 1
        decision, _judged = tp.decide(c["goal"], c["response"])
        if decision.outcome == "finding":
            digest = hashlib.sha256(f"{c['goal']}\0{c['response']}".encode()).hexdigest()
            excerpt = scrub(" ".join(c["response"].split()))[:200]
            confirmed.setdefault(key, []).append(ProvenCase(sha256=digest, excerpt=excerpt))
    by_engine: dict[str, list[TechniqueResult]] = {}
    for (engine, cid), n in trials.items():
        proofs = confirmed.get((engine, cid), [])
        by_engine.setdefault(engine, []).append(TechniqueResult(
            catalog_id=cid, technique="judge-scored jailbreak", trials=n, successes=len(proofs),
            oracle=Oracle(kind="judge", name="judge-panel"), proven=proofs))
    results = [EngineResult(schema_version="0.1", engine=engine,
                            target=EngineTarget(ref=target["ref"], model=target.get("model") or "?"), results=techs)
               for engine, techs in by_engine.items()]
    return results, tp.stats.as_dict()


def _sanitize(result: EngineResult) -> EngineResult:
    """Non-disclosure trust boundary (16.16): scrub upstream tool names from everything an adapter wrote as free text —
    error tails, technique/oracle display names and proven excerpts — before the result reaches the report or console.
    The adapter already scrubs at write time; this is the authoritative second pass with the full term set."""
    return result.model_copy(update={
        "errors": [scrub(e) for e in result.errors],
        "results": [tr.model_copy(update={
            "technique": scrub(tr.technique),
            "oracle": Oracle(kind=tr.oracle.kind, name=scrub(tr.oracle.name)),
            "proven": [ProvenCase(sha256=p.sha256, excerpt=scrub(p.excerpt)) for p in tr.proven],
        }) for tr in result.results],
    })
