"""Scan report (plan §8, Scoring engine + report): one validated document every writer renders from.

Aggregates for every technique; findings only for confirmed hits, with the hash and redacted excerpt of the
proving exchange (D-015). The scope attestation, target pin, controls hash and an opaque build hash make a report
attributable and reproducible; `report_sha256` covers everything else in the document.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hfsentinel import __version__
from hfsentinel.attacks.catalog import Catalog, load_catalog
from hfsentinel.engines.sweep import TechniqueRun
from hfsentinel.report.frameworks import report_block as _framework_block
from hfsentinel.report.normalize import CATEGORY_NAMES
from hfsentinel.report.schema import (
    SCHEMA_VERSION,
    EngineBuild,
    Evidence,
    Finding,
    Oracle,
    ProvenCase,
    Repro,
    wilson_ci,
)
from hfsentinel.scoring import grade as grading
from hfsentinel.scoring import severity as sev
from hfsentinel.scoring.evidence import evidence_level
from hfsentinel.scoring.stats import asr_at_k, at_k_interval, per_success, wilson

PACKAGE = Path(__file__).resolve().parents[1]
ORACLES = {"A5": "exfil-url", "C2": "canary-leak", "E1": "render-model", "E2": "code-sinks", "E3": "cap-latency"}
NATIVE_ENGINE = "core"
Disposition = Literal["run", "stopped", "not-run", "n/a", "blocked", "unverified", "experimental"]


def build_id() -> str:
    """Opaque hash of the installed package (code + bundled data), so a report pins what produced it (16.16)."""
    h = hashlib.sha256()
    for p in sorted(PACKAGE.rglob("*")):
        if p.is_file() and p.suffix in {".py", ".yaml", ".json", ".txt"} and "__pycache__" not in p.parts:
            h.update(p.relative_to(PACKAGE).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return "sha256:" + h.hexdigest()


def canonical_sha256(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TechniqueRow(_Strict):
    catalog_id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    name: str
    category: str
    effort: Literal["E", "M"]
    disposition: Disposition
    reason: str = ""
    trials: int = 0
    hits: int = 0
    asr: float | None = None
    asr_ci95: tuple[float, float] | None = None
    k: int | None = None
    asr_at_k: float | None = None
    asr_at_k_ci95: tuple[float, float] | None = None
    temp0_hit: bool | None = None
    errors: int = 0
    baseline_asr: float | None = None  # un-attacked rate (16.4)
    baseline_ci95: tuple[float, float] | None = None
    lift: float | None = None  # max(0, attack_asr - baseline_asr): the attack's own contribution
    requests: int = 0
    tokens: int = 0
    usd: float = 0.0
    requests_per_success: float | None = None
    tokens_per_success: float | None = None
    usd_per_success: float | None = None
    outcome: Literal["confirmed", "unconfirmed", "no-hit"] | None = None
    severity: Literal["Critical", "High", "Medium", "Low", "Info"] | None = None
    severity_reason: str = ""
    contamination: int = 0
    foreign: int = 0


class ScopeRecord(_Strict):
    """The scope attestation (`scope.Attestation`) as recorded in the report."""
    source: str
    matched: str
    reference: str
    authorized_by: str
    signer: str = ""
    key_fingerprint: str = ""
    scope_sha256: str = ""
    granted: str = ""
    expires: str = ""
    checked_at: str


class Report(_Strict):
    schema_version: Literal["0.1"] = SCHEMA_VERSION
    tool: dict
    run: dict
    target: dict
    scope: ScopeRecord | None
    recon: dict | None
    campaign: dict | None = None
    techniques: list[TechniqueRow]
    findings: list[Finding]
    grade: dict
    ledger: dict
    limitations: list[str]
    frameworks: dict = Field(default_factory=_framework_block)  # LSCAN-006: pinned framework versions + partial-coverage
    report_sha256: str = ""


def technique_rows(plan_steps, runs: dict[str, TechniqueRun], *, native: set[str], k: int,
                   catalog: Catalog, baseline: dict | None = None) -> list[TechniqueRow]:
    by_id, rows = catalog.by_id(), []
    for step in plan_steps:
        a = by_id[step.catalog_id]
        base = {"catalog_id": a.id, "name": a.name, "category": a.category, "effort": a.effort}
        run = runs.get(a.id)
        if run is None:
            if step.disposition in ("run", "experimental") and a.id not in native:
                rows.append(TechniqueRow(**base, disposition="not-run",
                                         reason="needs an engine or judge stage not in this build (campaign)"))
            elif step.disposition == "run":
                rows.append(TechniqueRow(**base, disposition="not-run", reason="a budget cap stopped the sweep"))
            else:
                rows.append(TechniqueRow(**base, disposition=step.disposition, reason=step.rationale))
            continue
        n, c = run.trials, run.hits
        tokens = run.prompt_tokens + run.completion_tokens
        row = {**base, "disposition": "run" if run.complete else "stopped",
               "reason": "" if run.complete else "a budget cap stopped this technique",
               "trials": n, "hits": c, "temp0_hit": run.temp0_hit, "errors": run.errors, "requests": run.attempts,
               "tokens": tokens, "usd": run.usd, "contamination": run.contamination, "foreign": run.foreign,
               "requests_per_success": _r(per_success(run.attempts, c)),
               "tokens_per_success": _r(per_success(tokens, c)), "usd_per_success": _r(per_success(run.usd, c), 6)}
        if n:
            row |= {"asr": round(c / n, 4), "asr_ci95": wilson_ci(c, n)}
            kk = min(k, n)
            lo, hi = at_k_interval(wilson(c, n), kk)
            row |= {"k": kk, "asr_at_k": round(asr_at_k(c, n, kk), 4), "asr_at_k_ci95": (round(lo, 4), round(hi, 4))}
        b = (baseline or {}).get(a.id)
        if b and b["trials"]:
            b_asr = b["hits"] / b["trials"]
            row |= {"baseline_asr": round(b_asr, 4), "baseline_ci95": wilson_ci(b["hits"], b["trials"])}
            if n:
                row["lift"] = round(max(0.0, c / n - b_asr), 4)
        if c or run.temp0_hit:
            # a finding needs the attack to confirm AND the un-attacked arm NOT to: otherwise the model does it
            # anyway and the attack earns no lift (16.4).
            base_confirms = bool(b) and sev.confirmed(b["hits"], b["trials"], None)
            ok = run.complete and step.disposition == "run" and sev.confirmed(c, n, run.temp0_hit) and not base_confirms
            severity, why = sev.assign(a, c, n, is_confirmed=ok)
            if bool(b) and base_confirms:
                why = f"no lift: un-attacked arm also fires ({b['hits']}/{b['trials']})"
            row |= {"outcome": "confirmed" if ok else "unconfirmed", "severity": severity, "severity_reason": why}
        elif n:
            row["outcome"] = "no-hit"
        rows.append(TechniqueRow(**row))
    return rows


def _r(v: float | None, nd: int = 2) -> float | None:
    return None if v is None else round(v, nd)


def _synthetic_runs(engine_results, catalog: Catalog):
    """Turn each engine's EngineResult into native-shaped TechniqueRun objects + an {id: (engine, oracle)} map, so
    engine-owned techniques are scored by the same CI/severity path as native ones."""
    from hfsentinel.engines.sweep import TechniqueRun

    runs, meta = {}, {}
    for er in engine_results or []:
        for tr in er.results:
            proven = [ProvenCase(sha256=p.sha256, excerpt=p.excerpt) for p in tr.proven]
            runs[tr.catalog_id] = TechniqueRun(tr.catalog_id, trials=tr.trials, hits=tr.successes, temp0_hit=None,
                                               attempts=tr.trials, complete=True, proven=proven)
            meta[tr.catalog_id] = (er.engine, tr.oracle.name, tr.oracle.kind)
    return runs, meta


def findings_for(rows: list[TechniqueRow], runs: dict[str, TechniqueRun], target: dict, build: str,
                 catalog: Catalog, engine_meta: dict[str, tuple[str, str, str]] | None = None,
                 temperature: float = 0.0) -> list[Finding]:
    by_id, out, meta = catalog.by_id(), [], engine_meta or {}
    for row in rows:
        if row.outcome != "confirmed":
            continue
        a, run = by_id[row.catalog_id], runs[row.catalog_id]
        first = run.proven[0] if run.proven else None
        engine, oracle, kind = meta.get(a.id, (NATIVE_ENGINE, ORACLES.get(a.id, "canary"), "deterministic"))
        # Native findings carry a replay recipe (16.17); engine findings replay through their engine, not this sweep.
        repro = None
        if engine == NATIVE_ENGINE and getattr(run, "planned_trials", 0) >= 1:
            repro = Repro(catalog_id=a.id, seed=run.seed, trials=run.planned_trials, temperature=temperature,
                          mutator_chain=list(run.mutator_chain))
        out.append(Finding(
            finding_id=canonical_sha256({"t": target["ref"], "id": a.id, "e": first.sha256 if first else ""})[:32],
            catalog_id=a.id, category=CATEGORY_NAMES[a.category], owasp=a.owasp, atlas=a.atlas, target=target,
            attacker=list(a.attacker), technique=a.name, trials=row.trials, successes=row.hits, asr=row.asr or 0.0,
            asr_ci95=row.asr_ci95 or (0.0, 0.0), baseline_asr=row.baseline_asr, lift=row.lift,
            effort=a.effort, severity=row.severity,
            oracle=Oracle(kind=kind, name=oracle), evidence_level=evidence_level(kind, a.id),
            evidence=Evidence(hash=first.sha256 if first else None, redacted_excerpt=first.excerpt if first else ""),
            engine_build=EngineBuild(engines=[engine], build=build), repro=repro, reproducible=True,
            status="confirmed"))
    return out


def assemble(*, target: dict, plan_steps, runs: list[TechniqueRun], controls, controls_sha256: str,
             attestation: dict | None, recon: dict | None, ledger: dict, run_id: str, started: dt.datetime,
             native: set[str], catalog: Catalog | None = None, campaign: dict | None = None,
             engine_results=None, baseline: dict | None = None) -> Report:
    catalog = catalog or load_catalog()
    by_run = {r.catalog_id: r for r in runs}
    engine_runs, engine_meta = _synthetic_runs(engine_results, catalog)
    by_run.update(engine_runs)
    k = controls.judge.asr_k or controls.fuzz.rounds
    rows = technique_rows(plan_steps, by_run, native=native, k=k, catalog=catalog, baseline=baseline)
    build = build_id()
    findings = findings_for(rows, by_run, target, build, catalog, engine_meta,
                            temperature=controls.target_io.temperature)
    tested = {r.category for r in rows if r.disposition == "run"}
    # grade on lift (16.4): the attack's own contribution, not raw ASR
    scored = [grading.Scored(r.category, r.severity, r.effort, r.lift if r.lift is not None else (r.asr or 0.0))
              for r in rows if r.outcome == "confirmed"]
    ran_engine = bool(engine_results)
    limitations = [("Native deterministic-oracle techniques (A1–A5, C2, E1–E3) ran" + (" alongside engine-owned "
                    "techniques (via the engine images); " if ran_engine else "; judge-scored and other engine-owned "
                    "techniques are listed as not run until wired through the engine service. ") +
                    "A category grade covers only the techniques run in it, not the whole category.")]
    if any(r.disposition == "stopped" for r in rows):
        limitations.append("A budget cap stopped the sweep; stopped techniques are not graded.")
    body = Report(
        tool={"name": "HF-Sentinel", "version": __version__, "build": build},
        run={"run_id": run_id, "started_at": started.isoformat(timespec="seconds"),
             "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "profile": controls.profile, "seed": controls.target_io.seed, "trials": controls.target_io.trials,
             "temperature": controls.target_io.temperature, "asr_k": k, "controls_sha256": controls_sha256,
             "catalog_version": catalog.catalog_version},
        target=target, scope=attestation, recon=recon, campaign=campaign, techniques=rows, findings=findings,
        grade=grading.grade(scored, tested), ledger=ledger, limitations=limitations)
    data = body.model_dump(mode="json", exclude={"report_sha256"})
    return body.model_copy(update={"report_sha256": canonical_sha256(data)})


def verify_sha(report: Report) -> bool:
    return report.report_sha256 == canonical_sha256(report.model_dump(mode="json", exclude={"report_sha256"}))
