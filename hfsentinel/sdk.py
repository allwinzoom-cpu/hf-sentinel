"""Programmatic SDK for HF-Sentinel — run a dynamic black-box LLM security scan from Python, without the CLI.

:func:`scan` runs the same staged pipeline the CLI runs (scope authorization → recon → plan → campaign → report) with
sensible DEFAULTS baked in, and RETURNS a structured :class:`ScanResult` instead of writing files or printing. Every
advanced control keeps its default; a caller overrides only what they need, via the exposed keyword knobs or a full
``controls_config`` mapping. The SDK adds no third-party dependencies — it is a thin, headless wrapper over the existing
engines, so the FastAPI layer (and any other embedding) can reuse one audited scan path.

Security:
  * Deny-by-default scope. Without a signed ``scope_file``, authorization falls back to the built-in scope, which admits
    only the built-in safe targets (e.g. the bundled vuln-target); any other target raises :class:`ScopeError` before a
    single request is sent — exactly as the CLI behaves.
  * Dynamic only: this attacks a live inference endpoint; it never inspects model files, weights, or local models.
"""
from __future__ import annotations

import datetime as dt
import inspect
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hfsentinel.controls import resolve_controls, selected_ids
from hfsentinel.core.system_one import SystemOne, http_client
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.recon import RECON_BUDGET_USD, RECON_MAX_REQUESTS, TargetProfile, run_recon
from hfsentinel.engines.strategy_library import StrategyLibrary
from hfsentinel.report.build import assemble_report, new_run_id
from hfsentinel.scope import Attestation, authorize, load_allowed_signers, load_scope
from hfsentinel.secrets import optional_token
from hfsentinel.targets.openai_compat import BudgetExceeded
from hfsentinel.targets.resolve import ResolvedTarget, TargetURIError, client, parse
from hfsentinel.targets.resolve import resolve as resolve_target

# Run from the campaign loop and graded into the report; distinct from the recon oracle's own id set.
__all__ = ["ScanError", "ScanResult", "run_campaign_from_controls", "scan"]


class ScanError(RuntimeError):
    """A scan could not run (bad target, scope denied, budget exhausted). Scope denials raise ``scope.ScopeError``."""


@dataclass
class ScanResult:
    """The outcome of a scan: the full report document plus the headline fields a caller usually wants."""
    run_id: str
    target: str
    report: Any                   # the assembled report document (pydantic model)
    findings: list                # confirmed findings (report.findings)
    grade: dict                   # report.grade
    decisions: list               # campaign decisions log (incl. advisory/N-A extended-stage verdicts)
    recon: dict
    started: dt.datetime

    @property
    def confirmed(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        """The report as a plain dict (JSON-safe), for an API response or a file."""
        report = self.report
        if hasattr(report, "model_dump"):
            return report.model_dump(mode="json")
        return dict(report)


def _build_config(target: str, *, profile: str | None, categories: list[str] | None,
                  attacks: list[str] | None, exclude: list[str] | None,
                  trials: int | None, max_tokens: int | None, temperature: float | None,
                  seed: int | None, concurrency: int | None, budget_usd: float | None,
                  max_requests: int | None, controls_config: dict | None) -> dict:
    """Assemble a controls config from the exposed knobs. Only set values are included, so unset knobs keep their
    defaults (or the named profile preset). A full ``controls_config`` is deep-merged last for advanced overrides."""
    cfg: dict[str, Any] = {"target": target}
    if profile:
        cfg["profile"] = profile
    select: dict[str, Any] = {}
    if categories is not None:
        select["categories"] = list(categories)
    if attacks is not None:
        select["attacks"] = list(attacks)
    if exclude is not None:
        select["exclude"] = list(exclude)
    if select:
        cfg["select"] = select
    io: dict[str, Any] = {}
    for key, value in (("trials", trials), ("max_tokens", max_tokens), ("temperature", temperature),
                       ("seed", seed), ("concurrency", concurrency)):
        if value is not None:
            io[key] = value
    if io:
        cfg["target_io"] = io
    budget: dict[str, Any] = {}
    if budget_usd is not None:
        budget["usd"] = budget_usd
    if max_requests is not None:
        budget["max_requests"] = max_requests
    if budget:
        cfg["budget"] = budget
    if controls_config:
        cfg = _deep_merge(cfg, controls_config)
    return cfg


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _recon(t: ResolvedTarget, controls, *, negotiate_features: bool) -> TargetProfile:
    gov = Governor(Ledger(RECON_MAX_REQUESTS, RECON_BUDGET_USD, deadline=time.monotonic() + 300),
                   rate_limit_per_min=controls.target_io.rate_limit, concurrency=1)
    target = client(t, optional_token(), max_requests=RECON_MAX_REQUESTS, governor=gov,
                    user_agent=controls.target_io.user_agent)
    try:
        return run_recon(target, None, negotiate_features=negotiate_features)
    except BudgetExceeded as e:
        raise ScanError("recon budget exhausted") from e


def scan(target: str, *,
         scope_file: str | Path | None = None,
         signers_file: str | Path | None = None,
         via: str = "auto",
         profile: str | None = None,
         categories: list[str] | None = None,
         attacks: list[str] | None = None,
         exclude: list[str] | None = None,
         extended: bool = False,
         check_triggered: bool = False,
         check_obfuscation: bool = False,
         check_evolution: bool = False,
         check_minimization: bool = False,
         trials: int | None = None,
         max_tokens: int | None = None,
         temperature: float | None = None,
         seed: int | None = None,
         concurrency: int | None = None,
         budget_usd: float | None = None,
         max_requests: int | None = None,
         system_one_url: str | None = None,
         system_one_multilingual_url: str | None = None,
         negotiate_features: bool = False,
         controls_config: dict | None = None) -> ScanResult:
    """Run a full scan and return a :class:`ScanResult`.

    `target` is a target URI (e.g. ``hf-provider://org/model@provider``). `profile` selects a preset
    (``quick``/``standard``/``deep``/``agentic``/``hallucination``), and `categories`/`attacks`/`exclude` refine the
    technique selection; the rest keep sensible defaults. `extended` runs the extended capability pass (agentic D-cores,
    attack-discipline, standalone engines) as advisory/N-A, and the four `check_*` flags enable the Laya-advised optional
    stages. Deny-by-default scope — see the module docstring. Raises :class:`ScanError` on a bad target/budget and
    ``scope.ScopeError`` when the target is not in scope (before any request is sent)."""
    started = dt.datetime.now(dt.timezone.utc)
    run_id = new_run_id(started)

    cfg = _build_config(target, profile=profile, categories=categories, attacks=attacks, exclude=exclude,
                        trials=trials, max_tokens=max_tokens, temperature=temperature, seed=seed,
                        concurrency=concurrency, budget_usd=budget_usd, max_requests=max_requests,
                        controls_config=controls_config)
    controls = resolve_controls(config=cfg).controls

    try:
        parsed = parse(target)
    except (TargetURIError, ValueError) as e:
        raise ScanError(f"unsupported or malformed target URI: {e}") from e

    # Deny-by-default scope: a signed scope file widens what is authorized; without one, only built-in safe targets pass.
    verified = (load_scope(Path(scope_file), signers=load_allowed_signers(Path(signers_file) if signers_file else None))
                if scope_file is not None else None)
    authorize(verified, parsed, resolved=False)                       # pre-resolve gate (raises ScopeError; no requests)
    resolved = resolve_target(parsed, via=via, token=optional_token())
    attestation: Attestation = authorize(verified, resolved, resolved=True)   # post-resolve gate

    profile_obj = _recon(resolved, controls, negotiate_features=negotiate_features)
    library = StrategyLibrary()
    plan = build_plan(resolved, selected=selected_ids(controls), profile=profile_obj, controls=controls, library=library)
    gov = Governor.from_controls(controls)
    try:
        target_client = client(resolved, optional_token(), max_requests=controls.budget.max_requests, governor=gov,
                               user_agent=controls.target_io.user_agent)
    except TargetURIError as e:
        raise ScanError(str(e)) from e

    s1 = SystemOne(http_client(system_one_url) if system_one_url else None,
                   multilingual_client=http_client(system_one_multilingual_url) if system_one_multilingual_url else None)

    # Optional stage flags are only forwarded if the installed run_campaign actually accepts them, so the SDK works across
    # campaign versions (e.g. `extended` may not yet be present in a given build); an unsupported flag is simply skipped.
    optional_flags = {"check_triggered": check_triggered, "check_obfuscation": check_obfuscation,
                      "check_evolution": check_evolution, "check_minimization": check_minimization,
                      "extended": extended}
    accepted = set(inspect.signature(run_campaign).parameters)
    optional_flags = {k: v for k, v in optional_flags.items() if k in accepted}
    result = run_campaign(target_client, gov, plan, trials=controls.target_io.trials,
                          temperature=controls.target_io.temperature, max_tokens=controls.target_io.max_tokens,
                          concurrency=controls.target_io.concurrency, seed=controls.target_io.seed,
                          system_one=s1, profile=profile_obj, library=library, controls=controls,
                          keep_transcripts=controls.output.save_transcripts, **optional_flags)

    recon = profile_obj.summary()
    campaign = {"decisions": result.decisions, "attack_requests": result.requests,
                "exhaustive_requests": result.exhaustive_requests,
                "requests_saved": result.exhaustive_requests - result.requests,
                "cross_verified": result.cross_verified, "experimental": result.experimental,
                "judge_calls_made": result.judge_calls_made, "judge_calls_saved": result.judge_calls_saved,
                "triage_agreement": result.triage_agreement, "baseline": result.baseline}
    report_doc = assemble_report(resolved=resolved, ref=controls.target, controls=controls, attestation=attestation,
                                 recon=recon, plan=plan, result=result, ledger=gov.ledger.snapshot(),
                                 run_id=run_id, started=started, campaign=campaign)

    return ScanResult(run_id=run_id, target=target, report=report_doc, findings=list(report_doc.findings),
                      grade=report_doc.grade, decisions=result.decisions, recon=recon, started=started)


def run_campaign_from_controls(*args, **kwargs):  # pragma: no cover - thin compatibility alias
    """Deprecated alias kept for embedders; use :func:`scan`."""
    return scan(*args, **kwargs)
