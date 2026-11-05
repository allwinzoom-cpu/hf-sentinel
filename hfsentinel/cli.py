"""HF-Sentinel command line: `resolve`, `scan [--config] [--dry-run] [--print-config]`, `report`.

Output is HF-Sentinel's own (D-014): no upstream tool names, no tracebacks, and every printed string is stripped of
control characters so attacker-influenced text cannot drive the operator's terminal.

Exit codes (stable): 0 ok · 1 internal error · 2 usage error · 3 refused by scope · 4 invalid input ·
5 not supported in this build · 6 Hugging Face Hub unavailable · 10 a confirmed finding meets --fail-on.
"""
from __future__ import annotations

import datetime as dt
import json
import secrets
import time
from enum import Enum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
import yaml
from pydantic import ValidationError

from hfsentinel.controls import (
    FLAG_PATHS,
    ControlError,
    Resolved,
    flatten,
    load_config,
    resolve_controls,
    selected_ids,
    to_config,
)
from hfsentinel.core.system_one import SystemOne, http_client
from hfsentinel.engines.campaign import run_campaign
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import Plan, build_plan
from hfsentinel.engines.recon import RECON_BUDGET_USD, RECON_MAX_REQUESTS, TargetProfile, run_recon
from hfsentinel.engines.strategy_library import StrategyLibrary
from hfsentinel.engines.sweep import NATIVE, TechniqueRun
from hfsentinel.report import render
from hfsentinel.report.build import assemble, canonical_sha256
from hfsentinel.report.schema import Finding
from hfsentinel.scope import Attestation, ScopeError, authorize, load_allowed_signers, load_scope
from hfsentinel.scoring.severity import at_least
from hfsentinel.secrets import SecretNotFound, hf_token
from hfsentinel.targets import hub
from hfsentinel.targets.openai_compat import HF_ROUTER, BudgetExceeded
from hfsentinel.targets.resolve import ResolvedTarget, TargetURIError, UnsupportedTarget, client, parse
from hfsentinel.targets.resolve import resolve as resolve_target

EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_SCOPE, EXIT_INPUT, EXIT_UNSUPPORTED, EXIT_HUB = 0, 1, 2, 3, 4, 5, 6
EXIT_FINDINGS = 10
WRITABLE_FORMATS = ("json", "sarif", "md", "html", "card")  # html: 16.5 safe encoding; card: model-card snippet
MAX_REPORT_BYTES = 10_000_000

app = typer.Typer(name="hfsentinel", help="HF-Sentinel — dynamic black-box LLM security testing (authorized targets "
                  "only).", add_completion=False, no_args_is_help=True, pretty_exceptions_enable=False)

TargetArg = Annotated[str, typer.Argument(help="hf-provider://org/model[@provider], hf-endpoint://<host>[#model], "
                                          "hf-space://owner/space[#model], openai+https://host/v1#model or "
                                          "hf-job://org/model[@flavor]", show_default=False)]


class Via(str, Enum):
    auto = "auto"
    direct = "direct"


ViaOpt = Annotated[Via, typer.Option(help="auto: pin the target via read-only Hub metadata; direct: no Hub calls.")]


def _clean(value: object, limit: int = 120) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _fail(message: str, code: int) -> typer.Exit:
    typer.echo(f"hfsentinel: {_clean(message, 300)}", err=True)
    return typer.Exit(code)


def _optional_token() -> str | None:
    try:
        return hf_token()
    except SecretNotFound:
        return None  # public repos resolve without one; the Hub hides private/gated ones


def _parse(uri: str) -> ResolvedTarget:
    try:
        return parse(uri)
    except UnsupportedTarget as e:
        raise _fail(str(e), EXIT_UNSUPPORTED) from None
    except TargetURIError as e:
        raise _fail(str(e), EXIT_INPUT) from None


def _print_attestation(a: Attestation | None) -> None:
    if a is None:
        typer.echo("scope     not checked (a dry run sends nothing) — live traffic needs a target in a signed "
                   "--scope file or a built-in source")
        return
    typer.echo(f"scope     in scope · source {a.source} · ref {_clean(a.reference, 80)} · authorized by "
               f"{_clean(a.authorized_by, 80)}")
    if a.signer:
        typer.echo(f"          signed by {_clean(a.signer, 80)} {a.key_fingerprint} · valid {a.granted}..{a.expires} "
                   f"· scope sha256 {a.scope_sha256[:16]}…")
    typer.echo(f"          matched {_clean(a.matched, 200)} · checked {a.checked_at}")


def _resolve(uri: str, via: Via):
    try:
        target = parse(uri)
        return resolve_target(target, via=via.value, token=_optional_token() if via is Via.auto else None)
    except UnsupportedTarget as e:
        raise _fail(str(e), EXIT_UNSUPPORTED) from None
    except TargetURIError as e:
        raise _fail(str(e), EXIT_INPUT) from None
    except hub.HubNotFound as e:
        raise _fail(f"{target.kind} {target.space or target.model}: {e}", EXIT_INPUT) from None
    except hub.HubError as e:
        raise _fail(str(e), EXIT_HUB) from None


def _print_plan(plan: Plan) -> None:
    t = plan.target
    typer.echo("HF-Sentinel attack plan (no requests sent to the target)")
    typer.echo(f"target    {_clean(t.uri, 300)}")
    typer.echo(f"  kind      {t.kind}")
    for label, value in (("space", t.space), ("api", t.api and f"/{t.api}"), ("model", t.model),
                         ("provider", t.provider), ("flavor", t.flavor), ("endpoint", t.base_url)):
        if value:
            typer.echo(f"  {label:<9} {_clean(value, 300)}")
    for note in t.notes:
        typer.echo(f"  note      {_clean(note, 300)}")
    typer.echo(f"catalog   v{plan.catalog_version} · {len(plan.steps)} attacks: {plan.count('run')} run · "
               f"{plan.count('experimental')} experimental (not scored) · {plan.count('unverified')} unverified · "
               f"{plan.count('blocked')} blocked · {plan.count('n/a')} n/a")
    typer.echo("recon     " + ("profile applied" if plan.recon else "not run — conditional attacks stay unverified "
                                                                       "(scan --dry-run --recon)"))
    typer.echo("engines   routing not yet assigned in this build")
    typer.echo("")
    typer.echo(f"{'#':>3} {'ID':<4} {'PLAN':<12} {'GAIN':>7} {'REQ':>4}  {'ATTACK':<44} WHY")
    for i, s in enumerate(plan.steps, 1):
        gain = f"{s.score:.3f}" if s.disposition in ("run", "experimental") else "-"
        why = s.rationale + (f"; mutators {','.join(s.mutators)}" if s.mutators else "")
        typer.echo(f"{i:>3} {s.catalog_id:<4} {s.disposition:<12} {gain:>7} {s.requests:>4}  "
                   f"{_clean(s.name, 44):<44} {_clean(why, 160)}".rstrip())


def _router_metadata(t: ResolvedTarget) -> tuple[dict, object | None]:
    """Router-declared capabilities and listed pricing for provider targets (({}, None) otherwise)."""
    if t.kind != "hf-provider":
        return {}, None
    try:
        found = hub.router_declared(t.model, t.provider)
    except hub.HubError:
        return {}, None
    if not found:
        return {}, None
    model, prov = found
    return ({"supports_tools": prov.supports_tools, "supports_structured_output": prov.supports_structured_output,
             "image_input": "image" in model.architecture.input_modalities, "context_length": prov.context_length},
            prov.pricing)


def _run_recon(t: ResolvedTarget, controls) -> TargetProfile:
    gov = Governor(Ledger(RECON_MAX_REQUESTS, RECON_BUDGET_USD, deadline=time.monotonic() + 300),
                   rate_limit_per_min=controls.target_io.rate_limit, concurrency=1)
    token = _optional_token()
    try:
        target = client(t, token, max_requests=RECON_MAX_REQUESTS, governor=gov,
                        user_agent=controls.target_io.user_agent)
    except TargetURIError as e:
        raise _fail(str(e), EXIT_INPUT) from None
    declared, pricing = _router_metadata(t)
    if pricing:
        gov.set_price(target.rate_key, pricing.input, pricing.output)
    try:
        profile = run_recon(target, declared)
    except BudgetExceeded:
        raise _fail("recon budget exhausted", EXIT_INPUT) from None
    led = gov.ledger.snapshot()
    typer.echo(f"recon     {profile.requests} requests · ${led['cost_reported_usd'] + led['cost_priced_usd']:.5f} "
               f"(+${led['cost_estimated_usd']:.5f} estimated) · over-refusal {profile.over_refusal_rate} · "
               f"max_tokens accepted {profile.max_tokens_accepted}")
    for name, fact in profile.facts.items():
        shown = {True: "yes", False: "no", None: "unknown"}[fact.value]
        typer.echo(f"  {name:<22} {shown:<8} {_clean(fact.reason, 60)}")
    for d in [k for k in ("supports_tools", "supports_structured_output", "image_input") if k in declared]:
        typer.echo(f"  declared {d:<22} {declared[d]}")
    for note in profile.disagreements:
        typer.echo(f"  DISAGREES {_clean(note, 120)}")
    typer.echo("")
    return profile


@app.command()
def resolve(target: TargetArg, via: ViaOpt = Via.auto) -> None:
    """Resolve a target and print the attack plan. Sends nothing to the target."""
    _print_plan(build_plan(_resolve(target, via)))


def _opt(help_text: str, panel: str, *names: str):
    return typer.Option(*names, help=help_text, rich_help_panel=panel, show_default=False)


SEL, FUZ, TIO, JDG, BUD = "Selection", "Fuzzing", "Target I/O", "Judging & extras", "Budget & output"
_EMPTY = {"top_p": "provider default", "rate_limit": "provider-aware", "attacks": "— (categories apply)"}


def _show(value: object) -> str:
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return "—" if value is None else str(value)


def _print_controls(res: Resolved) -> None:
    typer.echo("controls  (value · source)")
    for path, value in flatten(to_config(res.controls)).items():
        leaf = path.rsplit(".", 1)[-1]
        if path == "judge.asr_k" and value is None:
            shown = f"= rounds ({res.controls.fuzz.rounds})"
        elif value is None and leaf in _EMPTY:
            shown = _EMPTY[leaf]
        else:
            shown = _show(value)
        typer.echo(f"  {path:<28} {_clean(shown, 90):<40} {res.sources.get(path, 'default')}")


@app.command()
def scan(target: Annotated[str | None, typer.Argument(help="Target URI (or `target:` in --config).",
                                                      show_default=False)] = None,
         config: Annotated[Path | None, typer.Option(help="sentinel.yaml with any of the controls below.",
                                                     show_default=False)] = None,
         scope: Annotated[Path | None, typer.Option(help="Scope file authorizing this target, signed with "
                                                    "ssh-keygen -Y sign -n hfsentinel-scope (reads FILE.sig).",
                                                    show_default=False)] = None,
         signers: Annotated[Path | None, typer.Option(help="OpenSSH allowed_signers trusted to sign scope files "
                                                      "(default: $HFS_ALLOWED_SIGNERS or "
                                                      "~/.config/hfsentinel/allowed_signers).",
                                                      show_default=False)] = None,
         dry_run: Annotated[bool, typer.Option("--dry-run", help="Print the plan and controls; send nothing.")] = False,
         print_config: Annotated[bool, typer.Option("--print-config", help="Print the resolved controls as "
                                                    "sentinel.yaml and exit; send nothing.")] = False,
         recon: Annotated[bool, typer.Option("--recon", help="With --dry-run: send the benign recon probe set "
                                             "(≤ 24 requests) and plan from the observed profile.")] = False,
         engines: Annotated[bool, typer.Option("--engines/--no-engines", help="Also run engine-owned techniques "
                                               "(catalog B via the engine images); needs Docker, so run outside "
                                               "the hardened container.")] = False,
         system_one: Annotated[str | None, typer.Option("--system-one", metavar="URL", help="Laya System-1 "
                                               "server URL (engines/laya --serve); advisory triage/routing, logged "
                                               "in the report. Off = every response goes to System-2.")] = None,
         system_one_multilingual: Annotated[str | None, typer.Option("--system-one-multilingual", metavar="URL",
                                               help="Laya multilingual-variant server URL; non-Latin-script replies "
                                               "route here instead of the English checkpoint. Off = non-Latin replies "
                                               "escalate to System-2.")] = None,
         judges: Annotated[bool, typer.Option("--judges/--no-judges", help="Score engine-emitted judge candidates "
                                               "with the System-2 panel (needs a token; D-017 judge budget). Laya "
                                               "triage gates each judge call. Off by default.")] = False,
         via: ViaOpt = Via.auto,
         profile: Annotated[str | None, _opt("quick|standard|deep|agentic|hallucination|diff|custom", SEL)] = None,
         categories: Annotated[str | None, _opt("Categories, e.g. A,B,H.", SEL)] = None,
         attacks: Annotated[str | None, _opt("Explicit attack IDs, e.g. B4,C1 (replace categories).", SEL)] = None,
         exclude: Annotated[str | None, _opt("Attack IDs to drop.", SEL)] = None,
         scans: Annotated[str | None, _opt("Scan types S1..S10.", SEL)] = None,
         status: Annotated[str | None, _opt("ready | ready+conditional | all.", SEL)] = None,
         seed_set: Annotated[str | None, _opt("forbidden-prompts | harm-behaviors | jailbreak-behaviors | "
                                              "adv-behaviors | custom:<file>.", SEL)] = None,
         goals: Annotated[Path | None, _opt("Custom attack-goal file.", SEL)] = None,
         sample: Annotated[str | None, _opt("Run N prompts (integer) or a fraction (0-1].", SEL)] = None,
         fuzz_type: Annotated[str | None, _opt("mutation,template,generative,search,replay,composite.", FUZ)] = None,
         rounds: Annotated[int | None, _opt("Rounds per prompt (best-of-N).", FUZ)] = None,
         max_attempts: Annotated[int | None, _opt("Attempt cap per goal.", FUZ)] = None,
         mutators: Annotated[str | None, _opt("case,shuffle,typo,base64,leet,homoglyph,unicode-tag,ascii-art,"
                                              "flip,cipher.", FUZ)] = None,
         mutation_rate: Annotated[float | None, _opt("Mutation intensity 0-1.", FUZ)] = None,
         max_turns: Annotated[int | None, _opt("Multi-turn depth.", FUZ)] = None,
         tap_width: Annotated[int | None, _opt("Tree search width.", FUZ)] = None,
         tap_depth: Annotated[int | None, _opt("Tree search depth.", FUZ)] = None,
         strategy_lib: Annotated[str | None, _opt("off | read | read-write.", FUZ)] = None,
         compose: Annotated[bool | None, _opt("Allow stacking attacks.", FUZ, "--compose/--no-compose")] = None,
         max_compose: Annotated[int | None, _opt("Max stacking depth.", FUZ)] = None,
         stop_on_success: Annotated[bool | None, _opt("Stop at the first win per goal, or keep measuring ASR@k.",
                                                      FUZ, "--stop-on-success/--continue-after-success")] = None,
         trials: Annotated[int | None, _opt("Scored repetitions per attack.", TIO)] = None,
         temperature: Annotated[float | None, _opt("Target sampling temperature.", TIO)] = None,
         top_p: Annotated[float | None, _opt("Target top-p.", TIO)] = None,
         max_tokens: Annotated[int | None, _opt("Target response cap.", TIO)] = None,
         seed: Annotated[int | None, _opt("RNG seed for mutators and sampling.", TIO)] = None,
         concurrency: Annotated[int | None, _opt("Parallel requests.", TIO)] = None,
         rate_limit: Annotated[int | None, _opt("Requests/min cap.", TIO)] = None,
         retry: Annotated[int | None, _opt("Retries per request.", TIO)] = None,
         timeout: Annotated[float | None, _opt("Per-request timeout (s).", TIO)] = None,
         user_agent: Annotated[str | None, _opt("User-Agent sent to the target (printable ASCII; default "
                                                "hfsentinel/<version>).", TIO)] = None,
         judge: Annotated[str | None, _opt("ensemble | rubric,classifier,guard,nli,deterministic.", JDG)] = None,
         asr_k: Annotated[int | None, _opt("k for ASR@k (default: rounds).", JDG)] = None,
         system_prompt: Annotated[Path | None, _opt("Deployer system prompt file.", JDG)] = None,
         tools: Annotated[Path | None, _opt("Mock-tool manifest (enables D*).", JDG)] = None,
         halluc_registries: Annotated[str | None, _opt("pypi,npm,crates,rubygems.", JDG)] = None,
         sink_url: Annotated[str | None, _opt("Controlled https exfil sink.", JDG)] = None,
         with_firewall: Annotated[bool | None, _opt("Also run the guardrail differential.", JDG,
                                                    "--with-firewall/--without-firewall")] = None,
         budget_usd: Annotated[float | None, _opt("Target spend cap (USD, ≤ 20).", BUD)] = None,
         budget_judge_usd: Annotated[float | None, _opt("Judge spend cap (USD, ≤ 25).", BUD)] = None,
         max_minutes: Annotated[int | None, _opt("Wall-clock cap.", BUD)] = None,
         max_requests: Annotated[int | None, _opt("Request cap.", BUD)] = None,
         out: Annotated[Path | None, _opt("Report directory.", BUD)] = None,
         formats: Annotated[str | None, _opt("md,json,sarif,html,card.", BUD, "--format")] = None,
         push_to: Annotated[str | None, _opt("Private HF dataset repo for reports.", BUD)] = None,
         fail_on: Annotated[str | None, _opt("critical | high | medium.", BUD)] = None,
         save_transcripts: Annotated[bool | None, _opt("Keep full transcripts of confirmed findings only.", BUD,
                                                       "--save-transcripts/--redact")] = None,
         ) -> None:
    """Scan an authorized target. Refuses without a verified scope file (fail-closed)."""
    flags = {k: v for k, v in locals().items() if k in FLAG_PATHS}
    try:
        res = resolve_controls(flags, load_config(config) if config else None)
    except ControlError as e:
        raise _fail(str(e), EXIT_INPUT) from None
    if print_config:
        typer.echo(yaml.safe_dump(to_config(res.controls), sort_keys=False).rstrip())
        return
    if not res.controls.target:
        raise _fail("no target: pass one or set `target:` in --config", EXIT_USAGE)
    if recon and not dry_run:
        raise _fail("--recon is implied by a live scan; use it with --dry-run", EXIT_USAGE)
    unwritable = [f for f in res.controls.output.formats if f not in WRITABLE_FORMATS]
    if unwritable and not dry_run:
        raise _fail(f"report format(s) {', '.join(unwritable)} not available in this build; no requests sent",
                    EXIT_UNSUPPORTED)
    live = recon or not dry_run  # anything that would send traffic to the target needs authorization
    # Phase 1, offline: verify the scope signature and check the parsed URI before any Hub or target call.
    parsed = _parse(res.controls.target)
    attestation = None
    try:
        verified = load_scope(scope, signers=load_allowed_signers(signers)) if scope is not None else None
        if live or verified is not None:
            attestation = authorize(verified, parsed, resolved=False)
    except ScopeError as e:
        raise _fail(f"{e}; no requests sent", EXIT_SCOPE) from None
    # Phase 2: pin the target (Hub metadata only), then check the pinned target before any target traffic.
    resolved = _resolve(res.controls.target, via)
    if attestation is not None:
        try:
            attestation = authorize(verified, resolved, resolved=True)
        except ScopeError as e:
            raise _fail(f"{e} (as resolved: {resolved.request_model}); no requests sent", EXIT_SCOPE) from None
    if dry_run:
        profile = _run_recon(resolved, res.controls) if recon else None
        _print_plan(build_plan(resolved, selected=selected_ids(res.controls), profile=profile,
                               controls=res.controls))
        typer.echo("")
        _print_controls(res)
        typer.echo("")
        _print_attestation(attestation)
        return
    _print_attestation(attestation)
    _execute(resolved, res, attestation, config, run_engines=engines, system_one_url=system_one,
             system_one_multilingual_url=system_one_multilingual, use_judges=judges)


def _run_engines(t: ResolvedTarget, c, plan, config: Path | None, *, system_one=None, use_judges: bool = False):
    """Run engine-owned techniques (catalog B) in their engine images via the sandbox; returns `(engine_results,
    judge_stats)`. Engine-emitted judge-scored candidate exchanges are routed through the triage-gated System-2 panel
    when `--judges` is set and a token is available (D-017 budget); otherwise they are recorded as deferred. Host-only
    (needs Docker), off by default."""
    from hfsentinel.engines import engine_bridge

    ids = [s.catalog_id for s in plan.steps if s.disposition == "run"
           and s.catalog_id in engine_bridge.ENGINE_TECHNIQUES]
    work = engine_bridge.plan_engine_work(ids)
    if not work:
        typer.echo("engines   no engine-owned techniques selected")
        return None, None
    try:
        from engines import sandbox
    except Exception:  # noqa: BLE001 — the sandbox runner lives outside the package; absent inside the container
        typer.echo("engines   skipped: the engine sandbox is not available here (run outside the container)")
        return None, None
    endpoint = HF_ROUTER if t.kind == "hf-provider" else t.base_url
    allow = urlsplit(endpoint).hostname or sandbox.DEFAULT_ALLOW if t.kind != "openai" else ""
    target = {"ref": c.target, "endpoint": endpoint, "model": t.request_model or t.model or ""}
    out_dir = Path(c.output.out) / "engine-work"
    results, candidates = [], []
    for engine_key, techniques in work.items():
        typer.echo(f"engines   {engine_key}: {', '.join(sorted(techniques))}")
        outcome = engine_bridge.run_engine(engine_key, techniques, target=target, trials=c.target_io.trials,
                                           out_dir=out_dir, runner=sandbox.run,
                                           allow=allow or sandbox.DEFAULT_ALLOW)
        candidates.extend(outcome.candidates)
        if outcome.result is not None:
            results.append(outcome.result)
            hits = sum(r.successes for r in outcome.result.results)
            typer.echo(f"  {outcome.engine:<14} {hits} successes over {len(outcome.result.results)} techniques")
        else:
            typer.echo(f"  {outcome.engine:<14} {_clean(outcome.error, 80)}")
    judge_stats = _judge_engine_candidates(candidates, target, c, system_one=system_one, use_judges=use_judges,
                                           out=results)
    return (results or None), judge_stats


def _judge_engine_candidates(candidates: list, target: dict, c, *, system_one, use_judges: bool, out: list):
    """Route engine-emitted judge-scored candidate exchanges through the triage-gated System-2 panel (16.19). Appends
    the synthetic judge EngineResults to `out` and returns the triage-savings stats, or records them as deferred."""
    if not candidates:
        return None
    if not use_judges:
        typer.echo(f"engines   {len(candidates)} judge-scored candidate(s) deferred (pass --judges to score them)")
        return None
    token = _optional_token()
    if not token:
        typer.echo(f"engines   {len(candidates)} judge-scored candidate(s) deferred: no token for the judge panel")
        return None
    from hfsentinel.engines import engine_bridge
    from hfsentinel.engines.governor import Governor, Ledger
    from hfsentinel.judges.ensemble import Panel
    try:
        judge_gov = Governor(Ledger(max_requests=10**6, budget_usd=c.budget.judge_usd),
                             concurrency=c.target_io.concurrency)
        panel = Panel(token, judge_gov, user_agent=c.target_io.user_agent)
        judge_results, stats = engine_bridge.judge_candidates(candidates, panel, system_one, target=target)
    except Exception as e:  # noqa: BLE001 — a judge-path failure degrades to deferred, never crashes the scan
        typer.echo(f"engines   judge panel unavailable ({type(e).__name__}); {len(candidates)} candidate(s) deferred")
        return None
    out.extend(judge_results)
    typer.echo(f"engines   judged {stats['judge_calls_made']} candidate(s), triage saved "
               f"{stats['judge_calls_saved']} judge call(s)")
    return stats


def _execute(t: ResolvedTarget, res: Resolved, attestation: Attestation | None, config: Path | None,
             *, run_engines: bool = False, system_one_url: str | None = None,
             system_one_multilingual_url: str | None = None, use_judges: bool = False) -> None:
    """Live scan: staged campaign (scope → recon → plan → breadth → confirm → report)."""
    c = res.controls
    started = dt.datetime.now(dt.timezone.utc)
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    profile = _run_recon(t, c)
    library = StrategyLibrary()
    plan = build_plan(t, selected=selected_ids(c), profile=profile, controls=c, library=library)
    gov = Governor.from_controls(c)
    try:
        target = client(t, _optional_token(), max_requests=c.budget.max_requests, governor=gov,
                        user_agent=c.target_io.user_agent)
    except TargetURIError as e:
        raise _fail(str(e), EXIT_INPUT) from None
    _, pricing = _router_metadata(t)
    if pricing:
        gov.set_price(target.rate_key, pricing.input, pricing.output)
    sink_host = urlsplit(c.extras.sink_url).hostname if c.extras.sink_url else None
    s1 = SystemOne(http_client(system_one_url) if system_one_url else None,
                   multilingual_client=http_client(system_one_multilingual_url) if system_one_multilingual_url else None)
    if system_one_url:
        ml = f" · multilingual at {_clean(system_one_multilingual_url, 60)}" if system_one_multilingual_url else \
             " · non-Latin replies escalate (no multilingual variant)"
        typer.echo(f"system-1  Laya advisory at {_clean(system_one_url, 80)} (never confirms; escalates to judges){ml}")
    runnable = sum(1 for s in plan.steps if s.disposition == "run" and s.catalog_id in NATIVE)
    typer.echo(f"campaign  S3 breadth: {runnable} techniques with native oracles · up to {c.target_io.trials} "
               f"trials each, stopping early once decided")

    def progress(run: TechniqueRun) -> None:
        tail = (" · stopped by budget" if not run.complete
                else f" · {run.stopped_early}" if run.stopped_early else "")
        typer.echo(f"  {run.catalog_id:<4} {run.hits}/{run.trials} hits · temp0 "
                   f"{'-' if run.temp0_hit is None else ('hit' if run.temp0_hit else 'no')} · "
                   f"{run.attempts} req · {run.errors} errors{tail}")

    result = run_campaign(target, gov, plan, trials=c.target_io.trials, temperature=c.target_io.temperature,
                          max_tokens=c.target_io.max_tokens, concurrency=c.target_io.concurrency,
                          seed=c.target_io.seed, sink_host=sink_host, system_one=s1, profile=profile,
                          library=library, controls=c, keep_transcripts=c.output.save_transcripts, progress=progress)
    saved = result.exhaustive_requests - result.requests
    pct = round(100 * saved / result.exhaustive_requests) if result.exhaustive_requests else 0
    typer.echo(f"campaign  {result.requests} attack requests vs {result.exhaustive_requests} exhaustive "
               f"({pct}% fewer)")
    recon = {"requests": profile.requests, "over_refusal_rate": profile.over_refusal_rate,
             "refusal_style": profile.refusal_style, "disagreements": list(profile.disagreements),
             "facts": {k: {"value": f.value, "reason": f.reason} for k, f in profile.facts.items()}}
    campaign = {"decisions": result.decisions, "attack_requests": result.requests,
                "exhaustive_requests": result.exhaustive_requests, "requests_saved": saved,
                "cross_verified": result.cross_verified, "verify_requests": result.verify_requests,
                "escalations": result.escalations, "depth_requests": result.depth_requests,
                "baseline": result.baseline, "baseline_requests": result.baseline_requests,
                "judge_calls_made": result.judge_calls_made, "judge_calls_saved": result.judge_calls_saved,
                "triage_agreement": result.triage_agreement, "experimental": result.experimental,
                "strategy_library": "read-only (no write-back)" if library.write_failed else str(library.path)}
    if result.judge_calls_made or result.judge_calls_saved:
        typer.echo(f"system-1  Laya triage saved {result.judge_calls_saved} of "
                   f"{result.judge_calls_made + result.judge_calls_saved} judge calls "
                   f"({result.judge_saved_fraction:.0%}) · agreement {result.triage_agreement}")
    engine_results, engine_judge_stats = (_run_engines(t, c, plan, config, system_one=s1, use_judges=use_judges)
                                          if run_engines else (None, None))
    if engine_results is not None:
        campaign["engine_findings"] = sum(len(er.results) for er in engine_results)
    if engine_judge_stats:  # fold the engine-service judge path's triage savings into the campaign totals (16.19)
        campaign["judge_calls_made"] = campaign.get("judge_calls_made", 0) + engine_judge_stats["judge_calls_made"]
        campaign["judge_calls_saved"] = campaign.get("judge_calls_saved", 0) + engine_judge_stats["judge_calls_saved"]
        campaign["triage_agreement"] = engine_judge_stats["triage_agreement"]
    target_doc = {"ref": c.target, "kind": t.kind, "resolved_model": t.model, "provider": t.provider,
                  "request_model": t.request_model}
    report_doc = assemble(target=target_doc, plan_steps=plan.steps, runs=result.runs, controls=c,
                          controls_sha256=canonical_sha256(to_config(c)),
                          attestation=attestation.to_dict() if attestation else None, recon=recon,
                          campaign=campaign, engine_results=engine_results, baseline=result.baseline,
                          ledger=gov.ledger.snapshot(), run_id=run_id, started=started, native=set(NATIVE))
    try:
        paths = render.write(report_doc, c.output.out, list(c.output.formats), anchor=render.sarif_anchor(config))
        if c.output.save_transcripts:  # 16.17: full transcripts for confirmed findings only
            confirmed_ids = {f.catalog_id for f in report_doc.findings}
            tx = {r.catalog_id: r.transcripts for r in result.runs if r.catalog_id in confirmed_ids and r.transcripts}
            tx_path = render.write_transcripts(Path(c.output.out), run_id, tx)
            if tx_path:
                paths.append(tx_path)
    except OSError:
        raise _fail("could not write the report (directory not writable or file exists)", EXIT_INPUT) from None
    g = report_doc.grade
    typer.echo(f"grade     {g['overall'] or 'not graded'} ({_clean(g['reason'], 60)}) · covers "
               f"{', '.join(g['covered']) or 'none'} · {len(report_doc.findings)} confirmed findings")
    for f in report_doc.findings:
        typer.echo(f"  {f.catalog_id:<4} {f.severity:<8} ASR {f.asr:.0%} (95% CI {f.asr_ci95[0]:.0%}–"
                   f"{f.asr_ci95[1]:.0%}) {_clean(f.technique, 60)}")
    for p in paths:
        typer.echo(f"report    {_clean(p, 200)}")
    fail_on = c.output.fail_on.capitalize()
    if any(at_least(f.severity, fail_on) for f in report_doc.findings):
        raise _fail(f"confirmed finding at or above --fail-on {c.output.fail_on}", EXIT_FINDINGS)


@app.command()
def report(findings: Annotated[Path, typer.Argument(help="Findings JSON written by HF-Sentinel.",
                                                    show_default=False)]) -> None:
    """Summarize a findings file (counts and rates only; no evidence text)."""
    if not findings.is_file():
        raise _fail("findings file not found or not a regular file", EXIT_INPUT)
    if findings.stat().st_size > MAX_REPORT_BYTES:
        raise _fail(f"findings file exceeds {MAX_REPORT_BYTES // 1_000_000} MB", EXIT_INPUT)
    try:
        data = json.loads(findings.read_text(encoding="utf-8"))
        rows = data.get("findings") if isinstance(data, dict) else data
        parsed = [Finding.model_validate(r) for r in rows] if isinstance(rows, list) else None
    except (OSError, UnicodeDecodeError, ValueError, ValidationError):
        parsed = None
    if parsed is None:
        raise _fail("not a valid HF-Sentinel findings file", EXIT_INPUT)
    typer.echo(f"HF-Sentinel findings · {len(parsed)} total")
    typer.echo(f"{'ID':<4} {'STATUS':<12} {'TRIALS':>6} {'HITS':>5} {'ASR':>6}  {'95% CI':<15} TECHNIQUE")
    for f in sorted(parsed, key=lambda f: f.catalog_id):
        ci = f"{f.asr_ci95[0]:.2f}–{f.asr_ci95[1]:.2f}"
        typer.echo(f"{f.catalog_id:<4} {f.status:<12} {f.trials:>6} {f.successes:>5} {f.asr:>6.2f}  {ci:<15} "
                   f"{_clean(f.technique, 60)}")


def main() -> None:
    try:
        app()
    except Exception:  # noqa: BLE001 — never show a traceback (may carry paths/secrets/upstream names)
        typer.echo("hfsentinel: internal error", err=True)
        raise SystemExit(EXIT_INTERNAL) from None


if __name__ == "__main__":
    main()
