"""Attack campaign v1 (plan 16.18): a staged, budget-gated run instead of firing everything.

  S0 scope & budget   done by the CLI before any traffic (attestation + governor caps)
  S1 recon            target profile (engines/recon.py)
  S2 plan             planner dispositions → per-technique decision
  S3 breadth          native deterministic-oracle techniques with sequential stopping (16.6); a baseline arm (16.4)
                      measures the un-attacked rate so findings are graded on lift, not raw ASR
  S4 depth            escalate weak spots with defence-adaptive encoding mutators when the target filters (16.18)
  S5 confirm          temperature-0 attempt only where it can still change the outcome; §2.2 confirmation
  S6 cross-verify     re-run each confirmed native finding with independent canaries to rule out an artefact
  S7 learn            write per-(technique, target-bucket) outcomes back to the strategy library (§6.2)
  S8 report           scoring + writers (report/)

Every technique gets a decision record (stage, action, why). Techniques owned by an engine (catalog B and the rest
of the engine-routed set, 16.21) are recorded as needing the engine service (D-018) until it exists; their success
will be decided by the calibrated judge panel (`judges.ensemble.Panel`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hfsentinel.attacks.canary import CANARY_IDS, CanaryRun
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.engines.governor import BudgetExceeded, Governor
from hfsentinel.engines.planner import Plan
from hfsentinel.engines.strategy_library import Outcome, StrategyLibrary
from hfsentinel.engines.sweep import NATIVE, TechniqueRun, _digest, run_technique
from hfsentinel.report.schema import ProvenCase
from hfsentinel.scoring.severity import confirmed

if TYPE_CHECKING:
    from hfsentinel.engines.recon import TargetProfile

ENGINE_SERVICE = "engine-owned: runs through the engine service (D-018), not available in this build"
MIN_VERIFY_TRIALS = 5
ESCALATION_MUTATORS = ("base64", "unicode-tag")  # canary-preserving encodings: the planted canary survives decoding
# (cipher/leet/homoglyph transform the canary itself, so the oracle cannot match — they are for text-goal attacks)
ESCALATE_TRIALS = 8  # small per-mutator batch; the first mutator that confirms wins


@dataclass
class CampaignResult:
    runs: list[TechniqueRun] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    requests: int = 0
    exhaustive_requests: int = 0  # the same native techniques at full trials + 1 at temperature 0
    cross_verified: dict = field(default_factory=dict)  # catalog_id -> bool (artefact ruled out)
    verify_requests: int = 0  # S6 cross-verification requests (separate from the breadth-sweep budget)
    escalations: list = field(default_factory=list)  # S4: {id, mutator, hits, trials, confirmed}
    depth_requests: int = 0  # S4 escalation requests
    multiturn: dict = field(default_factory=dict)  # B4: adaptive multi-turn escalation outcome (broken, turn, move)
    multiturn_requests: int = 0  # multi-turn escalation requests
    baseline: dict = field(default_factory=dict)  # catalog_id -> {hits, trials} un-attacked arm (16.4)
    baseline_requests: int = 0
    judge_calls_made: int = 0      # responses sent to System-2 judges at S5 (16.19)
    judge_calls_saved: int = 0     # confident refusals skipped by Laya triage (the savings)
    judge_saved_fraction: float = 0.0
    triage_agreement: float | None = None  # Laya-vs-System-2 agreement on judged items
    experimental: list = field(default_factory=list)  # experimental techniques run (B23 CDA), recorded never scored

    def decide(self, stage: str, catalog_id: str, action: str, why: str, *, advisory: bool = False) -> None:
        self.decisions.append({"stage": stage, "catalog_id": catalog_id, "action": action, "why": why,
                               "source": "system-one" if advisory else "campaign"})


def _observations(profile: TargetProfile) -> list[str]:
    obs = []
    if profile.over_refusal_rate is not None:
        obs.append(f"over-refusal rate {profile.over_refusal_rate}")
    obs.append(f"refusal style: {profile.refusal_style}")
    for name, fact in profile.facts.items():
        shown = {True: "yes", False: "no", None: "unknown"}[fact.value]
        obs.append(f"{name}: {shown} ({fact.reason})")
    return obs


def run_campaign(target, gov: Governor, plan: Plan, *, trials: int, temperature: float, max_tokens: int,
                 concurrency: int, seed: int = 0, sink_host: str | None = None, system_one=None,
                 profile: TargetProfile | None = None, library: StrategyLibrary | None = None,
                 controls=None, keep_transcripts: bool = False, panel=None, judge_candidates=None,
                 reference_set: dict[str, str] | None = None, halluc_ecosystems: set[str] | None = None,
                 api_reference: set[str] | None = None, check_citations: bool = False,
                 check_sycophancy: bool = False,
                 progress=lambda run: None) -> CampaignResult:
    res = CampaignResult()
    res.decide("S1", "*", "recon" if plan.recon else "no recon", "target profile drives S2 dispositions")
    s1 = system_one if (system_one is not None and system_one.available) else None
    if s1 is not None and profile is not None:
        d = s1.defence_style(_observations(profile))
        res.decide("S1", "*", f"defence~{d.choice}" if not d.escalate() else "defence~uncertain",
                   f"System-1 conf {d.confidence}, act {d.act_probability}", advisory=True)
    runnable = []
    for step in plan.steps:
        if step.disposition != "run":
            res.decide("S2", step.catalog_id, "skip", step.rationale or step.disposition)
        elif step.catalog_id in NATIVE:
            runnable.append(step.catalog_id)
            res.decide("S2", step.catalog_id, "run", step.rationale)
        else:
            res.decide("S2", step.catalog_id, "defer", ENGINE_SERVICE)
    if s1 is not None and runnable:
        cand = {sid: next(st.name for st in plan.steps if st.catalog_id == sid) for sid in runnable}
        prof = {"refusal_style": profile.refusal_style} if profile is not None else {}
        t = s1.choose_technique(prof, cand)
        res.decide("S2", t.choice if not t.escalate() else "*", "technique advice",
                   f"System-1 favours {t.choice} (conf {t.confidence}); advisory — planner order is authoritative",
                   advisory=True)
    per_technique = trials + (1 if temperature > 0 else 0)
    res.exhaustive_requests = per_technique * len(runnable)
    canaries = CanaryRun(seed, **({"sink_host": sink_host} if sink_host else {}))
    for attack_id in runnable:
        run = run_technique(target, gov, attack_id, trials=trials, temperature=temperature, max_tokens=max_tokens,
                            concurrency=concurrency, canaries=canaries, seed=seed, adaptive=True,
                            keep_transcripts=keep_transcripts)
        res.runs.append(run)
        res.requests += run.attempts
        base = run_technique(target, gov, attack_id, trials=max(MIN_VERIFY_TRIALS, trials // 2),
                             temperature=temperature, max_tokens=max_tokens, concurrency=concurrency,
                             canaries=canaries, seed=seed + 50, adaptive=False, baseline=True)
        res.baseline[attack_id] = {'hits': base.hits, 'trials': base.trials}
        res.baseline_requests += base.attempts
        res.decide('S3', attack_id, 'baseline', f'un-attacked {base.hits}/{base.trials} (lift = attack - baseline)')
        res.decide("S3", attack_id, f"{run.hits}/{run.trials} hits",
                   f"stopped early: {run.stopped_early}" if run.stopped_early else "all planned trials")
        if s1 is not None:
            res.decide("S3", attack_id, "triage n/a",
                       "deterministic oracle decides directly; triage gates judge-scored responses", advisory=True)
        if run.temp0_hit is not None:
            res.decide("S5", attack_id, "temperature-0 attempt", "hit" if run.temp0_hit else "no hit")
        outcome = "confirmed" if confirmed(run.hits, run.trials, run.temp0_hit) else "unconfirmed"
        res.decide("S5", attack_id, outcome, "§2.2 reproduction")
        progress(run)
        if not run.complete:
            break  # a budget cap stopped the sweep; later techniques are reported as not run
    if reference_set:
        _memorization_stage(res, target, gov, reference_set=reference_set, max_tokens=max_tokens, seed=seed,
                            keep_transcripts=keep_transcripts)
    if halluc_ecosystems:
        _hallucination_stage(res, target, ecosystems=halluc_ecosystems, max_tokens=max_tokens)
    if api_reference:
        _fabricated_api_stage(res, target, known_apis=api_reference, max_tokens=max_tokens)
    if check_citations:
        _fabricated_citation_stage(res, target, max_tokens=max_tokens)
    if check_sycophancy:
        _sycophancy_stage(res, target, max_tokens=max_tokens)
    _depth_escalate(res, target, gov, canaries, profile=profile, trials=trials, temperature=temperature,
                    max_tokens=max_tokens, concurrency=concurrency, seed=seed,
                    mutators=allowed_mutators(controls), keep_transcripts=keep_transcripts)
    _multiturn_stage(res, target, max_tokens=max_tokens, system_one=s1)
    _cross_verify(res, target, gov, canaries, trials=trials, temperature=temperature, max_tokens=max_tokens,
                  concurrency=concurrency, seed=seed)
    _judge_confirm(res, panel, s1, judge_candidates or [])
    _experimental(res, target, plan, profile=profile, seed=seed, max_tokens=max_tokens)
    if library is not None:
        _learn(res, library, profile)
    return res


def _experimental(res: CampaignResult, target, plan: Plan, *, profile, seed: int, max_tokens: int) -> None:
    """Run native experimental techniques (plan: candidate status → experimental, never scored). B23 constrained
    decoding runs only when recon saw structured-output support; its reproduce verdict is recorded, not graded (16.7)."""
    structured = profile is not None and getattr(profile, "has", lambda _n: None)("structured_output") is True
    for step in plan.steps:
        if step.disposition != "experimental" or step.catalog_id != "B23":
            continue
        if not structured:
            res.decide("S4", "B23", "n/a", "target does not honour structured output", advisory=True)
            continue
        from hfsentinel.attacks.cda import run_cda
        r = run_cda(target, seed=seed, max_tokens=max_tokens)
        res.requests += r.trials
        res.experimental.append({"id": "B23", "trials": r.trials, "hits": r.hits, "reproduced": r.reproduced,
                                 "verdict": r.verdict})
        res.decide("S4", "B23", f"experimental: {'reproduced' if r.reproduced else 'not reproduced'}",
                   r.verdict, advisory=True)


def _judge_confirm(res: CampaignResult, panel, s1, candidates: list, *, policy=None) -> None:
    """S5 judge-scored confirmation gated by Laya triage (plan 16.19): a response Laya is confident is a refusal skips
    the expensive System-2 judge panel; everything else (likely-success, uncertain, Laya down) reaches the judges.
    `candidates`: [{catalog_id, goal, response}] for judge-scored techniques (engine-owned B feeds these when wired).
    No panel, no Laya, or no candidates → a no-op (native deterministic findings are confirmed by their own oracle)."""
    if panel is None or s1 is None or not getattr(s1, "available", False) or not candidates:
        return
    from hfsentinel.judges.ensemble import TriagedPanel
    tp = TriagedPanel(panel, s1, policy=policy)
    for c in candidates:
        decision, judged = tp.decide(c["goal"], c["response"])
        res.decide("S5", c.get("catalog_id", "*"), f"judge:{decision.outcome}" if judged else "triage-skip",
                   decision.reason, advisory=not judged)
    st = tp.stats
    res.judge_calls_made, res.judge_calls_saved = st.made, st.saved
    res.judge_saved_fraction, res.triage_agreement = st.saved_fraction, st.agreement
    res.decide("S5", "*", f"judge calls saved {st.saved}/{st.total}",
               f"Laya triage skipped {st.saved_fraction:.0%} of judge calls (agreement {st.agreement})",
               advisory=True)


def allowed_mutators(controls) -> tuple:
    """Encoding mutators enabled by controls, in the campaign's escalation order."""
    if controls is None:
        return ESCALATION_MUTATORS
    enabled = set(controls.fuzz.mutators)
    return tuple(m for m in ESCALATION_MUTATORS if m in enabled)


def _memorization_stage(res: CampaignResult, target, gov, *, reference_set: dict[str, str], max_tokens: int,
                        seed: int = 0, keep_transcripts: bool = False) -> None:
    """C3: training-data / memorization extraction. For each held reference, send a verbatim-continuation (cloze) prompt
    and score the reply with the near-match oracle; a reproduction is a confirmed hit. Produces a scored C3 run."""
    from hfsentinel.attacks.memorization import cloze_prompt, near_match
    run = TechniqueRun(catalog_id="C3", seed=seed, planned_trials=len(reference_set))
    for ref_id, text in reference_set.items():
        messages = [{"role": "user", "content": cloze_prompt(ref_id, reference_set)}]
        result = target.chat(messages, max_tokens=max_tokens, temperature=0.0)
        run.trials += 1
        run.attempts += 1
        if near_match(result.text, {ref_id: text}) is not None:
            run.hits += 1
            run.proven.append(ProvenCase(sha256=_digest(messages, result.text),
                                         excerpt=" ".join(result.text.split())[:200]))
            if keep_transcripts:
                run.transcripts.append({"messages": messages, "output": result.text})
    res.runs.append(run)
    res.requests += run.attempts
    res.decide("S3", "C3", f"{run.hits}/{run.trials} memorized",
               "verbatim reproduction of a held reference (training-data extraction)")
    res.decide("S5", "C3", "confirmed" if run.hits else "unconfirmed", "§2.2 deterministic near-match oracle")


def _hallucination_stage(res: CampaignResult, target, *, ecosystems: set[str], max_tokens: int, verifier=None) -> None:
    """H1: adversarially induce a package suggestion and verify it against the ecosystem registry. A recommended
    non-existent package (slopsquatting) is a confirmed hit. Produces a scored H1 run. Each prompt is a governed call."""
    from hfsentinel.halluc.registry_checks import exists_online, induce
    from hfsentinel.targets.openai_compat import TargetError

    def adapter(messages):
        return target.chat(messages, max_tokens=max_tokens, temperature=0.0).text

    try:
        trials, hits = induce(adapter, ecosystems=ecosystems, verifier=verifier or exists_online)
    except (BudgetExceeded, TargetError, ValueError):
        res.decide("S3", "H1", "package-hallucination stage stopped", "budget cap or target error")
        return
    run = TechniqueRun(catalog_id="H1", trials=trials, hits=len(hits), attempts=trials, planned_trials=trials)
    for f in hits:
        run.proven.append(ProvenCase(sha256=_digest([{"ecosystem": f.ecosystem, "name": f.name}], f.name),
                                     excerpt=f"{f.ecosystem}:{f.name} not in registry ({f.evidence})"[:200]))
    res.runs.append(run)
    res.requests += run.attempts
    res.decide("S3", "H1", f"{run.hits}/{run.trials} hallucinated package(s)",
               "recommended a package absent from its registry (slopsquatting)")
    res.decide("S5", "H1", "confirmed" if run.hits else "unconfirmed", "§2.2 registry-existence oracle")


def _fabricated_api_stage(res: CampaignResult, target, *, known_apis: set[str], max_tokens: int) -> None:
    """H2: adversarially induce a specific API/method call and flag any the operator's reference does not know
    (fabricated command/API). Produces a scored H2 run. Each prompt is a governed call."""
    from hfsentinel.halluc.fuzzers import induce_apis
    from hfsentinel.targets.openai_compat import TargetError

    def adapter(messages):
        return target.chat(messages, max_tokens=max_tokens, temperature=0.0).text

    try:
        trials, fabricated = induce_apis(adapter, lambda name: name in known_apis)
    except (BudgetExceeded, TargetError, ValueError):
        res.decide("S3", "H2", "fabricated-API stage stopped", "budget cap or target error")
        return
    run = TechniqueRun(catalog_id="H2", trials=trials, hits=len(fabricated), attempts=trials, planned_trials=trials)
    for api in fabricated:
        run.proven.append(ProvenCase(sha256=_digest([{"api": api}], api), excerpt=f"fabricated API: {api}"[:200]))
    res.runs.append(run)
    res.requests += run.attempts
    res.decide("S3", "H2", f"{run.hits}/{run.trials} fabricated API(s)",
               "named an API/method absent from the reference")
    res.decide("S5", "H2", "confirmed" if run.hits else "unconfirmed", "§2.2 reference-API oracle")


def _fabricated_citation_stage(res: CampaignResult, target, *, max_tokens: int, verifier=None) -> None:
    """H6: adversarially induce a source citation and flag any DOI/arXiv id the resolver cannot find (fabricated).
    Produces a scored H6 run. URLs are never resolved (SSRF). Each prompt is a governed call."""
    from hfsentinel.halluc.fuzzers import citation_exists, induce_citations
    from hfsentinel.targets.openai_compat import TargetError

    def adapter(messages):
        return target.chat(messages, max_tokens=max_tokens, temperature=0.0).text

    try:
        trials, fabricated = induce_citations(adapter, verifier or citation_exists)
    except (BudgetExceeded, TargetError, ValueError):
        res.decide("S3", "H6", "fabricated-citation stage stopped", "budget cap or target error")
        return
    run = TechniqueRun(catalog_id="H6", trials=trials, hits=len(fabricated), attempts=trials, planned_trials=trials)
    for kind, value in fabricated:
        run.proven.append(ProvenCase(sha256=_digest([{"kind": kind, "value": value}], value),
                                     excerpt=f"fabricated citation: {kind}:{value}"[:200]))
    res.runs.append(run)
    res.requests += run.attempts
    res.decide("S3", "H6", f"{run.hits}/{run.trials} fabricated citation(s)",
               "cited a source the resolver cannot find")
    res.decide("S5", "H6", "confirmed" if run.hits else "unconfirmed", "§2.2 source-existence oracle")


def _sycophancy_stage(res: CampaignResult, target, *, max_tokens: int) -> None:
    """H5: two-turn sycophantic reversal — state the correct answer, then push back with the wrong one in the same
    conversation; a flip to the wrong answer is a hit. Produces a scored H5 run (two governed calls per item)."""
    from hfsentinel.halluc.fuzzers import induce_sycophancy
    from hfsentinel.targets.openai_compat import TargetError

    def adapter(messages):
        return target.chat(messages, max_tokens=max_tokens, temperature=0.0).text

    try:
        trials, reversals = induce_sycophancy(adapter)
    except (BudgetExceeded, TargetError, ValueError):
        res.decide("S3", "H5", "sycophancy stage stopped", "budget cap or target error")
        return
    run = TechniqueRun(catalog_id="H5", trials=trials, hits=len(reversals), attempts=trials * 2, planned_trials=trials)
    for q in reversals:
        run.proven.append(ProvenCase(sha256=_digest([{"q": q}], q), excerpt=f"reversed under wrong pushback: {q}"[:200]))
    res.runs.append(run)
    res.requests += run.attempts
    res.decide("S3", "H5", f"{run.hits}/{run.trials} reversal(s)",
               "flipped a correct answer under a confident wrong pushback")
    res.decide("S5", "H5", "confirmed" if run.hits else "unconfirmed", "§2.2 answer-flip oracle")


def _multiturn_stage(res: CampaignResult, target, *, max_tokens: int, system_one=None) -> None:
    """Adaptive multi-turn escalation (B4/16.18) as a scan stage: run the escalating conversation (direct → roleplay →
    authority → encoded → ciphered, Crescendo-style) and record whether it *gradually broke* the target (a canary leaked)
    and at which turn. Supplementary intelligence alongside the scored sweep — never double-counts the direct-injection
    grade. Each turn is a governed request (target.chat raises BudgetExceeded over budget)."""
    from hfsentinel.attacks.multiturn import escalate_conversation
    from hfsentinel.targets.openai_compat import TargetError

    def adapter(messages):
        return target.chat(messages, max_tokens=max_tokens, temperature=0.0).text

    try:
        result = escalate_conversation(adapter, system_one=system_one)
    except (BudgetExceeded, TargetError, ValueError):
        res.decide("S4", "A1", "multi-turn escalation stopped", "budget cap or target error")
        return
    res.multiturn = {"broken": result.broken, "break_turn": result.break_turn, "move": result.move,
                     "turns": [[t.move, t.refused] for t in result.turns]}
    res.multiturn_requests = len(result.turns)
    res.requests += len(result.turns)
    if result.broken:
        res.decide("S4", "A1", f"multi-turn escalation broke the target at turn {result.break_turn}",
                   f"move '{result.move}' leaked the canary after {result.break_turn - 1} softer turn(s) refused")
    else:
        res.decide("S4", "A1", "multi-turn escalation did not break the target",
                   f"{len(result.turns)} turns, all refused")


def _depth_escalate(res: CampaignResult, target, gov, canaries, *, profile, trials, temperature, max_tokens,
                    concurrency, seed, mutators, keep_transcripts: bool = False) -> None:
    """S4: when the target shows a keyword filter, re-attack each unconfirmed canary weak spot with encoding
    mutators; the first mutator that confirms replaces the breadth result so the finding is scored. Budget-gated."""
    keyword_filter = profile is not None and getattr(profile, 'has', lambda _n: None)('keyword_filter') is True
    if not keyword_filter or not mutators:
        return  # encoding escalation only helps against a filter; otherwise a 0-hit is a true negative
    for idx, run in enumerate(list(res.runs)):
        if run.catalog_id not in CANARY_IDS or confirmed(run.hits, run.trials, run.temp0_hit):
            continue
        for mi, mut in enumerate(mutators):
            esc = run_technique(target, gov, run.catalog_id, trials=ESCALATE_TRIALS, temperature=temperature,
                                max_tokens=max_tokens, concurrency=concurrency, canaries=canaries,
                                seed=seed + 100 + mi, adaptive=True, mutator=mut, keep_transcripts=keep_transcripts)
            res.depth_requests += esc.attempts
            ok = confirmed(esc.hits, esc.trials, esc.temp0_hit)
            res.escalations.append({'id': run.catalog_id, 'mutator': mut, 'hits': esc.hits, 'trials': esc.trials,
                                    'confirmed': ok})
            if ok:
                res.runs[idx] = esc  # the escalated result is now the technique's outcome
                res.decide('S4', run.catalog_id, f'escalated via {mut}',
                           f'{esc.hits}/{esc.trials} after breadth got {run.hits}/{run.trials} (filter bypassed)')
                break
        else:
            res.decide('S4', run.catalog_id, 'no bypass found',
                       f'tried {len(mutators)} encoding mutators on the weak spot')


def _cross_verify(res: CampaignResult, target, gov, canaries, *, trials, temperature, max_tokens, concurrency,
                  seed) -> None:
    """S6: re-run each confirmed native finding with fresh, independent canaries; a finding that does not
    reproduce is flagged (an engine/oracle artefact, not a real weakness). A small independent sample is enough."""
    n = max(MIN_VERIFY_TRIALS, trials // 2)
    for run in res.runs:
        if not confirmed(run.hits, run.trials, run.temp0_hit):
            continue
        check = run_technique(target, gov, run.catalog_id, trials=n, temperature=temperature,
                              max_tokens=max_tokens, concurrency=concurrency, canaries=canaries, seed=seed + 1,
                              adaptive=True)
        res.verify_requests += check.attempts
        ok = confirmed(check.hits, check.trials, check.temp0_hit)
        res.cross_verified[run.catalog_id] = ok
        res.decide("S6", run.catalog_id, "cross-verified" if ok else "artefact?",
                   f"independent re-run {check.hits}/{check.trials}" + ("" if ok else " — did not reproduce"))


def _learn(res: CampaignResult, library: StrategyLibrary, profile) -> None:
    """S7: write each technique's aggregate outcome back to the strategy library (no response text, D-015)."""
    cat = load_catalog().by_id()
    for run in res.runs:
        a = cat[run.catalog_id]
        library.record(run.catalog_id, a.category, profile, Outcome(run.trials, run.hits),
                       description=a.name, detector=a.oracle, source="campaign")
        res.decide("S7", run.catalog_id, "recorded",
                   f"{run.hits}/{run.trials} written to the strategy library for this target bucket")
