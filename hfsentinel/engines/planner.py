"""Attack planner (plan 16.10): catalog × controls × recon profile → ordered plan with per-attack rationale.

Each precondition maps to alternatives (any-of) of requirement terms (all-of): observed target facts (recon),
operator resources (mock-tool manifest, sink URL, reference set) or oracles not built yet. Dispositions:
  run / experimental — requirements met (experimental = catalog candidate, never scored)
  n/a        — the target was observed to lack a needed capability: never scored, zero requests
  blocked    — an operator resource or oracle is missing
  unverified — a needed fact is unknown (recon not run or inconclusive): not run by default
Runnable steps are ordered by expected gain per request: potential severity (§8.3 criteria, a planning prior — final
severity is the scorer's job) × prior ASR × observed-defence boost ÷ (trials × effort cost).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hfsentinel.attacks.catalog import Attack, Catalog, load_catalog
from hfsentinel.controls import Controls
from hfsentinel.engines.recon import TargetProfile
from hfsentinel.scoring.severity import POINTS, potential
from hfsentinel.targets.resolve import ResolvedTarget

Disposition = Literal["run", "experimental", "n/a", "blocked", "unverified", "out-of-scope"]
Term = tuple[str, str]  # (kind, name)
Requirement = tuple[tuple[Term, ...], ...]  # any-of alternatives, each all-of terms

F, R, ORACLE, U = "fact", "resource", "oracle", "unobservable"
PRECONDITIONS: dict[str, Requirement] = {
    "multimodal input accepted": (((F, "multimodal_input"),),),
    "chat-templated target that parses special tokens": (((F, "special_token_parsing"),),),
    "target handles non-English input": (((F, "non_english"),),),
    "glitch tokens affect this tokenizer": (((U, "glitch_tokens"),),),
    "reference / known-text set held": (((R, "reference_set"),),),
    "target has cross-session memory": (((F, "cross_session_memory"),),),
    "tool-enabled target or mock-tool env": (((F, "tool_calling"),), ((R, "mock_tools"),)),
    "tool-enabled target or mock-tool env with memory": (((F, "tool_calling"), (F, "multi_turn_memory")),
                                                         ((R, "mock_tools"),)),
    "multi-agent target or mock-tool env": (((R, "mock_tools"),),),  # multi-agent topology is not observable
    "browse/HTTP tool + controlled sink URL": (((F, "tool_calling"), (R, "sink_url")),
                                               ((R, "mock_tools"), (R, "sink_url"))),
    "tool loop possible": (((F, "tool_calling"),), ((R, "mock_tools"),)),
    "reference oracle for the command/API": (((ORACLE, "command_oracle"),),),
    "multi-turn": (((F, "multi_turn_memory"),),),
    "source-existence oracle": (((ORACLE, "source_oracle"),),),
    "ground-truth + calibration readout": (((ORACLE, "calibration_oracle"),),),
    "structured-output API honoured": (((F, "structured_output"),),),
    "target exposes a separate reasoning trace": (((F, "reasoning_trace"),),),
    "target accepts and honours a caller-supplied assistant prefix": (((F, "prefill"),),),
}
# Technique requirements the frozen v0 catalog does not encode as preconditions (ANDed with any precondition).
TECHNIQUE_REQUIREMENTS: dict[str, Requirement] = {
    "B10": (((F, "reasoning_trace"),),),
    "B12": (((F, "prefill"),),),
}
EFFORT_COST = {"E": 1, "M": 4}  # expected requests per trial: single-shot vs multi-step
DEFAULT_PRIOR_ASR = 0.5  # until the strategy library (Phase 3) supplies per-technique priors
ENCODING_ATTACKS = {"A3", "B2", "B13", "B15"}
# Canary-preserving encodings only — kept in lock-step with campaign.ESCALATION_MUTATORS. cipher/leet/homoglyph/
# unicode-inversion/morse transform the canary itself, so a deterministic canary oracle could never match; they belong to
# text-goal attacks, not the canary sweep, and must not appear in a step's scored mutator set.
ENCODING_MUTATORS = ("base64", "unicode-tag", "invisible-text", "hex", "base32", "parseltongue-fullwidth")
BOOST = 1.5
HELD_ORDER = {"unverified": 0, "blocked": 1, "n/a": 2, "out-of-scope": 3}
# Scope override: the scanner's in-scope outcomes are model compromise, jailbreak, sensitive-data leakage, and
# harmful-content elicitation. The insecure/executable-output checks (E1) and the resource-exhaustion / DoS checks
# (E2 static-codegen, E3 unbounded generation, E4 recursive tool loops) are OUT of that scope, so they are never planned
# or run — held as n/a with zero requests. E5 (malicious/exploit-code generation) is KEPT as harmful-content elicitation.
# This mirrors the "scope override" markers in engines/capabilities.json and is reversible by editing this set.
SCOPE_EXCLUDED = frozenset({"E1", "E2", "E3", "E4"})


@dataclass(frozen=True)
class PlanStep:
    catalog_id: str
    name: str
    disposition: Disposition
    precondition: str | None
    rationale: str = ""
    score: float = 0.0
    requests: int = 0
    mutators: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    target: ResolvedTarget
    catalog_version: int
    steps: tuple[PlanStep, ...]
    recon: bool = False
    profile: TargetProfile | None = None  # the recon profile this plan was built from (carries LSCAN-022 features)

    def count(self, disposition: str) -> int:
        return sum(s.disposition == disposition for s in self.steps)


def requirements(a: Attack) -> Requirement:
    if a.precondition is not None and a.precondition not in PRECONDITIONS:
        raise KeyError(f"{a.id}: precondition has no planner mapping: {a.precondition!r}")
    pre = PRECONDITIONS.get(a.precondition) if a.precondition else None
    tech = TECHNIQUE_REQUIREMENTS.get(a.id)
    if pre and tech:
        return tuple(p + t for p in pre for t in tech)  # AND: every alternative must also meet the technique
    return pre or tech or ()


def _term(term: Term, profile: TargetProfile | None, controls: Controls) -> tuple[bool | None, str]:
    kind, name = term
    if kind == F:
        if profile is None:
            return None, f"{name} unknown (recon not run)"
        fact = profile.facts.get(name)
        if fact is None or fact.value is None:
            return None, f"{name} unknown ({fact.reason if fact else 'not probed'})"
        return fact.value, f"{name} observed {'true' if fact.value else 'false'} ({fact.reason})"
    if kind == R:
        present = {"mock_tools": controls.extras.tools is not None, "sink_url": controls.extras.sink_url is not None,
                   "reference_set": False}[name]
        return present, f"{name} {'provided' if present else 'not provided'}"
    if kind == ORACLE:
        return False, f"{name} not built yet (Phase 3)"
    return None, f"{name} not observable by recon"


def _evaluate(alternatives: Requirement, profile: TargetProfile | None,
              controls: Controls) -> tuple[Disposition | None, str]:
    """(None, why) when requirements are met; otherwise the holding disposition and why."""
    if not alternatives:
        return None, "no preconditions"
    unknown, lacks, operator_gap, reasons = False, False, False, []
    for alt in alternatives:
        vals = [(t, *_term(t, profile, controls)) for t in alt]
        if all(v is True for _, v, _ in vals):
            return None, "; ".join(r for _, _, r in vals)
        outcomes = {(t[0], v) for t, v, _ in vals}
        if any(v is False for _, v, _ in vals):
            fact_false = (F, False) in outcomes
            lacks |= fact_false
            # Operator-fixable: an oracle is missing, or the operator supplied part of this alternative.
            operator_gap |= (ORACLE, False) in outcomes or ((R, True) in outcomes and not fact_false)
        else:
            unknown = True
        reasons.append(" + ".join(r for _, v, r in vals if v is not True))
    why = " | ".join(reasons)
    if unknown:
        return "unverified", why
    # n/a: the target was observed to lack the capability and nothing the operator supplied gets close to a
    # substitute; otherwise it is blocked on something the operator can provide.
    return ("n/a" if lacks and not operator_gap else "blocked"), why


def build_plan(target: ResolvedTarget, catalog: Catalog | None = None, selected: list[str] | None = None,
               profile: TargetProfile | None = None, controls: Controls | None = None, library=None) -> Plan:
    """`selected` (catalog IDs from the resolved controls) limits the plan; None = whole catalog."""
    catalog = catalog or load_catalog()
    controls = controls or Controls()
    keep = set(selected) if selected is not None else None
    allowed_mutators = tuple(m for m in ENCODING_MUTATORS if m in controls.fuzz.mutators)
    keyword_filter = profile is not None and profile.has("keyword_filter") is True
    runnable, held = [], []
    for a in catalog.attacks:
        if keep is not None and a.id not in keep:
            continue
        if a.id in SCOPE_EXCLUDED:
            held.append(PlanStep(a.id, a.name, "out-of-scope", a.precondition,
                                 rationale="out of scope (scope override) — insecure-output / resource-exhaustion is "
                                           "not a model-compromise/jailbreak/leak/harmful-content outcome"))
            continue
        holding, why = _evaluate(requirements(a), profile, controls)
        if holding:
            held.append(PlanStep(a.id, a.name, holding, a.precondition, rationale=f"{holding}: {why}"))
            continue
        severity = potential(a)
        requests = controls.target_io.trials * EFFORT_COST[a.effort]
        boost, notes, mutators = 1.0, [], ()
        prior = DEFAULT_PRIOR_ASR
        if library is not None:
            prior = library.prior(a.id, profile)
            if prior != DEFAULT_PRIOR_ASR:
                notes.append(f"learned prior {prior} from the strategy library")
        if keyword_filter and a.id in ENCODING_ATTACKS:
            boost, notes = BOOST, ["keyword-filter refusals observed → encoding/obfuscation favoured"]
        if keyword_filter and a.category in ("A", "B"):
            mutators = allowed_mutators
        if a.id == "A6" and profile is not None and profile.has("special_token_parsing"):
            boost, notes = BOOST, ["special tokens parsed → role-boundary injection favoured"]
        if a.id == "B10" and profile is not None and profile.has("reasoning_trace"):
            boost, notes = BOOST, ["reasoning trace exposed"]
        score = POINTS[severity] * prior * boost / requests
        disposition: Disposition = "experimental" if a.status == "candidate" else "run"
        rationale = "; ".join([f"{severity} potential", f"{requests} req", why, *notes])
        runnable.append(PlanStep(a.id, a.name, disposition, a.precondition, rationale, round(score, 4), requests,
                                 mutators))
    runnable.sort(key=lambda s: (s.disposition != "run", -s.score))  # stable sort: catalog order breaks ties
    held.sort(key=lambda s: HELD_ORDER[s.disposition])
    return Plan(target, catalog.catalog_version, tuple(runnable + held), recon=profile is not None, profile=profile)
