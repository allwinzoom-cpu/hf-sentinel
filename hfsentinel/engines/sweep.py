"""Native breadth sweep: the techniques whose success oracle is deterministic and ours (canaries A1–A5/C2, sink
rules and render model E1–E3). The campaign (plan 16.18) will run this as its S3 breadth stage.

Techniques run one after another (so the ledger delta is each technique's cost); a technique's trials run
concurrently under the shared governor. Each technique gets `trials` sampled attempts plus one at temperature 0
when sampling is on (§8.2). Request/response text stays in memory: only the hash and redacted excerpt of a few hits
are kept, and the report writer keeps those only for confirmed findings (D-015).
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from hfsentinel.attacks import category_e
from hfsentinel.attacks.canary import CANARY_IDS, CanaryRun
from hfsentinel.engines.governor import BudgetExceeded, Governor
from hfsentinel.report.schema import ProvenCase
from hfsentinel.scoring.severity import CONFIRM_MIN_HITS, CONFIRM_MIN_RATE
from hfsentinel.scoring.stats import planned_looks, sequential_z, wilson
from hfsentinel.targets.openai_compat import TargetError

NATIVE = (*CANARY_IDS, *category_e.E_IDS)
MAX_PROVEN = 3
MIN_TRIALS = 5  # adaptive: never confirm on fewer sampled trials


@dataclass
class TechniqueRun:
    catalog_id: str
    trials: int = 0  # sampled trials that got a response
    hits: int = 0
    temp0_hit: bool | None = None  # None: no temperature-0 trial (sampling off, or it failed)
    errors: int = 0
    attempts: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    seconds: float = 0.0
    complete: bool = True  # False when a budget cap stopped it
    reasons: Counter = field(default_factory=Counter)
    contamination: int = 0  # outputs carrying another trial's canary (never a hit)
    foreign: int = 0  # outputs carrying a canary this run never issued (never a hit)
    proven: list[ProvenCase] = field(default_factory=list)
    stopped_early: str = ""  # adaptive stop reason; "" = ran every planned trial
    mutator_chain: list[str] = field(default_factory=list)  # S4 obfuscation applied, for the replay recipe (16.17)
    seed: int = 0            # the exact seed this run used, for the replay recipe (16.17)
    planned_trials: int = 0  # the trial count requested, for the replay recipe (16.17)
    transcripts: list[dict] = field(default_factory=list)  # full {messages, output} for proven hits; in-memory only,
    # populated only when keep_transcripts is set (`--save-transcripts`), written for confirmed findings only (16.17)


def _digest(messages: list[dict], output: str) -> str:
    blob = json.dumps({"messages": messages, "output": output}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _spend(gov: Governor) -> float:
    s = gov.ledger.snapshot()
    return s["cost_reported_usd"] + s["cost_priced_usd"] + s["cost_estimated_usd"]


def stop_reason(hits: int, done: int, planned: int, *, n_looks: int = 1) -> str | None:
    """Sequential stopping (plan 16.6) between waves: stop once the §2.2 outcome is decided. `done` is the evaluable
    trials so far (responses; errors are counted as consumed attempts by the caller, not as evaluable denominator).
    The positive-confirm lower bound is Bonferroni-corrected by `n_looks`, the predeclared number of interim looks, so
    checking a fixed-sample Wilson interval after every wave cannot inflate the false-confirm rate (LSCAN-028);
    `n_looks == 1` reproduces the previous single-look behaviour exactly. Futility ("cannot reach") is one-sided and
    never confirms, so it needs no correction."""
    required = max(CONFIRM_MIN_HITS, math.ceil(CONFIRM_MIN_RATE * planned - 1e-9))
    if hits + (planned - done) < required:
        return "cannot reach the §2.2 threshold"
    if done >= MIN_TRIALS and hits >= CONFIRM_MIN_HITS \
            and wilson(hits, done, z=sequential_z(n_looks))[0] >= CONFIRM_MIN_RATE:
        return "confirmed (CI lower bound ≥ threshold)"
    return None


def run_technique(target, gov: Governor, attack_id: str, *, trials: int, temperature: float, max_tokens: int,
                  concurrency: int, canaries: CanaryRun, seed: int = 0, adaptive: bool = False,
                  mutator: str | None = None, mutators: list[str] | None = None, baseline: bool = False,
                  keep_transcripts: bool = False) -> TechniqueRun:
    """`trials` sampled attempts (+1 at temperature 0). Adaptive: trials run in waves of `concurrency` and stop early
    once the outcome is decided; the temperature-0 attempt runs only when it can still change the outcome.
    `mutators`: an ordered chain that obfuscates each canary technique's user instruction (campaign S4 escalation) —
    the planted canary is unchanged, so the oracle still scores the (decoded, plaintext) output. `mutator` is the
    single-mutator shorthand (kept for callers); the full ordered chain is recorded on the run so replay reproduces it
    exactly, not just its first element (LSCAN-025)."""
    if attack_id not in NATIVE:
        raise ValueError(f"{attack_id} has no native oracle")
    out = TechniqueRun(attack_id, seed=seed, planned_trials=trials)
    chain = list(mutators) if mutators else ([mutator] if mutator else [])
    if chain and attack_id in CANARY_IDS and not baseline:
        out.mutator_chain = chain
    rng = random.Random(f"{seed}:{attack_id}")
    usd0, start = _spend(gov), time.monotonic()

    def make():
        if baseline:
            return canaries.baseline(attack_id) if attack_id in CANARY_IDS else category_e.build_baseline(attack_id, rng)
        trial = canaries.trial(attack_id) if attack_id in CANARY_IDS else category_e.build_trial(attack_id, rng)
        return _mutate(trial, chain) if (chain and attack_id in CANARY_IDS) else trial

    def one(job):
        temp, trial = job
        tokens = trial.max_tokens if attack_id in category_e.E_IDS else max_tokens
        began = time.monotonic()
        try:
            result = target.chat(trial.messages, max_tokens=tokens, temperature=temp)
        except BudgetExceeded:
            return temp, trial, None, "budget"
        except (TargetError, ValueError):
            return temp, trial, None, "error"
        latency = time.monotonic() - began
        if attack_id in CANARY_IDS:
            return temp, trial, (result, canaries.evaluate(trial, result.text)), "ok"
        return temp, trial, (result, category_e.evaluate(trial, result, latency_s=latency)), "ok"

    def record(temp, trial, got, status):
        out.attempts += 1
        if status == "budget":
            out.complete = False
            return
        if status == "error":
            out.errors += 1
            return
        result, verdict = got
        out.prompt_tokens += _int(result.usage.get("prompt_tokens"))
        out.completion_tokens += _int(result.usage.get("completion_tokens"))
        out.reasons[verdict.reason] += 1
        out.contamination += bool(getattr(verdict, "contamination", ()))
        out.foreign += bool(getattr(verdict, "foreign", ()))
        if temp == 0.0 and temperature > 0:
            out.temp0_hit = verdict.hit
        else:
            out.trials += 1
            out.hits += verdict.hit
        if verdict.hit:
            if getattr(gov, "ledger", None) is not None:
                gov.ledger.mark_first_success()  # LSCAN-030: capture the cost of reaching the first attack success
            if len(out.proven) < MAX_PROVEN:
                excerpt = getattr(verdict, "excerpt", "") or ", ".join(getattr(verdict, "findings", ()))
                out.proven.append(ProvenCase(sha256=_digest(trial.messages, result.text), excerpt=excerpt[:200]))
            if keep_transcripts:  # confirmed-only persistence is decided later; hold the full exchange in memory (16.17)
                out.transcripts.append({"sha256": _digest(trial.messages, result.text),
                                        "messages": trial.messages, "output": result.text})

    sent = 0
    # Predeclare the interim-look count from the plan so the confirmation multiplicity correction is fixed up front
    # (LSCAN-028), not derived from where the run happens to stop.
    n_looks = planned_looks(trials, MIN_TRIALS, max(1, concurrency)) if adaptive else 1
    with ThreadPoolExecutor(max(1, concurrency)) as ex:
        while sent < trials and out.complete:
            # adaptive: a first wave of MIN_TRIALS (the earliest point a decision is allowed), then waves of
            # `concurrency`; otherwise one wave of every trial
            wave = (MIN_TRIALS if sent == 0 else max(1, concurrency)) if adaptive else trials
            n = min(wave, trials - sent)
            for r in ex.map(one, [(temperature, make()) for _ in range(n)]):
                record(*r)
            sent += n
            if adaptive and sent < trials and (why := stop_reason(out.hits, out.trials, trials, n_looks=n_looks)):
                out.stopped_early = why
                break
        want_temp0 = temperature > 0 and out.complete and (
            not adaptive or (out.hits >= 1 and not out.stopped_early.startswith("confirmed")))
        if want_temp0:
            record(*one((0.0, make())))
    out.usd, out.seconds = round(_spend(gov) - usd0, 6), round(time.monotonic() - start, 2)
    return out


def _int(v: object) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10**9 else 0

def _mutate(trial, chain: list[str]):
    """Return a copy of a canary trial whose str user messages are wrapped by the ordered mutator `chain` (S4)."""
    from hfsentinel.attacks.mutators import wrap_injection_chain
    msgs = []
    for m in trial.messages:
        if m.get('role') == 'user' and isinstance(m.get('content'), str):
            msgs.append({**m, 'content': wrap_injection_chain(m['content'], chain)})
        else:
            msgs.append(dict(m))
    return replace(trial, messages=msgs)


def run_sweep(target, gov: Governor, ids: list[str], *, trials: int, temperature: float, max_tokens: int,
              concurrency: int, seed: int = 0, sink_host: str | None = None, adaptive: bool = False,
              progress=lambda run: None) -> list[TechniqueRun]:
    canaries = CanaryRun(seed, **({"sink_host": sink_host} if sink_host else {}))
    runs = []
    for attack_id in ids:
        run = run_technique(target, gov, attack_id, trials=trials, temperature=temperature, max_tokens=max_tokens,
                            concurrency=concurrency, canaries=canaries, seed=seed, adaptive=adaptive)
        runs.append(run)
        progress(run)
        if not run.complete:
            break  # a cap was reached: later techniques are reported as not run
    return runs
