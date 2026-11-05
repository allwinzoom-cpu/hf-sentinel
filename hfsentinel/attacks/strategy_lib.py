"""Strategy pipeline (plan §6.2 / Strategy-library task): the generate/succeeded adapter contract, a
reproduce-before-trust gate, and composition search over the mutator battery — on top of the durable record in
`engines/strategy_library.py` (retrieval + write-back).

A `Strategy` pairs a **generate** (produce an attack payload) with a **succeeded** (score a response) — the §6.2 adapter
contract. A candidate is only *trusted* (written back, later retrievable as a learned prior) once it **reproduces** on
the target per the §2.2 threshold, so one lucky hit never becomes a trusted strategy. `search_compositions` stacks the
mutators (`attacks.mutators`) to find a transform that gets a payload through, keeping only compositions that pass the
reproduce gate — then `learn_if_reproduced` stores the winner for retrieval on a similar target.
"""
from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from hfsentinel.attacks import mutators
from hfsentinel.engines.strategy_library import Outcome, StrategyLibrary
from hfsentinel.scoring.severity import confirmed

Send = Callable[[str], str]        # payload -> target response
Oracle = Callable[[str], bool]     # response -> succeeded


@dataclass(frozen=True)
class Strategy:
    """The §6.2 generate/succeeded contract."""
    id: str
    category: str
    generate: Callable[[random.Random], str]
    succeeded: Oracle


@dataclass(frozen=True)
class ReproResult:
    trials: int
    successes: int

    @property
    def reproduced(self) -> bool:
        """Reproduce-before-trust: the §2.2 confirmation threshold (≥ 2 hits and ≥ 30 % of trials)."""
        return confirmed(self.successes, self.trials, None)

    @property
    def asr(self) -> float:
        return self.successes / self.trials if self.trials else 0.0


def reproduce(strategy: Strategy, send: Send, *, trials: int = 10, seed: int = 0) -> ReproResult:
    """Run `strategy` `trials` times against `send` and score each response with `strategy.succeeded`."""
    rng = random.Random(f"strat:{strategy.id}:{seed}")
    successes = sum(bool(strategy.succeeded(send(strategy.generate(rng)))) for _ in range(trials))
    return ReproResult(trials=trials, successes=successes)


def learn_if_reproduced(library: StrategyLibrary, strategy: Strategy, profile, repro: ReproResult, *,
                        description: str = "", detector: str = "") -> bool:
    """Store the outcome in the library only when it reproduced (the trust gate). Returns whether it was stored."""
    if not repro.reproduced:
        return False
    library.record(strategy.id, strategy.category, profile, Outcome(repro.trials, repro.successes),
                   description=description, detector=detector, source="strategy-pipeline")
    return True


def compose_wrap(instruction: str, names: tuple[str, ...]) -> str:
    """Apply a stack of mutators to `instruction` (left to right) and prepend each decode hint (reverse order)."""
    text = instruction
    for name in names:
        text = mutators.MUTATORS[name](text)
    hint = " ".join(mutators._HINTS[n] for n in reversed(names) if n in mutators._HINTS)
    return f"{hint}\n{text}" if hint else text


@dataclass(frozen=True)
class Composition:
    names: tuple[str, ...]
    successes: int
    trials: int

    @property
    def asr(self) -> float:
        return self.successes / self.trials if self.trials else 0.0


def search_compositions(instruction: str, send: Send, oracle: Oracle, *, mutator_names: list[str] | None = None,
                        max_depth: int = 2, trials: int = 8, seed: int = 0) -> list[Composition]:
    """Search mutator compositions (single, then ordered pairs up to `max_depth`) for ones that get `instruction`
    through `send`, scored by `oracle`. Returns the compositions that pass the reproduce-before-trust gate, ranked by
    ASR (best first)."""
    names = list(mutator_names if mutator_names is not None else mutators.MUTATORS)
    combos: list[tuple[str, ...]] = [(n,) for n in names]
    if max_depth >= 2:
        combos += [(a, b) for a in names for b in names if a != b]
    found: list[Composition] = []
    for combo in combos:
        strat = Strategy(id="+".join(combo), category="B",
                         generate=lambda _rng, c=combo: compose_wrap(instruction, c), succeeded=oracle)
        r = reproduce(strat, send, trials=trials, seed=seed)
        if r.reproduced:
            found.append(Composition(combo, r.successes, r.trials))
    return sorted(found, key=lambda c: (c.asr, -len(c.names)), reverse=True)
