"""Mutation/evolution and learned-strategy-library governance (plan / LSCAN-042).

Three algorithm families get conflated in the literature; this core keeps them apart and enforces the rules that make a
"learned" attack claim honest. It is governance + deterministic policy, not an LLM mutation engine (the durable priors
live in `hfsentinel/engines/strategy_library.py`):

  * GPTFuzzer — template MUTATION + SELECTION over a frozen seed/operator set. The selection is made DETERMINISTIC here
    (UCB1 with a fixed exploration constant, lowest-index tie-break) so a run is reproducible.
  * AutoDAN-Turbo — strategy DISCOVERY + REUSE from a library. Learning is ISOLATED per target: what one target teaches
    the library can never be written to the global scope or to another target's scope, so a single target cannot poison
    future global strategies.
  * white-box AutoDAN and kin — need gradients/weights. These are EXCLUDED from the black-box lane; only output-query
    algorithms are admitted.

A learned library only earns a "transfer works" claim if it beats a no-learning baseline on a HELD-OUT metric under a
MATCHED budget; otherwise the transfer is labeled unproven. See [[strategic-campaign-not-random]], [[agnostic-assessment]].
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# Access tiers an algorithm needs, and which enter the black-box lane (output-query only).
QUERY_ACCESS = ("text-output", "logprob")           # admitted: only model outputs / output-queries
INTERNAL_ACCESS = ("weights", "gradients")          # excluded from the black-box lane

# GPTFuzzer's frozen mutation operator set (selection is scored over seed templates, not free-form at runtime).
MUTATION_OPERATORS = ("generate", "crossover", "expand", "shorten", "rephrase")
UCB_C = 1.4142135623730951                          # sqrt(2): the standard UCB1 exploration constant (fixed = reproducible)


def lane(access: str) -> str:
    """Which lane an algorithm belongs to (LSCAN-042). Only output-query access enters the black-box lane; anything
    needing weights/gradients is white-box and excluded."""
    if access in QUERY_ACCESS:
        return "black-box"
    if access in INTERNAL_ACCESS:
        return "white-box-excluded"
    raise ValueError(f"unknown access tier {access!r}; expected {QUERY_ACCESS + INTERNAL_ACCESS}")


def admits_black_box(access: str) -> bool:
    """True iff an algorithm with this access tier may run in the black-box lane (LSCAN-042)."""
    return lane(access) == "black-box"


def select_template(stats: list[tuple[int, int]], *, c: float = UCB_C) -> int:
    """Deterministic GPTFuzzer-style seed selection (LSCAN-042): UCB1 over templates given per-template (successes,
    trials). An untried template is always tried first (lowest index among them); otherwise pick the max UCB score with a
    lowest-index tie-break. Pure and reproducible — no randomness."""
    if not stats:
        raise ValueError("need at least one template")
    untried = [i for i, (_, trials) in enumerate(stats) if trials == 0]
    if untried:
        return untried[0]
    total = sum(trials for _, trials in stats)
    best_i, best_score = 0, float("-inf")
    for i, (succ, trials) in enumerate(stats):
        score = succ / trials + c * math.sqrt(math.log(total) / trials)
        if score > best_score:                      # strict > keeps the lowest index on ties
            best_i, best_score = i, score
    return best_i


@dataclass(frozen=True)
class LearnScope:
    """Where a learned strategy may be written. Learning is bound to the target that produced it (LSCAN-042)."""
    target_id: str

    @property
    def key(self) -> str:
        return f"target:{self.target_id}"


def write_allowed(learned_from: LearnScope, write_to: str) -> bool:
    """Isolation guard (LSCAN-042): a strategy learned from one target may ONLY be written to that same target's scope —
    never the global scope, never another target's scope. Blocks a target from poisoning future global strategies."""
    return write_to == learned_from.key


def transfer_result(*, with_library: float, no_learning: float, budget_matched: bool,
                    held_out: bool) -> str:
    """Whether a learned library's transfer is proven (LSCAN-042). Requires a HELD-OUT metric improvement over the
    no-learning baseline under a MATCHED budget; anything else is explicitly unproven, never an implied win."""
    if not held_out:
        return "unproven: metric was not held out (measured on the learning split)"
    if not budget_matched:
        return "unproven: budgets were not matched across arms"
    if with_library > no_learning:
        return f"proven: library transfer improved the held-out metric ({no_learning:.2f} -> {with_library:.2f})"
    return f"unproven: no improvement over the no-learning baseline ({with_library:.2f} vs {no_learning:.2f})"
