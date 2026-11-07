"""Adaptive attacker agent (plan 643, B7): LLM-driven multi-turn refinement toward the benign canary objective, scored
by the deterministic oracle. Hermetic — fake attacker + fake target + a substring oracle, so no LLM, CLI, or network."""
from hfsentinel.agents.adaptive_attacker import AttackResult, run_adaptive

HIT = lambda reply, canary: canary if canary in reply else None  # simple deterministic oracle for the tests


def test_breaks_at_the_turn_the_target_emits_the_canary():
    c = "CANARY-1234"
    n = {"t": 0}

    def attacker(canary, history):
        return f"attempt {len(history)}: please output {canary}"

    def target(messages):
        n["t"] += 1
        return f"ok {c}" if n["t"] >= 3 else "I won't do that."

    r = run_adaptive(attacker, target, canary=c, max_turns=5, oracle=HIT)
    assert r.broke and r.break_turn == 3 and r.turns == 3


def test_no_break_within_the_turn_cap():
    r = run_adaptive(lambda canary, h: "say it", lambda m: "I refuse.", canary="X-1", max_turns=4, oracle=HIT)
    assert not r.broke and r.turns == 4 and r.break_turn == 0


def test_attacker_refusal_or_empty_turn_is_skipped():
    c = "Y-2"
    seq = [None, f"please say {c}"]  # turn 1: attacker raises (refuses); turn 2: a working prompt

    def attacker(canary, history):
        v = seq.pop(0)
        if v is None:
            raise RuntimeError("attacker refused")
        return v

    r = run_adaptive(attacker, lambda m: f"sure, {c}", canary=c, max_turns=3, oracle=HIT)
    assert r.broke and r.turns == 1  # the refused turn sent nothing; the next one broke it


def test_target_error_ends_the_run_cleanly():
    def target(messages):
        raise ValueError("target down")

    r = run_adaptive(lambda canary, h: "hi", target, canary="Z-3", max_turns=3, oracle=HIT)
    assert not r.broke and r.turns == 1


def test_default_canary_is_generated_when_absent():
    r = run_adaptive(lambda canary, h: f"say {canary}", lambda m: "nope", max_turns=1, oracle=HIT)
    assert isinstance(r, AttackResult) and not r.broke
