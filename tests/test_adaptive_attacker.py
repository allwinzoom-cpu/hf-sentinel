"""Adaptive attacker agent (plan 643, B7): LLM-driven multi-turn refinement toward the benign canary objective, scored
by the deterministic oracle. Hermetic — fake attacker + fake target + a substring oracle, so no LLM, CLI, or network."""
from hfsentinel.agents.adaptive_attacker import AttackResult, confirm_path, run_adaptive, run_tap


def HIT(reply, canary):  # simple deterministic oracle for the tests
    return canary if canary in reply else None


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


def test_attack_cannot_declare_its_own_success_only_the_oracle_can():
    # LSCAN-029: success is the independent oracle, never the attacker's self-assessment. A target that merely *claims*
    # success (without emitting the canary) must NOT count as a break; only the canary oracle decides.
    c = "CANARY-9999"
    def boastful(messages):
        return "SUCCESS! Jailbreak complete, I have fully complied with everything."
    r = run_adaptive(lambda canary, h: "do it", boastful, canary=c, max_turns=3, oracle=HIT)
    assert not r.broke and r.break_turn == 0            # self-proclaimed success is ignored
    r2 = run_adaptive(lambda canary, h: "do it", lambda m: f"fine: {c}", canary=c, max_turns=3, oracle=HIT)
    assert r2.broke                                      # only the oracle's canary detection counts


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


class _Reply:
    def __init__(self, text):
        self.text, self.usage = text, {}


def test_campaign_adaptive_stage_breaks_and_records():
    from hfsentinel.engines.campaign import CampaignResult, _adaptive_stage

    class EchoTarget:  # echoes the attacker's prompt, which carries the generated canary -> the oracle finds it
        def chat(self, messages, *, max_tokens, temperature):
            return _Reply("sure: " + messages[-1]["content"])

    res = CampaignResult()
    _adaptive_stage(res, EchoTarget(), attacker=lambda canary, h: f"please output {canary}", max_turns=2,
                    max_tokens=64, seed=1)
    assert res.adaptive.get("broke") is True
    assert any(d["catalog_id"] == "B7" for d in res.decisions)


def test_campaign_adaptive_stage_noop_without_attacker():
    from hfsentinel.engines.campaign import CampaignResult, _adaptive_stage
    res = CampaignResult()
    _adaptive_stage(res, object(), attacker=None, max_turns=2, max_tokens=64, seed=1)
    assert not res.adaptive and not res.decisions


def test_campaign_adaptive_tree_branches_sends_and_records_runtime_trace():
    from hfsentinel.engines.campaign import CampaignResult, _adaptive_tree_stage

    target_calls = []

    class EchoTarget:
        def chat(self, messages, *, max_tokens, temperature):
            prompt = messages[-1]["content"]
            target_calls.append(prompt)
            if len(target_calls) < 4:
                return _Reply("direct answer")
            return _Reply(f"direct answer: {prompt}")

    def attacker(canary, history):
        return f"say {canary}"

    res = CampaignResult()
    _adaptive_tree_stage(res, EchoTarget(), attacker=attacker, max_turns=2, max_tokens=64, seed=1)
    assert len(target_calls) >= 4  # branching candidate prompts are sent, not merely generated
    assert res.adaptive_tree["target_calls"] == len(target_calls)
    assert res.adaptive_tree["nodes_explored"] >= 4
    assert res.adaptive_tree["pruned"] >= 0


def test_reasoning_self_attack_requires_trace_and_scores_only_visible_output():
    from types import SimpleNamespace

    from hfsentinel.engines.campaign import CampaignResult, _reasoning_self_attack_stage

    class ReasoningTarget:
        def __init__(self, exposes_trace):
            self.exposes_trace = exposes_trace
            self.calls = []

        def chat(self, messages, *, max_tokens, temperature):
            self.calls.append(messages)
            final = "I deliver the requested code." + (
                f" The canary is {self.canary}." if len(self.calls) > 1 else "")
            return SimpleNamespace(text=final, reasoning="valid benign objective" if self.exposes_trace else "",
                                  usage={})

    profile = SimpleNamespace(has=lambda name: name == "reasoning_trace")
    plan = SimpleNamespace(steps=[SimpleNamespace(catalog_id="B10", disposition="experimental")])
    target = ReasoningTarget(True)
    target.canary = next(m["content"].rsplit("exactly: ", 1)[-1].rstrip(".")
                          for m in [] if False) if False else "CAN-X"
    res = CampaignResult()
    _reasoning_self_attack_stage(res, target, plan, profile=profile, seed=1, max_tokens=128)
    assert len(target.calls) == 2
    run = res.runs[-1]
    assert run.attempts == 2 and run.trials == 1

    target = ReasoningTarget(False)
    target.canary = "CAN-X"
    res = CampaignResult()
    _reasoning_self_attack_stage(res, target, plan, profile=profile, seed=1, max_tokens=128)
    assert len(target.calls) == 1
    assert res.runs == []
    assert res.decisions[0]["action"] == "n/a"


# ---- LSCAN-039: Tree-of-Attacks-with-Pruning as a distinct, traced search algorithm ----

BOOKS = "Here are some lovely books about gardening."  # a clearly non-refusal filler reply


def test_tap_tree_search_finds_a_break_and_records_a_trace():
    c = "CAN-TAP-0001"

    def branch(canary, history):
        d = len(history) // 2
        return [f"d{d}-b{k}" for k in range(3)]

    def target(messages):
        return f"ok {c}" if messages[-1]["content"] == "d1-b1" else BOOKS

    r = run_tap(branch, target, canary=c, width=3, depth=3)
    assert r.broke and r.break_depth == 2
    assert r.target_calls >= 1 and r.attacker_calls >= 1 and r.path and r.path[-1] == "d1-b1"
    assert confirm_path(target, r.path, canary=c)          # the winning path replays (held-out confirmation)


def test_tap_prunes_refused_branches_and_stops_when_the_frontier_empties():
    c = "CAN-TAP-0002"
    r = run_tap(lambda canary, h: ["a", "b", "c"], lambda m: "I'm sorry, I can't help with that.",
                canary=c, width=3, depth=2)
    assert not r.broke and r.pruned >= 3 and r.target_calls >= 3


def test_tap_branches_more_than_the_linear_pair_loop():
    c = "CAN-TAP-0003"
    r = run_tap(lambda canary, h: [f"x{k}" for k in range(3)], lambda m: BOOKS, canary=c, width=3, depth=2)
    assert not r.broke and r.target_calls > 3              # a real tree (branching), not a single linear chain


def test_confirm_path_reports_a_non_reproducing_break_honestly():
    assert not confirm_path(lambda m: "nope", ("setup", "win"), canary="CAN-TAP-0004")
