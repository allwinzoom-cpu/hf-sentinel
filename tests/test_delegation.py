"""Inter-agent delegation & trust propagation (plan / LSCAN-068): forged peer messages, first trust boundary crossed,
final unauthorized effect, and a single-model roleplay labeled a simulation."""
import pytest

from hfsentinel.agents import delegation as dg

TRUSTED = frozenset({"planner", "verifier"})


def test_trust_level_validated_and_forgery_detected():
    forged = dg.Message(0, "tool", "worker", claimed_identity="planner", sender_trust="lower-trust")
    assert dg.is_forged(forged, TRUSTED)
    genuine = dg.Message(0, "planner", "worker", claimed_identity="planner", sender_trust="trusted")
    assert not dg.is_forged(genuine, TRUSTED)
    with pytest.raises(ValueError, match="unknown trust level"):
        dg.Message(0, "a", "b", claimed_identity="x", sender_trust="semi")


def test_first_boundary_is_the_earliest_crossing():
    msgs = [
        dg.Message(0, "planner", "worker", "planner", "trusted", reached_instruction_path=True),
        dg.Message(1, "web", "worker", "peer", "lower-trust", reached_instruction_path=True),   # first crossing
        dg.Message(2, "doc", "verifier", "peer", "lower-trust", reached_instruction_path=True),
    ]
    b = dg.first_boundary_crossed(msgs)
    assert b is not None and b.step == 1
    # lower-trust content that stayed as data (not instructions) is not a crossing
    data_only = [dg.Message(0, "web", "worker", "peer", "lower-trust", reached_instruction_path=False)]
    assert dg.first_boundary_crossed(data_only) is None


def test_single_model_roleplay_is_a_simulation():
    msgs = (dg.Message(0, "web", "worker", "peer", "lower-trust", reached_instruction_path=True),)
    sim = dg.AgentGraph(messages=msgs, distinct_models=1)
    assert sim.is_simulation
    assert "simulation" in dg.analyze(sim, final_unauthorized_effect=True)


def test_real_multi_agent_finding_names_boundary_and_effect():
    msgs = (
        dg.Message(0, "planner", "worker", "planner", "trusted", reached_instruction_path=True),
        dg.Message(1, "web", "worker", "peer", "lower-trust", reached_instruction_path=True),
    )
    graph = dg.AgentGraph(messages=msgs, distinct_models=2)
    assert "trust-propagation finding" in dg.analyze(graph, final_unauthorized_effect=True)
    assert "no unauthorized effect" in dg.analyze(graph, final_unauthorized_effect=False)
    clean = dg.AgentGraph(messages=(msgs[0],), distinct_models=2)
    assert dg.analyze(clean, final_unauthorized_effect=False) == "no trust boundary crossed"
