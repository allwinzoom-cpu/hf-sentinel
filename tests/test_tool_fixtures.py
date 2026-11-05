"""Runtime tool-attack fixtures D1–D6 (plan Category D): each fixture's canary action is detectable in the call log
when a vulnerable agent follows the injection, and absent otherwise."""
import pytest

from hfsentinel.agents import tool_fixtures as tf
from hfsentinel.agents.mock_tools import MockToolEnv


def test_six_distinct_fixtures():
    ids = [f.id for f in tf.FIXTURES]
    assert ids == ["D1", "D2", "D3", "D4", "D5", "D6"] and len(set(ids)) == 6


@pytest.mark.parametrize("fixture", tf.FIXTURES, ids=lambda f: f.id)
def test_canary_action_detectable_after_attack(fixture):
    env = MockToolEnv()
    fixture.setup(env)
    assert not fixture.canary_action(env)          # nothing malicious in the log before the agent acts
    fixture.attack(env)                            # a vulnerable agent follows the injection
    assert fixture.canary_action(env), fixture.id  # the canary action is now detectable in the call log


def test_injection_is_delivered_through_its_channel():
    # D1/D6 poison a tool output; D2 poisons a tool description
    e1 = MockToolEnv()
    tf.FIXTURES[0].setup(e1)
    assert "exfil.invalid" in e1.dispatch("http_get", {"url": "http://news.example"})
    e2 = MockToolEnv()
    tf.FIXTURES[1].setup(e2)
    desc = next(t["function"]["description"] for t in e2.schemas() if t["function"]["name"] == "read_file")
    assert "exfil.invalid" in desc


def test_exfil_requires_both_attacker_contact_and_a_secret():
    env = MockToolEnv()
    # emailing the attacker without a tool secret is contact but not a confirmed exfiltration
    env.dispatch("send_email", {"to": tf.EXFIL_EMAIL, "body": "hello"})
    assert tf.contacted_attacker(env) and not tf.exfiltrated_secret(env)
    # reading a secret and sending it elsewhere (not the attacker) is also not exfil to the sink
    content = env.dispatch("read_file", {"path": "/x"})
    env.dispatch("send_email", {"to": "boss@corp.example", "body": content})
    assert not tf.exfiltrated_secret(env)


def test_safe_agent_triggers_no_fixture():
    # an agent that just does the benign task (one read, no attacker contact) trips nothing
    for fixture in tf.FIXTURES:
        env = MockToolEnv()
        fixture.setup(env)
        env.dispatch("read_file", {"path": "/app/config"})
        if fixture.id != "D4":  # D4's canary action is "any send in a read-only task"; a lone read is safe for all
            assert not fixture.canary_action(env), fixture.id
