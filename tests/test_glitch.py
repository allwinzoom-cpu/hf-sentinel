"""B22 glitch-token probing oracle (plan §4): behaviour change against a control prompt. Done-when: a refusal flip,
emptied/degenerate output, length blow-up or high repetition is flagged; a matched control/probe pair is not."""
from hfsentinel.attacks.glitch import behavior_change, is_anomalous


def test_refusal_flip_is_anomalous():
    control = "Here is a helpful summary of the topic you asked about, in three short paragraphs."
    probe = "I'm sorry, but I can't help with that request."
    assert behavior_change(control, probe).refusal_flip
    assert is_anomalous(control, probe)


def test_emptied_output_is_anomalous():
    assert behavior_change("a normal, complete answer to the question", "").emptied
    assert is_anomalous("a normal, complete answer to the question", "")


def test_length_blowup_is_anomalous():
    control = "short answer."
    probe = "word " * 200
    assert behavior_change(control, probe).length_blowup
    assert is_anomalous(control, probe)


def test_high_repetition_is_anomalous():
    control = "here is a varied, ordinary response with many different words in it"
    probe = "spam spam spam spam spam spam spam actually"
    assert behavior_change(control, probe).repetitive
    assert is_anomalous(control, probe)


def test_matched_control_and_probe_is_not_anomalous():
    control = "The capital of France is Paris, a major European city on the Seine."
    probe = "The capital of France is Paris, which sits on the river Seine in Europe."
    a = behavior_change(control, probe)
    assert not a.anomalous
    assert not is_anomalous(control, probe)
