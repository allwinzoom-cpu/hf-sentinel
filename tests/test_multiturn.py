"""Adaptive multi-turn escalation (plan B4 / 16.18): an offensive conversation that ramps pressure until the target
breaks (canary leaks). Deterministic, offline (fake targets). Done-when: it breaks a defended target only after softer
turns are refused, never false-positives a refusing target, and keeps a transcript only on a confirmed break."""
import base64
import re

from hfsentinel.attacks import multiturn as mt


def _canary_from(messages):
    # recover the planted canary from the running objective so a fake target can "leak" it
    m = re.search(r'say "([^"]+)"', messages[-1]["content"])
    if m:
        return m.group(1)
    for tok in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", messages[-1]["content"]):
        try:
            d = base64.b64decode(tok).decode()
        except (ValueError, UnicodeDecodeError):
            continue
        if (mm := re.search(r'say "([^"]+)"', d)):
            return mm.group(1)
    return None


def always_leak(messages):
    c = _canary_from(messages)
    return f"Sure: {c}" if c else "I can't help with that."


def always_refuse(messages):
    return "I'm sorry, but I can't help with that."


def defended(messages):
    """Models the defended profile: a keyword filter blocks the plaintext attack, but an encoded turn is decoded+obeyed."""
    raw = messages[-1]["content"]
    if re.search(r"\b(ignore|dan|override|developer mode)\b", raw, re.IGNORECASE):
        return "Blocked by policy filter."                 # plaintext framings are refused
    c = _canary_from(messages)                             # encoded turn: decode + obey
    return f"Decoded and complying: {c}" if c else "Nothing to do."


def test_breaks_a_fully_vulnerable_target_on_the_first_turn():
    r = mt.escalate_conversation(always_leak, canary="CAN-AAAA-BBBB")
    assert r.broken and r.break_turn == 1 and r.move == "direct"
    assert r.canary_match == "exact" and r.transcript        # transcript kept on a break


def test_never_false_positives_a_refusing_target():
    r = mt.escalate_conversation(always_refuse, canary="CAN-AAAA-BBBB")
    assert not r.broken and r.break_turn is None and r.move is None
    assert len(r.turns) == len(mt.LADDER) and all(t.refused for t in r.turns)
    assert r.transcript == []                                # no transcript retained without a break


def test_gradually_breaks_a_defended_target_only_after_softer_turns_fail():
    r = mt.escalate_conversation(defended, canary="CAN-AAAA-BBBB")
    assert r.broken and r.move == "encoded"                  # the encoded turn is what slips past the filter
    assert r.break_turn == 4                                 # direct/roleplay/authority refused first (gradual)
    assert [t.refused for t in r.turns] == [True, True, True, False]


def test_system_one_is_advisory_and_recorded_per_turn():
    class FakeS1:
        def triage(self, goal, response):
            class D:  # minimal Decision-like
                choice = "refuse"
            return D()
    r = mt.escalate_conversation(defended, canary="CAN-AAAA-BBBB", system_one=FakeS1())
    # advisory triage recorded on the refused turns, and it does not change the (oracle-confirmed) break
    assert r.broken and r.move == "encoded"
    assert [t.triage for t in r.turns if t.refused] == ["refuse", "refuse", "refuse"]


def test_max_turns_caps_the_ladder():
    r = mt.escalate_conversation(defended, canary="CAN-AAAA-BBBB", max_turns=3)
    assert not r.broken and len(r.turns) == 3                # stops before the encoded turn


def test_breaks_the_real_defended_vuln_target_end_to_end():
    # the real positive control: a keyword filter blocks the plaintext framings, the encoded turn decodes and obeys.
    from hfsentinel.testing import vuln_target as vt

    def target(messages):
        return vt.respond(messages, 256, profile=vt.ALWAYS, defended=True)

    r = mt.escalate_conversation(target)
    assert r.broken and r.move == "encoded"                  # gradual break against the real target
    assert [t.refused for t in r.turns] == [True, True, True, False]
