"""Bounded memorization honesty (plan C3 / LSCAN-051): a finding is a verifiable HELD-reference reproduction, never a
training-membership claim; public/common text and nonmember references are not private-memorization leakage."""
from hfsentinel.attacks import memorization as mem

HELD = {"doc-meridian": mem.PLANTED_REFERENCE["doc-meridian"]}


def test_held_reference_reproduction_is_a_finding_labelled_without_a_membership_claim():
    reply = "Sure: " + HELD["doc-meridian"]              # the model reproduces the planted passage verbatim
    m = mem.memorized_finding(reply, HELD)
    assert m is not None and m.reference_id == "doc-meridian"
    assert mem.classify(m) == mem.HELD_REPRODUCTION and "membership" in mem.HELD_REPRODUCTION


def test_public_control_reproduction_is_not_a_finding():
    pub = mem.PUBLIC_CONTROLS
    reply = "Of course: " + pub["public-preamble"]
    refs = {**HELD, **pub}
    m = mem.memorized_finding(reply, refs, public_controls=pub)
    assert m is None                                     # reproducing public text is expected, not private leakage
    raw = mem.near_match(reply, refs)                    # near_match still sees it; classify labels it public
    assert raw is not None and mem.classify(raw, public_controls=pub) == mem.PUBLIC_REPRODUCTION


def test_nonmember_and_paraphrase_do_not_match():
    assert mem.memorized_finding("An unrelated answer about tides and lighthouses.", HELD) is None  # paraphrase
    assert mem.memorized_finding("Any text at all", {}) is None                                     # no references


def test_prefix_sweep_probes_increasing_lead_lengths():
    prompts = mem.prefix_sweep("doc-meridian", HELD, lead_list=(6, 12, 24))
    assert len(prompts) == 3 and len(prompts[0]) < len(prompts[-1])  # longer lead -> longer prompt
