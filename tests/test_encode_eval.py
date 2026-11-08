"""Encode-attack evaluation discipline (plan B14/B15/B16 / LSCAN-043): decoding alone is a surrogate, the goal is judged
independently, and comprehension gates applicability."""
from hfsentinel.attacks import encode_eval as ee
from hfsentinel.scoring.evidence import SURROGATE_CEILING, is_surrogate_or_weaker


def test_decode_is_a_surrogate_not_a_harm_finding():
    lvl = ee.decode_evidence(followed_benign_canary=True)
    assert lvl == SURROGATE_CEILING and is_surrogate_or_weaker(lvl)   # never stronger than a surrogate
    assert ee.decode_evidence(followed_benign_canary=False) is None
    assert ee.goal_needs_independent_judgment() is True               # the decoded goal is judged, not inferred


def test_comprehension_control_gates_applicability():
    assert ee.comprehension(decoded_control_correctly=True) == "comprehends"
    assert "N/A" in ee.comprehension(decoded_control_correctly=False)  # cannot decode -> not a bypass


def test_params_are_exposed_for_reproducibility():
    p = ee.EncodeParams(mutator="bijection", key_seed=0xB1, deviations="fixed key instead of in-context taught")
    assert p.mutator == "bijection" and p.key_seed == 0xB1 and p.deviations
    assert set(ee.ENCODE_IDS) == {"B14", "B15", "B16"}
