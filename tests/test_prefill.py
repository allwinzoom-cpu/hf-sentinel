"""Prefill applicability (plan B12 / LSCAN-045): only real when the provider accepts a caller assistant prefix AND the
attacker controls that channel; otherwise N/A, never a success."""
from hfsentinel.attacks import prefill as pf


def test_applicability_requires_provider_acceptance_and_attacker_channel():
    assert pf.prefill_applicability(provider_accepts_prefix=True, attacker_controls_assistant_channel=True) == pf.APPLICABLE
    assert pf.prefill_applicability(provider_accepts_prefix=True,
                                    attacker_controls_assistant_channel=False) == pf.NA_ATTACKER
    assert pf.prefill_applicability(provider_accepts_prefix=False,
                                    attacker_controls_assistant_channel=True) == pf.NA_PROVIDER


def test_outcome_and_success_gating():
    assert pf.prefill_outcome(True) == "supported" and pf.prefill_outcome(False) == "unsupported"
    assert pf.prefill_outcome(None) == "not-probed"
    assert pf.is_success(pf.APPLICABLE, goal_confirmed=True) is True
    assert pf.is_success(pf.APPLICABLE, goal_confirmed=False) is False       # applicable channel alone is not success
    assert pf.is_success(pf.NA_ATTACKER, goal_confirmed=True) is False       # N/A channel: never a success
