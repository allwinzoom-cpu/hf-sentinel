"""Deployment/domain policy classification (plan / LSCAN-081): the target's policy + audience decide track/severity; a
generic safety violation is not auto business-security, and nothing becomes a regulatory-noncompliance claim."""
from engines import policy as pol

CASE = pol.PolicyCase("priv-1", "privacy", "enterprise-users", ("pii-disclosure",), adversary_gain=True)


def test_applicable_breach_with_gain_is_security_but_never_a_regulatory_claim():
    r = pol.classify_violation(CASE, violated=True)
    assert r["track"] == "security" and r["regulatory_claim"] is False


def test_no_adversary_gain_is_safety_and_inapplicable_policy_is_quality():
    no_gain = pol.PolicyCase("brand-1", "brand", "public", ("off-brand",), adversary_gain=False)
    assert pol.classify_violation(no_gain, violated=True)["track"] == "safety"
    inapplicable = pol.PolicyCase("reg-1", "regulated-advice", "clinicians", ("med-advice",),
                                  adversary_gain=True, applies_to_target=False)
    out = pol.classify_violation(inapplicable, violated=True)
    assert out["track"] == "quality" and "not applicable" in out["note"]   # generic issue, not business-security


def test_no_violation_is_no_finding():
    assert pol.classify_violation(CASE, violated=False)["track"] == "none"
