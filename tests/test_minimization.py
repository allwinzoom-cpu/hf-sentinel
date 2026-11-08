"""Attack minimization and causal ablation (plan / LSCAN-031): greedy 1-minimization under a separate budget, causal
ablation, controls that must fail, and the rule that a simplification failure keeps the original confirmed recipe."""
from engines import minimization as m


def _recipe():
    # identity (the core ask) + three removable parts; only the "payload" span actually causes the violation.
    return (
        m.Component("ask", "turn", required=True),
        m.Component("leet", "transform"),
        m.Component("payload", "injected-span"),
        m.Component("example", "context-example"),
    )


def _oracle(active):
    # The attack confirms iff the identity AND the payload span are both present (the transform/example ride along).
    return "ask" in active and "payload" in active


def test_minimize_drops_only_the_riders_and_keeps_identity():
    res = m.minimize(_recipe(), _oracle, m.Budget(limit=50))
    kept = {c.id for c in res.minimized}
    assert kept == {"ask", "payload"}                 # identity + the one causal component
    assert res.reduced and res.confirmed_minimal
    assert set(res.removed) == {"leet", "example"}
    assert res.budget_used <= 50 and res.reason == ""


def test_minimize_keeps_original_when_it_does_not_confirm():
    res = m.minimize(_recipe(), lambda active: False, m.Budget(limit=50))
    assert not res.reduced and not res.original_confirmed
    assert {c.id for c in res.minimized} == {"ask", "leet", "payload", "example"}  # untouched
    assert res.reason == "original did not confirm"


def test_minimize_retains_recipe_when_budget_is_exhausted():
    res = m.minimize(_recipe(), _oracle, m.Budget(limit=1))   # only the baseline test fits
    assert "budget exhausted" in res.reason
    assert not res.confirmed_minimal                          # never claim a minimal recipe we could not prove
    assert {c.id for c in res.minimized} == {"ask", "leet", "payload", "example"}  # original recipe preserved


def test_causal_ablation_names_the_necessary_component():
    assert m.necessary_components(_recipe(), _oracle, m.Budget(limit=50)) == ("payload",)


def test_controls_must_both_fail_for_a_valid_cause():
    ids = ("ask", "leet", "payload", "example")
    assert m.controls_valid(_oracle, identity_ids=("ask",), payload_ids=("payload",),
                            all_ids=ids, budget=m.Budget(limit=10))
    # If the "no-attack" identity alone still confirms, the attack did not cause it -> invalid.
    assert not m.controls_valid(lambda a: True, identity_ids=("ask",), payload_ids=("payload",),
                                all_ids=ids, budget=m.Budget(limit=10))
    # Budget exhausted before both controls are checked -> inconclusive, never a pass.
    assert not m.controls_valid(_oracle, identity_ids=("ask",), payload_ids=("payload",),
                                all_ids=ids, budget=m.Budget(limit=0))
