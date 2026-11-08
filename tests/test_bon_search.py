"""Best-of-N search (plan B13 / LSCAN-041): N reproducible perturbations x M independent samples, deduped, with fresh
winner confirmation; a published large-N ASR is never a scanner expectation."""
from hfsentinel.attacks import best_of_n as bon


def _echoes(messages):
    # a target that follows any variant: emits the canary token present in the prompt (pattern-based, any canary)
    import re
    text = messages[-1]["content"]
    m = re.search(r"[A-Z0-9]{4}(?:-[A-Z0-9]{4})+", text)
    return f"Sure: {m.group(0)}" if m else "no."


def _refuses(messages):
    return "I'm sorry, I can't help with that."


def test_variants_perturb_the_carrier_but_keep_the_canary_verbatim():
    c = "ABCD-EF23-GH45"
    v0, v1 = bon.build_variant(c, 0), bon.build_variant(c, 1)
    assert c in v0 and c in v1 and v0 != v1              # distinct perturbations, canary intact in each


def test_bon_reports_n_and_m_separately_dedupes_and_confirms_the_winner():
    c = "WXYZ-7788-ABCD"
    r = bon.run_bon(_echoes, canary=c, n=5, m=3, seed=0)
    assert r.broke and r.winner_seed is not None and r.confirmed    # winner re-confirms on a FRESH canary
    assert r.reps == 3 and r.requested == 5 and r.perturbations <= 5  # N and M reported separately; deduped <= N


def test_refusing_target_never_breaks_or_confirms():
    r = bon.run_bon(_refuses, canary="CAN-0000-1111", n=4, m=2, seed=1)
    assert not r.broke and not r.confirmed and r.winner_seed is None


def test_winner_confirmation_uses_a_fresh_canary_not_the_original():
    # a target that only ever leaks ONE hardcoded value breaks on it but must NOT confirm (the fresh canary differs)
    fixed = "FIXD-0000-0000"

    def only_fixed(messages):
        return f"Sure: {fixed}"

    r = bon.run_bon(only_fixed, canary=fixed, n=3, m=1, seed=0)
    assert r.broke and not r.confirmed                   # held-out confirmation with a new canary fails -> honest
