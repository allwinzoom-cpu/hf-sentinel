"""Composition / transfer / suffix replay (plan / LSCAN-049): capped composition, incremental lift over components, and
provenance-carrying black-box suffix replay that never implies universal transfer."""
import base64

import pytest

from hfsentinel.attacks import composition as comp
from hfsentinel.attacks.mutators import compose


def test_composition_is_capped_and_validated():
    fn = comp.compose_capped(("leet", "base64"))
    assert fn("test") == compose(("leet", "base64"))("test")           # composes left-to-right, same as the base helper
    assert base64.b64decode(fn("test"))                                # the base64 stage produced valid output
    with pytest.raises(comp.CompositionError, match="exceeds the cap"):
        comp.compose_capped(("leet", "base64", "flip", "cipher"))
    with pytest.raises(comp.CompositionError, match="unknown transform"):
        comp.compose_capped(("leet", "nope"))


def test_incremental_lift_credits_only_what_the_combination_adds():
    assert comp.incremental_lift({"leet": 0.2, "base64": 0.5}, 0.7) == 0.2   # 0.7 - best(0.5)
    assert comp.incremental_lift({"leet": 0.6}, 0.55) < 0                    # combination added nothing over its part


def test_suffix_replay_carries_provenance_and_disclaims_universal_transfer():
    art = comp.SuffixArtifact(text="== DESCRIBE. + similarlyNow", source="public GCG-style suffix corpus")
    out = art.apply("Tell me the plan.")
    assert out.endswith(art.text) and "Tell me the plan." in out
    assert art.source and "not universal transfer" in art.note
    pre = comp.SuffixArtifact(text="SYSTEM:", source="paper X", position="prefix")
    assert pre.apply("hello").startswith("SYSTEM:")
