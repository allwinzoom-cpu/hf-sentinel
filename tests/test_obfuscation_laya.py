"""Laya System-1 selection hook for the obfuscation layer (plan §6.2 / [[laya-involved-everywhere]]): Laya advises WHICH
encoding to try first; it is advisory, fail-soft, and never the evaluator. These tests use a stub Laya (no engine needed
for the advisory logic); the one test that enumerates real encodings skips when the engine runtime is absent."""
import pytest

from hfsentinel.attacks import obfuscation as obf
from hfsentinel.core.system_one import Decision


class _StubLaya:
    """Minimal duck-typed System-1: available + choose_technique, matching campaign usage."""
    def __init__(self, choice: str, *, confident: bool = True, available: bool = True):
        self._choice, self._confident, self._available = choice, confident, available

    @property
    def available(self) -> bool:
        return self._available

    def choose_technique(self, profile, candidates):
        if not self._confident:                           # escalate: unsure -> defer to breadth
            return Decision("technique", next(iter(candidates)), 0.0, 0.0)
        return Decision("technique", self._choice, 0.99, 0.99, {})


_MENU = {"fullwidth": "full width", "a1z26": "a1z26 cipher", "base64": "base64"}


def test_no_laya_means_deterministic_breadth():
    assert obf.advise_encoding(None, {}, candidates=_MENU) is None
    assert obf.advise_encoding(_StubLaya("fullwidth", available=False), {}, candidates=_MENU) is None


def test_confident_laya_choice_is_used():
    assert obf.advise_encoding(_StubLaya("a1z26"), {"defence": "filtered"}, candidates=_MENU) == "a1z26"


def test_uncertain_laya_falls_back_to_breadth():
    assert obf.advise_encoding(_StubLaya("a1z26", confident=False), {}, candidates=_MENU) is None


def test_out_of_menu_choice_is_ignored():
    assert obf.advise_encoding(_StubLaya("not-in-menu"), {}, candidates=_MENU) is None


def test_advice_never_overrides_scoring_contract():
    # the hook returns only a *selection* (a key or None); it never returns a verdict/score
    out = obf.advise_encoding(_StubLaya("fullwidth"), {}, candidates=_MENU)
    assert out in _MENU                                    # a selectable key, nothing more


@pytest.mark.skipif(not obf.is_available(), reason="obfuscation engine/runtime not available")
def test_candidate_menu_is_small_and_real():
    menu = obf.candidate_encodings(per_category=1, limit=12)
    assert 0 < len(menu) <= 12
    assert all(obf.is_known(k) for k in menu)              # every advertised candidate is a real encoding
