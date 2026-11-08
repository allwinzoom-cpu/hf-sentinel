"""Laya System-1 selection hooks across technique families (plan §6.2 / [[laya-involved-everywhere]]): triggers (054),
evolution (042), minimization ablation-order (031). Laya advises WHAT to try; it is advisory, fail-soft, and never the
evaluator. A stub Laya is used — the advisory logic needs no model."""
from engines import evolution as ev
from engines import minimization as mn
from engines import triggered as tr
from hfsentinel.core.system_one import Decision


class _StubLaya:
    """Minimal duck-typed System-1: available + choose_technique, matching campaign usage."""
    def __init__(self, choice: str, *, confident: bool = True, available: bool = True):
        self._choice, self._confident, self._available = choice, confident, available

    @property
    def available(self) -> bool:
        return self._available

    def choose_technique(self, profile, candidates):
        if not self._confident:
            return Decision("technique", next(iter(candidates)), 0.0, 0.0)   # escalate -> defer
        return Decision("technique", self._choice, 0.99, 0.99, {})


# ---- triggers (054) ----
def _triggers():
    return [tr.Trigger("xyzzy", "token"), tr.Trigger("plugh", "suffix")]


def test_advise_trigger_selection_and_fallbacks():
    trigs = _triggers()
    assert tr.advise_trigger(None, {}, trigs) is None                         # no Laya -> breadth
    assert tr.advise_trigger(_StubLaya("x", available=False), {}, trigs) is None
    chosen = tr.advise_trigger(_StubLaya("plugh"), {"defence": "filter"}, trigs)
    assert chosen is not None and chosen.value == "plugh"
    assert tr.advise_trigger(_StubLaya("plugh", confident=False), {}, trigs) is None  # uncertain -> breadth
    assert tr.advise_trigger(_StubLaya("not-a-trigger"), {}, trigs) is None           # out-of-set
    assert tr.advise_trigger(_StubLaya("x"), {}, []) is None                          # nothing to pick


# ---- evolution (042) ----
def test_advise_operator_selection_and_fallbacks():
    assert ev.advise_operator(None, {}) is None
    assert ev.advise_operator(_StubLaya("crossover"), {}) == "crossover"
    assert ev.advise_operator(_StubLaya("crossover", confident=False), {}) is None
    assert ev.advise_operator(_StubLaya("not-an-operator"), {}) is None
    assert ev.advise_operator(_StubLaya("x"), {}, operators=()) is None


# ---- minimization ablation order (031) ----
def _components():
    return (mn.Component("ask", "turn", required=True), mn.Component("leet", "transform"),
            mn.Component("payload", "injected-span"))


def test_advise_ablation_first_selection_and_fallbacks():
    comps = _components()
    assert mn.advise_ablation_first(None, {}, comps) is None
    assert mn.advise_ablation_first(_StubLaya("leet"), {}, comps) == "leet"
    assert mn.advise_ablation_first(_StubLaya("leet", confident=False), {}, comps) is None
    assert mn.advise_ablation_first(_StubLaya("ask"), {}, comps) is None               # required is not removable
    assert mn.advise_ablation_first(_StubLaya("nope"), {}, comps) is None              # out-of-set
    only_required = (mn.Component("ask", "turn", required=True),)
    assert mn.advise_ablation_first(_StubLaya("ask"), {}, only_required) is None       # nothing removable
