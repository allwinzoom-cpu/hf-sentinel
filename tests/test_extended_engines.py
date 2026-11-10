"""Tests for the five EXTENDED standalone-engine stages (extended_engines.py).

Each stage must: return the contractually expected outcome type, flip the infra-gated ones to an advisory when the
precondition is supplied via the profile, and NEVER raise — for both ``profile=None`` and a populated profile variant,
and against a tiny fake target. The top-level ``engines.*`` modules are a precondition for a live stage, so the whole
module skips if they cannot be imported (the stages themselves still fail-soft to ``na`` in that case)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from hfsentinel.engines import extended_engines as ee
from hfsentinel.engines.extended_base import StageResult
from hfsentinel.engines.recon import Fact, TargetProfile

# The standalone engines live in the top-level engines/ package; skip if that package is not importable here.
pytest.importorskip("engines.reasoning_reframe")
pytest.importorskip("engines.temporal_modal")
pytest.importorskip("engines.gateway_isolation")
pytest.importorskip("engines.membership")
pytest.importorskip("engines.session_fixture")


class FakeTarget:
    """A minimal black-box: ``.chat(...) -> SimpleNamespace(text=..., usage={})``, tolerant of any kwargs."""

    def __init__(self, text: str = "ok"):
        self._text = text
        self.calls = 0

    def chat(self, messages, **kwargs):
        self.calls += 1
        return SimpleNamespace(text=self._text, usage={})


STAGE_KEYS = ("B9", "LSCAN-060", "LSCAN-076", "LSCAN-053", "LSCAN-026")


def _profile(**facts) -> TargetProfile:
    return TargetProfile(facts={name: Fact(value, "test") for name, value in facts.items()})


# --------------------------------------------------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------------------------------------------------
def test_stages_registry_exports_five_callables():
    assert set(ee.STAGES) == set(STAGE_KEYS)
    assert all(callable(fn) for fn in ee.STAGES.values())


@pytest.mark.parametrize("key", STAGE_KEYS)
def test_every_stage_returns_stageresult_and_never_raises(key):
    """Each stage, for profile=None and a rich profile variant, returns a StageResult with a valid outcome."""
    rich = _profile(reasoning_trace=True, multimodal_input=True,
                    cross_session_memory=True, multi_turn_memory=True)
    for profile in (None, rich):
        res = ee.STAGES[key](FakeTarget(), profile=profile, max_tokens=64, system_one=None, seed=1)
        assert isinstance(res, StageResult)
        assert res.outcome in ("na", "advisory", "scored")
        # Non-catalog capability ids must never be reported as scored.
        if key.startswith("LSCAN-"):
            assert res.outcome != "scored"


# --------------------------------------------------------------------------------------------------------------------
# 1. reasoning reframe -> advisory on B9 (scored natively)
# --------------------------------------------------------------------------------------------------------------------
def test_reasoning_reframe_is_advisory_on_b9():
    for profile in (None, _profile(reasoning_trace=True)):
        res = ee.stage_reasoning_reframe(FakeTarget(), profile=profile, max_tokens=64, seed=0)
        assert res.outcome == "advisory"
        assert res.catalog_id == "B9"
        assert res.label in ("reframe-followed", "reframe-not-followed")


def test_reasoning_reframe_follows_benign_canary_when_echoed():
    # A target that echoes the planted canary scores a "followed" advisory — still advisory, never scored.
    canary = ee._canary(0, "RF")
    res = ee.stage_reasoning_reframe(FakeTarget(text=f"The code is {canary}."), profile=None, max_tokens=64, seed=0)
    assert res.outcome == "advisory"
    assert res.label == "reframe-followed"


# --------------------------------------------------------------------------------------------------------------------
# 2. temporal / modal -> advisory LSCAN-060 (text-runnable)
# --------------------------------------------------------------------------------------------------------------------
def test_temporal_modal_is_advisory():
    for profile in (None, _profile(multimodal_input=True)):
        res = ee.stage_temporal_modal(FakeTarget(), profile=profile, max_tokens=64, seed=2)
        assert res.outcome == "advisory"
        assert res.catalog_id == "LSCAN-060"


# --------------------------------------------------------------------------------------------------------------------
# 3. gateway isolation -> na unless a gateway/cache is declared
# --------------------------------------------------------------------------------------------------------------------
def test_gateway_isolation_na_without_gateway():
    for profile in (None, _profile(tool_calling=True)):
        res = ee.stage_gateway_isolation(FakeTarget(), profile=profile, max_tokens=64, seed=0)
        assert res.outcome == "na"
        assert res.catalog_id == "LSCAN-076"
        assert res.na_reason


def test_gateway_isolation_advisory_when_declared():
    prof = TargetProfile(facts={}, declared={"gateway": True})
    res = ee.stage_gateway_isolation(FakeTarget(), profile=prof, max_tokens=64, seed=0)
    assert res.outcome == "advisory"
    assert res.catalog_id == "LSCAN-076"
    # A fixed benign echo carries no foreign canary, so the honest verdict is no-crossover.
    assert res.label == "no-crossover"


# --------------------------------------------------------------------------------------------------------------------
# 4. membership inference -> na unless a reference set is supplied
# --------------------------------------------------------------------------------------------------------------------
def test_membership_na_without_refset():
    for profile in (None, _profile(structured_output=True)):
        res = ee.stage_membership(FakeTarget(), profile=profile, max_tokens=64, seed=0)
        assert res.outcome == "na"
        assert res.catalog_id == "LSCAN-053"
        assert "member/nonmember reference set" in res.na_reason


def test_membership_advisory_with_refset():
    refset = [(0.9, True), (0.8, True), (0.7, True), (0.6, True),
              (0.2, False), (0.1, False), (0.15, False), (0.05, False)]
    prof = TargetProfile(facts={}, features={"membership_refset": refset})
    res = ee.stage_membership(FakeTarget(), profile=prof, max_tokens=64, seed=0)
    assert res.outcome == "advisory"
    assert res.catalog_id == "LSCAN-053"
    assert res.label in ("above-chance", "not-above-chance")


# --------------------------------------------------------------------------------------------------------------------
# 5. session fixture -> advisory when stateful, else na
# --------------------------------------------------------------------------------------------------------------------
def test_session_fixture_na_when_stateless():
    for profile in (None, _profile(cross_session_memory=False, multi_turn_memory=False)):
        res = ee.stage_session_fixture(FakeTarget(), profile=profile, max_tokens=64, seed=0)
        assert res.outcome == "na"
        assert res.catalog_id == "LSCAN-026"
        assert res.na_reason


def test_session_fixture_advisory_when_stateful():
    for profile in (_profile(cross_session_memory=True), _profile(multi_turn_memory=True)):
        res = ee.stage_session_fixture(FakeTarget(), profile=profile, max_tokens=64, seed=0)
        assert res.outcome == "advisory"
        assert res.catalog_id == "LSCAN-026"
        assert res.label == "fixture-up"


# --------------------------------------------------------------------------------------------------------------------
# fail-soft: a target that raises must not crash a stage
# --------------------------------------------------------------------------------------------------------------------
class ExplodingTarget:
    def chat(self, messages, **kwargs):
        raise RuntimeError("transport down")


@pytest.mark.parametrize("key", STAGE_KEYS)
def test_stages_fail_soft_against_exploding_target(key):
    rich = _profile(reasoning_trace=True, multimodal_input=True,
                    cross_session_memory=True, multi_turn_memory=True)
    prof = TargetProfile(facts=rich.facts, declared={"gateway": True},
                         features={"membership_refset": [(0.9, True), (0.1, False)]})
    res = ee.STAGES[key](ExplodingTarget(), profile=prof, max_tokens=64, seed=0)
    assert isinstance(res, StageResult)
    assert res.outcome in ("na", "advisory", "scored")
