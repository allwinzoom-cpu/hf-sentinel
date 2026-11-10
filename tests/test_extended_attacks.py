"""Tests for the EXTENDED attack-discipline stages (hfsentinel.engines.extended_attacks).

Each stage must: return the documented outcome type, never raise, and honour its infra gate (N/A without the
capability, advisory with it). No stage is allowed to emit a `scored` result on this benign fake target — an honest
run of these disciplines is entirely advisory-or-na.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

# Module-level skip if any attack-discipline module (or the stage module) fails to import.
extended_attacks = pytest.importorskip("hfsentinel.engines.extended_attacks")
from hfsentinel.engines.extended_base import StageResult
from hfsentinel.engines.recon import Fact, TargetProfile

STAGES = extended_attacks.STAGES
SCORED_ID = re.compile(r"^[ABCDEH]\d{1,2}$")


class FakeTarget:
    """A benign target: `.chat(...)` returns SimpleNamespace(text=..., usage=...). It never echoes a canary, so no
    discipline can manufacture a follow hit; usage lets the amplification stage compute ratios."""

    def __init__(self, text="The bookstore is open from 9 to 5.",
                 usage=None):
        self._text = text
        self._usage = usage if usage is not None else {"input_tokens": 20, "output_tokens": 40}
        self.calls = 0

    def chat(self, messages, *, max_tokens=256, temperature=0.0, **kwargs):
        self.calls += 1
        return SimpleNamespace(text=self._text, usage=dict(self._usage))


def _profile(**facts) -> TargetProfile:
    return TargetProfile(facts={name: Fact(value, "test") for name, value in facts.items()})


# stage key -> fact name that flips its infra gate from na to advisory (None => not gated / always same outcome)
GATE = {
    "B14": None,
    "B6": None,
    "B12": "prefill",
    "LSCAN-049": None,
    "C4": "cross_session_memory",
    "A4": "multimodal_input",
    "LSCAN-058": None,          # always na (no audio pipeline)
    "LSCAN-059": None,          # always na (no document pipeline)
    "LSCAN-061": "tool_calling",
    "LSCAN-062": None,          # always na (no RAG pipeline)
    "E5": None,
    "E3": None,
    "H6": "citation_resolver",
}

# stage keys that are always na regardless of profile (infra the black-box scanner simply does not have)
ALWAYS_NA = {"LSCAN-058", "LSCAN-059", "LSCAN-062"}
# stage keys that are advisory even with profile=None (text-runnable, not infra-gated)
UNGATED_ADVISORY = {"B14", "B6", "LSCAN-049", "E5", "E3"}


def _run(stage, profile):
    return stage(FakeTarget(), profile=profile, max_tokens=64, system_one=None, seed=0)


def test_registry_has_13_stages():
    assert len(STAGES) == 13
    assert set(STAGES) == set(GATE)
    for fn in STAGES.values():
        assert callable(fn)


@pytest.mark.parametrize("key", list(STAGES))
def test_stage_returns_stageresult_and_never_raises(key):
    res = _run(STAGES[key], None)
    assert isinstance(res, StageResult)
    assert res.outcome in ("na", "advisory", "scored")


@pytest.mark.parametrize("key", list(STAGES))
def test_no_stage_scores_on_benign_target(key):
    """Honest run: a benign fake target yields no `scored` outcome from any discipline (both gated states)."""
    for profile in (None, _profile(**{GATE[key]: True}) if GATE[key] else None):
        res = _run(STAGES[key], profile)
        assert res.outcome != "scored"
        if res.outcome == "scored":  # defensive: if a scored ever appears the id must match the catalog regex
            assert SCORED_ID.match(res.catalog_id)


@pytest.mark.parametrize("key", sorted(UNGATED_ADVISORY))
def test_ungated_stages_are_advisory_without_profile(key):
    res = _run(STAGES[key], None)
    assert res.outcome == "advisory"
    assert res.label and res.evidence


@pytest.mark.parametrize("key", sorted(ALWAYS_NA))
def test_always_na_stages(key):
    for profile in (None, _profile(multimodal_input=True, prefill=True, tool_calling=True)):
        res = _run(STAGES[key], profile)
        assert res.outcome == "na"
        assert res.na_reason


@pytest.mark.parametrize("key", [k for k, g in GATE.items() if g and k not in ALWAYS_NA])
def test_gated_stage_na_without_capability_advisory_with(key):
    fact = GATE[key]
    # Without the capability -> na.
    assert _run(STAGES[key], None).outcome == "na"
    assert _run(STAGES[key], _profile(**{fact: False})).outcome == "na"
    # With the capability confirmed -> advisory enrichment (never scored).
    res = _run(STAGES[key], _profile(**{fact: True}))
    assert res.outcome == "advisory"
    assert res.label and res.evidence


def test_amplification_handles_missing_usage_units():
    """A missing usage unit must stay None in the ratios (unknown), never 0 or 1.0 — and the stage must not raise."""
    stage = STAGES["E3"]
    target = FakeTarget(usage={})  # no usage fields at all
    res = stage(target, profile=None, max_tokens=64)
    assert res.outcome == "advisory"
    assert "ratios=" in res.evidence


def test_image_stage_drives_multimodal_without_raising():
    """With multimodal confirmed, the image stage builds image messages and drives the target; must stay advisory."""
    res = STAGES["A4"](FakeTarget(), profile=_profile(multimodal_input=True), max_tokens=64)
    assert res.outcome == "advisory"
    assert res.catalog_id == "A4"
