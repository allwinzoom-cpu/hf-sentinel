"""LSCAN-005: the external-tool integration inventory obeys the acceptance contract — required evidence per candidate,
documentation-only/rejected never integrated, and Promptfoo assessed without adding a duplicate engine."""
import copy

import engines.integration_review as review


def test_inventory_passes_the_contract():
    assert review.check() == []  # no violations


def test_promptfoo_is_assessed_but_not_integrated():
    c = review.load()["candidates"]["promptfoo"]
    assert c["status"] == "documentation-only" and c["owner_capability"] is None
    assert "telemetry" in c["egress"] or "data-handling" in c["egress"]  # data-flow resolved before adoption


def test_missing_evidence_is_a_violation():
    d = copy.deepcopy(review.load())
    d["candidates"]["garak"].pop("scorecard")
    assert any("missing required field 'scorecard'" in v for v in review.check(d))


def test_documentation_only_cannot_own_a_capability():
    d = copy.deepcopy(review.load())
    d["candidates"]["promptfoo"]["owner_capability"] = "adaptive-multiturn-and-converters"
    assert any("must not own a capability" in v for v in review.check(d))


def test_integrated_engine_must_own_a_capability():
    d = copy.deepcopy(review.load())
    d["candidates"]["garak"]["owner_capability"] = None
    assert any("must own a capability" in v for v in review.check(d))
