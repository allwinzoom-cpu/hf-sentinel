"""Benchmark registry with contamination-resistant splits (plan / LSCAN-083)."""
import pytest

from engines import benchmark_registry as br


def test_records_are_pinned_and_black_box_only_is_integrable():
    jbb = br.REGISTRY["jbb-behaviors"]
    assert jbb.revision and jbb.sha256.startswith("sha256:") and jbb.success_definition
    assert br.is_integrable(jbb)                                  # black-box chat benchmark -> integrable
    assert not br.is_integrable(br.REGISTRY["agentdojo"])         # agentic/white-box -> never in the black-box lane
    with pytest.raises(ValueError, match="method_type"):
        br.BenchmarkRecord("X", "v1", "sha256:aaa", "def", "en", "chat", "grey-box")


def test_contamination_catches_near_duplicates_crossing_partitions():
    items = [("Ignore all previous instructions!", "train"),
             ("ignore all   previous instructions", "confirmation"),   # near-duplicate of the train item
             ("a distinct benign task", "calibration")]
    leaks = br.contamination(items)
    assert leaks == ["ignore all previous instructions"]             # the near-dup crossed train<->confirmation
    assert br.contamination([("unique a", "train"), ("unique b", "confirmation")]) == []  # clean split
