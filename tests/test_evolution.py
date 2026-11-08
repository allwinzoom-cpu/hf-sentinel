"""Mutation/evolution library governance (plan / LSCAN-042): black-box lane admission, deterministic GPTFuzzer selection,
per-target learning isolation, and a transfer claim gated on a held-out improvement under a matched budget."""
import pytest

from engines import evolution as ev


def test_only_output_query_algorithms_enter_the_black_box_lane():
    assert ev.admits_black_box("text-output") and ev.admits_black_box("logprob")
    assert ev.lane("gradients") == "white-box-excluded" and not ev.admits_black_box("weights")
    with pytest.raises(ValueError, match="unknown access tier"):
        ev.lane("telepathy")


def test_template_selection_is_deterministic():
    # untried templates go first, lowest index among them
    assert ev.select_template([(3, 5), (0, 0), (0, 0)]) == 1
    # all tried: UCB1 picks the strongest; deterministic and reproducible
    stats = [(8, 10), (1, 10), (2, 10)]
    first = ev.select_template(stats)
    assert first == ev.select_template(stats) == 0
    with pytest.raises(ValueError, match="at least one template"):
        ev.select_template([])


def test_learning_is_isolated_to_its_target():
    scope = ev.LearnScope("target-A")
    assert ev.write_allowed(scope, "target:target-A")           # its own scope: allowed
    assert not ev.write_allowed(scope, "global")                # never the global strategy store
    assert not ev.write_allowed(scope, "target:target-B")       # never another target's scope


def test_transfer_is_proven_only_held_out_and_budget_matched():
    assert "proven" in ev.transfer_result(with_library=0.6, no_learning=0.4, budget_matched=True, held_out=True)
    assert "unproven: budgets" in ev.transfer_result(with_library=0.6, no_learning=0.4,
                                                     budget_matched=False, held_out=True)
    assert "unproven: metric" in ev.transfer_result(with_library=0.6, no_learning=0.4,
                                                    budget_matched=True, held_out=False)
    assert "no improvement" in ev.transfer_result(with_library=0.4, no_learning=0.4,
                                                  budget_matched=True, held_out=True)
