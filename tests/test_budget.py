"""LSCAN-030: fair query/token/cost budget accounting — ASR is reported against every budget unit, calls are counted per
role (target vs judge/attacker/translator), every paid attempt is accounted, and the first-success cost is explicit."""
from hfsentinel.scoring.budget import budget_report


def test_budget_report_normalises_by_each_unit_and_separates_roles():
    ledger = {"requests": 100, "prompt_tokens": 4000, "completion_tokens": 1000,
              "cost_reported_usd": 2.0, "cost_priced_usd": 0.0, "cost_estimated_usd": 0.0,
              "first_success_requests": 7, "first_success_usd": 0.14, "first_success_tokens": 350}
    r = budget_report(ledger, confirmed_hits=5, elapsed_s=120.0, judge_calls=12, attacker_calls=30)
    assert r["calls_by_role"] == {"target": 100, "judge": 12, "attacker": 30, "translator": 0}
    assert r["paid_attempts"] == 100                       # every metered attempt, retries/errors included
    assert r["asr_per_budget"] == {"per_query": 0.05, "per_1k_tokens": 1.0, "per_usd": 2.5, "per_minute": 2.5}
    assert r["first_success_cost"] == {"queries": 7, "usd": 0.14, "tokens": 350}
    assert set(r["budget_units"]) == {"query", "token", "time", "spend"}


def test_zero_denominators_are_none_not_zero_and_absent_first_success_is_none():
    ledger = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_reported_usd": 0.0,
              "cost_priced_usd": 0.0, "cost_estimated_usd": 0.0, "first_success_requests": -1}
    r = budget_report(ledger, confirmed_hits=0, elapsed_s=0.0)
    assert r["asr_per_budget"] == {"per_query": None, "per_1k_tokens": None, "per_usd": None, "per_minute": None}
    assert r["first_success_cost"] is None and r["paid_attempts"] == 0
