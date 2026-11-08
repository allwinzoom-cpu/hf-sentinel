"""Fair query/token/cost budget accounting (plan LSCAN-030). Attack-success rate is only comparable when the budget it
was earned under is explicit, so a report must state ASR against each budget unit — queries, tokens, wall-clock and
spend — count calls per role (so an attacker/judge/translator call is never silently folded into the target query
count), account every paid attempt including retries and errors, and give the cost of reaching the FIRST success rather
than only an amortised average. Pure over a ledger snapshot; no I/O."""
from __future__ import annotations


def _rate(num: float, den: float) -> float | None:
    """A per-budget-unit rate, or None when the denominator is zero (undefined, never silently 0)."""
    return round(num / den, 6) if den else None


def budget_report(ledger: dict, confirmed_hits: int, *, elapsed_s: float, judge_calls: int = 0,
                  attacker_calls: int = 0, translator_calls: int = 0) -> dict:
    """Budget-normalised accounting for a run (LSCAN-030). `ledger` is `Ledger.snapshot()`; `confirmed_hits` is the
    number of confirmed findings. Calls are separated by role — target queries come from the ledger, while judge,
    attacker and translator calls are passed in (the attacker/judge may run off this ledger, e.g. a CLI subprocess, and
    must not inflate the target query count). Every rate names its budget unit; a zero denominator yields None, never a
    misleading 0."""
    requests = int(ledger.get("requests", 0))
    tokens = int(ledger.get("prompt_tokens", 0)) + int(ledger.get("completion_tokens", 0))
    spend = (float(ledger.get("cost_reported_usd", 0.0)) + float(ledger.get("cost_priced_usd", 0.0))
             + float(ledger.get("cost_estimated_usd", 0.0)))
    fsr = int(ledger.get("first_success_requests", -1))
    first_success = None if fsr < 0 else {
        "queries": fsr, "usd": round(float(ledger.get("first_success_usd", 0.0)), 6),
        "tokens": int(ledger.get("first_success_tokens", 0))}
    return {
        "budget_units": {"query": "target API calls (incl. retries/errors)", "token": "prompt+completion tokens",
                         "time": "wall-clock seconds", "spend": "USD"},
        "calls_by_role": {"target": requests, "judge": int(judge_calls), "attacker": int(attacker_calls),
                          "translator": int(translator_calls)},
        "paid_attempts": requests,  # every metered target attempt, retries and errors included (nothing is dropped)
        "confirmed_hits": int(confirmed_hits),
        "asr_per_budget": {"per_query": _rate(confirmed_hits, requests),
                           "per_1k_tokens": _rate(confirmed_hits, tokens / 1000.0),
                           "per_usd": _rate(confirmed_hits, spend),
                           "per_minute": _rate(confirmed_hits, elapsed_s / 60.0)},
        "first_success_cost": first_success,  # cost to reach the first success, or None if none was reached
    }
