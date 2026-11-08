"""Gateway/cache/concurrency isolation (plan / LSCAN-076): a fresh-canary crossover is the only leak confirmation, a
cancel/retry race is caught, cache-key isolation is checked, and a timing-only signal stays experimental."""
from engines import gateway_isolation as gi


def _ids():
    return [gi.Identity("alice", "tok-a", "CANARY-AAAA-1111"),
            gi.Identity("bob", "tok-b", "CANARY-BBBB-2222")]


def test_session_crossover_is_confirmed_only_by_a_foreign_canary():
    a, b = _ids()
    # bob's response leaks alice's canary -> (alice -> bob)
    responses = {"alice": "here is CANARY-AAAA-1111 your answer", "bob": "oops CANARY-AAAA-1111 leaked"}
    assert gi.session_crossover(responses, [a, b]) == [("alice", "bob")]
    # each only sees its own canary -> no crossover
    clean = {"alice": "CANARY-AAAA-1111 ok", "bob": "CANARY-BBBB-2222 ok"}
    assert gi.session_crossover(clean, [a, b]) == []


def test_cancel_retry_leak_detected():
    assert gi.cancel_retry_leak("CANARY-AAAA-1111", "retry produced CANARY-AAAA-1111")
    assert not gi.cancel_retry_leak("CANARY-AAAA-1111", "fresh unrelated output")


def test_cache_key_isolation():
    a, b = _ids()
    assert gi.cache_key_isolated(a, b, "CANARY-AAAA-1111 ans", "CANARY-BBBB-2222 ans")       # each own content
    assert not gi.cache_key_isolated(a, b, "CANARY-AAAA-1111 ans", "CANARY-AAAA-1111 ans")   # bob got alice's cache


def test_timing_signal_stays_experimental_without_a_canary():
    assert "confirmed" in gi.timing_verdict(canary_confirmed=True, latency_delta_ms=5, noise_floor_ms=50)
    assert "experimental" in gi.timing_verdict(canary_confirmed=False, latency_delta_ms=200, noise_floor_ms=50)
    assert "no signal" in gi.timing_verdict(canary_confirmed=False, latency_delta_ms=10, noise_floor_ms=50)


def test_quota_bounds_concurrency():
    assert gi.within_quota(2, max_concurrency=4)
    assert not gi.within_quota(8, max_concurrency=4)
    assert not gi.within_quota(0, max_concurrency=4)
