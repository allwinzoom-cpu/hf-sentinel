"""Adaptive rate governor + ledger (plan 16.9). Unit dynamics run on a fake clock; the done-when runs twice: a
deterministic simulation over simulated minutes, and real adapters against a loopback stub that 429s above N."""
import json
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import pairwise

import pytest

from hfsentinel.controls import resolve_controls
from hfsentinel.engines.governor import (
    MAX_RETRY_AFTER_S,
    UNPRICED_USD_PER_MTOK,
    Governor,
    Ledger,
    retry_after_seconds,
)
from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import BudgetExceeded, OpenAICompatTarget, TargetError

KEY = ("https://router.example/v1", "org/model:prov")


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        assert s >= 0
        self.t += s


def gov(clock, *, rate=None, concurrency=4, max_requests=10_000, usd=20.0, deadline=None):
    return Governor(Ledger(max_requests, usd, deadline), rate_limit_per_min=rate, concurrency=concurrency,
                    clock=clock, sleep=clock.sleep)


def one(g, key=KEY, status=200, **kw):
    with g.slot(key):
        pass
    g.record(key, status, **kw)


# ---- Retry-After ----
@pytest.mark.parametrize("value, want", [("5", 5.0), ("0", 0.0), ("-3", 0.0), ("2.5", 2.5),
                                         ("100000", MAX_RETRY_AFTER_S), (None, None), ("", None), ("soon", None),
                                         ("nan", None)])
def test_retry_after_seconds(value, want):
    assert retry_after_seconds(value) == want


def test_retry_after_http_date():
    assert retry_after_seconds(formatdate(1_000_030, usegmt=True), now_epoch=1_000_000) == pytest.approx(30, abs=1)
    assert retry_after_seconds(formatdate(999_000, usegmt=True), now_epoch=1_000_000) == 0.0


# ---- pacing + AIMD ----
def test_strict_pacing_from_rate_limit():
    c = FakeClock()
    g = gov(c, rate=30)  # 30/min → one start every 2 s, no burst
    starts = []
    for _ in range(4):
        with g.slot(KEY):
            starts.append(c())
    assert [round(b - a, 6) for a, b in pairwise(starts)] == [2.0, 2.0, 2.0]


def test_aimd_halves_on_throttle_and_recovers_additively():
    c = FakeClock()
    g = gov(c)  # provider-aware start: 60/min
    assert g.rate_per_min(KEY) == pytest.approx(60)
    one(g, status=429)
    assert g.rate_per_min(KEY) == pytest.approx(30)
    one(g, status=503)
    assert g.rate_per_min(KEY) == pytest.approx(15)
    one(g, status=500)  # plain server errors are not throttles
    assert g.rate_per_min(KEY) == pytest.approx(15)
    one(g)
    assert g.rate_per_min(KEY) == pytest.approx(15.6)
    for _ in range(40):
        one(g, status=429)
    assert g.rate_per_min(KEY) == pytest.approx(2.0)  # floor


def test_explicit_rate_limit_is_a_ceiling():
    c = FakeClock()
    g = gov(c, rate=30)
    for _ in range(200):
        one(g)
    assert g.rate_per_min(KEY) == pytest.approx(30)


def test_keys_are_independent():
    c = FakeClock()
    g = gov(c)
    one(g, status=429)
    assert g.rate_per_min(("other", "m")) == pytest.approx(60)


def test_retry_after_pauses_the_key():
    c = FakeClock()
    g = gov(c, rate=600)
    one(g, status=429, retry_after="7")
    t0 = c()
    with g.slot(KEY):
        assert c() >= t0 + 7


# ---- ledger caps (fail closed before sending) ----
def test_request_cap():
    c = FakeClock()
    g = gov(c, max_requests=3)
    for _ in range(3):
        one(g)
    with pytest.raises(BudgetExceeded, match="request cap"):
        one(g)
    assert g.ledger.requests == 3


def test_usd_cap_reported_and_unpriced():
    c = FakeClock()
    g = gov(c, usd=0.01)
    one(g, usage={"prompt_tokens": 10, "completion_tokens": 8, "estimated_cost": 0.006})
    one(g, usage={"prompt_tokens": 1_000, "completion_tokens": 1_000})  # provider reported no cost
    led = g.ledger
    assert led.cost_reported_usd == pytest.approx(0.006)
    assert led.cost_estimated_usd == pytest.approx(2_000 / 1e6 * UNPRICED_USD_PER_MTOK)
    assert led.unpriced_successes == 1
    with pytest.raises(BudgetExceeded, match="budget"):
        one(g)


@pytest.mark.parametrize("usage", [{"estimated_cost": True}, {"estimated_cost": -1}, {"estimated_cost": "1"},
                                   {"prompt_tokens": -5, "completion_tokens": "9"}, None])
def test_malformed_usage_never_lowers_spend(usage):
    c = FakeClock()
    g = gov(c)
    one(g, usage=usage)
    assert g.ledger.cost_reported_usd == 0 and g.ledger.unpriced_successes == 1 and g.ledger.prompt_tokens == 0


def test_deadline_fails_closed_without_sleeping():
    c = FakeClock()
    g = gov(c, rate=1, deadline=c() + 30)  # one start per 60 s
    one(g)
    t = c()
    with pytest.raises(BudgetExceeded, match="time budget"), g.slot(KEY):
        pass  # next start would be after the deadline
    assert c() == t and g.ledger.requests == 1


def test_from_controls():
    c = FakeClock()
    res = resolve_controls({"profile": "custom", "rate_limit": 90, "concurrency": 2, "max_requests": 50,
                            "budget_usd": 3, "max_minutes": 10})
    g = Governor.from_controls(res.controls, clock=c)
    assert g.rate_per_min(KEY) == pytest.approx(90)
    assert (g.ledger.max_requests, g.ledger.budget_usd, g.ledger.deadline) == (50, 3.0, c() + 600)


# ---- concurrency ----
def test_thread_safe_metering_and_concurrency_limit():
    g = Governor(Ledger(10_000, 20.0), rate_limit_per_min=6000, concurrency=3)
    in_flight, peak, lock = [0], [0], threading.Lock()

    def work(i):
        key = ("k", str(i % 4))
        with g.slot(key):
            with lock:
                in_flight[0] += 1
                peak[0] = max(peak[0], in_flight[0])
            threading.Event().wait(0.002)
            with lock:
                in_flight[0] -= 1
        g.record(key, 429 if i in (0, 50, 100, 150) else 200, usage={"prompt_tokens": 1, "completion_tokens": 1})

    with ThreadPoolExecutor(8) as ex:
        list(ex.map(work, range(200)))
    snap = g.ledger.snapshot()
    assert snap["requests"] == 200 and snap["throttled"] == 4 and snap["successes"] == 196
    assert peak[0] <= 3


# ---- Done when (1): deterministic simulation over simulated minutes ----
class SlidingLimiter:
    """Stub provider: 429 when more than N requests (all hits, including refused ones) arrived in the last window."""

    def __init__(self, n, window=60.0):
        self.n, self.window, self.recent = n, window, deque()
        self.hits = self.refused = 0
        self.log = []

    def hit(self, now):
        while self.recent and self.recent[0] <= now - self.window:
            self.recent.popleft()
        self.hits += 1
        self.recent.append(now)
        ok = len(self.recent) <= self.n
        self.refused += not ok
        self.log.append((now, ok))
        return 200 if ok else 429


def test_simulated_convergence_below_n():
    c = FakeClock()
    n = 30
    stub = SlidingLimiter(n)
    g = gov(c)  # starts at 60/min: twice the stub's limit
    failed = 0
    for _ in range(400):
        for _attempt in range(9):  # adapter semantics: up to 8 throttle retries
            with g.slot(KEY):
                status = stub.hit(c())
            g.record(KEY, status)
            if status == 200:
                break
        else:
            failed += 1
    snap = g.ledger.snapshot()
    assert failed == 0
    assert snap["requests"] == stub.hits and snap["throttled"] == stub.refused and snap["successes"] == 400
    t_end = c()
    last = [t for t, _ in stub.log if t > t_end - 300]  # final five simulated minutes
    assert len(last) / 5 <= n  # converged: average arrival rate below N/min
    late_refusals = sum(1 for t, ok in stub.log if t > t_end - 300 and not ok)
    assert late_refusals / max(len(last), 1) < 0.05  # steady state: under 5 % of attempts throttled
    assert len(last) / 5 >= 0.5 * n  # and still using at least half the allowance


# ---- Done when (2): real adapters + threads against a loopback stub that 429s above N per window ----
class StubServer:
    def __init__(self, n, window):
        self.limiter = SlidingLimiter(n, window)
        self.lock = threading.Lock()
        limiter, lock = self.limiter, self.lock

        class H(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                with lock:
                    status = limiter.hit(time.monotonic())
                body = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                                   "usage": {"prompt_tokens": 3, "completion_tokens": 1, "estimated_cost": 1e-6}}
                                  if status == 200 else {"error": "rate limited"}).encode()
                self.send_response(status)
                if status == 429:
                    self.send_header("Retry-After", "1")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/v1"


def test_real_adapters_converge_with_zero_failed_trials():
    n, window = 10, 1.0  # stub limit: 10 per second (600/min)
    stub = StubServer(n, window)
    g = Governor(Ledger(10_000, 20.0), rate_limit_per_min=1800, concurrency=4)  # ceiling 3x the limit
    target = OpenAICompatTarget(stub.url, "m", max_requests=10_000, governor=g)

    def trial(_):
        try:
            return target.chat([{"role": "user", "content": "x"}]).text == "ok"
        except (TargetError, BudgetExceeded):
            return False

    try:
        with ThreadPoolExecutor(4) as ex:
            results = list(ex.map(trial, range(60)))
    finally:
        stub.srv.shutdown()
    snap = g.ledger.snapshot()
    assert all(results)  # zero failed trials
    assert snap["requests"] == stub.limiter.hits == target.requests_made  # ledger matches the stub's hit count
    assert snap["throttled"] == stub.limiter.refused and snap["successes"] == 60
    assert stub.limiter.refused >= 1  # the ceiling really was above N, so the governor had to adapt
    assert g.rate_per_min(target.rate_key) < n / window * 60  # converged below N
    assert snap["cost_reported_usd"] == pytest.approx(60e-6)


def test_gradio_adapter_is_metered_too():
    from tests.test_gradio_space import USER, Space

    sp = Space(post_status=[429])
    try:
        g = Governor(Ledger(100, 20.0), rate_limit_per_min=6000)
        t = GradioSpaceTarget(sp.url, governor=g)
        assert t.chat(USER).text == "Hello pong!"
    finally:
        sp.srv.shutdown()
    snap = g.ledger.snapshot()
    assert snap["requests"] == len(sp.seen) == t.requests_made == 5 and snap["throttled"] == 1


def test_without_governor_adapters_behave_as_before():
    stub = StubServer(1000, 1.0)
    try:
        t = OpenAICompatTarget(stub.url, "m")
        assert t.chat([{"role": "user", "content": "x"}]).text == "ok" and t.governor is None
    finally:
        stub.srv.shutdown()
