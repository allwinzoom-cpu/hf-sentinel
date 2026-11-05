"""Adaptive rate governor + budget ledger (plan 16.9, D-005).

Per-key (provider/host, model) pacing with AIMD: halve the rate on 429/503 and pause for `Retry-After`; add back a
little on every success. An explicit rate limit is a ceiling that is never exceeded. One global concurrency limit.
Every attempt — retries included — is metered in a shared ledger whose caps (requests, USD, wall clock) are checked
before the attempt is sent; a wait that would cross the deadline fails closed instead of sleeping.

Thread-safe (the target adapters are synchronous); clock and sleep are injectable for deterministic tests.
"""
from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

from hfsentinel.targets.openai_compat import THROTTLE_STATUS, BudgetExceeded

DEFAULT_RATE_PER_MIN = 60.0  # provider-aware start when no --rate-limit is given
UNCAPPED_MAX_PER_MIN = 600.0
MIN_RATE_PER_MIN = 2.0
MAX_RETRY_AFTER_S = 120.0
# Charged for calls whose provider reports no cost. A deliberately pessimistic assumption, not a price.
UNPRICED_USD_PER_MTOK = 2.0


def retry_after_seconds(value: str | None, now_epoch: float | None = None) -> float | None:
    """Parse Retry-After (delta-seconds or HTTP-date) into seconds from now, capped; None if absent/invalid."""
    if not value:
        return None
    value = value.strip()
    try:
        secs = float(value)
    except ValueError:
        try:
            secs = parsedate_to_datetime(value).timestamp() - (time.time() if now_epoch is None else now_epoch)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
    if math.isnan(secs):
        return None
    return min(max(secs, 0.0), MAX_RETRY_AFTER_S)


@dataclass
class Ledger:
    """Shared, thread-safe meter for one budget (target traffic; judges get their own, D-017)."""
    max_requests: int
    budget_usd: float
    deadline: float | None = None  # clock() value after which no attempt starts
    requests: int = 0
    successes: int = 0
    throttled: int = 0
    errors: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_reported_usd: float = 0.0
    cost_priced_usd: float = 0.0  # from the router's listed per-token price
    cost_estimated_usd: float = 0.0
    unpriced_successes: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def spent_usd(self) -> float:
        return self.cost_reported_usd + self.cost_priced_usd + self.cost_estimated_usd

    def reserve(self, now: float, start: float) -> None:
        """Check every cap, then meter one attempt (reserved before sending so parallel callers cannot overshoot)."""
        with self._lock:
            if self.requests >= self.max_requests:
                raise BudgetExceeded(f"request cap {self.max_requests} reached")
            if self.spent_usd >= self.budget_usd:
                raise BudgetExceeded(f"budget ${self.budget_usd:.2f} reached")
            if self.deadline is not None and max(now, start) >= self.deadline:
                raise BudgetExceeded("time budget reached")
            self.requests += 1

    def throttle(self) -> None:
        with self._lock:
            self.throttled += 1

    def error(self) -> None:
        with self._lock:
            self.errors += 1

    def add_usage(self, usage: dict | None, price: tuple[float, float] | None = None) -> None:
        """Cost precedence: provider-reported `estimated_cost` → listed price (USD per 1M input/output tokens) →
        conservative estimate."""
        usage = usage or {}
        p, c = _int(usage.get("prompt_tokens")), _int(usage.get("completion_tokens"))
        cost = usage.get("estimated_cost")
        with self._lock:
            self.successes += 1
            self.prompt_tokens += p
            self.completion_tokens += c
            if isinstance(cost, (int, float)) and not isinstance(cost, bool) and 0 <= cost < 1e6:
                self.cost_reported_usd += float(cost)
            elif price is not None:
                self.cost_priced_usd += (p * price[0] + c * price[1]) / 1e6
            else:
                self.unpriced_successes += 1
                self.cost_estimated_usd += (p + c) / 1e6 * UNPRICED_USD_PER_MTOK

    def snapshot(self) -> dict:
        with self._lock:
            return {k: getattr(self, k) for k in ("requests", "successes", "throttled", "errors", "prompt_tokens",
                                                   "completion_tokens", "cost_reported_usd", "cost_priced_usd",
                                                   "cost_estimated_usd",
                                                   "unpriced_successes")}


def _int(v: object) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10**9 else 0


@dataclass
class _KeyState:
    rate: float  # requests per second
    next_start: float = 0.0
    paused_until: float = 0.0


class Governor:
    def __init__(self, ledger: Ledger, *, rate_limit_per_min: float | None = None, concurrency: int = 4,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.ledger = ledger
        self.ceiling = (rate_limit_per_min or UNCAPPED_MAX_PER_MIN) / 60.0
        self.start_rate = min(rate_limit_per_min or DEFAULT_RATE_PER_MIN, self.ceiling * 60.0) / 60.0
        self.floor = min(MIN_RATE_PER_MIN / 60.0, self.start_rate)
        # Additive step per success (req/s): ~1% of the start rate, so a halved key probes back up gently.
        self.increase = max(self.start_rate / 100.0, 0.1 / 60.0)
        self.clock, self.sleep = clock, sleep
        self._slots = threading.BoundedSemaphore(concurrency)
        self._lock = threading.Lock()
        self._keys: dict[tuple[str, str], _KeyState] = {}
        self._prices: dict[tuple[str, str], tuple[float, float]] = {}

    @classmethod
    def from_controls(cls, controls, clock: Callable[[], float] = time.monotonic) -> Governor:
        """Target-traffic governor from resolved controls (target_io + budget)."""
        tio, budget = controls.target_io, controls.budget
        ledger = Ledger(max_requests=budget.max_requests, budget_usd=budget.usd,
                        deadline=clock() + budget.minutes * 60)
        return cls(ledger, rate_limit_per_min=tio.rate_limit, concurrency=tio.concurrency, clock=clock)

    def set_price(self, key: tuple[str, str], input_per_mtok: float, output_per_mtok: float) -> None:
        """Listed price for a key (router `/v1/models` pricing) used when the provider reports no cost."""
        if not (0 <= input_per_mtok <= 1000 and 0 <= output_per_mtok <= 1000):
            raise ValueError("price out of range")
        with self._lock:
            self._prices[key] = (float(input_per_mtok), float(output_per_mtok))

    def rate_per_min(self, key: tuple[str, str]) -> float:
        with self._lock:
            return self._state(key).rate * 60.0

    def _state(self, key: tuple[str, str]) -> _KeyState:
        if key not in self._keys:
            self._keys[key] = _KeyState(rate=self.start_rate)
        return self._keys[key]

    @contextmanager
    def slot(self, key: tuple[str, str]) -> Iterator[None]:
        """Wait for this key's next start time and a concurrency slot; meter the attempt; hold the slot while the
        request is in flight."""
        with self._lock:
            now = self.clock()
            st = self._state(key)
            start = max(now, st.next_start, st.paused_until)
            self.ledger.reserve(now, start)  # raises before the schedule advances if any cap is hit
            st.next_start = start + 1.0 / st.rate
        if start > now:
            self.sleep(start - now)
        with self._slots:
            yield

    def record(self, key: tuple[str, str], status: int | None, *, retry_after: str | None = None,
               usage: dict | None = None) -> None:
        """Feed back an attempt's outcome. status None = transport error (no response)."""
        if status is not None and 200 <= status < 300:
            with self._lock:
                price = self._prices.get(key)
            self.ledger.add_usage(usage, price)
            with self._lock:
                st = self._state(key)
                st.rate = min(st.rate + self.increase, self.ceiling)
            return
        with self._lock:
            if status in THROTTLE_STATUS:
                self.ledger.throttle()
                st = self._state(key)
                st.rate = max(st.rate / 2.0, self.floor)
                wait = retry_after_seconds(retry_after)
                now = self.clock()
                st.next_start = max(st.next_start, now + 1.0 / st.rate)
                if wait:
                    st.paused_until = max(st.paused_until, now + wait)
            else:
                self.ledger.error()
