"""Minimal OpenAI-compatible chat client (HF Inference Providers router or any /v1 endpoint).

Pooled urllib3 transport (D-022). HTTPS required except for loopback test targets; no redirects; bounded timeouts and
response size;
bounded retries on 429/5xx and on transient transport failures (every attempt counts against the request cap). With a
rate governor (plan 16.9) every attempt is paced and metered by it, and throttles are retried on its schedule instead of
a fixed backoff.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hfsentinel.targets.protocols import normalize as normalize_protocol
from hfsentinel.targets.transport import SHARED as SHARED_TRANSPORT
from hfsentinel.targets.transport import Transport, TransportError

if TYPE_CHECKING:
    from hfsentinel.engines.governor import Governor
from urllib.parse import urlparse

HF_ROUTER = "https://router.huggingface.co/v1"
MAX_RESPONSE_BYTES = 2_000_000
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
THROTTLE_STATUS = {429, 503}
MAX_THROTTLE_RETRIES = 8
DEFAULT_USER_AGENT = "hfsentinel/0.0.1"  # honest identification in authorized tests; override per engagement
MAX_USER_AGENT = 200
# The request fields callers may add (LSCAN-022 feature negotiation): structured-output/tool fields plus the standard
# generation controls a probe sends to test whether a target actually honours them. Unknown fields are still refused.
EXTRA_PARAMS = frozenset({"response_format", "tools", "tool_choice", "seed", "stop", "top_p", "top_k", "logprobs"})
MAX_TOOL_CALLS = 16
MAX_BACKOFF_S = 30.0


class TargetError(RuntimeError):
    """Generic, secret-free failure talking to a target. `status` is the HTTP status when the target answered."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class BudgetExceeded(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def check_user_agent(value: str) -> str:
    """A User-Agent must be a single printable-ASCII header value: CR/LF would let it inject extra headers."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_USER_AGENT or not all(" " <= c <= "~" for c in value):
        raise ValueError(f"user agent must be 1-{MAX_USER_AGENT} printable ASCII characters (no CR/LF)")
    return value


def _check_base_url(base_url: str) -> str:
    u = urlparse(base_url)
    if u.scheme == "https" and u.hostname:
        return base_url.rstrip("/")
    if u.scheme == "http" and u.hostname in LOOPBACK_HOSTS:
        return base_url.rstrip("/")  # local deliberately-vulnerable test target only
    raise ValueError("target base URL must be https (http allowed only for loopback test targets)")


@dataclass
class ChatResult:
    text: str
    model: str
    usage: dict = field(default_factory=dict)
    reasoning: str = ""  # reasoning-model trace (`reasoning_content` / `reasoning`), kept separate from the answer
    finish_reason: str | None = None
    tool_calls: list[dict] = field(default_factory=list)  # [{"name": str, "arguments": str}], bounded
    refusal: bool = False  # provider-side refusal (content filter), per the protocol contract — distinct from empty text


@dataclass
class OpenAICompatTarget:
    base_url: str
    model: str
    api_key: str = field(repr=False, default="")
    timeout: float = 60.0
    max_requests: int = 100
    retries: int = 2
    requests_made: int = 0
    governor: Governor | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.base_url = _check_base_url(self.base_url)
        self.user_agent = check_user_agent(self.user_agent)

    @property
    def rate_key(self) -> tuple[str, str]:
        """Governor key: (endpoint, model) — the router's model string carries the pinned provider."""
        return (self.base_url, self.model)

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        payload = {"model": self.model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        if extra:
            unknown = set(extra) - EXTRA_PARAMS
            if unknown:
                raise ValueError(f"unsupported request fields: {sorted(unknown)}")
            payload.update(extra)
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": self.user_agent}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        url = f"{self.base_url}/chat/completions"
        gov, key = self.governor, self.rate_key
        attempt = throttles = 0
        while True:
            if self.requests_made >= self.max_requests:
                raise BudgetExceeded(f"request cap {self.max_requests} reached")
            self.requests_made += 1
            try:
                with gov.slot(key) if gov else nullcontext():
                    resp = self.transport.request("POST", url, headers=headers, body=body, timeout=self.timeout,
                                                  limit=MAX_RESPONSE_BYTES)
            except TransportError as e:
                if gov:
                    gov.record(key, None)
                # A transient transport failure (connection reset, TLS blip, read timeout) is the commonest flake against
                # a remote endpoint; retry it like a 5xx — bounded by self.retries, every attempt metered. With a governor
                # the next slot() re-paces this key (next_start already advanced); without one, back off first.
                if attempt < self.retries:
                    if not gov:
                        time.sleep(_backoff(None, attempt))
                    attempt += 1
                    continue
                raise TargetError(f"target unreachable: {e}") from None
            if 200 <= resp.status < 300:
                raw = resp.body
                break
            retry_after = resp.headers.get("retry-after")
            if gov:
                gov.record(key, resp.status, retry_after=retry_after)
                if resp.status in THROTTLE_STATUS and throttles < MAX_THROTTLE_RETRIES:
                    throttles += 1
                    continue  # the governor has slowed this key and schedules the retry
            if resp.status in RETRYABLE_STATUS and attempt < self.retries:
                if not gov:
                    time.sleep(_backoff(retry_after, attempt))
                attempt += 1
                continue
            raise TargetError(f"target returned HTTP {resp.status}", status=resp.status)
        if len(raw) > MAX_RESPONSE_BYTES:
            if gov:
                gov.record(key, None)
            raise TargetError("target response exceeded size limit")
        try:
            result = parse_chat_response(raw, self.model)
        except TargetError:
            if gov:
                gov.record(key, None)
            raise
        if gov:
            gov.record(key, 200, usage=result.usage)
        return result


def _backoff(retry_after: str | None, attempt: int) -> float:
    try:
        if retry_after is not None:
            return min(max(float(retry_after), 0.0), MAX_BACKOFF_S)
    except ValueError:
        pass  # HTTP-date form: fall back to exponential backoff
    return min(2.0 ** attempt, MAX_BACKOFF_S)


def parse_chat_response(raw: bytes, requested_model: str) -> ChatResult:
    try:
        data = json.loads(raw)
        choice = data["choices"][0]
        msg = choice["message"]
        text = msg.get("content") or ""
        reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise TargetError("target returned an unexpected response shape") from None
    if not isinstance(text, str) or not isinstance(reasoning, str):
        raise TargetError("target returned non-text content")
    usage = data.get("usage")
    # LSCAN-013: the provider-side refusal signal comes from the shared protocol contract (content_filter stop), so the
    # adapter and the normalizer can never disagree on what counts as a refusal.
    refusal = normalize_protocol("chat-completions", data)["refusal"]
    return ChatResult(text=text, model=str(data.get("model", requested_model)),
                      usage=dict(usage) if isinstance(usage, dict) else {}, reasoning=reasoning,
                      finish_reason=choice.get("finish_reason"), tool_calls=_tool_calls(msg.get("tool_calls")),
                      refusal=refusal)


def _tool_calls(raw: object) -> list[dict]:
    """Well-formed function calls only, bounded in count and size; anything else is dropped."""
    calls = []
    for c in raw[:MAX_TOOL_CALLS] if isinstance(raw, list) else []:
        fn = c.get("function") if isinstance(c, dict) else None
        name = fn.get("name") if isinstance(fn, dict) else None
        args = fn.get("arguments", "") if isinstance(fn, dict) else ""
        if isinstance(name, str) and 0 < len(name) <= 64:
            calls.append({"name": name, "arguments": args[:4000] if isinstance(args, str) else ""})
    return calls
