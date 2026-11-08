"""Native Anthropic Messages target adapter (plan LSCAN-014). Speaks the real Messages API contract — the system
instruction is a TOP-LEVEL field (never folded into a user turn), the `anthropic-version` header is sent, and the
provider key is a per-target credential bound to the Anthropic origin (never the HF token). The response is normalized by
`anthropic_messages.normalize_messages`, preserving native roles, tool-use blocks, usage and the `stop_reason=="refusal"`
signal. Unsupported prefill/thinking access is reported as unsupported, never a successful check.

The offline contract (request shape + normalization) is unit-tested with an injected transport; a live smoke needs an
Anthropic key (GATE). Only a single bounded request is issued here; retry/governor hardening matches openai_compat when
wired live.
"""
from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import dataclass, field

from hfsentinel.targets.anthropic_messages import normalize_messages, prefill_outcome
from hfsentinel.targets.openai_compat import (
    DEFAULT_USER_AGENT,
    MAX_RESPONSE_BYTES,
    BudgetExceeded,
    ChatResult,
    TargetError,
    check_user_agent,
)
from hfsentinel.targets.transport import SHARED as SHARED_TRANSPORT
from hfsentinel.targets.transport import Transport, TransportError

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
EXTRA_PARAMS = frozenset({"tools", "tool_choice", "stop_sequences", "top_p", "top_k"})


def to_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """Split OpenAI-style messages into the Anthropic top-level `system` string and the user/assistant turn list. The
    system instruction stays a native top-level field — never merged into a user message (LSCAN-014)."""
    system = "\n".join(m["content"] for m in messages
                       if m.get("role") == "system" and isinstance(m.get("content"), str))
    turns = [{"role": m["role"], "content": m["content"]} for m in messages if m.get("role") in ("user", "assistant")]
    return system, turns


@dataclass
class AnthropicTarget:
    model: str
    api_key: str = field(repr=False, default="")   # per-target Anthropic credential; never logged, never the HF token
    endpoint: str = DEFAULT_ENDPOINT
    version: str = ANTHROPIC_VERSION
    timeout: float = 60.0
    max_requests: int = 100
    requests_made: int = 0
    governor: object | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.user_agent = check_user_agent(self.user_agent)

    @property
    def rate_key(self) -> tuple[str, str]:
        return (self.endpoint, self.model)

    def build_request(self, messages: list[dict], *, max_tokens: int, temperature: float,
                      extra: dict | None = None) -> tuple[dict, dict]:
        """(body, headers) for the Messages request. Raises on an unsupported extra field (no silent drop)."""
        system, turns = to_anthropic(messages)
        body: dict = {"model": self.model, "messages": turns, "max_tokens": max_tokens, "temperature": temperature}
        if system:
            body["system"] = system
        if extra:
            unknown = set(extra) - EXTRA_PARAMS
            if unknown:
                raise ValueError(f"unsupported request fields: {sorted(unknown)}")
            body.update(extra)
        headers = {"content-type": "application/json", "anthropic-version": self.version,
                   "user-agent": self.user_agent}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return body, headers

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"request cap {self.max_requests} reached")
        body, headers = self.build_request(messages, max_tokens=max_tokens, temperature=temperature, extra=extra)
        gov, key = self.governor, self.rate_key
        self.requests_made += 1
        try:
            with gov.slot(key) if gov else nullcontext():
                resp = self.transport.request("POST", self.endpoint, headers=headers,
                                              body=json.dumps(body).encode(), timeout=self.timeout,
                                              limit=MAX_RESPONSE_BYTES)
        except TransportError as e:
            if gov:
                gov.record(key, None)
            raise TargetError(f"target unreachable: {e}") from None
        if not (200 <= resp.status < 300):
            if gov:
                gov.record(key, resp.status, retry_after=resp.headers.get("retry-after"))
            raise TargetError(f"target returned HTTP {resp.status}", status=resp.status)
        try:
            raw = json.loads(resp.body)
            norm = normalize_messages(raw)
        except (ValueError, AttributeError, TypeError):
            raise TargetError("target returned an unexpected response shape") from None
        usage = norm.get("usage") or {}
        if gov:
            gov.record(key, 200, usage=usage)
        return ChatResult(text=norm["text"], model=str(raw.get("model", self.model)), usage=usage,
                          finish_reason=raw.get("stop_reason"), tool_calls=list(norm["tool_calls"]),
                          refusal=bool(norm["refusal"]))

    def prefill(self, accepted: bool | None) -> str:
        """Record an assistant-prefill attempt (LSCAN-014): unsupported/rejected prefill is never a successful check."""
        return prefill_outcome(accepted)
