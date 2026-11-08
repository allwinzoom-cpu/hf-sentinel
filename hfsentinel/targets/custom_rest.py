"""Declarative custom-REST target adapter (plan LSCAN-018). A target whose request/response shape is described by DATA,
not code: a body template with a fixed set of named placeholders ({prompt}/{max_tokens}/{temperature}), dotted-path
selectors for the text / usage in the response, and an auth header reference bound to the target origin. There is NO
arbitrary template execution (only the allow-listed placeholders are substituted) and NO response-driven fetching (a URL
in the response is never followed). An unknown/under-specified contract is reported unsupported, never guessed."""
from __future__ import annotations

import copy
import json
from contextlib import nullcontext
from dataclasses import dataclass, field

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

ALLOWED_PLACEHOLDERS = frozenset({"prompt", "max_tokens", "temperature"})  # the only names a body template may reference


@dataclass(frozen=True)
class RestContract:
    """A golden, declarative contract for a custom REST target (LSCAN-018)."""
    url: str
    text_path: str                      # dotted path to the answer text in the response JSON
    body_template: dict                 # request body; string leaves may contain {prompt}/{max_tokens}/{temperature}
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    auth_header: str = ""               # header name that carries the per-target credential
    usage_path: str = ""                # optional dotted path to usage

    def supported(self) -> tuple[bool, str]:
        """A contract is supported only if it has a URL, a text selector, and every template placeholder is allow-listed
        (no arbitrary names/expressions). Returns (ok, reason)."""
        if not self.url or not self.text_path:
            return False, "contract missing url or text_path"
        bad = _bad_placeholders(self.body_template)
        if bad:
            return False, f"body template references non-allow-listed placeholders: {sorted(bad)}"
        return True, ""


def _bad_placeholders(obj) -> set[str]:
    import string
    out: set[str] = set()
    if isinstance(obj, str):
        for _, field_name, _, _ in string.Formatter().parse(obj):
            if field_name:
                out.add(field_name.split(".")[0].split("[")[0])
    elif isinstance(obj, dict):
        for v in obj.values():
            out |= _bad_placeholders(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _bad_placeholders(v)
    return out - ALLOWED_PLACEHOLDERS


def _fill(obj, values: dict):
    if isinstance(obj, str):
        return obj.format(**values)                # only allow-listed names (validated by supported()); no code
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, values) for v in obj]
    return obj


def select(data, path: str):
    """Follow a dotted path (keys and integer list indices) into `data`; None if any step is missing. No code, no fetch."""
    cur = data
    for part in path.split(".") if path else []:
        if isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            cur = cur[idx] if -len(cur) <= idx < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


@dataclass
class CustomRestTarget:
    model: str
    contract: RestContract
    api_key: str = field(repr=False, default="")   # per-target credential; bound to the contract origin, never HF token
    timeout: float = 60.0
    max_requests: int = 100
    requests_made: int = 0
    governor: object | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)

    def __post_init__(self) -> None:
        ok, reason = self.contract.supported()
        if not ok:
            raise ValueError(f"unsupported custom-REST contract: {reason}")
        self.user_agent = check_user_agent(self.user_agent)

    @property
    def rate_key(self) -> tuple[str, str]:
        return (self.contract.url, self.model)

    def _prompt(self, messages: list[dict]) -> str:
        return "\n".join(m["content"] for m in messages if isinstance(m.get("content"), str))

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"request cap {self.max_requests} reached")
        values = {"prompt": self._prompt(messages), "max_tokens": max_tokens, "temperature": temperature}
        body = _fill(copy.deepcopy(self.contract.body_template), values)
        headers = {"content-type": "application/json", "user-agent": self.user_agent, **self.contract.headers}
        if self.contract.auth_header and self.api_key:
            headers[self.contract.auth_header] = self.api_key
        gov, key = self.governor, self.rate_key
        self.requests_made += 1
        try:
            with gov.slot(key) if gov else nullcontext():
                resp = self.transport.request(self.contract.method, self.contract.url, headers=headers,
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
            data = json.loads(resp.body)
        except (ValueError, TypeError):
            raise TargetError("target returned an unexpected response shape") from None
        text = select(data, self.contract.text_path)
        if not isinstance(text, str):
            raise TargetError("response text selector did not resolve to a string")
        usage = select(data, self.contract.usage_path) if self.contract.usage_path else {}
        usage = usage if isinstance(usage, dict) else {}
        if gov:
            gov.record(key, 200, usage=usage)
        return ChatResult(text=text, model=self.model, usage=usage)  # the URL, if any, in `text` is never followed
