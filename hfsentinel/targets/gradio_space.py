"""Gradio Space adapter over Gradio's REST API (stdlib only; no vendor client, so no client fingerprint reaches the
target — D-014/16.16).

Protocol (verified live on Gradio 6.30/6.31, 2026-11-03): GET /config → api_prefix; GET {prefix}/info → named
endpoints; POST {prefix}/call/{api} → {"event_id"}; GET {prefix}/call/{api}/{event_id} → SSE ending in
`event: complete` / `data: [...]`. Everything the Space returns is untrusted: identifiers are validated before they
reach a URL, bodies are size-capped, redirects are refused, and file outputs are never downloaded.
"""
from __future__ import annotations

import json
import re
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hfsentinel.targets.openai_compat import (
    DEFAULT_USER_AGENT,
    MAX_RESPONSE_BYTES,
    MAX_THROTTLE_RETRIES,
    RETRYABLE_STATUS,
    THROTTLE_STATUS,
    BudgetExceeded,
    ChatResult,
    TargetError,
    _backoff,
    _check_base_url,
    check_user_agent,
)
from hfsentinel.targets.transport import SHARED as SHARED_TRANSPORT
from hfsentinel.targets.transport import Transport, TransportError

API_PREFIXES = ("", "/gradio_api")
# Named inputs of the HF chatbot-template shape (ChatInterface additional inputs): when an endpoint exposes them, the
# trial's system message and sampling settings are passed through; otherwise they are app-controlled.
SYSTEM_PARAMS = ("system_message", "system_prompt", "system")
MAX_TOKENS_PARAMS = ("max_tokens", "max_new_tokens")
TEMPERATURE_PARAMS = ("temperature",)
NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$", re.ASCII)
EVENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$", re.ASCII)
MAX_INFO_BYTES = 4_000_000  # /config embeds the whole component tree
MAX_DEFAULT_CHARS = 2_000

if TYPE_CHECKING:
    from hfsentinel.engines.governor import Governor


@dataclass
class GradioSpaceTarget:
    base_url: str
    api_name: str | None = None  # endpoint without '/', e.g. "chat"; None = discover
    api_key: str = field(repr=False, default="")
    timeout: float = 60.0
    max_requests: int = 100
    retries: int = 2
    requests_made: int = 0
    governor: Governor | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)
    _prefix: str | None = field(default=None, repr=False)
    _shape: _Shape | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.base_url = _check_base_url(self.base_url)
        self.user_agent = check_user_agent(self.user_agent)
        if self.api_name is not None and not NAME.match(self.api_name):
            raise ValueError("invalid Gradio endpoint name")

    @property
    def rate_key(self) -> tuple[str, str]:
        return (self.base_url, "gradio")  # one Space is one rate domain

    # ---- transport ----
    def _request(self, path: str, body: dict | None = None, *, limit: int | None = None,
                 retry: bool = False) -> bytes:
        limit = limit or MAX_RESPONSE_BYTES
        headers = {"Accept": "application/json, text/event-stream", "User-Agent": self.user_agent}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        gov, key = self.governor, self.rate_key
        attempt = throttles = 0
        method = "POST" if body is not None else "GET"
        payload = json.dumps(body).encode() if body is not None else None
        while True:
            if self.requests_made >= self.max_requests:
                raise BudgetExceeded(f"request cap {self.max_requests} reached")
            self.requests_made += 1
            try:
                with gov.slot(key) if gov else nullcontext():
                    resp = self.transport.request(method, f"{self.base_url}{path}", headers=headers, body=payload,
                                                  timeout=self.timeout, limit=limit)
            except TransportError as e:
                if gov:
                    gov.record(key, None)
                raise TargetError(f"space unreachable: {e}") from None
            if 200 <= resp.status < 300:
                raw = resp.body
                break
            retry_after = resp.headers.get("retry-after")
            if gov:
                gov.record(key, resp.status, retry_after=retry_after)
                if resp.status in THROTTLE_STATUS and throttles < MAX_THROTTLE_RETRIES:
                    throttles += 1
                    continue  # a throttled request was not processed; the governor schedules the retry
            if retry and resp.status in RETRYABLE_STATUS and attempt < self.retries:
                if not gov:
                    time.sleep(_backoff(retry_after, attempt))
                attempt += 1
                continue
            raise TargetError(f"space returned HTTP {resp.status}", status=resp.status)
        if len(raw) > limit:
            if gov:
                gov.record(key, None)
            raise TargetError("space response exceeded size limit")
        if gov:
            gov.record(key, 200)
        return raw

    def _json(self, path: str, *, limit: int = MAX_INFO_BYTES) -> object:
        try:
            return json.loads(self._request(path, limit=limit))
        except ValueError:
            raise TargetError("space returned an unexpected response") from None

    # ---- endpoint discovery ----
    def _discover(self) -> None:
        cfg = self._json("/config")
        prefix = cfg.get("api_prefix", "") if isinstance(cfg, dict) else None
        if prefix not in API_PREFIXES:
            raise TargetError("space is not a supported Gradio app")
        info = self._json(f"{prefix}/info")
        endpoints = info.get("named_endpoints") if isinstance(info, dict) else None
        if not isinstance(endpoints, dict):
            raise TargetError("space exposes no Gradio API")
        usable = {}
        for raw_name, ep in endpoints.items():
            name = raw_name[1:] if isinstance(raw_name, str) and raw_name.startswith("/") else ""
            if NAME.match(name) and isinstance(ep, dict) and ep.get("api_visibility", "public") == "public":
                shape = _text_shape(ep.get("parameters"))
                if shape:
                    usable[name] = shape
        if self.api_name:
            if self.api_name not in usable:
                raise TargetError(f"space endpoint /{self.api_name} is missing or does not take one text input")
            name = self.api_name
        elif "chat" in usable:
            name = "chat"
        elif len(usable) == 1:
            name = next(iter(usable))
        else:
            raise TargetError("space has no single text endpoint to attack; pin one with hf-space://owner/space@api"
                              if not usable else "space has several text endpoints; pin one with @api: "
                              + ", ".join(sorted(usable))[:200])
        self._prefix, self.api_name = prefix, name
        self._shape = usable[name]

    # ---- chat ----
    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7) -> ChatResult:
        """Single-turn text in, text out. A system message and sampling settings are passed only when the endpoint
        exposes them as named inputs (HF chatbot-template shape); otherwise the app controls them."""
        system = None
        if len(messages) == 2 and messages[0].get("role") == "system":
            system, messages = messages[0].get("content"), messages[1:]
        if (len(messages) != 1 or messages[0].get("role") != "user" or not isinstance(messages[0].get("content"), str)
                or not (system is None or isinstance(system, str))):
            raise TargetError("Gradio Space targets accept one text user message (plus a system message when the "
                              "endpoint exposes one); no history")
        if self._prefix is None:
            self._discover()
        shape = self._shape
        if system is not None and shape.system is None:
            raise TargetError(f"Space endpoint /{self.api_name} takes no system message")
        data = list(shape.template)
        data[shape.text] = messages[0]["content"]
        if system is not None:
            data[shape.system] = system
        if shape.max_tokens is not None:
            data[shape.max_tokens] = int(max_tokens)
        if shape.temperature is not None:
            data[shape.temperature] = float(temperature)
        base = f"{self._prefix}/call/{self.api_name}"
        try:
            event = json.loads(self._request(base, {"data": data}, limit=10_000, retry=True)).get("event_id")
        except (ValueError, AttributeError):
            raise TargetError("space returned an unexpected response") from None
        if not isinstance(event, str) or not EVENT_ID.match(event):
            raise TargetError("space returned an invalid event id")
        text = _complete_text(self._request(f"{base}/{event}"))
        return ChatResult(text=text, model=f"space:/{self.api_name}", finish_reason="stop")


@dataclass(frozen=True)
class _Shape:
    template: list  # positional data: defaults, with the text slot set to None
    text: int
    system: int | None = None
    max_tokens: int | None = None
    temperature: int | None = None


def _text_shape(params: object) -> _Shape | None:
    """Shape of an endpoint with exactly one required str parameter (the user text); other params keep their
    (small, JSON-scalar) defaults, and recognised names become the system / max_tokens / temperature slots. None if
    the endpoint does not fit."""
    if not isinstance(params, list) or not params:
        return None
    template, slot, named = [], None, {}
    for i, p in enumerate(params):
        if not isinstance(p, dict):
            return None
        ptype = (p.get("python_type") or {}).get("type") if isinstance(p.get("python_type"), dict) else None
        if not p.get("parameter_has_default"):
            if slot is not None or ptype != "str":
                return None
            slot = i
            template.append(None)
            continue
        default = p.get("parameter_default")
        if not (default is None or isinstance(default, (bool, int, float))
                or isinstance(default, str) and len(default) <= MAX_DEFAULT_CHARS):
            return None
        template.append(default)
        name = p.get("parameter_name")
        if name in SYSTEM_PARAMS and ptype == "str" and "system" not in named:
            named["system"] = i
        elif name in MAX_TOKENS_PARAMS and ptype in ("int", "float") and "max_tokens" not in named:
            named["max_tokens"] = i
        elif name in TEMPERATURE_PARAMS and ptype in ("int", "float") and "temperature" not in named:
            named["temperature"] = i
    return _Shape(template, slot, **named) if slot is not None else None


def _complete_text(raw: bytes) -> str:
    """Parse the SSE stream; return the text of the `complete` event's first output."""
    event, data = None, []
    for line in raw.decode("utf-8", errors="replace").splitlines() + [""]:
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].strip())
        elif line == "" and event:
            if event == "error":
                raise TargetError("space reported an error")
            if event == "complete":
                try:
                    out = json.loads("\n".join(data))
                except ValueError:
                    raise TargetError("space returned an unexpected response") from None
                first = out[0] if isinstance(out, list) and out else None
                if isinstance(first, dict):
                    first = first.get("content")
                if not isinstance(first, str):
                    raise TargetError("space returned non-text output")
                return first
            event, data = None, []
    raise TargetError("space stream ended without a result")
