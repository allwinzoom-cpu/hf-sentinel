"""AWS Bedrock Converse target adapter (plan LSCAN-017). Speaks the Converse contract (top-level `system`, typed message
content, `inferenceConfig`) and normalizes native usage / tool content / stopReason. API compatibility is validated
PER MODEL — the adapter never assumes one universal URL/shape; a model that only supports InvokeModel (not Converse) is
reported, not forced. Signing is a pluggable abstraction (consistent with D-019: no vendored SDK); the credential/region
identity is recorded for repro but a real SigV4 signer is required for a live call, so this ships the offline contract.
"""
from __future__ import annotations

import json
from collections.abc import Callable
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

# Per-model API compatibility (illustrative pins): Converse-capable vs InvokeModel-only. Never a single universal URL.
_CONVERSE_CAPABLE = ("anthropic.claude", "meta.llama", "mistral.", "cohere.command-r", "amazon.nova")
Signer = Callable[[str, dict, bytes], dict]   # (url, headers, body) -> signed headers (SigV4); injected, not vendored


def api_compatibility(model_id: str) -> str:
    """'converse' if the model supports the Converse API, else 'invoke-only' (reported, never forced into Converse)."""
    return "converse" if any(model_id.startswith(p) for p in _CONVERSE_CAPABLE) else "invoke-only"


def to_converse(messages: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split into Converse top-level `system` blocks and typed `messages` (assistant stays the native 'assistant' role)."""
    system = [{"text": m["content"]} for m in messages
              if m.get("role") == "system" and isinstance(m.get("content"), str)]
    turns = [{"role": m["role"], "content": [{"text": m["content"]}]}
             for m in messages if m.get("role") in ("user", "assistant")]
    return system, turns


def normalize_converse(raw: dict) -> dict:
    """Converse response -> {text, tool_calls, stop_reason, usage, role_invented:False}."""
    msg = (raw.get("output", {}) or {}).get("message", {}) or {}
    text, tools = "", []
    for block in msg.get("content", []) or []:
        if "text" in block:
            text += block.get("text") or ""
        elif "toolUse" in block:
            tools.append(block["toolUse"])
    return {"text": text, "tool_calls": tools, "stop_reason": raw.get("stopReason", ""),
            "usage": raw.get("usage", {}) or {}, "role_invented": False}


@dataclass
class BedrockTarget:
    model_id: str
    region: str
    endpoint: str = ""                       # defaults to the regional Bedrock runtime host
    inference_profile: str = ""              # recorded identity when routing via an inference profile
    signer: Signer | None = field(default=None, repr=False)   # SigV4 signer; required for a live call
    timeout: float = 60.0
    max_requests: int = 100
    requests_made: int = 0
    governor: object | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.user_agent = check_user_agent(self.user_agent)
        if not self.endpoint:
            self.endpoint = f"https://bedrock-runtime.{self.region}.amazonaws.com"

    @property
    def url(self) -> str:
        return f"{self.endpoint}/model/{self.model_id}/converse"

    @property
    def rate_key(self) -> tuple[str, str]:
        return (f"{self.region}:{self.endpoint}", self.model_id)

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        if api_compatibility(self.model_id) != "converse":
            raise TargetError(f"model {self.model_id} is not Converse-compatible (InvokeModel-only); unsupported here")
        if self.signer is None:
            raise TargetError("Bedrock requires a configured SigV4 signer for a live call")
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"request cap {self.max_requests} reached")
        system, turns = to_converse(messages)
        body: dict = {"messages": turns, "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature}}
        if system:
            body["system"] = system
        raw_body = json.dumps(body).encode()
        headers = self.signer(self.url, {"content-type": "application/json", "user-agent": self.user_agent}, raw_body)
        gov, key = self.governor, self.rate_key
        self.requests_made += 1
        try:
            with gov.slot(key) if gov else nullcontext():
                resp = self.transport.request("POST", self.url, headers=headers, body=raw_body,
                                              timeout=self.timeout, limit=MAX_RESPONSE_BYTES)
        except TransportError:
            if gov:
                gov.record(key, None)
            raise TargetError("target unreachable") from None
        if not (200 <= resp.status < 300):
            if gov:
                gov.record(key, resp.status, retry_after=resp.headers.get("retry-after"))
            raise TargetError(f"target returned HTTP {resp.status}", status=resp.status)
        try:
            norm = normalize_converse(json.loads(resp.body))
        except (ValueError, AttributeError, TypeError):
            raise TargetError("target returned an unexpected response shape") from None
        usage = norm["usage"]
        if gov:
            gov.record(key, 200, usage=usage)
        return ChatResult(text=norm["text"], model=self.model_id, usage=usage,
                          finish_reason=norm["stop_reason"], tool_calls=list(norm["tool_calls"]))

    def repro_identity(self) -> dict:
        return {"model_id": self.model_id, "region": self.region, "inference_profile": self.inference_profile,
                "api": api_compatibility(self.model_id)}
