"""Native Gemini GenerateContent target adapter (plan LSCAN-015). Speaks the real GenerateContent contract: a top-level
`systemInstruction`, `contents` with typed `parts`, function calls, and `generationConfig`. The response normalizer keeps
three outcomes DISTINCT — blocked (the platform's safety layer blocked the prompt/response), refused-or-answered (model
content), and errored (HTTP) — so a safety BLOCK is never conflated with a model refusal or a successful answer. The
provider key is a per-target credential bound to the Google origin (never the HF token). Offline contract is unit-tested
with an injected transport; a live smoke needs a Google key (GATE)."""
from __future__ import annotations

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

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"


def to_gemini(messages: list[dict]) -> tuple[dict | None, list[dict]]:
    """Split OpenAI-style messages into Gemini's top-level systemInstruction and `contents` (role 'user'/'model', with
    text parts). The system instruction stays top-level; assistant maps to the native 'model' role (LSCAN-015)."""
    system = "\n".join(m["content"] for m in messages
                       if m.get("role") == "system" and isinstance(m.get("content"), str))
    contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                for m in messages if m.get("role") in ("user", "assistant")]
    sys_instr = {"parts": [{"text": system}]} if system else None
    return sys_instr, contents


def normalize_generate_content(raw: dict) -> dict:
    """GenerateContent response -> {text, tool_calls, finish_reason, blocked, block_reason, usage, role_invented:False}.
    A promptFeedback.blockReason or a SAFETY finishReason is a platform BLOCK — distinct from model content."""
    feedback = raw.get("promptFeedback") or {}
    block_reason = feedback.get("blockReason") or ""
    candidates = raw.get("candidates") or []
    text, tools, finish = "", [], ""
    if candidates:
        finish = candidates[0].get("finishReason", "") or ""
        for part in (candidates[0].get("content", {}) or {}).get("parts", []) or []:
            if "text" in part:
                text += part.get("text") or ""
            elif "functionCall" in part:
                tools.append(part["functionCall"])
    blocked = bool(block_reason) or finish == "SAFETY"
    return {"text": text, "tool_calls": tools, "finish_reason": finish, "blocked": blocked,
            "block_reason": block_reason or ("SAFETY" if finish == "SAFETY" else ""),
            "usage": raw.get("usageMetadata", {}) or {}, "role_invented": False}


def outcome(raw: dict) -> str:
    """Distinct outcome (LSCAN-015): 'blocked' (platform safety), 'empty' (no candidates), or 'answered' (model content).
    'refused' vs 'answered' within content is a judge decision, not an adapter one — never inferred here."""
    norm = normalize_generate_content(raw)
    if norm["blocked"]:
        return "blocked"
    if not (raw.get("candidates") or []):
        return "empty"
    return "answered"


@dataclass
class GeminiTarget:
    model: str
    api_key: str = field(repr=False, default="")   # per-target Google credential; never the HF token
    endpoint: str = DEFAULT_ENDPOINT
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

    def build_request(self, messages: list[dict], *, max_tokens: int, temperature: float) -> tuple[dict, dict, str]:
        sys_instr, contents = to_gemini(messages)
        body: dict = {"contents": contents,
                      "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}}
        if sys_instr:
            body["systemInstruction"] = sys_instr
        headers = {"content-type": "application/json", "user-agent": self.user_agent}
        if self.api_key:
            headers["x-goog-api-key"] = self.api_key          # isolated key header, not a URL-embedded secret
        url = f"{self.endpoint}/{self.model}:generateContent"
        return body, headers, url

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"request cap {self.max_requests} reached")
        body, headers, url = self.build_request(messages, max_tokens=max_tokens, temperature=temperature)
        gov, key = self.governor, self.rate_key
        self.requests_made += 1
        try:
            with gov.slot(key) if gov else nullcontext():
                resp = self.transport.request("POST", url, headers=headers, body=json.dumps(body).encode(),
                                              timeout=self.timeout, limit=MAX_RESPONSE_BYTES)
        except TransportError as e:
            if gov:
                gov.record(key, None)
            raise TargetError(f"target unreachable: {e}") from None
        if not (200 <= resp.status < 300):
            if gov:
                gov.record(key, resp.status, retry_after=resp.headers.get("retry-after"))
            raise TargetError(f"target returned HTTP {resp.status}", status=resp.status)
        try:
            norm = normalize_generate_content(json.loads(resp.body))
        except (ValueError, AttributeError, TypeError):
            raise TargetError("target returned an unexpected response shape") from None
        usage = norm.get("usage") or {}
        if gov:
            gov.record(key, 200, usage=usage)
        # A platform block is a distinct outcome: recorded as a refusal signal, never a produced answer (LSCAN-015).
        return ChatResult(text=norm["text"], model=self.model, usage=usage,
                          finish_reason=norm["block_reason"] or norm["finish_reason"],
                          tool_calls=list(norm["tool_calls"]), refusal=norm["blocked"])
