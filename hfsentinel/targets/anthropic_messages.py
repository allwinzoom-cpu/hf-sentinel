"""Native Anthropic Messages normalization (plan LSCAN-014). Maps a Messages API response to the common target shape,
preserving native semantics: typed content blocks (text / tool_use / thinking), tool calls, usage, and the refusal
signal via `stop_reason == "refusal"`. Unsupported prefill or thinking access is reported as **unsupported**, never a
successful check (`stop_reason: "refusal"` is a judge/target error -> escalate, not a "safe" result). Pure + offline.
"""
from __future__ import annotations

STOP_REFUSAL = "refusal"


def normalize_messages(raw: dict) -> dict:
    """Anthropic Messages response -> {text, refusal, tool_calls, thinking_present, usage, role_invented:False}."""
    text, tools, thinking = "", [], False
    for block in raw.get("content", []) or []:
        bt = block.get("type")
        if bt == "text":
            text += block.get("text", "") or ""
        elif bt == "tool_use":
            tools.append(block)
        elif bt in ("thinking", "redacted_thinking"):
            thinking = True
    return {"text": text, "refusal": raw.get("stop_reason") == STOP_REFUSAL, "tool_calls": tools,
            "thinking_present": thinking, "usage": raw.get("usage", {}), "role_invented": False}


def prefill_outcome(accepted: bool | None) -> str:
    """How to record an assistant-prefill attempt. `accepted` True/False from the live model/version; None = not probed.
    An unsupported/rejected prefill is 'unsupported' — never counted as a successful check (LSCAN-014)."""
    if accepted is True:
        return "supported"
    if accepted is False:
        return "unsupported"
    return "not-probed"
