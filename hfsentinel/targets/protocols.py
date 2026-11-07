"""Protocol normalization (plan LSCAN-013): map legacy text-completion, Chat Completions and Responses-style results to
one shape WITHOUT inventing chat roles, and fail explicitly on unimplemented stateful operations.

`normalize(protocol, raw)` returns {text, refusal, tool_calls, usage, role_invented:False}. Raw text completions are
read as text — never silently wrapped in a fabricated assistant turn. Native chat/Responses semantics (refusal events,
typed content blocks, tool calls, usage) are preserved. Stateful continuation is only claimed where the protocol
supports it; elsewhere `require_stateful` raises rather than pretending.
"""
from __future__ import annotations

PROTOCOLS = ("text-completion", "chat-completions", "responses")
_STATEFUL = ("responses",)  # only Responses-style APIs expose server-side continuation state


def normalize(protocol: str, raw: dict) -> dict:
    if protocol == "text-completion":
        text = (raw.get("choices") or [{}])[0].get("text", "") or ""
        return {"text": text, "refusal": False, "tool_calls": [], "usage": raw.get("usage", {}), "role_invented": False}
    if protocol == "chat-completions":
        ch = (raw.get("choices") or [{}])[0]
        msg = ch.get("message", {}) or {}
        return {"text": msg.get("content") or "", "refusal": ch.get("finish_reason") == "content_filter",
                "tool_calls": list(msg.get("tool_calls") or []), "usage": raw.get("usage", {}), "role_invented": False}
    if protocol == "responses":
        text, tools = "", []
        for item in raw.get("output", []) or []:
            if item.get("type") == "message":
                for block in item.get("content", []) or []:
                    if block.get("type") in ("output_text", "text"):
                        text += block.get("text", "") or ""
            elif item.get("type") in ("tool_use", "function_call"):
                tools.append(item)
        return {"text": text, "refusal": raw.get("stop_reason") == "refusal",
                "tool_calls": tools, "usage": raw.get("usage", {}), "role_invented": False}
    raise ValueError(f"unknown protocol: {protocol!r} (use one of {', '.join(PROTOCOLS)})")


def supports_stateful(protocol: str) -> bool:
    return protocol in _STATEFUL


def require_stateful(protocol: str) -> None:
    """Raise if `protocol` has no server-side stateful continuation — an unimplemented stateful op fails explicitly
    rather than silently degrading."""
    if not supports_stateful(protocol):
        raise NotImplementedError(f"{protocol} has no server-side stateful continuation; operation unsupported")
