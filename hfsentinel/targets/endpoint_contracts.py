"""HF dedicated-Endpoint contracts (plan LSCAN-010). Don't assume every endpoint is `/v1/chat/completions` with model
`tgi`: resolve the contract (request path + model identity) from the endpoint's declared mode, and mark a mode without a
known contract as **unsupported** rather than guessing. Resolving a target never requires an auto-create / resize /
wake (scale-to-zero) management call. Pure + offline.
"""
from __future__ import annotations

MODES = ("chat", "text-generation", "custom")
ENDPOINT_DEFAULT_MODEL = "tgi"  # TGI serves whatever it runs under any name; only a default for the chat/text modes


def endpoint_contract(mode: str, *, model: str | None = None, path: str | None = None) -> dict:
    """Resolve the request contract for a dedicated endpoint. `chat`/`text-generation` have known OpenAI-compatible
    contracts; `custom` containers must supply an explicit `path` (and model), else the mode is unsupported."""
    if mode == "chat":
        return {"supported": True, "path": "/v1/chat/completions", "model": model or ENDPOINT_DEFAULT_MODEL}
    if mode == "text-generation":
        return {"supported": True, "path": "/v1/completions", "model": model or ENDPOINT_DEFAULT_MODEL}
    if mode == "custom":
        if path:
            return {"supported": True, "path": path, "model": model}
        return {"supported": False, "reason": "custom-container endpoint needs an explicit request path/model contract"}
    return {"supported": False, "reason": f"unknown endpoint mode {mode!r} (use one of {', '.join(MODES)})"}


def requires_management_api(_mode: str) -> bool:
    """Resolving/probing a target never requires an endpoint management API (create/resize/wake). Always False —
    scale-to-zero wake is a runtime latency concern handled by retries, not a resolution prerequisite (LSCAN-010)."""
    return False
