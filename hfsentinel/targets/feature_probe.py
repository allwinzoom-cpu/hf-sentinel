"""Feature negotiation (plan LSCAN-022). A target's generation controls must be *established*, not assumed from a brand
name: a strict baseline probe sends each control and classifies it by what is actually observable —

  * verified — the control demonstrably took effect (e.g. a 1-token cap shortened the output, a stop string truncated it);
  * ignored  — the field was accepted but had no observable effect (silently dropped);
  * rejected — the adapter/target refused the field;
  * unknown  — the control could not be sent or its effect could not be observed in this build.

Controls this build cannot yet send or observe are reported `unknown` with a reason, never guessed as supported. The
result records requested-vs-effective support so a report/replay states real capability instead of inventing it.
"""
from __future__ import annotations

import json
from collections.abc import Callable

from hfsentinel.targets.openai_compat import TargetError

VERIFIED, IGNORED, REJECTED, UNKNOWN = "verified", "ignored", "rejected", "unknown"
STATES = (VERIFIED, IGNORED, REJECTED, UNKNOWN)

# Known generation controls that this build does not yet send/observe: reported unknown (never guessed), with a reason.
UNPROBED = ("top_p", "top_k", "logprobs", "tools", "prefill", "reasoning_budget", "media", "caching")


def _ask(target, content: str, **kw):
    """One probe call. Returns (ChatResult, None) on success, or (None, state) when the control cannot be concluded:
    a refused field is `rejected`; a target error is `unknown` (we cannot tell support from an unrelated failure)."""
    try:
        return target.chat([{"role": "user", "content": content}], **kw), None
    except ValueError:
        return None, REJECTED
    except TargetError:
        return None, UNKNOWN


def _completion_tokens(result) -> int | None:
    v = (getattr(result, "usage", None) or {}).get("completion_tokens")
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _probe_max_tokens(target) -> str:
    big, e = _ask(target, "Count slowly from one to forty, in words.", max_tokens=200, temperature=0.0)
    if e:
        return e
    small, e = _ask(target, "Count slowly from one to forty, in words.", max_tokens=1, temperature=0.0)
    if e:
        return e
    sc, bc = _completion_tokens(small), _completion_tokens(big)
    if sc is not None and bc is not None:
        return VERIFIED if (sc <= 1 or sc < bc) else IGNORED  # the usage count is the most reliable signal
    return VERIFIED if len(small.text) < len(big.text) else IGNORED


def _probe_stop(target) -> str:
    r, e = _ask(target, "Output exactly these words separated by spaces: alpha bravo charlie delta echo",
                max_tokens=60, temperature=0.0, extra={"stop": ["charlie"]})
    if e:
        return e
    t = r.text.lower()
    return VERIFIED if ("charlie" not in t and "delta" not in t and "echo" not in t) else IGNORED


def _probe_seed(target) -> str:
    p = "Write one short, surprising sentence about the ocean."
    r1, e = _ask(target, p, max_tokens=40, temperature=0.9, extra={"seed": 4242})
    if e:
        return e
    r2, e2 = _ask(target, p, max_tokens=40, temperature=0.9, extra={"seed": 4242})
    r3, e3 = _ask(target, p, max_tokens=40, temperature=0.9, extra={"seed": 101})
    if e2 or e3:
        return UNKNOWN
    if r1.text == r2.text and r1.text != r3.text:
        return VERIFIED           # same seed -> identical, different seed -> different: the seed is honoured
    if r1.text != r2.text:
        return IGNORED            # same seed produced different output: the seed was not honoured
    return UNKNOWN                # everything identical: inconclusive (could be low-entropy), never claimed as verified


def _probe_response_format(target) -> str:
    r, e = _ask(target, "Return a JSON object with a single key 'ok' whose value is true.",
                max_tokens=60, temperature=0.0, extra={"response_format": {"type": "json_object"}})
    if e:
        return e
    try:
        json.loads((r.text or "").strip())
        return VERIFIED
    except (ValueError, AttributeError):
        return IGNORED


PROBES: dict[str, Callable] = {"max_tokens": _probe_max_tokens, "stop": _probe_stop, "seed": _probe_seed,
                               "response_format": _probe_response_format}


def negotiate(target) -> dict:
    """Probe every negotiable control and return {feature: {state, probed, [reason]}} (LSCAN-022). Probed features carry
    an observed state; controls this build cannot negotiate are `unknown` with a reason — support is never inferred."""
    out = {name: {"state": fn(target), "probed": True} for name, fn in PROBES.items()}
    for name in UNPROBED:
        out[name] = {"state": UNKNOWN, "probed": False, "reason": "not negotiated in this build"}
    return out
