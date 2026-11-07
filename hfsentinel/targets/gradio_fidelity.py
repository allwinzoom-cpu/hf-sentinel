"""Gradio/Space parameter & control fidelity (plan LSCAN-011). Pure logic over a Gradio endpoint's named-parameter spec,
so an attack lands in the *intended* parameter and a Space's fixed instructions are never assessed as if the scanner
controlled them.

A Gradio fn exposes named parameters (from its API page). The attack text must go into the component the Space treats as
the user message — not an arbitrary slot — and the scanner only "controls" the system instruction if the endpoint
exposes a settable system/instruction parameter. When the Space fixes its instructions (no such parameter), system-prompt
techniques (set/extract the system prompt) are **not scanner-controlled** and must be reported N/A rather than as if the
scanner planted or extracted the provider's instructions (ties to LSCAN-004 attacker-power).
"""
from __future__ import annotations

from dataclasses import dataclass

# Parameter-name hints (lowercased, substring match) for the user-message slot and the system/instruction slot.
_USER_HINTS = ("message", "prompt", "text", "input", "question", "query", "user")
_SYSTEM_HINTS = ("system", "instruction", "persona", "preamble", "system_prompt", "system_message")


@dataclass(frozen=True)
class GradioFidelity:
    endpoint: str                      # the named endpoint (fn_index / api_name) the attack targets
    attack_param: str | None           # the parameter the attack text lands in (None = no user-message slot found)
    system_param: str | None           # a settable system/instruction parameter, if any
    scanner_controls_system: bool      # False when the Space fixes its instructions (no settable system param)


def _match(name: str, hints: tuple[str, ...]) -> bool:
    n = name.lower()
    return any(h in n for h in hints)


def analyze_endpoint(endpoint: str, params: list[dict]) -> GradioFidelity:
    """`params`: ordered [{name, type?}] for one named endpoint (as the Gradio API page lists them). Picks the user-message
    parameter (first string-typed name matching a user hint, else the first string param) and detects a settable system
    parameter. A Space with no system parameter does NOT give the scanner control of its instructions."""
    def is_str(p: dict) -> bool:
        return (p.get("type") or "str") in ("str", "string", "text", None)

    names = [p.get("name", "") for p in params]
    system = next((n for n in names if _match(n, _SYSTEM_HINTS)), None)
    # user-message slot: a string param matching a user hint, else the first string param that isn't the system one
    attack = next((p["name"] for p in params if is_str(p) and _match(p.get("name", ""), _USER_HINTS)
                   and p.get("name") != system), None)
    if attack is None:
        attack = next((p["name"] for p in params if is_str(p) and p.get("name") != system), None)
    return GradioFidelity(endpoint=endpoint, attack_param=attack, system_param=system,
                          scanner_controls_system=system is not None)


def system_prompt_technique_applicable(fidelity: GradioFidelity) -> bool:
    """True iff a set/extract-system-prompt technique is in scope — only when the scanner can actually set the system
    instruction. A Space with fixed instructions returns False (report N/A, not a scanner-controlled result)."""
    return fidelity.scanner_controls_system
