"""Toolchain non-disclosure (plan 16.16, D-014): upstream engine names never leave the CLI.

Engines are addressed by neutral aliases; reports, SARIF, Markdown and the console carry only aliases + an opaque
engine-build hash. This module is the single source of truth for the upstream terms that must never appear in anything
a target owner or an end user can see, and the `scrub` that redacts them from strings we didn't author (engine
stdout/stderr tails, tracebacks, banners). The term set is derived from `engines/versions.json` — the one place the
real tool names live — plus a short curated list of transitive libraries that surface in those tools' tracebacks.

    from hfsentinel.engines.nondisclosure import scrub, scan, terms
    scrub("Traceback ... File '/opt/garak/cli.py' ... NVIDIA/garak")  # -> "...[engine]...[engine]"
    scan(any_user_visible_string)                                      # -> [] when clean

`sandbox.py` reuses `terms()` for the target-side header-fingerprint check, so the header log and the report share one
definition of a leak.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_VERSIONS = Path(__file__).resolve().parents[2] / "engines" / "versions.json"
PLACEHOLDER = "[engine]"
_MIN_LEN = 4  # ignore short tokens that collide with ordinary words

# Transitive dependencies / internal module names that appear in the engines' own tracebacks and banners but are not in
# versions.json as a top-level engine. Kept distinctive (no bare "meta"/"llama") so scrubbing never mangles our text.
_CURATED = frozenset({
    "garak", "pyrit", "deepteam", "deepeval", "litellm", "semgrep", "osemgrep", "codeshield", "llamafirewall",
    "agentdojo", "promptmap", "strong_reject", "strongreject", "purplellama", "jailbreakbench",
    "nvidia", "microsoft", "meta-llama", "ethz-spylab", "confident-ai", "utkusen", "dsbowen",
    # Vendored encoding engine behind the optional obfuscation layer (hfsentinel/attacks/obfuscation.py): addressed only
    # by neutral keys (`fullwidth`, `a1z26`) under the `obf:` namespace; its project name must never surface either.
    "parseltongue", "p4rs3lt0ngv3",
})


@lru_cache(maxsize=1)
def terms() -> frozenset[str]:
    """Lower-cased upstream tool/repo tokens that must never be visible outside the CLI."""
    manifest = json.loads(_VERSIONS.read_text(encoding="utf-8"))
    out: set[str] = set(_CURATED)
    for name, spec in manifest["engines"].items():
        # repo is owner/name; keep each whole segment (split only on "/", never on "-") so "meta-llama" stays one token.
        for tok in (name, spec.get("package", ""), *spec["repo"].split("/")):
            tok = tok.strip().lower()
            if len(tok) >= _MIN_LEN:
                out.add(tok)
    return frozenset(out)


@lru_cache(maxsize=1)
def _pattern() -> re.Pattern[str]:
    # Longest-first so "meta-llama" matches before a hypothetical "meta"; terms are literal, matched case-insensitively.
    return re.compile("|".join(re.escape(t) for t in sorted(terms(), key=len, reverse=True)), re.IGNORECASE)


def scan(text: str) -> list[str]:
    """The distinct upstream terms present in `text` (lower-cased, sorted). Empty list means non-disclosure holds."""
    if not text:
        return []
    return sorted({m.group(0).lower() for m in _pattern().finditer(text)})


def scrub(text: str, placeholder: str = PLACEHOLDER) -> str:
    """Redact every upstream term from a string we did not author (engine tails, tracebacks), collapsing runs of
    placeholders (e.g. an owner/name path) into one. Our own text contains none of these tokens, so it is unchanged."""
    if not text:
        return text
    redacted = _pattern().sub(placeholder, text)
    return re.sub(rf"(?:{re.escape(placeholder)}[/\\.]*){{2,}}", placeholder, redacted)
