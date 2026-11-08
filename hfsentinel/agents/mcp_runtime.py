"""MCP runtime metadata and tool-change attacks (plan Category D / LSCAN-065).

An isolated MCP test client/server model (no real MCP network, no real server process) for the RUNTIME-metadata attack
surface: tool descriptions, input schemas, resource/prompt content, name collisions, tool shadowing, and post-approval
metadata changes ("rug pulls"). The client observes each tool's advertised metadata at APPROVAL time and again at CALL
time; a change between the two is recorded and flagged. Two scope limits are explicit (LSCAN-065):

  * Effects are judged through the ACTUAL integration path — the metadata the client would act on at call time — not by
    statically scanning a server's source files.
  * OAuth / transport exploitation is OUT OF SCOPE here; this core is about tool-metadata trust only.

Pure + offline: oracles over metadata snapshots. No real side effects. See [[no-tool-name-leak]].
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolMeta:
    """A tool's runtime-advertised metadata (what the MCP client sees and acts on)."""
    name: str
    description: str
    input_schema: dict
    resource_content: str = ""        # attached resource/prompt content the model may ingest

    @property
    def meta_hash(self) -> str:
        """Stable hash of the metadata the client trusts — any runtime change moves it (LSCAN-065)."""
        canonical = json.dumps({"name": self.name, "description": self.description,
                                "input_schema": self.input_schema, "resource_content": self.resource_content},
                               sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def name_collisions(tools: list[ToolMeta]) -> list[str]:
    """Tool names advertised more than once (LSCAN-065) — a collision the client cannot disambiguate safely."""
    seen: dict[str, int] = {}
    for t in tools:
        seen[t.name] = seen.get(t.name, 0) + 1
    return sorted(n for n, c in seen.items() if c > 1)


def is_shadowing(candidate: ToolMeta, trusted: dict[str, str]) -> bool:
    """Tool shadowing / impersonation (LSCAN-065): a tool advertises the NAME of an already-trusted tool but with
    different metadata (a different hash), so it impersonates the trusted tool in the client's view."""
    return candidate.name in trusted and candidate.meta_hash != trusted[candidate.name]


def is_rug_pull(approved_hash: str, current: ToolMeta) -> bool:
    """Post-approval metadata change (LSCAN-065): the tool's metadata at call time differs from what was approved."""
    return current.meta_hash != approved_hash


@dataclass(frozen=True)
class ChangeRecord:
    name: str
    before_hash: str
    after_hash: str
    before_description: str
    after_description: str

    @property
    def changed(self) -> bool:
        return self.before_hash != self.after_hash


def record_change(approved: ToolMeta, current: ToolMeta) -> ChangeRecord:
    """Record a metadata change observed through the integration path (LSCAN-065) — the before/after the client acted on,
    not a static file read."""
    return ChangeRecord(name=current.name, before_hash=approved.meta_hash, after_hash=current.meta_hash,
                        before_description=approved.description, after_description=current.description)


def verdict(approved: ToolMeta, current: ToolMeta, *, trusted: dict[str, str] | None = None) -> str:
    """Grade a tool at call time against its approved snapshot (LSCAN-065)."""
    if trusted and is_shadowing(current, trusted):
        return "tool-shadowing: impersonates a trusted tool's name with altered metadata"
    if is_rug_pull(approved.meta_hash, current):
        return "rug-pull: metadata changed after approval (recorded) — re-approval required"
    return "unchanged: metadata matches the approved snapshot"


SCOPE_NOTE = ("judged through the live MCP integration path (call-time metadata), not static server-file scanning; "
              "OAuth/transport exploitation is out of scope")
