"""Repeatable primary-source research refresh (plan / LSCAN-088). A manual/opt-in procedure: for each newly surveyed item
(tool release, provider contract, paper, benchmark, dated disclosure) decide a disposition, and gate entry to production.
An unverified name or a bare ASR claim can NEVER auto-enter production — an accepted runnable item needs a source, a date,
preconditions, a bounded replication task and an oracle. This module makes the decision; it NEVER executes downloaded
code or starts a target scan, and it creates no schedule."""
from __future__ import annotations

from dataclasses import dataclass

DISPOSITIONS = ("duplicate", "existing-family-variant", "runnable-task", "conditional-extension",
                "experimental-candidate", "out-of-scope")


@dataclass(frozen=True)
class ResearchItem:
    name: str
    source: str = ""            # primary source URL/citation
    date: str = ""              # dated (disclosure/release/paper date)
    preconditions: str = ""     # what the item requires to run
    replication_task: str = ""  # a bounded replication task
    oracle: str = ""            # how success is decided
    agentic: bool = False       # agentic/white-box items are out of scope (strictly-LLM-only)
    duplicate_of: str = ""      # set if it duplicates an existing family


def triage(item: ResearchItem) -> str:
    """Classify a surveyed item into a disposition (LSCAN-088). Agentic items are out-of-scope; a duplicate collapses to
    its family; a fully-specified item (source+date+preconditions+task+oracle) is runnable; a partially-specified one is
    a conditional extension or an experimental candidate."""
    if item.agentic:
        return "out-of-scope"
    if item.duplicate_of:
        return "existing-family-variant" if item.preconditions else "duplicate"
    complete = all((item.source, item.date, item.preconditions, item.replication_task, item.oracle))
    if complete:
        return "runnable-task"
    if item.source and item.date and (item.preconditions or item.replication_task):
        return "conditional-extension"
    return "experimental-candidate"


def can_enter_production(item: ResearchItem) -> bool:
    """Production entry requires a verified, fully-specified item (LSCAN-088): source + date + preconditions + bounded
    replication task + oracle, and not agentic. An unverified name or a bare ASR claim never qualifies."""
    return (not item.agentic and all((item.source, item.date, item.preconditions, item.replication_task, item.oracle)))
