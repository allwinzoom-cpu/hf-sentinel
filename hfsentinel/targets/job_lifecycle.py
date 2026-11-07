"""HF-job lifecycle contract (plan LSCAN-012; the live runner itself is `targets/job_target.py`, shipped + live-proven
in task 617). This encodes the two lifecycle invariants that must always hold, independent of a live run:

  * a **dry-run submits nothing** — it only renders the job spec;
  * a job left in a non-terminal stage (scheduling/running) on cancel or error **must be cancelled** so no orphan compute
    keeps billing; terminal stages need no cleanup.

Pure + offline. `cleanup_targets` tells a monitor/CLI which live job ids still need a cancel after an error.
"""
from __future__ import annotations

# Ordered lifecycle stages for a submitted job (dry-run never enters these).
STAGES = ("submitted", "scheduling", "running", "report-uploaded", "terminal")
_NEEDS_CANCEL = ("submitted", "scheduling", "running")  # compute may be/becoming active -> cancel on abort
_TERMINAL = ("report-uploaded", "terminal")


def dry_run_submits_nothing(action: str) -> bool:
    """Contract: a dry-run must not submit. True iff `action == 'dry-run'` means no job is created."""
    return action == "dry-run"  # the CLI/job path renders the spec and returns; it never calls run_job on a dry-run


def needs_cleanup(stage: str) -> bool:
    """True iff a job in `stage` must be cancelled on abort/error to avoid orphan compute."""
    return stage in _NEEDS_CANCEL


def cleanup_targets(jobs: dict[str, str]) -> list[str]:
    """`jobs`: {job_id: stage}. Returns the job ids that still need a cancel (non-terminal) — a terminated or
    report-uploaded job is left alone."""
    return [jid for jid, stage in jobs.items() if needs_cleanup(stage)]


def is_terminal(stage: str) -> bool:
    return stage in _TERMINAL
