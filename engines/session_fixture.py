"""Session/environment fixture lifecycle (plan / LSCAN-026, depends on LSCAN-024). Versioned setup/reset/teardown for a
scan session: identity/tenant, planted canaries, tool inventory, memory/retrieval snapshot and initial task state. The
core invariants: a CONTROL session must not inherit a previous attack (contamination is detected BEFORE scoring, not
after), and a retry resumes only a proven state or restarts cleanly. Pure + offline."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SessionFixture:
    session_id: str
    identity: str                              # identity/tenant this session runs as
    planted_canaries: frozenset[str] = frozenset()
    tool_inventory: tuple[str, ...] = ()
    memory_snapshot: str = ""                  # a hash/marker of the starting memory/retrieval state
    task_state: str = "initial"

    def reset(self, *, new_session_id: str) -> SessionFixture:
        """A clean teardown+setup: a fresh session with the SAME configuration but NO carried canaries or task state."""
        return SessionFixture(session_id=new_session_id, identity=self.identity,
                              planted_canaries=frozenset(), tool_inventory=self.tool_inventory,
                              memory_snapshot=self.memory_snapshot, task_state="initial")


def contaminated(control_output: str, prior_attack_canaries: frozenset[str]) -> list[str]:
    """Canaries from a PRIOR attack that leaked into a control session's output — contamination that must be caught
    BEFORE scoring, or the control is invalid (LSCAN-026). Empty = the control session is clean."""
    return sorted(c for c in prior_attack_canaries if c and c in (control_output or ""))


def control_is_valid(control_output: str, prior_attack_canaries: frozenset[str]) -> bool:
    """A control session is valid for scoring only if it inherited none of a prior attack's canaries."""
    return not contaminated(control_output, prior_attack_canaries)


def safe_to_resume(*, state_proven: bool) -> str:
    """After an interruption, resume only a proven state; otherwise restart cleanly — never resume an unproven state
    (LSCAN-026)."""
    return "resume" if state_proven else "restart-clean"
