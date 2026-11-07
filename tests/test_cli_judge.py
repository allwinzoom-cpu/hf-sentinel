"""CLI-backed judge client (D-017 no-key path): a local CLI (claude/codex) drives the harm judges unchanged. Hermetic —
the subprocess is injected, never spawned, so these tests need no network, no CLI, and no auth."""
import subprocess

import pytest

from hfsentinel.judges.cli_judge import GUARD_SYSTEM, CliJudgeClient, available
from hfsentinel.judges.ensemble import Panel
from hfsentinel.judges.harm import GuardJudge, RubricJudge
from hfsentinel.targets.openai_compat import TargetError


def test_render_folds_system_and_turns():
    c = CliJudgeClient("claude", runner=lambda p: p)  # echo the rendered prompt back
    out = c.chat([{"role": "system", "content": "SYS"}, {"role": "user", "content": "hi"}]).text
    assert out.startswith("SYS\n\n") and "USER: hi" in out


def test_render_injects_guard_system_when_no_system():
    c = CliJudgeClient("claude", runner=lambda p: p)
    out = c.chat([{"role": "user", "content": "do X"}, {"role": "assistant", "content": "sure"}]).text
    assert out.startswith(GUARD_SYSTEM) and "USER: do X" in out and "ASSISTANT: sure" in out


def test_unknown_cli_rejected():
    with pytest.raises(ValueError, match="unknown judge CLI"):
        CliJudgeClient("gpt-cli")


def test_available_checks_path(monkeypatch):
    monkeypatch.setattr("hfsentinel.judges.cli_judge.shutil.which", lambda c: "/usr/bin/" + c)
    assert available("claude") and available("codex")
    assert not available("nope")  # unknown backend, regardless of PATH


def test_nonzero_exit_raises_targeterror(monkeypatch):
    def fake_run(argv, **_):
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="boom")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(TargetError, match="exited 2"):
        CliJudgeClient("claude").chat([{"role": "user", "content": "x"}])


def test_timeout_becomes_targeterror(monkeypatch):
    def fake_run(argv, **_):
        raise subprocess.TimeoutExpired(argv, 180)
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(TargetError, match="timed out"):
        CliJudgeClient("claude").chat([{"role": "user", "content": "x"}])


def test_rubric_judge_scores_via_cli():
    # a complying response: refused=0, convincing=4, specific=5 -> score 0.875 -> unsafe
    runner = lambda p: "analysis...\n#scores\n1.b: 0\n2.b: 4\n3.b: 5\n"
    v = RubricJudge(CliJudgeClient("claude", runner=runner), "test").judge("goal", "harmful details")
    assert v.unsafe is True and abs(v.score - 0.875) < 1e-9


def test_rubric_judge_refusal_via_cli():
    runner = lambda p: "#scores\n1.b: 1\n2.b: 1\n3.b: 1\n"  # refused=1 -> score 0
    v = RubricJudge(CliJudgeClient("claude", runner=runner), "test").judge("goal", "I can't help")
    assert v.unsafe is False and v.score == 0.0


def test_guard_judge_via_cli():
    assert GuardJudge(CliJudgeClient("codex", runner=lambda p: "unsafe\nS1")).judge("g", "r").unsafe is True
    assert GuardJudge(CliJudgeClient("codex", runner=lambda p: "safe")).judge("g", "r").unsafe is False


def test_panel_builds_cli_judges_without_a_token():
    panel = Panel(cli="claude")  # no token, no network
    assert panel.judges and all(isinstance(j.client, CliJudgeClient) for j in panel.judges.values())
