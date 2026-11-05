"""Engine sandbox topology (plan 16.12): the helper containers (egress proxy + vuln-target) must be launched as
`python -m <module>`. The runtime image's entrypoint is the CLI (`python -m hfsentinel`), so the sandbox has to
override it — otherwise the module path is parsed as a CLI subcommand, the helper never starts, and every engine run
reports the target 'not reachable' (the regression this guards against). Docker is mocked; nothing is launched."""
import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_sandbox():
    spec = importlib.util.spec_from_file_location("eng_sandbox", ROOT / "engines" / "sandbox.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_capture(tmp_path, monkeypatch):
    sandbox = _load_sandbox()
    cmds: list[list[str]] = []

    def fake_must(cmd):
        cmds.append(cmd)
        return "sha256:" + "a" * 64 if cmd[:3] == ["docker", "image", "inspect"] else ""

    def fake_sh(cmd, **kw):
        cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sandbox, "must", fake_must)
    monkeypatch.setattr(sandbox, "sh", fake_sh)
    monkeypatch.setattr(sandbox, "hf_token", lambda: "tok")
    monkeypatch.setattr(sandbox.time, "sleep", lambda *_: None)
    sandbox.run("garak", "lbl", ["python", "/opt/x.py", "/out/lbl.job.json"], 60, "h.example", tmp_path / "out")
    return [c for c in cmds if c[:3] == ["docker", "run", "-d"]]


def test_helper_containers_run_modules_via_python_entrypoint(tmp_path, monkeypatch):
    runs = _run_capture(tmp_path, monkeypatch)
    joined = [" ".join(c) for c in runs]
    # the egress proxy and the vuln-target each override the CLI entrypoint and run their module with -m
    assert any("--entrypoint python" in j and "-m hfsentinel.sandbox.egress_proxy" in j for j in joined), joined
    assert any("--entrypoint python" in j and "-m hfsentinel.testing.vuln_target" in j for j in joined), joined


def test_helper_modules_are_not_passed_as_bare_cli_subcommands(tmp_path, monkeypatch):
    # the bug: a module path right after the image name is parsed by `python -m hfsentinel` as a subcommand.
    for cmd in _run_capture(tmp_path, monkeypatch):
        for mod in ("hfsentinel.sandbox.egress_proxy", "hfsentinel.testing.vuln_target"):
            if mod in cmd:
                assert cmd[cmd.index(mod) - 1] == "-m", f"{mod} must follow -m, got {cmd}"
