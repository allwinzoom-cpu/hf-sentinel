"""HF Jobs target runner (plan 617): building the job spec, loopback-only scan (no SSRF), and — most importantly — the
scoped job.write token being passed only as a secret, never in the command/env/spec. No network and no newer
huggingface_hub: run_job is injected for the success path and simulated-absent for the clear-error path. Launching a
real Job (the done-when) is the operator step; everything checkable offline is checked here."""
from __future__ import annotations

import re
import sys
import types

import pytest

from hfsentinel.targets import job_target
from hfsentinel.targets.job_target import JobTargetError, build_job_spec, launch

GOOD = {"model_id": "meta-llama/Llama-3.1-8B-Instruct", "dataset_repo": "my-org/scan-reports",
        "image": "ghcr.io/example/sentinel-vllm:pinned"}


def test_build_job_spec_valid():
    spec = build_job_spec(flavor="l4x1", trials=8, max_minutes=20, **GOOD)
    assert spec.image == GOOD["image"] and spec.flavor == "l4x1"
    assert spec.command[0] == "sh" and spec.command[1] == "-c"
    assert spec.secret_keys == ("HF_TOKEN",)


@pytest.mark.parametrize("bad", [
    {"model_id": "not-a-repo"},
    {"model_id": "../etc/passwd"},
    {"dataset_repo": "no-slash"},
    {"flavor": "h100-mega"},
    {"image": "noslash"},
    {"image": "has space/x"},
    {"trials": 0},
    {"trials": 99999},
    {"max_minutes": 0},
    {"max_minutes": 999},
])
def test_build_job_spec_rejects_bad_inputs(bad):
    args = {**GOOD, "flavor": "l4x1", "trials": 8, "max_minutes": 20, **bad}
    with pytest.raises(JobTargetError):
        build_job_spec(**args)


def test_token_never_appears_in_spec():
    spec = build_job_spec(**GOOD)
    blob = str(spec.as_dict())
    assert "token" not in blob.lower() or "HF_TOKEN" in blob  # only the secret *key* name may appear, never a value
    # the command must not contain any literal token placeholder expanded at build time
    assert "${HF_TOKEN}" not in " ".join(spec.command)  # the token is read from env inside the job, not interpolated


def test_scan_script_is_loopback_only_and_uploads():
    spec = build_job_spec(**GOOD)
    script = spec.command[2]
    assert "127.0.0.1" in script and "localhost" not in script  # loopback IP only; no hostname resolution
    # no external host in any URL (SSRF-safe): every http target is the loopback vLLM
    hosts = re.findall(r"http://([^/:]+)", script)
    assert hosts and all(h == "127.0.0.1" for h in hosts)
    assert f"http://127.0.0.1:{job_target.PORT}/v1" in script
    assert GOOD["model_id"] in script and GOOD["dataset_repo"] in script
    assert "upload_file" in script and "repo_type='dataset'" in script


def test_launch_requires_token():
    spec = build_job_spec(**GOOD)
    with pytest.raises(JobTargetError, match="token is required"):
        launch(spec, "")


def test_launch_passes_token_only_as_secret():
    spec = build_job_spec(**GOOD)
    captured = {}

    def fake_run_job(**kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(id="job-123")

    job_id = launch(spec, "hf_secret_tok", namespace="my-org", run_job=fake_run_job)
    assert job_id == "job-123"
    assert captured["secrets"] == {"HF_TOKEN": "hf_secret_tok"}       # token only in secrets
    assert "hf_secret_tok" not in " ".join(captured["command"])       # never in the command
    assert "hf_secret_tok" not in str(captured["env"])                # never in env
    assert captured["flavor"] == "l4x1" and captured["namespace"] == "my-org"


def test_launch_without_run_job_gives_clear_error(monkeypatch):
    spec = build_job_spec(**GOOD)
    stub = types.ModuleType("huggingface_hub")  # a hub with no run_job attribute
    monkeypatch.setitem(sys.modules, "huggingface_hub", stub)
    with pytest.raises(JobTargetError, match="no run_job"):
        launch(spec, "hf_secret_tok")


def test_cli_job_dry_run_prints_spec_and_submits_nothing():
    import json

    from typer.testing import CliRunner

    from hfsentinel import cli
    res = CliRunner().invoke(cli.app, ["job", GOOD["model_id"], "--dataset", GOOD["dataset_repo"],
                                       "--image", GOOD["image"], "--flavor", "t4-small", "--dry-run"])
    assert res.exit_code == cli.EXIT_OK, res.output
    spec = json.loads(res.output)
    assert spec["flavor"] == "t4-small" and spec["secret_keys"] == ["HF_TOKEN"]
    assert "127.0.0.1" in spec["command"][2]


def test_cli_job_rejects_bad_dataset():
    from typer.testing import CliRunner

    from hfsentinel import cli
    res = CliRunner().invoke(cli.app, ["job", GOOD["model_id"], "--dataset", "no-slash",
                                       "--image", GOOD["image"], "--dry-run"])
    assert res.exit_code == cli.EXIT_INPUT
