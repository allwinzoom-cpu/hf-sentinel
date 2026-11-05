"""GitHub Action PR gate (plan task 668): wrap the CLI, upload SARIF to code scanning, honor --fail-on. Done-when: a
PR gate fails on a seeded Critical finding. The structural test guards the composite action; the end-to-end test runs
the exact CLI invocation the action makes against the loopback vulnerable target and asserts the gate trips (exit 10)
with a Critical result in the SARIF that would be uploaded."""
import json
import re
from pathlib import Path

import yaml
from typer.testing import CliRunner

from hfsentinel import cli

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
SHA40 = re.compile(r"@[0-9a-f]{40}$")


def _action() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def test_action_is_a_wellformed_composite_with_required_inputs():
    a = _action()
    assert a["runs"]["using"] == "composite"
    # fail-closed: the target and its signed scope must be supplied
    for req in ("target", "scope", "signers"):
        assert a["inputs"][req]["required"] is True
    assert a["inputs"]["fail-on"]["default"] in ("critical", "high", "medium")


def test_third_party_actions_are_pinned_to_full_commit_shas():
    a = _action()
    used = [s["uses"] for s in a["runs"]["steps"] if "uses" in s]
    assert used, "the action should reuse setup-python and the SARIF uploader"
    for ref in used:
        assert SHA40.search(ref), f"third-party action must be pinned to a 40-hex commit SHA, not {ref!r}"


def test_steps_wrap_the_cli_upload_sarif_and_enforce_fail_on():
    steps = _action()["runs"]["steps"]
    run_blobs = "\n".join(s.get("run", "") for s in steps)
    assert "hfsentinel" in run_blobs and "--fail-on" in run_blobs and "sarif" in run_blobs
    assert any("upload-sarif" in s.get("uses", "") for s in steps)       # SARIF reaches code scanning
    # the SARIF upload runs even when the gate trips, so findings always publish
    upload = next(s for s in steps if "upload-sarif" in s.get("uses", ""))
    assert "always()" in upload["if"]
    # a dedicated step turns the CLI's exit 10 into a failed job (the gate)
    assert any('"10"' in s.get("run", "") and "exit 1" in s.get("run", "") for s in steps)


def test_pr_gate_fails_on_a_seeded_critical_finding(tmp_path, signed_scope):
    from hfsentinel.testing import vuln_target

    srv, base = vuln_target.serve(profile="high", seed=7)
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        scope, signers = signed_scope([uri])
        out = tmp_path / "report"
        # the exact invocation action.yml makes (scan step), with --fail-on critical
        res = CliRunner().invoke(cli.app, [
            "scan", uri, "--scope", str(scope), "--signers", str(signers),
            "--format", "sarif,json", "--fail-on", "critical", "--out", str(out),
            "--budget-usd", "1", "--max-requests", "4000", "--trials", "8",
        ])
        assert res.exit_code == cli.EXIT_FINDINGS, res.output         # the gate trips (exit 10)
        sarifs = list(out.glob("*.sarif"))
        assert sarifs, "a SARIF report must be written for code-scanning upload"
        doc = json.loads(sarifs[0].read_text(encoding="utf-8"))
        results = doc["runs"][0]["results"]
        crit = [r for r in results if r["properties"]["severity"] == "Critical"]
        assert crit, "the seeded Critical finding must appear in the SARIF"
        assert all(r["level"] == "error" for r in crit)              # Critical → SARIF error level
        assert doc["runs"][0]["properties"]["grade"] == "F"          # confirmed Critical caps the grade at F
    finally:
        srv.shutdown()


def test_no_critical_means_no_gate_trip(tmp_path):
    # with --fail-on but no confirmed finding (a dry-run plan sends no traffic), the gate must not trip.
    res = CliRunner().invoke(cli.app, ["scan", "openai+https://api.example.com/v1#m", "--dry-run"])
    assert res.exit_code == cli.EXIT_OK, res.output
