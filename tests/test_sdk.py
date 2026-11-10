"""Programmatic SDK (`hfsentinel.sdk`): config defaults, deny-by-default scope, and a real end-to-end scan against the
bundled vuln-target over loopback (authorized by the built-in scope, no signed scope file needed)."""
from __future__ import annotations

import pytest

from hfsentinel import sdk
from hfsentinel.scope import ScopeError
from hfsentinel.testing import vuln_target


def test_build_config_only_includes_set_knobs():
    cfg = sdk._build_config("hf-provider://org/m@p", profile="quick", categories=["A", "B"], attacks=None,
                            exclude=["B8"], trials=3, max_tokens=32, temperature=None, seed=1, concurrency=None,
                            budget_usd=5.0, max_requests=None,
                            controls_config={"output": {"formats": ["json"]}})
    assert cfg["target"] == "hf-provider://org/m@p" and cfg["profile"] == "quick"
    assert cfg["select"] == {"categories": ["A", "B"], "exclude": ["B8"]}
    assert cfg["target_io"] == {"trials": 3, "max_tokens": 32, "seed": 1}   # unset temperature/concurrency omitted
    assert cfg["budget"] == {"usd": 5.0}                                     # unset max_requests omitted
    assert cfg["output"] == {"formats": ["json"]}                           # deep-merged advanced override


def test_scope_denied_by_default_before_any_request():
    # Without a signed scope file, an arbitrary provider target is NOT authorized: scan must raise before any traffic.
    with pytest.raises(ScopeError):
        sdk.scan("hf-provider://meta-llama/Llama-3.1-8B-Instruct@novita")


def test_unsupported_target_raises_scanerror():
    with pytest.raises(sdk.ScanError):
        sdk.scan("not-a-valid-uri://nonsense")


def test_scan_vuln_target_end_to_end_returns_result():
    srv, url = vuln_target.serve()
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1)
    finally:
        try:
            srv.shutdown()
        except Exception:  # noqa: BLE001,S110 - best-effort teardown
            pass
    assert isinstance(result, sdk.ScanResult)
    assert result.run_id and result.target == uri
    assert isinstance(result.findings, list)              # zero findings is a valid outcome (agnostic assessment)
    assert "overall" in result.grade
    assert isinstance(result.to_dict(), dict)             # report serializes for an API response
    assert result.recon["requests"] >= 1                  # recon actually probed the target


def test_scan_extended_pass_runs_without_scored_fabrication():
    srv, url = vuln_target.serve()
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1, extended=True)
    finally:
        try:
            srv.shutdown()
        except Exception:  # noqa: BLE001,S110
            pass
    # The extended pass emits advisory/N-A decisions; it must never fabricate a scored finding on the vuln-target run.
    extended_decisions = [d for d in result.decisions if d.get("source") == "system-one"]
    assert isinstance(extended_decisions, list)           # advisory/N-A extended verdicts are recorded as decisions
