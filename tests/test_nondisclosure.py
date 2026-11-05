"""Toolchain non-disclosure (plan 16.16, D-014): upstream engine/repo names never leave the CLI.

Two done-when checks:
  1. every output format (JSON/SARIF/Markdown) and the CLI's console output from a run that includes engine results and
     forced engine errors carries no upstream tool/repo name;
  2. the vulnerable target's request-header view from an engine's sandbox run shows no tool fingerprint.
"""
import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

from hfsentinel.controls import resolve_controls
from hfsentinel.engines import engine_bridge as eb
from hfsentinel.engines import nondisclosure as nd
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report import render
from hfsentinel.report.build import assemble
from hfsentinel.report.schema import EngineResult
from hfsentinel.targets.resolve import parse

ROOT = Path(__file__).resolve().parents[1]
TARGET = {"ref": "openai+http://127.0.0.1:9/v1#m", "endpoint": "http://127.0.0.1:9/v1", "model": "m"}
SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-04T00:00:00+00:00"}
# A traceback / banner an engine would print, naming itself, its repo owner and its transitive deps.
DIRTY = ("Traceback (most recent call last): File '/opt/garak/cli.py' line 1, in run; garak.exception from "
         "NVIDIA/garak; pyrit converter failed in microsoft/PyRIT; litellm.BadRequest; semgrep-core; "
         "codeshield (meta-llama/PurpleLlama); deepeval telemetry")


def _adapter_common():
    spec = importlib.util.spec_from_file_location("_adapter_common", ROOT / "engines" / "adapters" / "_common.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- term set + scrub -------------------------------------------------------------------------------------------

def test_terms_cover_tools_and_repos_without_oversplitting():
    t = nd.terms()
    for name in ("garak", "pyrit", "nvidia", "microsoft", "meta-llama", "codeshield", "deepeval"):
        assert name in t, name
    # splitting repo owners on '-' would redact ordinary words — never do it.
    assert "meta" not in t and "llama" not in t
    assert all(len(x) >= 4 for x in t)


def test_scrub_redacts_every_term_and_leaves_our_text_untouched():
    assert nd.scan(DIRTY)  # the raw text clearly leaks
    cleaned = nd.scrub(DIRTY)
    assert nd.scan(cleaned) == []
    assert "garak" not in cleaned.lower() and "pyrit" not in cleaned.lower()
    ours = "HF-Sentinel probe-suite orchestrator guard-suite: 6 successes over 2 techniques; grade D"
    assert nd.scrub(ours) == ours  # neutral aliases and our own words are preserved verbatim
    assert nd.scan(ours) == []


def test_adapter_side_scrub_matches_core():
    """The image-side scrub (stdlib-only, inline token list) must agree with the core term set on these tools."""
    common = _adapter_common()
    assert nd.scan(common.scrub(DIRTY)) == []
    assert nd.scan(common.USER_AGENT) == []  # the adapter's outbound User-Agent is neutral


# ---- core ingestion sanitises a misbehaving adapter -------------------------------------------------------------

def _dirty_engine_json(label):
    return {"schema_version": "0.1", "engine": "probe-suite", "target": {"ref": TARGET["ref"], "model": "m"},
            "results": [{"catalog_id": "B1", "technique": "garak dan.Dan_11_0 persona", "trials": 10, "successes": 9,
                         "oracle": {"kind": "tool-deterministic", "name": "garak probe-detectors"},
                         "proven": [{"sha256": "a" * 64, "excerpt": "emitted via pyrit converter stack"}]}],
            "errors": [f"garak exited 1; no report ({DIRTY})"]}


def test_engine_bridge_sanitises_result(tmp_path):
    def runner(engine_key, label, command, max_seconds, allow, out_dir):
        (out_dir / f"{label}.engine.json").write_text(json.dumps(_dirty_engine_json(label)))

    out = eb.run_engine("garak", ["B1"], target=TARGET, trials=10, out_dir=tmp_path, runner=runner)
    assert out.result is not None and out.error == ""
    assert nd.scan(out.result.model_dump_json()) == []  # errors, technique, oracle and excerpt all scrubbed
    assert out.result.results[0].successes == 9  # scrubbing never touches counts


def test_engine_bridge_failure_messages_are_clean(tmp_path):
    def boom(*a):
        raise RuntimeError("garak NVIDIA traceback")  # even a tool-named exception message must not leak

    def dirty_schema(engine_key, label, command, max_seconds, allow, out_dir):
        (out_dir / f"{label}.engine.json").write_text('{"garak": "NVIDIA/garak internals"}')
    for runner, needle in ((boom, "engine run failed"), (dirty_schema, "schema validation")):
        err = eb.run_engine("garak", ["B1"], target=TARGET, trials=4, out_dir=tmp_path, runner=runner).error
        # engine_bridge translates failures to its own enumerated messages (only the exception class name survives).
        assert needle in err and nd.scan(err) == []


# ---- every output format is clean, with engine results present --------------------------------------------------

def _report_with_engine():
    controls = resolve_controls({"trials": 10, "attacks": "B1"}).controls
    plan = build_plan(parse(TARGET["ref"]), selected=["B1"], controls=controls)
    er = EngineResult.model_validate(_dirty_engine_json("x"))
    er = eb._sanitize(er)  # as ingested by run_engine
    return assemble(target={"ref": TARGET["ref"], "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps,
                    runs=[], controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                    engine_results=[er], ledger={}, run_id="nd", native=set(NATIVE),
                    started=dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc))


def test_every_output_format_has_no_upstream_name():
    report = _report_with_engine()
    assert report.findings and report.findings[0].engine_build.engines == ["probe-suite"]
    rendered = {"json": render.to_json(report), "sarif": render.to_sarif(report),
                "markdown": render.to_markdown(report)}
    for fmt, text in rendered.items():
        assert nd.scan(text) == [], f"{fmt}: {nd.scan(text)}"
    assert "probe-suite" in rendered["json"]  # engines are represented by their neutral alias, not the tool name


def test_console_fields_from_a_run_are_clean():
    """The only engine-derived strings the scan command echoes are the alias and engine_bridge's own error text."""
    report = _report_with_engine()
    lines = ["engines   probe-suite: B1"]
    for f in report.findings:
        lines.append(f"  {f.catalog_id} {f.severity} {f.technique}")
    lines.append(f"grade     {report.grade['overall']} covers {','.join(report.grade['covered'])}")
    console = "\n".join(lines)
    assert nd.scan(console) == []


# ---- target header view shows no tool fingerprint (done-when 2) -------------------------------------------------

def test_target_header_view_detects_and_clears_fingerprints():
    from engines import sandbox

    common = _adapter_common()
    # A compliant engine run: the adapter's neutral User-Agent and ordinary headers → no leak.
    clean = sandbox.fingerprint_leaks([common.USER_AGENT], ["content-type", "user-agent", "authorization", "accept"])
    assert clean == []
    # If a tool's default client UA or an identifying header slipped through, the check must catch it.
    assert sandbox.fingerprint_leaks(["garak/0.17.1 python-requests/2.32"], ["content-type"]) == ["garak"]
    assert "pyrit" in sandbox.fingerprint_leaks(["python"], ["x-pyrit-run", "content-type"])


def test_probe_suite_configures_a_neutral_user_agent():
    """The real garak run sets its outbound User-Agent in run.json; it must be our neutral one, not the tool default."""
    src = (ROOT / "engines" / "adapters" / "probe-suite.py").read_text(encoding="utf-8")
    assert '"user_agent": "hfsentinel/0.0.1"' in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
