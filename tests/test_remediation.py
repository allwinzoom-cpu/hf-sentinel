"""Per-category remediation guidance: every catalog category maps to OWASP-grounded, defender-side mitigation steps,
surfaced on the SARIF alert (rule.help + helpUri, which GitHub code scanning renders) and in the /catalog response the
console drill-down reads. The guidance names no scanning tool (no-tool-name-leak) and prescribes controls, not attacks."""
import datetime as dt
import json

import pytest

from hfsentinel import api
from hfsentinel.controls import resolve_controls
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE
from hfsentinel.report import render
from hfsentinel.report.build import Report, assemble
from hfsentinel.report.remediation import REMEDIATION, for_catalog_id, for_category
from hfsentinel.targets.resolve import parse

_SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
          "checked_at": "2026-11-16T00:00:00+00:00"}
_CATEGORIES = set("ABCDEH")


def test_every_catalog_category_has_grounded_remediation():
    assert _CATEGORIES <= set(REMEDIATION)
    for cat in _CATEGORIES:
        r = REMEDIATION[cat]
        assert r["title"] and r["summary"]
        assert r["owasp"].startswith("LLM") and len(r["steps"]) >= 2
        assert r["reference"].startswith("https://")
        assert all(isinstance(s, str) and s.strip() for s in r["steps"])


def test_lookup_maps_by_leading_category_letter():
    assert for_catalog_id("A1")["owasp"] == "LLM01"
    assert for_catalog_id("E2")["owasp"] == "LLM05"
    assert for_catalog_id("C2") is for_category("C")
    assert for_category("zz") is None and for_catalog_id("") is None


def test_remediation_is_defensive_and_leaks_no_tool_name():
    blob = json.dumps(REMEDIATION).lower()
    for banned in ("garak", "pyrit", "promptfoo", "hf-sentinel", "sentinel"):
        assert banned not in blob


def _report_with_finding(catalog_id: str, owasp: list[str]) -> Report:
    uri = "openai+http://127.0.0.1:9/#m"
    controls = resolve_controls({"trials": 2}).controls
    plan = build_plan(parse(uri), controls=controls)
    rep = assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs={},
                   controls=controls, controls_sha256="0" * 64, attestation=_SCOPE, recon=None,
                   ledger={"requests": 0, "errors": 0, "cost_priced_usd": 0.0}, run_id="R",
                   native=set(NATIVE), started=dt.datetime(2026, 11, 16, tzinfo=dt.timezone.utc))
    d = rep.model_dump(mode="json")
    d["findings"] = [{
        "schema_version": "0.1", "finding_id": "f1", "catalog_id": catalog_id, "category": "cat",
        "owasp": owasp, "atlas": ["AML.T0050"], "target": {"ref": uri}, "attacker": ["T1"], "technique": "t",
        "trials": 5, "successes": 5, "asr": 1.0, "asr_ci95": [0.5, 1.0], "effort": "E", "severity": "High",
        "oracle": {"kind": "deterministic", "name": "code-sink"},
        "evidence": {"hash": "a" * 64, "redacted_excerpt": "x"}, "evidence_level": "reproduced-behavior",
        "engine_build": {"engines": ["native"], "build": "sha256:" + "a" * 12}, "reproducible": True,
        "status": "confirmed"}]
    return Report.model_validate(d)


def test_sarif_rule_carries_remediation_help_and_helpuri():
    sarif = json.loads(render.to_sarif(_report_with_finding("E2", ["LLM05"])))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"].startswith("https://genai.owasp.org")
    assert "Remediation" in rule["help"]["text"] and "Improper Output Handling" in rule["help"]["text"]
    assert "LLM05" in rule["help"]["markdown"]
    # still clean: no raw canary / tool name leaks into the rendered SARIF
    assert "garak" not in json.dumps(sarif).lower()


def test_all_renderers_still_work_with_a_finding():
    rep = _report_with_finding("A1", ["LLM01"])
    assert json.loads(render.to_json(rep))["findings"][0]["catalog_id"] == "A1"
    assert render.to_markdown(rep).startswith("# HF-Sentinel")
    assert "<" in render.to_html(rep)


@pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed (optional `api` extra)")
def test_catalog_endpoint_exposes_remediation_per_category():
    from fastapi.testclient import TestClient
    client = TestClient(api.create_app(api_keys=["secret"]))
    c = client.get("/catalog", headers={"X-API-Key": "secret"}).json()
    by_id = {x["id"]: x for x in c["categories"]}
    assert _CATEGORIES <= set(by_id)
    for row in by_id.values():
        rem = row["remediation"]
        assert rem and rem["owasp"].startswith("LLM") and rem["steps"] and rem["reference"].startswith("https://")
