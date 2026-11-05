"""Model-card snippet (plan Phase 5): a short, pasteable Markdown results block with scores + run metadata, safely
encoded and alias-only."""
import datetime as dt

from hfsentinel.controls import resolve_controls
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan
from hfsentinel.engines.sweep import NATIVE, run_sweep
from hfsentinel.report import render
from hfsentinel.report.build import assemble
from hfsentinel.report.model_card import model_card
from hfsentinel.targets.openai_compat import ChatResult, OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

SCOPE = {"source": "loopback", "matched": "127.0.0.1", "reference": "loopback", "authorized_by": "operator",
         "checked_at": "2026-11-05T00:00:00+00:00"}
XSS = "![x](https://evil.example/?q=1)<img src=x onerror=alert(1)> [click](javascript:alert(1)) ```"


def _report(target, uri, *, trials=4, ids=None):
    controls = resolve_controls({"trials": trials, "concurrency": 2}).controls
    plan = build_plan(parse(uri), selected=ids, controls=controls)
    run_ids = [s.catalog_id for s in plan.steps if s.disposition == "run" and s.catalog_id in NATIVE]
    gov = Governor(Ledger(max_requests=500, budget_usd=1.0), concurrency=2)
    runs = run_sweep(target, gov, run_ids, trials=trials, temperature=0.7, max_tokens=256, concurrency=2)
    return assemble(target={"ref": uri, "kind": "openai", "resolved_model": "m"}, plan_steps=plan.steps, runs=runs,
                    controls=controls, controls_sha256="0" * 64, attestation=SCOPE, recon=None,
                    ledger=gov.ledger.snapshot(), run_id="20261105T000000Z-card", native=set(NATIVE),
                    started=dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc))


class Refuser:
    def chat(self, messages, *, max_tokens=256, temperature=0.7):
        return ChatResult("I can't help with that.", "m", finish_reason="stop")


def test_snippet_has_scores_and_run_metadata():
    srv, base = vuln_target.serve()
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        report = _report(OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=1000), uri)
        card = model_card(report)
        assert report.findings  # the vuln target yields confirmed findings
        assert card.startswith("## 🛡️ HF-Sentinel security scan")
        assert f"**Grade: {report.grade['overall']}**" in card
        assert "| Category | Score | Grade |" in card  # scores table
        assert "20261105T000000Z" in card and report.report_sha256[:16] in card  # run metadata (run id + sha)
        assert f"{len(report.findings)} confirmed finding" in card
        # only tested categories appear as rows
        tested = {c for c, v in report.grade["categories"].items() if v["tested"]}
        untested = {c for c, v in report.grade["categories"].items() if not v["tested"]}
        for c in tested:
            assert f"| {c} ·" in card
        for c in untested:
            assert f"| {c} ·" not in card
    finally:
        srv.shutdown()


def test_no_findings_renders_cleanly():
    report = _report(Refuser(), "openai+http://127.0.0.1:9/v1#m", trials=3)
    card = model_card(report)
    assert report.findings == []
    assert "**No confirmed findings.**" in card and "**Grade:" in card and "not an endorsement" in card


def test_hostile_target_strings_are_escaped():
    report = _report(Refuser(), "openai+http://127.0.0.1:9/v1#m", trials=3)
    poisoned = report.model_copy(update={"target": {**report.target, "ref": XSS, "resolved_model": XSS}})
    card = model_card(poisoned)
    # the markdown-image / html / link payload must be neutralised (escaped), not live markup
    assert "![x](" not in card and "<img" not in card and "](javascript" not in card
    assert "\\!\\[x\\]" in card or "\\[x\\]" in card  # markdown specials backslash-escaped by render.md


def test_card_is_a_writable_format(tmp_path):
    report = _report(Refuser(), "openai+http://127.0.0.1:9/v1#m", trials=3)
    paths = render.write(report, tmp_path, ["card"])
    assert len(paths) == 1 and paths[0].name.endswith(".modelcard.md")
    text = paths[0].read_text(encoding="utf-8")
    assert text.startswith("## 🛡️ HF-Sentinel security scan") and (paths[0].stat().st_mode & 0o777) == 0o600
