"""B23 constrained-decoding attack (plan 16.7): structured output (response_format enum) coerces a refused request into
emitting a planted canary. Experimental, deterministic canary oracle; N/A on targets that reject structured output."""
import random
import re

from hfsentinel.attacks.cda import CdaResult, cda_request, make_canary, run_cda
from hfsentinel.targets.openai_compat import ChatResult, OpenAICompatTarget, TargetError
from hfsentinel.testing import vuln_target

CANARY_RE = re.compile(r"^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$")


def _target(base):
    return OpenAICompatTarget(base, vuln_target.MODEL_ID, max_requests=1000)


def test_make_canary_and_request_shape():
    canary = make_canary(random.Random(0))
    assert CANARY_RE.match(canary)
    messages, rf = cda_request(canary)
    schema = rf["json_schema"]["schema"]
    assert schema["properties"]["code"]["enum"] == [canary]  # only the canary is a valid answer
    assert any(m["role"] == "user" for m in messages)


def test_structured_output_bypasses_refusal_on_the_vuln_target():
    srv, base = vuln_target.serve()  # ALWAYS profile: honours structured output every time
    try:
        res = run_cda(_target(base), trials=6, seed=1)
        assert res.supported and res.hits == res.trials == 6 and res.reproduced
        assert "reproduced" in res.verdict and res.excerpt  # a short redacted bypass excerpt is kept (D-015)
    finally:
        srv.shutdown()


def test_plaintext_without_structured_output_is_refused():
    """The same request, sent without response_format, is refused — the constraint is what bypasses (control)."""
    srv, base = vuln_target.serve()
    try:
        canary = make_canary(random.Random(2))
        messages, _ = cda_request(canary)
        plain = _target(base).chat(messages, max_tokens=64, temperature=0.0)
        assert canary not in plain.text and plain.text == vuln_target.REFUSAL
    finally:
        srv.shutdown()


class _Ignores:
    """A target that accepts response_format but ignores it and refuses (structured output not honoured)."""
    def chat(self, messages, *, max_tokens=256, temperature=0.7, extra=None):
        return ChatResult("I can't help with that.", "m", finish_reason="stop")


class _Unsupported:
    """A target that rejects response_format (no structured-output support)."""
    def chat(self, messages, *, max_tokens=256, temperature=0.7, extra=None):
        raise TargetError("response_format not supported")


def test_target_that_ignores_structured_output_does_not_reproduce():
    res = run_cda(_Ignores(), trials=5, seed=3)
    assert res.supported and res.hits == 0 and not res.reproduced and "not reproduced" in res.verdict


def test_unsupported_target_is_recorded_na():
    res = run_cda(_Unsupported(), trials=5, seed=4)
    assert res == CdaResult(trials=0, hits=0, supported=False)
    assert not res.reproduced and res.verdict.startswith("n/a")


def test_campaign_runs_b23_experimental_and_records_the_verdict():
    """A scan on a structured-output target runs B23 experimentally and records its reproduce verdict (never scored)."""
    from hfsentinel.controls import resolve_controls
    from hfsentinel.engines.campaign import run_campaign
    from hfsentinel.engines.governor import Governor, Ledger
    from hfsentinel.engines.planner import build_plan
    from hfsentinel.engines.recon import run_recon
    from hfsentinel.targets.resolve import parse

    srv, base = vuln_target.serve()
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        controls = resolve_controls({"trials": 8, "status": "all"}).controls
        profile = run_recon(_target(base))  # detects structured_output -> B23 precondition met
        plan = build_plan(parse(uri), profile=profile, controls=controls)
        gov = Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=2)
        res = run_campaign(_target(base), gov, plan, trials=8, temperature=0.7, max_tokens=64, concurrency=2,
                           seed=1, profile=profile)
        b23 = next(e for e in res.experimental if e["id"] == "B23")
        assert b23["reproduced"] and "reproduced" in b23["verdict"]  # recorded, experimental
        assert any(d["stage"] == "S4" and d["catalog_id"] == "B23" for d in res.decisions)
    finally:
        srv.shutdown()
