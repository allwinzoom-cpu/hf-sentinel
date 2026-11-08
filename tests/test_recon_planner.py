"""Target recon + attack planner (plan 16.10): deterministic probe oracles against the vuln target, a scripted capable
endpoint and a scripted restrictive one; planner dispositions, ordering and defence adaptation; CLI `--recon`."""
import dataclasses
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from hfsentinel import cli
from hfsentinel.attacks.catalog import Attack, load_catalog
from hfsentinel.controls import resolve_controls
from hfsentinel.engines import planner
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import build_plan, requirements
from hfsentinel.engines.recon import FACTS, SPECIAL_TOKENS, Fact, TargetProfile, run_recon
from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.resolve import parse
from hfsentinel.testing import vuln_target

CAT = load_catalog()
TARGET = parse("openai+http://127.0.0.1:1/v1#m")


def _text(content):
    return content if isinstance(content, str) else " ".join(
        p.get("text", "") for p in content if isinstance(p, dict))


def capable(body):
    """A well-behaved modern endpoint: honours everything recon checks for."""
    msgs = body["messages"]
    last = _text(msgs[-1]["content"])
    system = " ".join(_text(m["content"]) for m in msgs if m["role"] == "system")
    usage = {"prompt_tokens": sum(len(_text(m["content"]).split()) for m in msgs) * 3, "completion_tokens": 2}
    if any(t in last for t in SPECIAL_TOKENS):
        usage["prompt_tokens"] -= 5  # delimiters parsed as single special tokens
    msg = {"role": "assistant", "content": "", "reasoning_content": "thinking..."}
    if "tools" in body:
        msg["tool_calls"] = [{"id": "1", "type": "function", "function": {"name": "get_time",
                                                                       "arguments": '{"city": "Paris"}'}}]
    elif "response_format" in body:
        msg["content"] = '{"answer": "alpha"}'
    elif msgs[-1]["role"] == "assistant":
        msg["content"] = " 7 8 9 10"
    elif m := re.search(r"code (N[0-9A-F]{8})", system):
        msg["content"] = f"Hello! {m[1]}"
    elif "What is the code" in last:
        m = re.search(r"code (N[0-9A-F]{8})", _text(msgs[0]["content"]))
        msg["content"] = m[1]
    elif "Ufaransa" in last:
        msg["content"] = "Paris"
    elif isinstance(msgs[-1]["content"], list):
        msg["content"] = "Red"
    else:
        msg["content"] = "Sure: here is how."
    return 200, {"model": "m", "choices": [{"message": msg, "finish_reason": "stop"}], "usage": usage}


def restrictive(body):
    """An endpoint that rejects every optional feature with 400."""
    if "tools" in body or "response_format" in body or isinstance(body["messages"][-1]["content"], list) \
            or body["messages"][-1]["role"] == "assistant":
        return 400, {"error": "unsupported"}
    return 200, {"model": "m", "choices": [{"message": {"content": "I'm sorry, I can't help with that."},
                                            "finish_reason": "stop"}]}


@pytest.fixture
def server():
    made = []

    def make(fn):
        seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(body)
                status, payload = fn(body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        made.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/v1", seen
    yield make
    for srv in made:
        srv.shutdown()


def facts(profile):
    return {k: v.value for k, v in profile.facts.items()}


# ---- recon ----
def test_recon_vuln_target():
    srv, url = vuln_target.serve()
    try:
        prof = run_recon(OpenAICompatTarget(url, vuln_target.MODEL_ID, max_requests=30))
    finally:
        srv.shutdown()
    assert facts(prof) == {"keyword_filter": True, "non_english": False, "system_prompt": False,
                           "multi_turn_memory": False, "structured_output": True, "tool_calling": False,
                           "prefill": False, "special_token_parsing": None, "multimodal_input": False,
                           "cross_session_memory": False, "reasoning_trace": False}  # honours response_format (B23)
    assert prof.facts["structured_output"].reason == "enforced"  # output conformed to the response_format schema (B23)
    assert prof.facts["special_token_parsing"].reason == "no_usage"
    assert prof.over_refusal_rate == 1.0 and prof.refusal_style == "templated"
    assert prof.max_tokens_accepted == 4096 and prof.requests <= 18


def test_recon_capable_endpoint(server):
    url, seen = server(capable)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30),
                     declared={"supports_tools": True, "supports_structured_output": False})
    assert facts(prof) == {f: f != "cross_session_memory" and f != "keyword_filter" for f in FACTS}
    assert prof.facts["special_token_parsing"].reason.startswith("token_delta_")
    assert prof.over_refusal_rate == 0.0 and prof.refusal_style == "none"
    assert prof.disagreements == ["structured_output: declared False, observed True"]
    assert all(b.get("temperature") == 0.0 for b in seen)
    budgets = sorted(b["max_tokens"] for b in seen)
    assert budgets[-1] == 4096 and budgets[-2] <= 1024  # only the cap probe asks for a large answer


def test_recon_restrictive_endpoint(server):
    url, _ = server(restrictive)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30))
    for f in ("structured_output", "tool_calling", "prefill", "multimodal_input"):
        assert prof.facts[f] == Fact(False, "rejected_http_400"), f
    assert prof.facts["keyword_filter"].value is True


def test_recon_profile_holds_no_response_text(server):
    url, _ = server(capable)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30))
    blob = json.dumps(dataclasses.asdict(prof))
    assert "Paris" not in blob and "Sure" not in blob and not re.search(r"N[0-9A-F]{8}", blob)


def test_recon_gradio_marks_interface_facts_unknown():
    from tests.test_gradio_space import Space

    sp = Space(results={"predict": 'event: complete\ndata: ["Paris"]\n\n'})
    try:
        prof = run_recon(GradioSpaceTarget(sp.url, max_requests=30))
    finally:
        sp.srv.shutdown()
    assert prof.facts["non_english"].value is True
    for f in ("system_prompt", "tool_calling", "structured_output", "prefill", "multimodal_input"):
        assert prof.facts[f] == Fact(None, "interface"), f


def test_recon_stops_at_budget(server):
    url, seen = server(capable)
    gov = Governor(Ledger(max_requests=5, budget_usd=1.0), rate_limit_per_min=6000)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30, governor=gov))
    assert len(seen) == 5 and gov.ledger.requests == 5
    assert prof.facts["tool_calling"] == Fact(None, "budget")


# ---- planner ----
def test_every_precondition_is_mapped():
    for a in CAT.attacks:
        requirements(a)  # raises on catalog/planner drift


def test_technique_requirement_is_anded_with_precondition():
    a = Attack(id="B12", category="B", name="prefill test", owasp=["LLM01"], atlas=["AML.T0054"], attacker=["T1"],
               effort="E", status="conditional", precondition="multi-turn", oracle="judge on output")
    assert requirements(a) == ((("fact", "multi_turn_memory"), ("fact", "prefill")),)


def profile(**overrides):
    base = {f: Fact(False, "test") for f in FACTS}
    base.update({k: Fact(v, "test") for k, v in overrides.items()})
    return TargetProfile(facts=base)


def plan_for(prof, flags=None):
    c = resolve_controls({"profile": "custom", "status": "all", **(flags or {})}).controls
    return {s.catalog_id: s for s in build_plan(TARGET, profile=prof, controls=c).steps}


def test_plan_carries_profile_and_cli_prints_negotiated_features(capsys):
    # LSCAN-022: the plan keeps the recon profile, and the dry-run print shows the negotiated controls by state.
    from hfsentinel import cli
    prof = profile()
    prof.features = {"max_tokens": {"state": "verified", "probed": True},
                     "seed": {"state": "ignored", "probed": True},
                     "top_p": {"state": "unknown", "probed": False, "reason": "not negotiated in this build"}}
    plan = build_plan(TARGET, profile=prof, controls=resolve_controls({"profile": "custom", "status": "all"}).controls)
    assert plan.profile is prof
    cli._print_plan(plan)
    out = capsys.readouterr().out
    assert "features  " in out and "max_tokens=verified" in out and "seed=ignored" in out
    assert "top_p" not in out  # an unprobed control is never presented as a negotiated result


def test_no_tools_no_structured_output_means_na_with_zero_requests():
    steps = plan_for(profile())
    # LSCAN-004: a plain-chat target (no tools, no cross-session memory, no structured output) shows every
    # privileged-surface technique as N/A — the declared attacker controls only user text.
    for cid in ("D1", "D2", "D3", "D4", "D5", "E4", "B23", "C4"):
        assert steps[cid].disposition == "n/a" and steps[cid].requests == 0, cid
    assert steps["D7"].disposition == "n/a" and steps["D7"].requests == 0  # nothing supplied either
    assert steps["C3"].disposition == "blocked" and steps["H2"].disposition == "blocked"  # operator/oracle gaps
    assert all(s.requests == 0 for s in steps.values() if s.disposition not in ("run", "experimental"))


def test_mock_tool_env_makes_agentic_attacks_runnable(tmp_path):
    manifest = tmp_path / "tools.json"
    manifest.write_text("{}")
    steps = plan_for(profile(), {"tools": manifest})
    assert steps["D1"].disposition == "run" and steps["D1"].requests > 0
    assert steps["D7"].disposition == "blocked"  # still needs a controlled sink URL


def test_without_recon_nothing_is_na():
    steps = {s.catalog_id: s for s in build_plan(TARGET).steps}
    assert not any(s.disposition == "n/a" for s in steps.values())
    assert steps["A6"].disposition == "unverified" and steps["H2"].disposition == "blocked"


def test_runnable_steps_are_ordered_by_gain_and_held_steps_last():
    steps = build_plan(TARGET, profile=profile(), controls=resolve_controls({"status": "all"}).controls).steps
    runs = [s for s in steps if s.disposition == "run"]
    assert [s.score for s in runs] == sorted((s.score for s in runs), reverse=True)
    kinds = [s.disposition for s in steps]
    assert kinds.index("n/a") > max(i for i, k in enumerate(kinds) if k in ("run", "experimental"))
    assert runs[0].catalog_id in {"A5", "C2"}  # Critical, single-shot


def test_keyword_filter_favours_encoding_and_limits_mutators():
    plain = plan_for(profile())
    filtered = plan_for(profile(keyword_filter=True), {"mutators": "base64,leet,case"})
    assert filtered["B2"].score == pytest.approx(plain["B2"].score * planner.BOOST)
    assert filtered["B1"].score == pytest.approx(plain["B1"].score)
    assert filtered["B2"].mutators == ("base64", "leet") and plain["B2"].mutators == ()
    assert "keyword-filter" in filtered["B2"].rationale


def test_observed_capabilities_unlock_and_boost():
    steps = plan_for(profile(special_token_parsing=True, reasoning_trace=True, prefill=True, structured_output=True))
    assert steps["A6"].disposition == "run" and "special tokens parsed" in steps["A6"].rationale
    # B10 stays an experimental candidate; B23 is now a SCORED conditional → run once structured output is observed.
    assert steps["B10"].disposition == "experimental" and steps["B23"].disposition == "run"
    assert steps["B12"].disposition == "run"


# ---- CLI ----
runner = CliRunner()


def test_cli_recon_on_vuln_target_and_plan():
    srv, url = vuln_target.serve()
    try:
        res = runner.invoke(cli.app, ["scan", f"openai+{url}#{vuln_target.MODEL_ID}", "--dry-run", "--recon",
                                      "--status", "all", "--profile", "custom"])
    finally:
        srv.shutdown()
    out = res.output
    assert res.exit_code == cli.EXIT_OK, out
    assert re.search(r"tool_calling\s+no\s+no_tool_call", out) and "recon     profile applied" in out
    # structured_output is detected on the vuln target, so B23's precondition is met → run (now a scored conditional)
    assert re.search(r"^\s*\d+ D1\s+n/a\s", out, re.MULTILINE)
    assert re.search(r"^\s*\d+ B23\s+run\s", out, re.MULTILINE)


def test_cli_recon_refuses_unapproved_targets(monkeypatch):
    def deny(*_a, **_k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr("socket.socket.connect", deny)
    res = runner.invoke(cli.app, ["scan", "openai+https://api.example.com/v1#m", "--dry-run", "--recon"])
    assert res.exit_code == cli.EXIT_SCOPE and "no requests sent" in res.output
    assert runner.invoke(cli.app, ["scan", "openai+https://api.example.com/v1#m", "--recon"]).exit_code == \
        cli.EXIT_USAGE


def test_reference_targets_are_recon_authorized():
    from hfsentinel.scope import ScopeError, authorize

    for uri in ("hf-provider://Qwen/Qwen3-32B@deepinfra", "hf-provider://google/gemma-3-27b-it@deepinfra"):
        assert authorize(None, parse(uri), resolved=True).source == "reference-endpoints (D-007)"
    with pytest.raises(ScopeError):
        authorize(None, parse("hf-provider://Qwen/Qwen3-32B@groq"), resolved=True)


def test_reasoning_model_is_not_misread_as_lacking_features(server):
    def reasoning(body):
        if body["max_tokens"] < 100 and "tools" not in body and body["max_tokens"] != 1:
            return 200, {"model": "m", "choices": [{"message": {"content": "", "reasoning_content": "hmm " * 20},
                                                    "finish_reason": "length"}], "usage": {"prompt_tokens": 9}}
        return capable(body)

    url, seen = server(reasoning)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30))
    assert prof.facts["reasoning_trace"].value is True
    for f in ("system_prompt", "multi_turn_memory", "structured_output", "prefill", "non_english"):
        assert prof.facts[f].value is True, f  # answered once the budget was raised, never a false negative
    assert any(b["max_tokens"] == 1024 for b in seen)


def test_refusal_style_needs_enough_answers(server):
    def mostly_truncated(body):
        if "kill" in json.dumps(body) or "terminate" in json.dumps(body):
            return 200, {"model": "m", "choices": [{"message": {"content": ""}, "finish_reason": "length"}]}
        return capable(body)

    url, _ = server(mostly_truncated)
    prof = run_recon(OpenAICompatTarget(url, "m", max_requests=30))
    assert prof.facts["keyword_filter"] == Fact(None, "too_few_answers_1")
    assert prof.over_refusal_rate is None and prof.refusal_style == "unknown"
