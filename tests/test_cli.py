"""CLI skeleton (plan Phase 2): resolve prints a plan, scan fails closed on scope, report summarizes findings,
no network traffic from any of them, stable exit codes, and no upstream names in console output (D-014)."""
import json
import re
import socket
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hfsentinel import cli
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.targets import resolve

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "engines" / "versions.json").read_text(encoding="utf-8"))
UPSTREAM = sorted({t.lower() for name, spec in MANIFEST["engines"].items()
                   for t in (name, *re.split(r"[/_-]", spec["repo"])) if len(t) >= 5}
                  | {"pyrit", "deepeval", "litellm", "codeshield", "llamafirewall", "semgrep", "strong_reject",
                     "strongreject", "harmbench", "typer", "traceback"})
TARGET = "hf-provider://Qwen/Qwen3-32B@deepinfra"  # non-Llama: "llama" is an upstream token
SPIKE = sorted((ROOT / "docs" / "spike").glob("*.findings.json"))
runner = CliRunner()


@pytest.fixture(autouse=True)
def no_network(monkeypatch, fake_hub, tmp_path):
    """Any socket connect during a CLI test is a failure: resolve/scan/report send nothing to targets, and Hub
    metadata comes from the recorded fake. No real token is read."""
    def deny(*_a, **_k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    for name in ("HF_TOKEN", "hf_tok", "HF_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HFSENTINEL_ENV_FILE", str(tmp_path / "absent.env"))
    return fake_hub


def run(*args):
    res = runner.invoke(cli.app, list(args))
    assert not isinstance(res.exception, AssertionError), "network call attempted"
    return res


def assert_no_upstream(text: str):
    assert [t for t in UPSTREAM if t in text.lower()] == []


def test_resolve_prints_plan():
    res = run("resolve", TARGET)
    assert res.exit_code == cli.EXIT_OK
    out = res.output
    assert "model     Qwen/Qwen3-32B" in out and "provider  deepinfra" in out
    assert "https://router.huggingface.co/v1" in out
    cat = load_catalog()
    for a in cat.attacks:
        assert re.search(rf"^\s*\d+ {a.id}\s", out, re.MULTILINE), a.id
    m = re.search(r"(\d+) attacks: (\d+) run · (\d+) experimental \(not scored\) · (\d+) unverified · "
                  r"(\d+) blocked · (\d+) n/a", out)
    assert m and int(m[1]) == len(cat.attacks) == sum(int(x) for x in m.groups()[1:])
    assert int(m[6]) == 0  # nothing is n/a without recon: absence of a capability must be observed
    assert "recon     not run" in out
    for row, disposition in (("A1", "run"), ("B12", "unverified"), ("D1", "unverified"), ("C3", "blocked"),
                             ("D7", "blocked"), ("B6", "run"), ("B8", "experimental")):
        assert re.search(rf"^\s*\d+ {row}\s+{re.escape(disposition)}\s", out, re.MULTILINE), row
    assert_no_upstream(out)


def test_resolve_plan_shows_real_engine_routing():
    # task 599/600: the plan print now reports which capability owner handles each scored technique (from
    # engines/capabilities.json), not the old "routing not yet assigned" placeholder — and never leaks a tool name.
    out = run("resolve", TARGET).output
    m = re.search(r"^engines\s+(.+)$", out, re.MULTILINE)
    assert m and "routing not yet assigned" not in out
    assert "built-by-us" in m[1] and "unassigned" not in m[1]  # every scored native ID has a real owner
    assert_no_upstream(out)


def test_resolve_openai_loopback_target():
    res = run("resolve", "openai+http://127.0.0.1:8765/v1#hfsentinel/vuln-target-v0")
    assert res.exit_code == cli.EXIT_OK and "kind      openai" in res.output


@pytest.mark.parametrize("uri", ["gopher://x", "hf-provider://no-slash", "openai+http://example.com/v1#m",
                                 "openai+https://user:pw@example.com/v1#m", "hf-provider://a/b@UPPER",
                                 "hf-provider://" + "a" * 600 + "/b", "hf-provider://org/mödel"])
def test_resolve_rejects_bad_uris(uri):
    res = run("resolve", uri)
    assert res.exit_code == cli.EXIT_INPUT
    assert "pw" not in res.output and "Traceback" not in res.output


def test_resolve_pins_provider_and_reports_alternatives(no_network):
    res = run("resolve", "hf-provider://Qwen/Qwen3-32B")
    assert res.exit_code == cli.EXIT_OK
    assert "provider  nscale" in res.output and "also live: featherless-ai, deepinfra" in res.output
    assert "groq" not in res.output  # listed by the Hub with status=error
    assert no_network == [("/api/models/Qwen/Qwen3-32B?expand[]=inferenceProviderMapping", None)]


def test_resolve_space_plan():
    res = run("resolve", "hf-space://gradio/hello_world")
    assert res.exit_code == cli.EXIT_OK
    assert "endpoint  https://gradio-hello-world.hf.space" in res.output and "sdk gradio" in res.output
    assert "Gradio app" in res.output


def test_resolve_explicit_provider_must_be_live():
    res = run("resolve", "hf-provider://Qwen/Qwen3-32B@groq")
    assert res.exit_code == cli.EXIT_INPUT and "not live" in res.output


def test_via_direct_makes_no_hub_calls(no_network):
    assert run("resolve", TARGET, "--via", "direct").exit_code == cli.EXIT_OK
    assert run("resolve", "hf-provider://Qwen/Qwen3-32B", "--via", "direct").exit_code == cli.EXIT_INPUT
    assert run("resolve", "hf-space://gradio/hello_world", "--via", "direct").exit_code == cli.EXIT_INPUT
    assert no_network == []


def test_hub_not_found_and_unavailable(monkeypatch):
    res = run("resolve", "hf-provider://org/missing")
    assert res.exit_code == cli.EXIT_INPUT and "not found or not accessible" in res.output

    def down(*_a, **_k):
        raise cli.hub.HubError("the Hub is unreachable: URLError")
    monkeypatch.setattr(cli.hub, "_get_json", down)
    assert run("resolve", TARGET).exit_code == cli.EXIT_HUB


@pytest.mark.parametrize("uri", ["hf-job://org/model", "hf-job://org/model@a10g-small",
                                 "hf-provider://org/no-provider"])
def test_job_path_is_unsupported_not_invalid(uri):
    res = run("resolve", uri)
    assert res.exit_code == cli.EXIT_UNSUPPORTED and "D-004" in res.output


def test_job_dry_run_submits_nothing(monkeypatch):
    # LSCAN-012: the job dry-run renders the spec and must NEVER reach launch (no compute, no token read).
    import hfsentinel.targets.job_target as jt
    monkeypatch.setattr(jt, "launch", lambda *a, **k: (_ for _ in ()).throw(AssertionError("launch called on dry-run")))
    res = run("job", "Qwen/Qwen2.5-0.5B-Instruct", "--dataset", "org/ds", "--image", "org/img:sha", "--dry-run")
    assert res.exit_code == cli.EXIT_OK
    spec = json.loads(res.output)
    assert spec["image"] == "org/img:sha" and "command" in spec


@pytest.mark.parametrize("uri", ["hf-endpoint://x", "hf-endpoint://evil.example.com", "hf-job://x"])
def test_malformed_planned_schemes_are_invalid(uri):
    assert run("resolve", uri).exit_code == cli.EXIT_INPUT


def test_endpoint_resolves_offline(no_network):
    res = run("resolve", "hf-endpoint://abc123.us-east-1.aws.endpoints.huggingface.cloud")
    assert res.exit_code == cli.EXIT_OK
    assert "endpoint  https://abc123.us-east-1.aws.endpoints.huggingface.cloud/v1" in res.output
    assert "model     tgi" in res.output and no_network == []


def test_scan_refuses_out_of_scope_target_with_zero_network_calls(no_network):
    res = run("scan", "hf-provider://org/not-approved")  # --via auto would call the Hub: scope is checked first
    assert res.exit_code == cli.EXIT_SCOPE and "--scope" in res.output and "no requests sent" in res.output
    assert no_network == []


def test_reference_target_is_in_builtin_scope(monkeypatch):
    monkeypatch.setattr(cli, "_optional_token", lambda: None)
    res = run("scan", TARGET)  # authorized, then stops at the token check before any target request
    assert "reference-endpoints (D-007)" in res.output
    assert res.exit_code == cli.EXIT_INPUT and "need an HF token" in res.output


def test_scan_fails_closed_even_with_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_optional_token", lambda: None)
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets: []\n")
    res = run("scan", TARGET, "--scope", str(scope))
    assert res.exit_code == cli.EXIT_SCOPE and "no requests sent" in res.output


def test_scan_dry_run_prints_plan_and_scope_status():
    res = run("scan", TARGET, "--dry-run")
    assert res.exit_code == cli.EXIT_OK
    assert "no requests sent" in res.output and "scope     not checked" in res.output
    assert_no_upstream(res.output)


def test_scan_rejects_bad_target_before_scope():
    assert run("scan", "gopher://x", "--dry-run").exit_code == cli.EXIT_INPUT


@pytest.mark.parametrize("path", SPIKE, ids=lambda p: p.stem)
def test_report_summarizes_spike_findings(path):
    n = len(json.loads(path.read_text(encoding="utf-8"))["findings"])
    res = run("report", str(path))
    assert res.exit_code == cli.EXIT_OK and f"{n} total" in res.output
    assert_no_upstream(res.output)


def test_report_never_prints_evidence_and_strips_control_chars(tmp_path):
    data = json.loads(SPIKE[0].read_text(encoding="utf-8"))
    f = dict(data["findings"][0], technique="evil\x1b]0;pwned\x07\u202etech",
             evidence={"hash": None, "redacted_excerpt": "SECRET-EXCERPT"})
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"findings": [f]}))
    res = run("report", str(p))
    assert res.exit_code == cli.EXIT_OK
    assert "\x1b" not in res.output and "\x07" not in res.output and "\u202e" not in res.output
    assert "SECRET-EXCERPT" not in res.output


@pytest.mark.parametrize("content", ["not json", "{}", '{"findings": [{"catalog_id": "Z9"}]}', "[1]"])
def test_report_rejects_invalid_files(tmp_path, content):
    p = tmp_path / "f.json"
    p.write_text(content)
    res = run("report", str(p))
    assert res.exit_code == cli.EXIT_INPUT and "not a valid HF-Sentinel findings file" in res.output


def test_report_rejects_missing_and_oversized(tmp_path, monkeypatch):
    assert run("report", str(tmp_path / "nope.json")).exit_code == cli.EXIT_INPUT
    assert run("report", str(tmp_path)).exit_code == cli.EXIT_INPUT
    monkeypatch.setattr(cli, "MAX_REPORT_BYTES", 10)
    p = tmp_path / "big.json"
    p.write_text("[]" + " " * 20)
    assert run("report", str(p)).exit_code == cli.EXIT_INPUT


def test_help_is_hf_sentinel_only():
    for args in ([], ["--help"], ["scan", "--help"], ["resolve", "--help"], ["report", "--help"]):
        res = run(*args)
        assert "HF-Sentinel" in res.output or "hfsentinel" in res.output.lower()
        assert_no_upstream(res.output)


def test_usage_error_exit_code():
    assert run("scan").exit_code == cli.EXIT_USAGE


def test_internal_error_is_generic(monkeypatch, capsys):
    def boom(*_a, **_k):
        raise RuntimeError("/secret/path hf_token")
    monkeypatch.setattr(cli, "build_plan", boom)
    monkeypatch.setattr("sys.argv", ["hfsentinel", "resolve", TARGET])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == cli.EXIT_INTERNAL
    err = capsys.readouterr().err
    assert err.strip() == "hfsentinel: internal error"


def test_resolver_request_model_and_token_rule():
    t = resolve.parse(TARGET)
    assert t.request_model == "Qwen/Qwen3-32B:deepinfra"
    with pytest.raises(resolve.TargetURIError):
        resolve.client(t, None, max_requests=1)


# ---- control surface on the CLI ----
def test_dry_run_prints_controls_with_sources():
    res = run("scan", TARGET, "--dry-run", "--profile", "deep", "--rounds", "20", "--categories", "B")
    assert res.exit_code == cli.EXIT_OK
    out = res.output
    assert re.search(r"fuzz\.rounds\s+20\s+flag", out) and re.search(r"fuzz\.max_turns\s+8\s+profile:deep", out)
    assert re.search(r"judge\.asr_k\s+= rounds \(20\)", out) and re.search(r"target_io\.top_p\s+provider default", out)
    assert re.search(r"^\s*\d+ B1\s", out, re.MULTILINE) and not re.search(r"^\s*\d+ A1\s", out, re.MULTILINE)
    assert_no_upstream(out)


def test_bad_control_values_exit_invalid_input():
    res = run("scan", TARGET, "--dry-run", "--budget-usd", "50")
    assert res.exit_code == cli.EXIT_INPUT and "flag: budget.usd" in res.output
    assert run("scan", TARGET, "--rounds", "abc").exit_code == cli.EXIT_USAGE  # type error caught by the parser


def test_config_target_print_config_and_scope(tmp_path):
    cfg = tmp_path / "sentinel.yaml"
    cfg.write_text(f"target: {TARGET}\nprofile: standard\nfuzz: {{rounds: 12}}\n")
    printed = run("scan", "--config", str(cfg), "--print-config", "--trials", "4")
    assert printed.exit_code == cli.EXIT_OK
    data = yaml.safe_load(printed.output)
    assert data["target"] == TARGET and data["fuzz"]["rounds"] == 12 and data["target_io"]["trials"] == 4
    dry = run("scan", "--config", str(cfg), "--dry-run")
    assert dry.exit_code == cli.EXIT_OK and "model     Qwen/Qwen3-32B" in dry.output
    override = run("scan", "hf-provider://openai/gpt-oss-120b@deepinfra", "--config", str(cfg), "--dry-run",
                   "--via", "direct")
    assert "model     openai/gpt-oss-120b" in override.output
    assert re.search(r"^  target\s+hf-provider://openai/gpt-oss-120b@deepinfra\s+flag$", override.output, re.MULTILINE)
    assert run("scan", "--config", str(cfg)).exit_code == cli.EXIT_INPUT  # in scope (D-007); no token, no traffic


def test_config_errors_and_missing_target(tmp_path):
    cfg = tmp_path / "sentinel.yaml"
    cfg.write_text("fuzz: {roundz: 3}\n")
    res = run("scan", TARGET, "--config", str(cfg), "--dry-run")
    assert res.exit_code == cli.EXIT_INPUT and "config: fuzz.roundz" in res.output
    assert run("scan", "--dry-run").exit_code == cli.EXIT_USAGE
