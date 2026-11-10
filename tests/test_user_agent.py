"""Configurable User-Agent (owner request): one control, CLI/config/profile precedence, header-safe validation, and
exactly what reaches the target."""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

import hfsentinel
from hfsentinel import cli
from hfsentinel.controls import ControlError, resolve_controls
from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import DEFAULT_USER_AGENT, OpenAICompatTarget

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.fixture(autouse=True)
def _offline_secrets(monkeypatch, tmp_path):
    """CLI dry runs must not depend on local secret files."""
    for name in ("HF_TOKEN", "hf_tok", "HF_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HFSENTINEL_ENV_FILE", str(tmp_path / "absent.env"))


def test_default_tracks_the_package_version():
    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)[1]
    assert hfsentinel.__version__ == version and DEFAULT_USER_AGENT == f"hfsentinel/{version}"


def test_control_precedence_and_source():
    res = resolve_controls({"user_agent": "Acme-AppSec-Scan/2.1 (+ticket SEC-42)"},
                           {"target_io": {"user_agent": "from-config/1"}})
    assert res.controls.target_io.user_agent == "Acme-AppSec-Scan/2.1 (+ticket SEC-42)"
    assert res.sources["target_io.user_agent"] == "flag"
    assert resolve_controls(config={"target_io": {"user_agent": "from-config/1"}}).sources[
        "target_io.user_agent"] == "config"
    assert resolve_controls().controls.target_io.user_agent == DEFAULT_USER_AGENT


@pytest.mark.parametrize("bad", ["a\r\nX-Injected: 1", "a\nb", "café", "", "x" * 201, "tab\there"])
def test_header_unsafe_values_are_refused(bad):
    with pytest.raises(ControlError, match="user_agent"):
        resolve_controls({"user_agent": bad})
    with pytest.raises(ValueError):
        OpenAICompatTarget("https://api.example.com/v1", "m", user_agent=bad)
    with pytest.raises(ValueError):
        GradioSpaceTarget("https://x.hf.space", user_agent=bad)


@pytest.fixture
def capture():
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(self.headers.get("User-Agent"))
            body = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1", seen
    srv.shutdown()


def test_exact_header_reaches_the_target(capture):
    url, seen = capture
    OpenAICompatTarget(url, "m").chat([{"role": "user", "content": "x"}])
    OpenAICompatTarget(url, "m", user_agent="Acme-Scan/1.0").chat([{"role": "user", "content": "x"}])
    assert seen == [DEFAULT_USER_AGENT, "Acme-Scan/1.0"]  # never the stdlib default


def test_gradio_adapter_sends_it_too():
    from tests.test_gradio_space import USER, Space

    sp = Space()
    try:
        GradioSpaceTarget(sp.url, user_agent="Acme-Scan/1.0").chat(USER)
    finally:
        sp.srv.shutdown()
    assert {s[2].get("User-Agent") for s in sp.seen} == {"Acme-Scan/1.0"}


def test_cli_dry_run_shows_value_and_source(monkeypatch):
    res = CliRunner().invoke(cli.app, ["scan", "openai+http://127.0.0.1:9/v1#m", "--dry-run",
                                       "--user-agent", "Acme-Scan/1.0"])
    assert res.exit_code == cli.EXIT_OK
    assert re.search(r"target_io\.user_agent\s+Acme-Scan/1\.0\s+flag", res.output)
    bad = CliRunner().invoke(cli.app, ["scan", "openai+http://127.0.0.1:9/v1#m", "--dry-run",
                                       "--user-agent", "x\r\nY: z"])
    assert bad.exit_code == cli.EXIT_INPUT
