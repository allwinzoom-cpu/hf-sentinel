"""Target URI parser + `--via auto` (plan Phase 2): every scheme parses, resolves and yields a client (hf-job: deferred,
D-004); repo ids cannot traverse Hub API paths; Hub responses are validated, size-capped and never redirected."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hfsentinel.targets import hub, resolve
from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import HF_ROUTER
from hfsentinel.targets.resolve import TargetURIError, UnsupportedTarget, parse

EP = "abc123.us-east-1.aws.endpoints.huggingface.cloud"


# ---- parse (offline) ----
@pytest.mark.parametrize("uri, expect", [
    ("hf-provider://Qwen/Qwen3-32B", {"kind": "hf-provider", "model": "Qwen/Qwen3-32B", "provider": None}),
    ("hf-provider://Qwen/Qwen3-32B@deepinfra", {"kind": "hf-provider", "provider": "deepinfra", "base_url": HF_ROUTER}),
    (f"hf-endpoint://{EP}", {"kind": "hf-endpoint", "model": "tgi", "base_url": f"https://{EP}/v1"}),
    (f"hf-endpoint://https://{EP}/#my-model", {"kind": "hf-endpoint", "model": "my-model", "base_url": f"https://{EP}/v1"}),
    ("hf-space://gradio/hello_world", {"kind": "hf-space", "space": "gradio/hello_world", "model": None, "base_url": ""}),
    ("hf-space://owner/zoo#zoo-c1", {"kind": "hf-space", "model": "zoo-c1"}),
    ("hf-space://owner/zoo#a..b", {"kind": "hf-space", "model": "a..b"}),  # repo-id rules don't leak into #model
    ("hf-space://owner/zoo@chat", {"kind": "hf-space", "api": "chat", "model": None}),
    ("hf-job://org/model", {"kind": "hf-job", "model": "org/model", "flavor": None}),
    ("hf-job://org/model@a10g-small", {"kind": "hf-job", "flavor": "a10g-small"}),
    ("openai+https://api.example.com/v1#m-1", {"kind": "openai", "model": "m-1", "base_url": "https://api.example.com/v1"}),
])
def test_parse_each_scheme(uri, expect):
    t = parse(uri)
    for k, v in expect.items():
        assert getattr(t, k) == v, k


@pytest.mark.parametrize("uri", [
    "hf-provider://../..", "hf-provider://org/..", "hf-provider://../api", "hf-provider://org/a--b",
    "hf-provider://org/a..b", "hf-provider://-org/m", "hf-provider://org/m.", "hf-provider://org/" + "m" * 97,
    "hf-provider://org/m/extra", "hf-provider://org/m?x=1", "hf-provider://org/m%2F..",
    "hf-space://../x", "hf-space://o/s#bad model", "hf-space://o/s@/chat", "hf-space://o/s@a#m",
    "hf-space://o/s@../x", "hf-job://org/m@A10G", "hf-job://org/m@" + "a" * 40,
    "hf-endpoint://evil.example.com", f"hf-endpoint://{EP}.evil.com", f"hf-endpoint://http://{EP}",
    f"hf-endpoint://{EP}/v1/admin", f"hf-endpoint://user@{EP}", "openai+https://user:pw@h/v1#m",
    "openai+http://example.com/v1#m", "", "x" * 600,
])
def test_parse_rejects(uri):
    with pytest.raises(TargetURIError):
        parse(uri)


def test_repo_rule_accepts_real_ids():
    for rid in ("Qwen/Qwen3-32B", "meta-llama/Llama-3.3-70B-Instruct", "google/gemma-3-27b-it", "a/b", "o_1/m.v2_x"):
        assert parse(f"hf-provider://{rid}").model == rid


# ---- resolve (--via) ----
def test_auto_pins_first_live_chat_provider(fake_hub):
    t = resolve.resolve(parse("hf-provider://Qwen/Qwen3-32B"), via="auto", token="hf_x")
    assert t.provider == "nscale" and t.request_model == "Qwen/Qwen3-32B:nscale"
    assert any("also live: featherless-ai, deepinfra" in n for n in t.notes)
    assert fake_hub[0][1] == "hf_x"  # token goes to the Hub only


def test_auto_keeps_explicit_live_provider_and_refuses_error_status(fake_hub):
    t = resolve.resolve(parse("hf-provider://Qwen/Qwen3-32B@deepinfra"))
    assert t.provider == "deepinfra"
    with pytest.raises(TargetURIError, match="not live"):
        resolve.resolve(parse("hf-provider://Qwen/Qwen3-32B@groq"))


def test_auto_pins_canonical_id(fake_hub):
    t = resolve.resolve(parse("hf-provider://legacy/gpt2"))
    assert t.model == "openai-community/gpt2" and t.provider == "hf-inference"
    assert any("canonical id openai-community/gpt2" in n for n in t.notes)


def test_auto_without_live_chat_provider_falls_back_to_deferred_job(fake_hub):
    with pytest.raises(UnsupportedTarget, match="D-004"):
        resolve.resolve(parse("hf-provider://org/no-provider"))


def test_auto_resolves_space_host_and_stage(fake_hub):
    gradio = resolve.resolve(parse("hf-space://gradio/hello_world"))
    assert gradio.base_url == "https://gradio-hello-world.hf.space" and gradio.model is None
    zoo = resolve.resolve(parse("hf-space://owner/zoo#zoo-c1"))
    assert zoo.base_url == "https://owner-zoo.hf.space/v1"
    assert any("not running" in n for n in zoo.notes)


def test_direct_never_calls_hub(fake_hub):
    t = parse("hf-provider://Qwen/Qwen3-32B@deepinfra")
    assert resolve.resolve(t, via="direct") is t
    assert resolve.resolve(parse(f"hf-endpoint://{EP}"), via="direct").kind == "hf-endpoint"
    with pytest.raises(TargetURIError):
        resolve.resolve(parse("hf-provider://Qwen/Qwen3-32B"), via="direct")
    with pytest.raises(TargetURIError):
        resolve.resolve(parse("hf-space://owner/zoo#m"), via="direct")
    assert fake_hub == []


@pytest.mark.parametrize("via", ["auto", "direct"])
def test_job_is_deferred(fake_hub, via):
    with pytest.raises(UnsupportedTarget, match="D-004"):
        resolve.resolve(parse("hf-job://org/model@a10g-small"), via=via)
    assert fake_hub == []


def test_unknown_via():
    with pytest.raises(TargetURIError):
        resolve.resolve(parse("hf-provider://a/b@p"), via="sideways")


# ---- client: each resolvable scheme yields a callable adapter ----
def test_clients(fake_hub):
    p = resolve.client(resolve.resolve(parse("hf-provider://Qwen/Qwen3-32B")), "hf_x", max_requests=3)
    assert p.base_url == HF_ROUTER and p.model == "Qwen/Qwen3-32B:nscale" and p.api_key == "hf_x"
    with pytest.raises(TargetURIError):
        resolve.client(parse("hf-provider://a/b@p"), None, max_requests=1)
    e = resolve.client(parse(f"hf-endpoint://{EP}#m"), "hf_x", max_requests=3)
    assert e.base_url == f"https://{EP}/v1" and e.model == "m" and e.api_key == "hf_x"
    s = resolve.client(resolve.resolve(parse("hf-space://owner/zoo#zoo-c1")), None, max_requests=3)
    assert s.base_url == "https://owner-zoo.hf.space/v1" and s.api_key == ""
    o = resolve.client(parse("openai+https://api.example.com/v1#m"), "hf_x", max_requests=3)
    assert o.api_key == ""  # HF token never goes to third-party hosts
    g = resolve.client(resolve.resolve(parse("hf-space://gradio/hello_world@predict")), "hf_x", max_requests=4)
    assert isinstance(g, GradioSpaceTarget) and g.base_url == "https://gradio-hello-world.hf.space"
    assert g.api_name == "predict" and g.api_key == "hf_x"
    with pytest.raises(TargetURIError):
        resolve.client(parse("hf-space://owner/zoo#m"), None, max_requests=1)  # unresolved
    with pytest.raises(UnsupportedTarget):
        resolve.client(parse("hf-job://org/m"), "hf_x", max_requests=1)


# ---- Hub record validation (responses are adversarial) ----
@pytest.mark.parametrize("record", [
    {"id": "../../etc", "inferenceProviderMapping": {}},
    {"id": "a/b", "inferenceProviderMapping": [{"provider": "x", "status": "live"}]},
    {"id": "a/b", "inferenceProviderMapping": {"Bad Name!": {"status": "live", "providerId": "x", "task": "t"}}},
    {"id": "a/b", "inferenceProviderMapping": {"p": {"status": "live"}}},
    ["not", "an", "object"],
])
def test_model_record_validation(monkeypatch, record):
    monkeypatch.setattr(hub, "_get_json", lambda *_: record)
    with pytest.raises(hub.HubError):
        hub.model_info("a/b", None)


@pytest.mark.parametrize("record", [
    {"id": "a/b", "subdomain": "a-b", "host": "https://evil.example.com"},
    {"id": "a/b", "subdomain": "a-b", "host": "https://a-b.hf.space.evil.com"},
    {"id": "a/b", "subdomain": "A_B", "host": "https://A_B.hf.space"},
    {"id": "a/b", "subdomain": "a-b", "host": "https://a-b.hf.space", "runtime": {"stage": "\x1b[31mRUNNING"}},
])
def test_space_record_validation(monkeypatch, record):
    monkeypatch.setattr(hub, "_get_json", lambda *_: record)
    with pytest.raises(hub.HubError):
        hub.space_info("a/b", None)


def test_hub_rejects_invalid_ids_before_any_request(monkeypatch):
    def boom(*_a):
        raise AssertionError("request attempted")
    monkeypatch.setattr(hub, "_get_json", boom)
    for bad in ("../x", "a/..", "a/b/c"):
        with pytest.raises(ValueError):
            hub.model_info(bad, None)
        with pytest.raises(ValueError):
            hub.space_info(bad, None)


# ---- Hub transport against a loopback server ----
@pytest.fixture
def hub_server(monkeypatch):
    seen = []
    routes = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            status, headers, body = routes.get(self.path.split("?")[0], (404, {}, b"{}"))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(hub, "HUB", f"http://127.0.0.1:{srv.server_address[1]}")
    yield routes, seen
    srv.shutdown()


def test_transport_ok_and_token_header(hub_server):
    routes, seen = hub_server
    routes["/api/models/a/b"] = (200, {}, json.dumps({"id": "a/b", "inferenceProviderMapping": {}}).encode())
    assert hub.model_info("a/b", "hf_x").id == "a/b"
    assert seen == [("/api/models/a/b?expand[]=inferenceProviderMapping", "Bearer hf_x")]


def test_transport_401_is_not_found(hub_server):
    routes, _ = hub_server
    routes["/api/models/a/b"] = (401, {}, b'{"error":"Invalid username or password."}')
    with pytest.raises(hub.HubNotFound):
        hub.model_info("a/b", None)


def test_transport_never_follows_redirects(hub_server):
    routes, seen = hub_server
    routes["/api/models/a/b"] = (307, {"Location": "/api/models/evil/x"}, b"")
    routes["/api/models/evil/x"] = (200, {}, json.dumps({"id": "evil/x"}).encode())
    with pytest.raises(hub.HubError, match="redirected"):
        hub.model_info("a/b", None)
    assert [p for p, _ in seen] == ["/api/models/a/b?expand[]=inferenceProviderMapping"]


def test_transport_size_cap_and_bad_json(hub_server, monkeypatch):
    routes, _ = hub_server
    routes["/api/models/a/b"] = (200, {}, b"x" * 64)
    with pytest.raises(hub.HubError, match="unexpected"):
        hub.model_info("a/b", None)
    monkeypatch.setattr(hub, "MAX_HUB_BYTES", 16)
    with pytest.raises(hub.HubError, match="size"):
        hub.model_info("a/b", None)


def test_transport_5xx(hub_server):
    routes, _ = hub_server
    routes["/api/models/a/b"] = (503, {}, b"")
    with pytest.raises(hub.HubError, match="503") as e:
        hub.model_info("a/b", None)
    assert not isinstance(e.value, hub.HubNotFound)
