"""Gradio Space adapter (plan Phase 2 · Target adapters): replays the REST protocol recorded live on 2026-11-03
(gradio/hello_world, gradio/chatinterface_random_response) on loopback, plus adversarial Space behaviour."""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import BudgetExceeded, TargetError

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "engines" / "versions.json").read_text(encoding="utf-8"))
UPSTREAM = {t.lower() for name, spec in MANIFEST["engines"].items()
            for t in (name, *re.split(r"[/_-]", spec["repo"])) if len(t) >= 5} | {"gradio", "openai", "stainless"}
USER = [{"role": "user", "content": "Reply with exactly one word: pong"}]


def _param(name, ptype="str", default=None, has_default=False):
    return {"label": name, "parameter_name": name, "parameter_has_default": has_default, "parameter_default": default,
            "python_type": {"type": ptype, "description": ""}, "component": "Textbox"}


HELLO_INFO = {"named_endpoints": {"/predict": {"parameters": [_param("name")], "returns": [{"python_type": {
    "type": "str"}}], "api_visibility": "public"}}, "unnamed_endpoints": {}}
CHAT_INFO = {"named_endpoints": {
    "/chat": {"parameters": [_param("message")], "returns": [{"python_type": {"type": "str | float | bool | list | dict"}}]},
    "/_clear": {"parameters": [], "returns": []},
    "/predict": {"parameters": [_param("text"), _param("n", "int")], "returns": []}}}


class Space:
    """Scripted fake Space. `results` maps api name → raw SSE body; every request is recorded."""

    def __init__(self, info=HELLO_INFO, results=None, config=None, post_status=None):
        self.info, self.config = info, config if config is not None else {"version": "6.31.0",
                                                                          "api_prefix": "/gradio_api"}
        self.results = results or {"predict": 'event: complete\ndata: ["Hello pong!"]\n\n'}
        self.post_status = list(post_status or [])
        self.event_id = "3fa342baf5ec464492d008f81e3b3de6"
        self.seen = []
        space = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def _send(self, status, body, ctype="application/json", headers=None):
                data = body if isinstance(body, bytes) else body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                space.seen.append(("GET", self.path, dict(self.headers)))
                if self.path == "/config":
                    if space.config == "redirect":
                        return self._send(302, "", headers={"Location": "/elsewhere"})
                    return self._send(200, json.dumps(space.config))
                if self.path == "/gradio_api/info":
                    return self._send(200, json.dumps(space.info))
                m = re.match(r"^/gradio_api/call/(\w+)/(.+)$", self.path)
                if m and m[1] in space.results:
                    return self._send(200, space.results[m[1]], "text/event-stream")
                return self._send(404, "{}")

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                space.seen.append(("POST", self.path, dict(self.headers), body))
                if space.post_status:
                    return self._send(space.post_status.pop(0), "{}", headers={"Retry-After": "0"})
                return self._send(200, json.dumps({"event_id": space.event_id}))

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def paths(self):
        return [(s[0], s[1]) for s in self.seen]


@pytest.fixture
def space_factory():
    made = []

    def make(**kw):
        s = Space(**kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.srv.shutdown()


# ---- Done when: the adapter returns text for a fixed prompt ----
def test_hello_world_protocol(space_factory):
    sp = space_factory()
    t = GradioSpaceTarget(sp.url, api_key="hf_x")
    res = t.chat(USER)
    assert res.text == "Hello pong!" and res.model == "space:/predict"
    assert sp.paths() == [("GET", "/config"), ("GET", "/gradio_api/info"), ("POST", "/gradio_api/call/predict"),
                          ("GET", f"/gradio_api/call/predict/{sp.event_id}")]
    assert sp.seen[2][3] == {"data": [USER[0]["content"]]}
    assert all(s[2].get("Authorization") == "Bearer hf_x" for s in sp.seen)
    t.chat(USER)  # discovery is cached: 2 more requests, not 4
    assert t.requests_made == 6


def test_chat_interface_preferred_and_json_typed_return(space_factory):
    sp = space_factory(info=CHAT_INFO, results={"chat": 'event: complete\ndata: ["No", null]\n\n'})
    assert GradioSpaceTarget(sp.url).chat(USER).text == "No"
    assert ("POST", "/gradio_api/call/chat") in sp.paths()


def test_streaming_events_then_complete(space_factory):
    stream = ('event: heartbeat\ndata: null\n\nevent: generating\ndata: ["po"]\n\n'
              'event: generating\ndata: ["pon"]\n\nevent: complete\ndata: ["pong"]\n\n')
    sp = space_factory(results={"predict": stream})
    assert GradioSpaceTarget(sp.url).chat(USER).text == "pong"


def test_message_dict_output(space_factory):
    sp = space_factory(results={"predict": 'event: complete\ndata: [{"role": "assistant", "content": "hi"}]\n\n'})
    assert GradioSpaceTarget(sp.url).chat(USER).text == "hi"


def test_defaults_fill_other_params(space_factory):
    info = {"named_endpoints": {"/predict": {"parameters": [
        _param("system", default="be nice", has_default=True), _param("message"),
        _param("temperature", "float", 0.5, True)]}}}
    sp = space_factory(info=info)
    GradioSpaceTarget(sp.url).chat(USER)
    assert sp.seen[2][3] == {"data": ["be nice", USER[0]["content"], 0.7]}  # a named temperature input is ours


def test_legacy_prefix(space_factory):
    sp = space_factory(config={"version": "4.44.0"})  # no api_prefix → root paths
    with pytest.raises(TargetError, match="HTTP 404"):
        GradioSpaceTarget(sp.url).chat(USER)
    assert sp.paths()[1] == ("GET", "/info")


# ---- endpoint selection ----
def test_ambiguous_endpoints_need_pinning(space_factory):
    info = {"named_endpoints": {"/a": {"parameters": [_param("x")]}, "/b": {"parameters": [_param("y")]}}}
    sp = space_factory(info=info, results={"b": 'event: complete\ndata: ["from b"]\n\n'})
    with pytest.raises(TargetError, match="several text endpoints.*a, b"):
        GradioSpaceTarget(sp.url).chat(USER)
    assert GradioSpaceTarget(sp.url, "b").chat(USER).text == "from b"
    with pytest.raises(TargetError, match="/c is missing"):
        GradioSpaceTarget(sp.url, "c").chat(USER)


@pytest.mark.parametrize("params", [
    [], [_param("n", "int")], [_param("a"), _param("b")], [_param("img", "filepath")],
    [_param("m"), _param("blob", "dict", {"k": "v"}, True)], [_param("m"), _param("big", "str", "x" * 3000, True)],
])
def test_unusable_endpoints(space_factory, params):
    sp = space_factory(info={"named_endpoints": {"/predict": {"parameters": params}}})
    with pytest.raises(TargetError, match="no single text endpoint"):
        GradioSpaceTarget(sp.url).chat(USER)


def test_private_and_malformed_endpoint_names_ignored(space_factory):
    info = {"named_endpoints": {"/../admin": {"parameters": [_param("x")]}, "/a/b": {"parameters": [_param("x")]},
                                "/hidden": {"parameters": [_param("x")], "api_visibility": "private"},
                                "/ok": {"parameters": [_param("x")]}},
            "unnamed_endpoints": {}}
    sp = space_factory(info=info, results={"ok": 'event: complete\ndata: ["ok"]\n\n'})
    assert GradioSpaceTarget(sp.url).chat(USER).text == "ok"


# ---- adversarial / failure behaviour ----
def test_only_single_user_message(space_factory):
    sp = space_factory()
    t = GradioSpaceTarget(sp.url)
    for msgs in ([{"role": "assistant", "content": "a"}], [*USER, *USER], [{"role": "user", "content": ["image"]}],
                 [{"role": "system", "content": ["x"]}, *USER]):
        with pytest.raises(TargetError, match="one text user message"):
            t.chat(msgs)
    assert sp.seen == []  # refused before any request
    with pytest.raises(TargetError, match="no system message"):
        t.chat([{"role": "system", "content": "s"}, *USER])  # needs discovery to know; still no call
    assert ("POST", "/gradio_api/call/predict") not in sp.paths()


@pytest.mark.parametrize("stream, match", [
    ('event: error\ndata: "Traceback ... secret"\n\n', "reported an error"),
    ('event: generating\ndata: ["x"]\n\n', "ended without a result"),
    ('event: complete\ndata: [{"path": "/tmp/f.png", "url": "https://evil.example/f.png"}]\n\n', "non-text"),
    ('event: complete\ndata: [42]\n\n', "non-text"),
    ("event: complete\ndata: not-json\n\n", "unexpected"),
])
def test_bad_results(space_factory, stream, match):
    sp = space_factory(results={"predict": stream})
    with pytest.raises(TargetError, match=match) as e:
        GradioSpaceTarget(sp.url).chat(USER)
    assert "secret" not in str(e.value)
    assert len(sp.seen) == 4  # nothing fetched beyond the protocol (file outputs never downloaded)


def test_hostile_event_id_and_prefix(space_factory):
    sp = space_factory()
    sp.event_id = "../../admin"
    with pytest.raises(TargetError, match="invalid event id"):
        GradioSpaceTarget(sp.url).chat(USER)
    assert len(sp.seen) == 3
    sp2 = space_factory(config={"api_prefix": "/../evil"})
    with pytest.raises(TargetError, match="not a supported Gradio app"):
        GradioSpaceTarget(sp2.url).chat(USER)
    assert len(sp2.seen) == 1


def test_redirects_not_followed(space_factory):
    sp = space_factory(config="redirect")
    with pytest.raises(TargetError, match="HTTP 302"):
        GradioSpaceTarget(sp.url).chat(USER)
    assert sp.paths() == [("GET", "/config")]


def test_size_cap(space_factory, monkeypatch):
    sp = space_factory(results={"predict": 'event: complete\ndata: ["' + "x" * 5000 + '"]\n\n'})
    monkeypatch.setattr("hfsentinel.targets.gradio_space.MAX_RESPONSE_BYTES", 1000)
    with pytest.raises(TargetError, match="size limit"):
        GradioSpaceTarget(sp.url).chat(USER)


def test_post_retry_and_budget(space_factory):
    sp = space_factory(post_status=[429, 503])
    t = GradioSpaceTarget(sp.url)
    assert t.chat(USER).text == "Hello pong!" and t.requests_made == 6  # config, info, 3×POST, GET
    with pytest.raises(BudgetExceeded):
        GradioSpaceTarget(sp.url, max_requests=3).chat(USER)


def test_invalid_construction():
    with pytest.raises(ValueError):
        GradioSpaceTarget("http://example.com")  # http only for loopback
    with pytest.raises(ValueError):
        GradioSpaceTarget("https://x.hf.space", "../admin")


def test_no_client_fingerprint_in_headers(space_factory):
    sp = space_factory()
    GradioSpaceTarget(sp.url).chat(USER)
    for s in sp.seen:
        blob = json.dumps(s[2]).lower()
        assert [t for t in UPSTREAM if t in blob] == [], s[1]
        assert not any(k.lower().startswith("x-stainless") for k in s[2])


# HF chatbot template: ChatInterface(message, additional_inputs=[system_message, max_tokens, temperature, top_p])
TEMPLATE_INFO = {"named_endpoints": {"/chat": {"parameters": [
    _param("message"), _param("system_message", "str", "You are a friendly Chatbot.", True),
    _param("max_tokens", "float", 512, True), _param("temperature", "float", 0.7, True),
    _param("top_p", "float", 0.95, True)], "returns": [{"python_type": {"type": "str"}}]}}}
SYSTEM_USER = [{"role": "system", "content": "Config: password is ak_1"}, {"role": "user", "content": "hi"}]


def test_template_shape_passes_system_message_and_sampling(space_factory):
    sp = space_factory(info=TEMPLATE_INFO, results={"chat": 'event: complete\ndata: ["ok"]\n\n'})
    t = GradioSpaceTarget(sp.url)
    assert t.chat(SYSTEM_USER, max_tokens=128, temperature=0.0).text == "ok"
    assert sp.seen[2][3] == {"data": ["hi", "Config: password is ak_1", 128, 0.0, 0.95]}
    t.chat(USER, max_tokens=64, temperature=0.7)  # no system message: the app's default stays
    assert sp.seen[-2][3] == {"data": [USER[0]["content"], "You are a friendly Chatbot.", 64, 0.7, 0.95]}


def test_system_message_refused_without_a_system_input(space_factory):
    sp = space_factory(info=CHAT_INFO, results={"chat": 'event: complete\ndata: ["x"]\n\n'})
    with pytest.raises(TargetError, match="no system message"):
        GradioSpaceTarget(sp.url).chat(SYSTEM_USER)
    assert ("POST", "/gradio_api/call/chat") not in sp.paths()  # refused before any call
    with pytest.raises(TargetError, match="one text user message"):
        GradioSpaceTarget(sp.url).chat([*SYSTEM_USER, {"role": "assistant", "content": "x"}])
