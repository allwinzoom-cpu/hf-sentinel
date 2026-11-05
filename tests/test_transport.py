"""Pooled transport (D-022): connections are reused, exactly the caller's headers are sent, redirects are returned
unfollowed, oversized bodies are capped and their connection discarded, and failures become TransportError."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hfsentinel.targets.openai_compat import OpenAICompatTarget
from hfsentinel.targets.transport import Transport, TransportError


@pytest.fixture
def server():
    seen = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keep-alive, like real endpoints

        def log_message(self, format, *args):
            pass

        def _reply(self, status, body=b"", headers=None):
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append({"port": self.client_address[1], "path": self.path, "headers": dict(self.headers),
                         "body": body})
            if self.path == "/redirect":
                return self._reply(302, headers={"Location": "/elsewhere"})
            if self.path == "/big":
                return self._reply(200, b"x" * 5000)
            if self.path == "/slow":
                time.sleep(1.5)
                return self._reply(200, b"late")
            if self.path == "/v1/chat/completions":
                data = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
                return self._reply(200, data.encode())
            return self._reply(200, b'{"ok": true}')

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def test_connections_are_reused(server):
    url, seen = server
    t = Transport()
    for _ in range(10):
        assert t.request("POST", url + "/ok", headers={"User-Agent": "u"}, body=b"{}", limit=1000).status == 200
    assert len({s["port"] for s in seen}) == 1  # one TCP connection for ten requests


def test_exactly_the_callers_headers(server):
    url, seen = server
    Transport().request("POST", url + "/ok", headers={"User-Agent": "Acme/1", "Content-Type": "application/json"},
                        body=b"{}", limit=1000)
    assert {k.lower(): v for k, v in seen[0]["headers"].items()} == {
        "host": url.split("//")[1], "user-agent": "Acme/1", "content-type": "application/json",
        "accept-encoding": "identity", "content-length": "2"}


def test_redirect_is_returned_not_followed(server):
    url, seen = server
    r = Transport().request("POST", url + "/redirect", headers={}, body=b"", limit=1000)
    assert r.status == 302 and r.headers["location"] == "/elsewhere" and len(seen) == 1


def test_oversized_body_is_capped_and_connection_discarded(server):
    url, seen = server
    t = Transport()
    r = t.request("POST", url + "/big", headers={}, body=b"", limit=100)
    assert len(r.body) == 101  # limit + 1: the caller sees the overflow
    t.request("POST", url + "/ok", headers={}, body=b"", limit=100)
    assert seen[0]["port"] != seen[1]["port"]  # the half-read connection was not reused


def test_timeout_and_refused_connection(server):
    url, _ = server
    with pytest.raises(TransportError):
        Transport().request("POST", url + "/slow", headers={}, body=b"", timeout=0.3, limit=100)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here now
    with pytest.raises(TransportError):
        Transport().request("POST", f"http://127.0.0.1:{port}/x", headers={}, body=b"", limit=100)


def test_adapter_reuses_the_shared_pool(server):
    url, seen = server
    target = OpenAICompatTarget(url + "/v1", "m")
    for _ in range(5):
        assert target.chat([{"role": "user", "content": "x"}]).text == "ok"
    assert len({s["port"] for s in seen}) == 1
