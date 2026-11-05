"""Egress allow-list proxy (plan 16.12). Offline: upstream is a loopback echo server via an injected resolver."""
import asyncio
import json

import pytest

from hfsentinel.sandbox import egress_proxy as ep

ALLOW = frozenset({"router.huggingface.co"})


@pytest.mark.parametrize("host, port, reason", [
    ("router.huggingface.co", 443, None),
    ("ROUTER.huggingface.co.", 443, None),
    ("router.huggingface.co", 80, "port-not-443"),
    ("evil.example", 443, "host-not-allowlisted"),
    ("router.huggingface.co.evil.example", 443, "host-not-allowlisted"),
    ("169.254.169.254", 443, "ip-literal"),
    ("[::1]", 443, "ip-literal"),
])
def test_decide(host, port, reason):
    assert ep.decide(host, port, ALLOW) == reason


def test_first_global_addr_rejects_private(monkeypatch):
    def fake(host, port, type):
        return [(None, None, None, None, (a, port)) for a in {"pub": ["8.8.8.8"], "mixed": ["8.8.8.8", "10.0.0.5"],
                                                               "meta": ["169.254.169.254"]}[host]]
    monkeypatch.setattr(ep.socket, "getaddrinfo", fake)
    assert ep.first_global_addr("pub", 443) == "8.8.8.8"
    assert ep.first_global_addr("mixed", 443) is None  # any non-global answer fails closed (rebinding)
    assert ep.first_global_addr("meta", 443) is None


async def _roundtrip(proxy, request: bytes, payload: bytes = b"") -> bytes:
    srv = await ep.serve("127.0.0.1", 0, proxy)
    port = srv.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(request)
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    body = b""
    if payload and head.startswith(b"HTTP/1.1 200"):
        w.write(payload)
        await w.drain()
        body = await r.readexactly(len(payload))
    w.close()
    srv.close()
    await srv.wait_closed()
    return head + body


def test_proxy_tunnels_allowed_and_logs(tmp_path):
    async def go():
        async def echo(r, w):
            w.write(await r.read(5))
            await w.drain()
            w.close()
        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        up_port = upstream.sockets[0].getsockname()[1]
        log = tmp_path / "egress.jsonl"
        proxy = ep.EgressProxy(ALLOW, log, resolver=lambda h, p: "127.0.0.1", ports=frozenset({up_port}))
        out = await _roundtrip(proxy, f"CONNECT router.huggingface.co:{up_port} HTTP/1.1\r\n\r\n".encode(), b"hello")
        upstream.close()
        return out, [json.loads(x) for x in log.read_text().splitlines()]
    out, recs = asyncio.run(go())
    assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"hello")
    assert recs[-1]["decision"] == "allow" and recs[-1]["host"] == "router.huggingface.co"


@pytest.mark.parametrize("request_bytes, reason", [
    (b"CONNECT telemetry.example.com:443 HTTP/1.1\r\n\r\n", "host-not-allowlisted"),
    (b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n", "ip-literal"),
    (b"GET http://router.huggingface.co/ HTTP/1.1\r\nHost: x\r\n\r\n", "not-connect"),
])
def test_proxy_denies_and_logs(tmp_path, request_bytes, reason):
    log = tmp_path / "egress.jsonl"
    proxy = ep.EgressProxy(ALLOW, log, resolver=lambda h, p: pytest.fail("must not resolve denied hosts"))
    out = asyncio.run(_roundtrip(proxy, request_bytes))
    assert out.startswith(b"HTTP/1.1 403")
    rec = json.loads(log.read_text().splitlines()[-1])
    assert rec["decision"] == "deny" and rec["reason"] == reason


def test_proxy_denies_rebinding_host(tmp_path):
    log = tmp_path / "egress.jsonl"
    proxy = ep.EgressProxy(ALLOW, log, resolver=lambda h, p: None)
    out = asyncio.run(_roundtrip(proxy, b"CONNECT router.huggingface.co:443 HTTP/1.1\r\n\r\n"))
    assert out.startswith(b"HTTP/1.1 403")
    assert json.loads(log.read_text().splitlines()[-1])["reason"] == "resolves-to-non-global"
