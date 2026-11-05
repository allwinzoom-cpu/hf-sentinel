"""Egress allow-list proxy for sandboxed tool/engine containers (plan 16.12).

HTTPS CONNECT only, to allow-listed hostnames on port 443. Denies IP literals, non-443 ports, plain-HTTP proxying,
and any hostname that resolves to a non-global address (private/loopback/link-local/metadata — blocks DNS rebinding).
Every decision is logged as one JSON line, so denied hosts expose telemetry or phone-home attempts.

    python -m hfsentinel.sandbox.egress_proxy --listen 0.0.0.0:3128 --allow router.huggingface.co,huggingface.co \
        --log /logs/egress.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path

MAX_HEADER_BYTES = 8192
CONNECT_TIMEOUT_S = 15
IDLE_TIMEOUT_S = 300


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def decide(host: str, port: int, allow: frozenset[str], ports: frozenset[int] = frozenset({443})) -> str | None:
    """Return a deny reason, or None if the request may proceed to DNS resolution."""
    if port not in ports:
        return "port-not-443"
    if is_ip_literal(host):
        return "ip-literal"
    if host.lower().rstrip(".") not in allow:
        return "host-not-allowlisted"
    return None


def first_global_addr(host: str, port: int) -> str | None:
    """Resolve and return the first address only if EVERY resolved address is globally routable."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [str(i[4][0]) for i in infos]
    if not addrs or any(not ipaddress.ip_address(a).is_global for a in addrs):
        return None
    return addrs[0]


class EgressProxy:
    def __init__(self, allow: frozenset[str], log_path: Path | None, resolver=first_global_addr,
                 ports: frozenset[int] = frozenset({443})) -> None:
        self.allow = allow
        self.ports = ports
        self.log_path = log_path
        self.resolver = resolver

    def log(self, **rec) -> None:
        line = json.dumps({"ts": round(time.time(), 3), **rec}, sort_keys=True)
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print(line, flush=True)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=CONNECT_TIMEOUT_S)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = request_line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            target = parts[1] if len(parts) > 1 else "?"
            self.log(decision="deny", reason="not-connect", method=parts[0] if parts else "?", target=target[:200])
            await self._reply(writer, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        host, _, port_s = parts[1].rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            host, port = parts[1], -1
        reason = decide(host, port, self.allow, self.ports)
        addr = None
        if reason is None:
            try:
                addr = await asyncio.get_running_loop().run_in_executor(None, self.resolver, host, port)
            except OSError:
                reason = "dns-failure"
            else:
                if addr is None:
                    reason = "resolves-to-non-global"
        if reason:
            self.log(decision="deny", reason=reason, host=host[:200], port=port)
            await self._reply(writer, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=CONNECT_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError):
            self.log(decision="error", reason="upstream-connect-failed", host=host, port=port)
            await self._reply(writer, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        self.log(decision="allow", host=host, port=port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, data: bytes) -> None:
        try:
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while chunk := await asyncio.wait_for(src.read(65536), timeout=IDLE_TIMEOUT_S):
                dst.write(chunk)
                await dst.drain()
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            dst.close()


async def serve(host: str, port: int, proxy: EgressProxy) -> asyncio.base_events.Server:
    return await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEADER_BYTES)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:3128")
    ap.add_argument("--allow", required=True, help="comma-separated exact hostnames")
    ap.add_argument("--log", type=Path)
    a = ap.parse_args()
    lhost, _, lport = a.listen.rpartition(":")
    allow = frozenset(h.strip().lower() for h in a.allow.split(",") if h.strip())
    proxy = EgressProxy(allow, a.log)

    async def run() -> None:
        srv = await serve(lhost, int(lport), proxy)
        print(json.dumps({"event": "listening", "listen": a.listen, "allow": sorted(allow)}), flush=True)
        async with srv:
            await srv.serve_forever()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
