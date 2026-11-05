"""Hosted-mode SSRF guard (plan 16.8).

In a hosted Space a user supplies the target (and exfil-sink) URL, so before any request the host must resolve to a
**globally-routable** address — never private, loopback, link-local or cloud-metadata (169.254.169.254) ranges — over
**HTTPS**, and a redirect must be re-checked hop by hop. Everything fails closed. Resolving every address of a name (not
just the first) blocks DNS-rebinding.

This is the scanner-side guard, applied to user-supplied URLs only when `HFS_HOSTED` is set — local/operator runs use
loopback test targets and are not hosted, so they are not guarded here. The engine sandbox enforces the same non-global
rule separately via its egress proxy (`sandbox/egress_proxy.py`).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

HOSTED_ENV = "HFS_HOSTED"
ALLOWED_SCHEMES = frozenset({"https"})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


class SsrfError(ValueError):
    """A URL/host that fails the hosted-mode SSRF guard (fail-closed)."""


def hosted_mode() -> bool:
    return os.environ.get(HOSTED_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _resolve(host: str, port: int) -> list[str]:
    return [str(i[4][0]) for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def guard_host(host: str, *, port: int = 443, resolver: Callable[[str, int], list[str]] = _resolve) -> None:
    """Raise SsrfError unless `host` (an IP literal, or a name whose EVERY resolved address) is globally routable."""
    host = (host or "").strip("[]")
    if not host:
        raise SsrfError("empty host")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            addrs = resolver(host, port)
        except OSError:
            raise SsrfError(f"host does not resolve: {host}") from None
    if not addrs:
        raise SsrfError(f"host does not resolve: {host}")
    for ip in addrs:
        if not ipaddress.ip_address(ip).is_global:
            raise SsrfError(f"{host} -> {ip}: non-global address (private/loopback/link-local/metadata)")


def guard_url(url: str, *, resolver: Callable[[str, int], list[str]] = _resolve) -> None:
    """Fail closed unless `url` is https and its host resolves to only globally-routable addresses."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SsrfError(f"scheme not allowed: {parts.scheme or '(none)'} (https only)")
    if not parts.hostname:
        raise SsrfError("no host in URL")
    try:
        port = parts.port or 443
    except ValueError:
        raise SsrfError("invalid port") from None
    guard_host(parts.hostname, port=port, resolver=resolver)


def guard_hosted(target, sink_url: str | None = None, *, resolver: Callable[[str, int], list[str]] = _resolve) -> None:
    """Guard a resolved target's endpoint URL and any user-supplied sink URL (call only in hosted mode). Provider/Hub
    targets whose traffic goes to the HF router have no user-controlled base URL and are skipped."""
    base = getattr(target, "base_url", None)
    for u in (base, sink_url):
        if u:
            guard_url(u, resolver=resolver)


def guarded_get(url: str, transport, *, max_redirects: int = 5, timeout: float = 30.0,
                resolver: Callable[[str, int], list[str]] = _resolve):
    """GET `url`, re-checking the guard on the initial URL and on every redirect hop (a hop to a blocked host or a
    non-HTTPS/redirect loop fails closed). `transport` is the stdlib-style client used elsewhere."""
    seen = 0
    while True:
        guard_url(url, resolver=resolver)
        resp = transport.request("GET", url, redirect=False, timeout=timeout)
        if resp.status not in REDIRECT_STATUS:
            return resp
        location = resp.headers.get("location") or resp.headers.get("Location")
        if not location:
            return resp
        seen += 1
        if seen > max_redirects:
            raise SsrfError("too many redirects")
        url = location
