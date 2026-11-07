"""Private-network targeting policy (plan LSCAN-008, depends on LSCAN-004). Decides whether a private/LAN/container
target may be reached, with explicit CLI-vs-hosted rules: the **CLI** may reach an *explicitly scoped* private target
(operator's own bridge/LAN/tunnel); **hosted mode** may never reach a private network from a user-supplied URL. A secret
is never forwarded to a new origin. Pure + offline; authorization (scope) is assumed already checked by the caller before
any resolving/probing traffic — this only encodes the reachability decision.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def is_private_host(host: str) -> bool:
    """True for loopback / RFC-1918 / link-local / unique-local addresses, `*.local`/`*.internal`, and bare hostnames
    (container service names have no dot) — i.e. anything not a public routable host."""
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    except ValueError:
        pass
    # mDNS / private DNS / bare container service name (no dot) → private
    return h.endswith((".local", ".internal", ".lan")) or "." not in h


def private_target_allowed(url: str, *, hosted_mode: bool, in_scope: bool) -> bool:
    """May traffic go to `url`? Public hosts: yes. Private hosts: never in hosted mode; in CLI mode only when the target
    is explicitly in scope (the operator declared this private endpoint)."""
    host = urlsplit(url).hostname or ""
    if not is_private_host(host):
        return True
    if hosted_mode:
        return False  # hosted: a user-supplied URL can never reach a private network (SSRF)
    return in_scope  # CLI: an explicitly scoped private target is reachable


def forward_secret_allowed(from_url: str, to_url: str) -> bool:
    """A secret (token) may only be sent to the same origin it was scoped to — never forwarded to a new origin."""
    a, b = urlsplit(from_url), urlsplit(to_url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
