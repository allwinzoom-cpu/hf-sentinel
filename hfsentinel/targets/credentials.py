"""Per-target credential handles with origin binding (plan LSCAN-020, depends on LSCAN-008). A credential is bound to the
exact origin (scheme+host+port) it was scoped to, and is emitted as an auth header ONLY for a request to that same origin
— so an HF token never reaches a non-HF service and a target key is never forwarded to a different origin (no SSRF-style
secret exfiltration, no credential guessing, no URL-embedded secrets). `redact()` strips the secret from any text before
it reaches a log, error or report (D-015). Pure + offline."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


def origin_of(url: str) -> str:
    """The (scheme, host, port) origin of a URL as a comparable string; '' if it has no host."""
    p = urlsplit(url)
    if not p.hostname:
        return ""
    port = p.port or {"https": 443, "http": 80}.get(p.scheme, 0)
    return f"{p.scheme}://{p.hostname.lower()}:{port}"


@dataclass(frozen=True)
class Credential:
    """A secret bound to one origin. `value` is never shown in a repr (D-015)."""
    value: str = field(repr=False)
    origin: str                      # the origin this credential is authorized for
    header: str = "authorization"    # the header name it is sent under
    scheme: str = "Bearer"           # "" for a raw key (e.g. x-api-key), else a prefix like "Bearer"

    @classmethod
    def for_url(cls, value: str, url: str, *, header: str = "authorization", scheme: str = "Bearer") -> Credential:
        return cls(value=value, origin=origin_of(url), header=header, scheme=scheme)


def auth_for(credential: Credential, url: str) -> dict[str, str]:
    """The auth header for a request to `url`, but ONLY when `url`'s origin matches the credential's bound origin. A
    mismatched origin returns {} — the secret is never forwarded to a new origin (LSCAN-020/008)."""
    if not credential.value or origin_of(url) != credential.origin:
        return {}
    return {credential.header: f"{credential.scheme} {credential.value}".strip() if credential.scheme
            else credential.value}


def redact(text: str, *credentials: Credential) -> str:
    """Replace each credential's secret value in `text` with [REDACTED] before it reaches a log/error/report (D-015)."""
    out = text or ""
    for c in credentials:
        if c.value:
            out = out.replace(c.value, "[REDACTED]")
    return out
