"""Pooled HTTP transport for the target adapters (D-022).

One process-wide urllib3 pool keeps TLS connections alive per host (measured: median request 164 ms → 99 ms against
the Hub). Guards match the stdlib client it replaces: redirects and retries off (the governor owns retrying), separate
connect/read timeouts, reads capped at `limit + 1` bytes with the connection discarded on overflow, identity encoding
(no decompression), and no headers beyond the caller's. Non-2xx responses are returned, never raised.
"""
from __future__ import annotations

from dataclasses import dataclass

import urllib3
from urllib3.exceptions import HTTPError as _U3Error

CONNECT_TIMEOUT_S = 15.0
POOL_HOSTS = 16
POOL_PER_HOST = 16


class TransportError(RuntimeError):
    """No usable HTTP response (connection, TLS, timeout or protocol failure)."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]  # lower-cased names
    body: bytes


class Transport:
    def __init__(self, *, maxsize: int = POOL_PER_HOST):
        self._pool = urllib3.PoolManager(num_pools=POOL_HOSTS, maxsize=maxsize, block=False, retries=False)

    def request(self, method: str, url: str, *, headers: dict[str, str], body: bytes | None = None,
                timeout: float = 60.0, limit: int) -> Response:
        try:
            resp = self._pool.request(method, url, body=body, headers={**headers, "Accept-Encoding": "identity"},
                                      redirect=False, retries=False, preload_content=False, decode_content=False,
                                      timeout=urllib3.Timeout(connect=min(timeout, CONNECT_TIMEOUT_S), read=timeout))
        except _U3Error as e:
            raise TransportError(type(e).__name__) from None
        try:
            data = resp.read(limit + 1, decode_content=False)
        except _U3Error as e:
            resp.close()
            raise TransportError(type(e).__name__) from None
        if len(data) > limit:
            resp.close()  # never return a half-read connection to the pool
        else:
            resp.release_conn()
        return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, data)


SHARED = Transport()
