"""Hosted-mode SSRF guard (plan 16.8): reject private/loopback/link-local/metadata hosts, non-HTTPS schemes, and
redirects to them — fail closed. Done-when: 127.0.0.1, 10.x, 169.254.169.254, file:// and a redirect-to-private all fail."""
import pytest
from typer.testing import CliRunner

from hfsentinel import cli
from hfsentinel.sandbox import ssrf

GLOBAL = lambda host, port: ["8.8.8.8"]
BY_NAME = lambda host, port: (["10.0.0.1"] if "evil" in host else ["8.8.8.8"])


def test_guard_host_blocks_non_global_literals():
    for bad in ("127.0.0.1", "10.0.0.1", "192.168.1.5", "169.254.169.254", "::1", "0.0.0.0"):
        with pytest.raises(ssrf.SsrfError):
            ssrf.guard_host(bad)
    ssrf.guard_host("8.8.8.8")  # a global literal is allowed, no resolution needed


def test_guard_host_resolves_names_and_blocks_rebinding():
    ssrf.guard_host("good.example", resolver=GLOBAL)                   # resolves to a global address
    with pytest.raises(ssrf.SsrfError):
        ssrf.guard_host("evil.example", resolver=lambda h, p: ["10.0.0.1"])
    with pytest.raises(ssrf.SsrfError):                                # DNS rebinding: one global + one private → blocked
        ssrf.guard_host("rebind.example", resolver=lambda h, p: ["8.8.8.8", "169.254.169.254"])
    with pytest.raises(ssrf.SsrfError):
        ssrf.guard_host("nxdomain.example", resolver=lambda h, p: [])


def test_guard_url_requires_https_and_a_global_host():
    with pytest.raises(ssrf.SsrfError):
        ssrf.guard_url("file:///etc/passwd")                           # non-HTTP scheme
    with pytest.raises(ssrf.SsrfError):
        ssrf.guard_url("http://8.8.8.8/", resolver=GLOBAL)             # http, not https
    with pytest.raises(ssrf.SsrfError):
        ssrf.guard_url("https://169.254.169.254/latest/meta-data/")   # cloud metadata
    ssrf.guard_url("https://good.example/v1", resolver=GLOBAL)         # https + global → allowed


class _Resp:
    def __init__(self, status, headers=None):
        self.status, self.headers = status, headers or {}


class _Transport:
    def __init__(self, *resps):
        self.resps, self.calls = list(resps), []

    def request(self, method, url, *, redirect=False, timeout=30.0):
        self.calls.append(url)
        return self.resps.pop(0)


def test_guarded_get_rechecks_every_redirect_hop():
    ok = _Transport(_Resp(200))
    assert ssrf.guarded_get("https://good.example/", ok, resolver=GLOBAL).status == 200
    # a redirect to a private host fails closed on the hop
    redir = _Transport(_Resp(302, {"location": "https://evil.example/"}))
    with pytest.raises(ssrf.SsrfError):
        ssrf.guarded_get("https://good.example/", redir, resolver=BY_NAME)
    # a redirect to a non-HTTPS URL fails closed too
    downgrade = _Transport(_Resp(302, {"location": "http://good.example/"}))
    with pytest.raises(ssrf.SsrfError):
        ssrf.guarded_get("https://good.example/", downgrade, resolver=GLOBAL)


def test_hosted_mode_env(monkeypatch):
    monkeypatch.delenv(ssrf.HOSTED_ENV, raising=False)
    assert not ssrf.hosted_mode()
    monkeypatch.setenv(ssrf.HOSTED_ENV, "1")
    assert ssrf.hosted_mode()


def test_cli_scan_refuses_private_target_in_hosted_mode():
    # a loopback target self-authorizes, but the hosted SSRF guard refuses it before any traffic (existing loopback
    # scan tests run without HFS_HOSTED and are not guarded, so non-hosted behaviour is unchanged).
    res = CliRunner().invoke(cli.app, ["scan", "openai+http://127.0.0.1:9/v1#m", "--via", "direct"],
                             env={ssrf.HOSTED_ENV: "1"})
    assert res.exit_code == cli.EXIT_SCOPE and "SSRF" in res.output
