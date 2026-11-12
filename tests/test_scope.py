"""Scope enforcement (plan 16.1): OpenSSH signature verification against real ssh-keygen vectors, scope schema and
validity window, per-kind matching, built-in sources, and the CLI's zero-network refusal of out-of-scope targets."""
import datetime as dt
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hfsentinel import cli, scope
from hfsentinel.scope import ScopeError, authorize, load_scope, parse_allowed_signers, verify_sshsig
from hfsentinel.targets.resolve import parse
from tests.conftest import ssh_pubkey_line, ssh_sign

FIX = Path(__file__).parent / "fixtures" / "scope"
MSG = (FIX / "scope.yaml").read_bytes()
SIGNERS = parse_allowed_signers((FIX / "allowed_signers").read_text())
TODAY = dt.date(2026, 11, 3)  # inside the fixture's 2026-11-01..2027-10-31 window
runner = CliRunner()


@pytest.fixture(autouse=True)
def _offline_secrets(monkeypatch, tmp_path):
    """Scope dry-run tests use no local secret source."""
    for name in ("HF_TOKEN", "hf_tok", "HF_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HFSENTINEL_ENV_FILE", str(tmp_path / "absent.env"))


def sig(name):
    return (FIX / name).read_text()


# ---- verification against real ssh-keygen output (OpenSSH 9.2) ----
@pytest.mark.parametrize("name", ["scope.yaml.sig", "sha256.sig"])
def test_real_ssh_keygen_signatures_verify(name):
    signer = verify_sshsig(MSG, sig(name), SIGNERS)
    assert signer.principals == "owner@example.com"
    assert signer.fingerprint == (FIX / "owner.fingerprint").read_text().strip()  # same as ssh-keygen -l


@pytest.mark.parametrize("name, match", [
    ("wrong-namespace.sig", "namespace"),
    ("untrusted.sig", "not in allowed_signers"),
    ("rsa.sig", "Ed25519"),
])
def test_real_ssh_keygen_negative_vectors(name, match):
    with pytest.raises(ScopeError, match=match):
        verify_sshsig(MSG, sig(name), SIGNERS)


def test_tampered_scope_fails():
    with pytest.raises(ScopeError, match="does not verify"):
        verify_sshsig(MSG.replace(b"TEST-001", b"TEST-002"), sig("scope.yaml.sig"), SIGNERS)
    with pytest.raises(ScopeError, match="does not verify"):
        verify_sshsig(MSG + b"\n", sig("scope.yaml.sig"), SIGNERS)


@pytest.mark.parametrize("armored", [
    "", "not a signature",
    "-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----",
    "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----",  # just the magic
])
def test_malformed_signatures(armored):
    with pytest.raises(ScopeError):
        verify_sshsig(MSG, armored, SIGNERS)


def test_trailing_bytes_rejected():
    import base64
    lines = sig("scope.yaml.sig").strip().splitlines()
    blob = base64.b64decode("".join(lines[1:-1])) + b"\x00"
    with pytest.raises(ScopeError, match="malformed"):
        verify_sshsig(MSG, "\n".join([lines[0], base64.b64encode(blob).decode(), lines[-1]]), SIGNERS)


def test_allowed_signers_options():
    file_only = parse_allowed_signers((FIX / "allowed_signers_file_only").read_text())
    with pytest.raises(ScopeError, match="namespaces"):
        verify_sshsig(MSG, sig("scope.yaml.sig"), file_only)
    assert parse_allowed_signers((FIX / "allowed_signers_rsa").read_text()) == []  # RSA keys are not usable
    key_line = (FIX / "allowed_signers").read_text().split(" ", 1)[1]
    assert parse_allowed_signers(f"ca@example.com cert-authority {key_line}") == []
    expired = parse_allowed_signers(f'owner@example.com valid-before="20260101" {key_line}')
    with pytest.raises(ScopeError, match="validity window"):
        verify_sshsig(MSG, sig("scope.yaml.sig"), expired)
    future = parse_allowed_signers(f'owner@example.com valid-after="20990101" {key_line}')
    with pytest.raises(ScopeError, match="validity window"):
        verify_sshsig(MSG, sig("scope.yaml.sig"), future)
    assert parse_allowed_signers("# comment\n\nbad line\n") == []


def test_signers_file_required(tmp_path, monkeypatch):
    monkeypatch.delenv(scope.SIGNERS_ENV, raising=False)
    monkeypatch.setattr(scope, "DEFAULT_SIGNERS", tmp_path / "missing")
    with pytest.raises(ScopeError, match="not found"):
        scope.load_allowed_signers()
    (tmp_path / "rsa_only").write_text((FIX / "allowed_signers_rsa").read_text())
    with pytest.raises(ScopeError, match="no usable"):
        scope.load_allowed_signers(tmp_path / "rsa_only")


def test_test_signer_matches_the_ssh_format(signed_scope):
    path, signers = signed_scope(["hf-provider://a/b@p"])
    verify_sshsig(path.read_bytes(), path.with_name("scope.yaml.sig").read_text(),
                  parse_allowed_signers(signers.read_text()))


# ---- scope file ----
def test_load_fixture_scope():
    s = load_scope(FIX / "scope.yaml", signers=SIGNERS, today=TODAY)
    assert s.source == "signed-file" and len(s.entries) == 4 and s.signer == "owner@example.com"
    assert s.authorization.reference == "TEST-001" and len(s.sha256) == 64


@pytest.mark.parametrize("today", [dt.date(2026, 10, 31), dt.date(2027, 11, 1)])
def test_window_enforced(today):
    with pytest.raises(ScopeError, match="not valid today"):
        load_scope(FIX / "scope.yaml", signers=SIGNERS, today=today)


def _doc(targets="  - uri: hf-provider://a/b@p\n", granted=None, expires=None, extra=""):
    t = dt.date.today()
    return ("version: 1\nauthorization:\n  reference: R\n  authorized_by: O\n  statement: S\n"
            f"  granted: {granted or t}\n  expires: {expires or t + dt.timedelta(days=5)}\n{extra}targets:\n{targets}")


@pytest.mark.parametrize("text, match", [
    (_doc(expires=dt.date.today() + dt.timedelta(days=400)), "window"),
    (_doc(expires=dt.date.today() - dt.timedelta(days=1)), "window|not valid"),
    (_doc(targets="  - uri: gopher://x\n"), "targets"),
    (_doc(targets="  - &a {uri: 'hf-provider://a/b'}\n  - *a\n"), "anchors"),
    (_doc(extra="extra_key: 1\n"), "extra_key"),
    (_doc().replace("version: 1", "version: 2"), "version"),
    (_doc(targets="  []\n"), "targets"),
])
def test_bad_scope_documents(signed_scope, text, match):
    path, signers = signed_scope([], text=text)
    with pytest.raises(ScopeError, match=match):
        load_scope(path, signers=parse_allowed_signers(signers.read_text()))


def test_signature_checked_before_yaml_is_parsed(signed_scope, monkeypatch):
    path, signers = signed_scope(["hf-provider://a/b@p"])
    path.write_text("!!python/object/apply:os.system ['id']\n")  # unsigned change
    monkeypatch.setattr(scope.yaml, "safe_load", lambda *_: pytest.fail("YAML parsed before signature check"))
    with pytest.raises(ScopeError, match="does not verify"):
        load_scope(path, signers=parse_allowed_signers(signers.read_text()))


def test_missing_signature_file(signed_scope):
    path, signers = signed_scope(["hf-provider://a/b@p"], sign=False)
    with pytest.raises(ScopeError, match="not found"):
        load_scope(path, signers=parse_allowed_signers(signers.read_text()))


# ---- matching ----
S = load_scope(FIX / "scope.yaml", signers=SIGNERS, today=TODAY)


@pytest.mark.parametrize("uri, resolved, ok", [
    ("hf-provider://Qwen/Qwen3-32B@deepinfra", True, True),
    ("hf-provider://Qwen/Qwen3-32B@groq", True, False),  # entry pins one provider
    ("hf-provider://Qwen/Qwen3-32B", False, True),  # pre-resolution: provider not chosen yet
    ("hf-provider://google/gemma-3-27b-it@novita", True, True),  # entry without provider = any provider
    ("hf-provider://google/gemma-3-27b-it", False, True),
    ("hf-provider://Qwen/Qwen3-8B@deepinfra", True, False),
    ("openai+https://api.example.com/v1#m", True, True),
    ("openai+https://api.example.com/v1#other", True, False),
    ("openai+https://api.example.org/v1#m", True, False),
    ("hf-space://owner/zoo", True, True),
    ("hf-space://owner/zoo@chat", True, True),  # a Space is authorized as a whole
    ("hf-space://owner/other", True, False),
    ("openai+http://127.0.0.1:9/v1#m", True, False),  # a scope file is authoritative: no built-ins
])
def test_matching(uri, resolved, ok):
    if ok:
        assert authorize(S, parse(uri), resolved=resolved).matched
    else:
        with pytest.raises(ScopeError):
            authorize(S, parse(uri), resolved=resolved)


def test_builtin_sources():
    a = authorize(None, parse("openai+http://127.0.0.1:9/v1#m"), resolved=True)
    assert a.source == "loopback" and a.authorized_by == "operator (own host)"
    a = authorize(None, parse("hf-provider://Qwen/Qwen3-32B@deepinfra"), resolved=True)
    assert a.source == "reference-endpoints (D-007)" and a.reference == "D-007"
    for uri in ("openai+https://api.example.com/v1#m", "hf-provider://Qwen/Qwen3-32B@nscale", "hf-space://a/b"):
        with pytest.raises(ScopeError):
            authorize(None, parse(uri), resolved=True)


def test_attestation_fields():
    a = authorize(S, parse("hf-provider://Qwen/Qwen3-32B@deepinfra"), resolved=True).to_dict()
    assert a["source"] == "signed-file" and a["reference"] == "TEST-001" and a["signer"] == "owner@example.com"
    assert a["key_fingerprint"].startswith("SHA256:") and a["scope_sha256"] == S.sha256
    assert a["expires"] == "2027-10-31" and a["matched"] == "hf-provider://Qwen/Qwen3-32B@deepinfra"


# ---- CLI: Done when — an out-of-scope target exits non-zero with zero network calls ----
@pytest.fixture
def no_net(monkeypatch, fake_hub):
    def deny(*_a, **_k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    return fake_hub


def run(*args):
    res = runner.invoke(cli.app, list(args))
    assert not isinstance(res.exception, AssertionError), "network call attempted"
    return res


@pytest.mark.parametrize("extra", [[], ["--dry-run", "--recon"]])
def test_out_of_scope_exits_nonzero_with_zero_network_calls(no_net, signed_scope, extra):
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    res = run("scan", "hf-provider://other/model", "--scope", str(path), "--signers", str(signers), *extra)
    assert res.exit_code == cli.EXIT_SCOPE and "not in the authorized scope" in res.output
    assert no_net == []  # not even the Hub was asked: refused before any network call


def test_resolved_target_is_rechecked(no_net, signed_scope):
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    res = run("scan", "hf-provider://Qwen/Qwen3-32B", "--scope", str(path), "--signers", str(signers))
    assert res.exit_code == cli.EXIT_SCOPE and "as resolved: Qwen/Qwen3-32B:nscale" in res.output  # auto-picked
    assert [p for p, _ in no_net] == ["/api/models/Qwen/Qwen3-32B?expand[]=inferenceProviderMapping"]  # Hub only


def test_in_scope_scan_attests_before_any_target_request(no_net, signed_scope, monkeypatch):
    monkeypatch.setattr(cli, "optional_token", lambda: None)
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    res = run("scan", "hf-provider://Qwen/Qwen3-32B@deepinfra", "--scope", str(path), "--signers", str(signers))
    assert "source signed-file" in res.output and "signed by owner@example.com SHA256:" in res.output
    assert res.exit_code == cli.EXIT_INPUT and "need an HF token" in res.output  # authorized; stops before traffic


def test_dry_run_with_scope_prints_attestation(no_net, signed_scope):
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    res = run("scan", "hf-provider://Qwen/Qwen3-32B@deepinfra", "--scope", str(path), "--signers", str(signers),
              "--dry-run")
    assert res.exit_code == cli.EXIT_OK and "scope     in scope · source signed-file · ref TEST-002" in res.output


def test_tampered_scope_refused_even_for_dry_run(no_net, signed_scope):
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    path.write_text(path.read_text().replace("TEST-002", "TEST-003"))
    res = run("scan", "hf-provider://Qwen/Qwen3-32B@deepinfra", "--scope", str(path), "--signers", str(signers),
              "--dry-run")
    assert res.exit_code == cli.EXIT_SCOPE and "does not verify" in res.output


def test_untrusted_signer_refused(no_net, signed_scope, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path, _ = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    other = tmp_path / "other_signers"
    other.write_text(ssh_pubkey_line(Ed25519PrivateKey.generate()))
    res = run("scan", "hf-provider://Qwen/Qwen3-32B@deepinfra", "--scope", str(path), "--signers", str(other))
    assert res.exit_code == cli.EXIT_SCOPE and "not in allowed_signers" in res.output


def test_signers_from_environment(no_net, signed_scope, monkeypatch):
    monkeypatch.setattr(cli, "optional_token", lambda: None)
    path, signers = signed_scope(["hf-provider://Qwen/Qwen3-32B@deepinfra"])
    monkeypatch.setenv(scope.SIGNERS_ENV, str(signers))
    res = run("scan", "hf-provider://Qwen/Qwen3-32B@deepinfra", "--scope", str(path))
    assert res.exit_code == cli.EXIT_INPUT and "source signed-file" in res.output


def test_ssh_sign_helper_is_not_shipped():
    assert not hasattr(scope, "ssh_sign") and callable(ssh_sign)  # production code verifies only
