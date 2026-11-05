"""Shared fixtures. `fake_hub` replays Hub API shapes captured live on 2026-11-02 (trimmed) so tests stay offline."""
import pytest

from hfsentinel.targets import hub


def _live(task="conversational"):
    return {"status": "live", "providerId": "x", "task": task, "isModelAuthor": False}


HUB_RECORDS = {
    "/api/models/Qwen/Qwen3-32B?expand[]=inferenceProviderMapping": {
        "_id": "680daa1b62e834e6fd9fdbdf", "id": "Qwen/Qwen3-32B",
        "inferenceProviderMapping": {"nscale": _live(), "featherless-ai": _live(), "deepinfra": _live(),
                                     "groq": {**_live(), "status": "error"}}},
    "/api/models/legacy/gpt2?expand[]=inferenceProviderMapping": {  # Hub answers with the canonical id
        "id": "openai-community/gpt2", "inferenceProviderMapping": {"hf-inference": _live()}},
    "/api/models/org/no-provider?expand[]=inferenceProviderMapping": {
        "id": "org/no-provider", "inferenceProviderMapping": {"some-provider": _live("text-to-image")}},
    "/api/spaces/gradio/hello_world": {
        "id": "gradio/hello_world", "subdomain": "gradio-hello-world", "host": "https://gradio-hello-world.hf.space",
        "sdk": "gradio", "private": False, "runtime": {"stage": "RUNNING"}},
    "/api/spaces/owner/zoo": {
        "id": "owner/zoo", "subdomain": "owner-zoo", "host": "https://owner-zoo.hf.space", "sdk": "docker",
        "private": True, "runtime": {"stage": "SLEEPING"}},
}


@pytest.fixture
def fake_hub(monkeypatch):
    """Replace the Hub transport; returns the list of (path, token) calls made."""
    calls = []

    def get_json(path, token):
        calls.append((path, token))
        if path not in HUB_RECORDS:
            raise hub.HubNotFound("not found or not accessible (private or gated repos need an HF token)")
        return HUB_RECORDS[path]

    monkeypatch.setattr(hub, "_get_json", get_json)
    return calls


# ---- OpenSSH-format signing for scope tests (test-only; production code only verifies) ----
def ssh_sign(message: bytes, private_key, namespace: str = "hfsentinel-scope", hash_alg: str = "sha512") -> str:
    import base64
    import hashlib
    import struct

    from cryptography.hazmat.primitives import serialization

    def s(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    pub = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_blob = s(b"ssh-ed25519") + s(pub)
    digest = hashlib.new(hash_alg, message).digest()
    signed = b"SSHSIG" + s(namespace.encode()) + s(b"") + s(hash_alg.encode()) + s(digest)
    sig_blob = s(b"ssh-ed25519") + s(private_key.sign(signed))
    blob = (b"SSHSIG" + struct.pack(">I", 1) + s(pub_blob) + s(namespace.encode()) + s(b"") + s(hash_alg.encode())
            + s(sig_blob))
    b64 = base64.b64encode(blob).decode()
    return "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70)) + \
        "\n-----END SSH SIGNATURE-----\n"


def ssh_pubkey_line(private_key, principal: str = "owner@example.com", options: str = "") -> str:
    import base64
    import struct

    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + raw
    return f"{principal} {options + ' ' if options else ''}ssh-ed25519 {base64.b64encode(blob).decode()}\n"


@pytest.fixture
def signed_scope(tmp_path):
    """Factory: write a scope file valid today for `uris`, sign it, and return (scope_path, signers_path)."""
    import datetime as dt

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    signers = tmp_path / "allowed_signers"
    signers.write_text(ssh_pubkey_line(key))

    def make(uris, *, text: str | None = None, sign: bool = True):
        today = dt.date.today()
        body = text if text is not None else (
            "version: 1\nauthorization:\n  reference: TEST-002\n  authorized_by: Test Owner\n"
            "  statement: Test scope.\n"
            f"  granted: {today - dt.timedelta(days=1)}\n  expires: {today + dt.timedelta(days=30)}\n"
            "targets:\n" + "".join(f"  - uri: {u}\n" for u in uris))
        path = tmp_path / "scope.yaml"
        path.write_text(body)
        if sign:
            (tmp_path / "scope.yaml.sig").write_text(ssh_sign(path.read_bytes(), key))
        return path, signers
    make.key = key
    return make
