"""Model placement + pinned local helper models (plan 16.14): placement from Hub metadata (records captured live
2026-11-03), strict manifest, exact-file-set verification, and a fail-closed downloader."""
import copy
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hfsentinel.targets import hub, local_hf
from hfsentinel.targets.local_hf import IntegrityError, ManifestError, placement, verify_dir

ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "engines" / "localmodel" / "server.py").read_text(encoding="utf-8")

QWEN_05B = {"gated": False, "pipeline_tag": "text-generation", "safetensors": {"total": 494032768}}
NLI = {"gated": False, "pipeline_tag": "zero-shot-classification", "safetensors": {"total": 184424963}}


# ---- placement ----
@pytest.mark.parametrize("info, local, why", [
    (QWEN_05B, True, "494M"),
    (NLI, True, "184M"),
    ({**QWEN_05B, "safetensors": {"total": 32762123264}}, False, "32.76B"),  # Qwen/Qwen3-32B
    ({**QWEN_05B, "safetensors": {"total": 500_000_001}}, False, "> 0.5B"),
    ({"gated": "manual", "pipeline_tag": "text-classification", "safetensors": {"total": 278810882}}, False, "gated"),
    ({**QWEN_05B, "safetensors": None}, False, "no safetensors"),
    ({**QWEN_05B, "safetensors": {"total": "494032768"}}, False, "no safetensors"),
    ({**QWEN_05B, "pipeline_tag": "text-to-image"}, False, "not served locally"),
])
def test_placement(info, local, why):
    p = placement(info)
    assert p.local is local and why in p.reason


# ---- manifest ----
def test_shipped_manifest_is_valid_and_local_only():
    models = local_hf.load_manifest()
    assert set(models) == {"tiny-instruct", "nli-base"}
    assert {m["kind"] for m in models.values()} == {"chat", "nli"}
    for m in models.values():
        assert m["params"] <= local_hf.LOCAL_MAX_PARAMS
        assert not any(n.endswith((".bin", ".pt", ".pkl", ".py", ".model")) for n in m["files"])


GOOD = local_hf.load_manifest()["nli-base"]


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(revision="main"),
    lambda e: e.update(revision="6f5cf0a2b59c"),
    lambda e: e.update(kind="judge"),
    lambda e: e.update(params=600_000_000),
    lambda e: e.update(repo="../x"),
    lambda e: e.update(extra=1),
    lambda e: e["files"].update({"pytorch_model.bin": {"sha256": "a" * 64, "size": 1}}),
    lambda e: e["files"].update({"modeling_evil.py": {"sha256": "a" * 64, "size": 1}}),
    lambda e: e["files"].update({"../config.json": {"sha256": "a" * 64, "size": 1}}),
    lambda e: e["files"]["config.json"].update(sha256="xyz"),
    lambda e: e["files"]["config.json"].update(size=0),
    lambda e: e["files"].pop("model.safetensors"),
])
def test_manifest_rejects(mutate):
    e = copy.deepcopy(GOOD)
    mutate(e)
    with pytest.raises(ManifestError):
        local_hf.validate_entry("nli-base", e)


def test_alias_rules():
    with pytest.raises(ManifestError):
        local_hf.validate_entry("Qwen-0.5b", GOOD)


# ---- verification ----
def make_model(tmp_path, files=None):
    files = files or {"config.json": b'{"a": 1}', "model.safetensors": b"\x00weights"}
    d = tmp_path / "m"
    d.mkdir()
    entry = {"repo": "o/m", "revision": "a" * 40, "kind": "nli", "params": 1, "license": "mit", "files": {}}
    for name, body in files.items():
        (d / name).write_bytes(body)
        entry["files"][name] = {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
    local_hf.validate_entry("m", entry)
    return d, entry


def test_verify_ok(tmp_path):
    d, entry = make_model(tmp_path)
    verify_dir(d, entry)


def test_verify_fails_closed(tmp_path):
    d, entry = make_model(tmp_path)
    (d / "config.json").write_bytes(b'{"a": 2}')  # same size, different bytes
    with pytest.raises(IntegrityError, match="config.json: size/sha256 mismatch"):
        verify_dir(d, entry)


@pytest.mark.parametrize("change, match", [
    (lambda d: (d / "pytorch_model.bin").write_bytes(b"pickle"), "extra"),
    (lambda d: (d / "config.json").unlink(), "missing"),
    (lambda d: ((d / "config.json").unlink(), (d / "config.json").symlink_to(d / "model.safetensors")), "regular"),
    (lambda d: (d / "model.safetensors").write_bytes(b"\x00weights!"), "mismatch"),
])
def test_verify_rejects(tmp_path, change, match):
    d, entry = make_model(tmp_path)
    change(d)
    with pytest.raises(IntegrityError, match=match):
        verify_dir(d, entry)


def test_verify_missing_dir_and_symlinked_dir(tmp_path):
    d, entry = make_model(tmp_path)
    with pytest.raises(IntegrityError):
        verify_dir(tmp_path / "nope", entry)
    (tmp_path / "link").symlink_to(d)
    with pytest.raises(IntegrityError):
        verify_dir(tmp_path / "link", entry)


# ---- download ----
@pytest.mark.parametrize("url, ok", [
    ("https://huggingface.co/api/resolve-cache/models/o/m/abc/config.json", True),
    ("https://us.aws.cdn.hf.co/xet-bridge-us/x/y", True),
    ("http://us.aws.cdn.hf.co/x", False),
    ("https://evil.example.com/x", False),
    ("https://huggingface.co.evil.com/x", False),
    ("https://evilhf.co/x", False),
    ("https://user@us.aws.cdn.hf.co/x", False),
    ("file:///etc/passwd", False),
])
def test_redirect_allow_list(url, ok):
    assert local_hf._allowed_redirect(url) is ok


@pytest.fixture
def fake_hub_files():
    """Loopback 'Hub' serving /{repo}/resolve/{rev}/{file}; `bodies` maps file name → bytes."""
    bodies, seen = {}, []

    class H(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            m = re.match(r"^/o/m/resolve/a{40}/(.+)$", self.path)
            if m and m[1] == "redirect.json":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()
                return
            body = bodies.get(m[1]) if m else None
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            self.wfile.write(body or b"")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", bodies, seen
    srv.shutdown()


def _entry_for(bodies):
    return {"repo": "o/m", "revision": "a" * 40, "kind": "nli", "params": 1, "license": "mit",
            "files": {n: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)} for n, b in bodies.items()}}


def test_fetch_ok_then_reuse(tmp_path, fake_hub_files):
    url, bodies, seen = fake_hub_files
    bodies.update({"config.json": b"{}", "model.safetensors": b"w" * 3000})
    entry = _entry_for(bodies)
    out = local_hf.fetch("m", entry, tmp_path, hub=url)
    verify_dir(out, entry)
    assert all(auth is None for _, auth in seen)  # no token is ever sent
    n = len(seen)
    local_hf.fetch("m", entry, tmp_path, hub=url)  # verified existing dir is reused
    assert len(seen) == n


@pytest.mark.parametrize("tamper", ["bytes", "longer", "missing"])
def test_fetch_mismatch_fails_closed(tmp_path, fake_hub_files, tamper):
    url, bodies, _ = fake_hub_files
    bodies.update({"config.json": b"{}", "model.safetensors": b"w" * 3000})
    entry = _entry_for(bodies)
    if tamper == "bytes":
        bodies["model.safetensors"] = b"x" * 3000
    elif tamper == "longer":
        bodies["model.safetensors"] = b"w" * 4000
    else:
        del bodies["model.safetensors"]
    with pytest.raises(IntegrityError):
        local_hf.fetch("m", entry, tmp_path, hub=url)
    assert list(tmp_path.iterdir()) == []  # partial download removed, nothing left to load


def test_fetch_refuses_non_hf_redirect(tmp_path, fake_hub_files):
    url, _, _ = fake_hub_files
    with pytest.raises(IntegrityError, match="non-HF host"):
        local_hf._download_file(f"{url}/o/m/resolve/{'a' * 40}/redirect.json", tmp_path / "f",
                                {"size": 2, "sha256": "0" * 64})


def test_existing_tampered_dir_is_not_reused(tmp_path, fake_hub_files):
    url, bodies, _ = fake_hub_files
    bodies.update({"config.json": b"{}", "model.safetensors": b"w"})
    entry = _entry_for(bodies)
    local_hf.fetch("m", entry, tmp_path, hub=url)
    (tmp_path / "m" / "model.safetensors").write_bytes(b"x")
    with pytest.raises(IntegrityError):
        local_hf.fetch("m", entry, tmp_path, hub=url)


# ---- pinning refuses models that must stay remote ----
def test_pin_refuses_remote_models(monkeypatch):
    record = {"sha": "9" * 40, "gated": False, "pipeline_tag": "text-generation",
              "safetensors": {"total": 32762123264}}
    monkeypatch.setattr(hub, "get_json", lambda *_: record)
    with pytest.raises(ManifestError, match="must stay remote"):
        local_hf.pin("Qwen/Qwen3-32B", "chat")
    with pytest.raises(ManifestError, match="invalid repo"):
        local_hf.pin("../api", "chat")


def test_pin_wrong_kind(monkeypatch):
    monkeypatch.setattr(hub, "get_json", lambda *_: {"sha": "9" * 40, **NLI})
    with pytest.raises(ManifestError, match="not chat"):
        local_hf.pin("o/nli", "chat")


# ---- server loads safely (static check: torch is not installed in the core test image) ----
def test_server_loader_flags():
    calls = re.findall(r"from_pretrained\((.*?)\)", SERVER, re.DOTALL)
    assert len(calls) == 4
    for c in calls:
        assert "local_files_only=True" in c and "trust_remote_code=False" in c
    model_calls = [c for c in calls if "use_safetensors" in c]
    assert len(model_calls) == 2
    assert "trust_remote_code=True" not in SERVER
    assert SERVER.index("verify_dir(models_dir / alias") < SERVER.index("(ChatModel if manifest")
    assert json.loads((ROOT / "config" / "local_models.json").read_text())["models"]
