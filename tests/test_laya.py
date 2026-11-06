"""Laya System-1 two-variant pin + fetch + server variant selection (plan 16.19, task 616).

The multilingual checkpoint is pinned alongside the English `typed-decisions` one (non-Latin-script replies route to it;
the English checkpoint is confidently wrong on them per its card). These tests need no network and no model: they prove
the pins are well-formed and real (64-hex sha256, positive size, both variants complete), the fetch tool writes each
variant to its own subdir and refuses any file whose bytes do not match its pin, and the server selects the right
variant's file set. The actual offline load + triage direction is the container selftest (`server.py --selftest`)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

from hfsentinel.engines import laya_fetch

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config" / "laya_model.json").read_text(encoding="utf-8"))
EXPECTED_FILES = {"rl_agent_config.json", "encoder/config.json", "model.safetensors",
                  "tokenizer/tokenizer.json", "tokenizer/tokenizer_config.json"}


def _load_server():
    spec = importlib.util.spec_from_file_location("laya_server", ROOT / "engines" / "laya" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- pins ----
def test_both_variants_pinned_and_wellformed():
    assert CONFIG["default_variant"] == "typed-decisions"
    assert set(CONFIG["variants"]) == {"typed-decisions", "multilingual"}
    assert re.fullmatch(r"[0-9a-f]{40}", CONFIG["revision"])
    for name, v in CONFIG["variants"].items():
        assert v["variant"] == name
        assert set(v["files"]) == EXPECTED_FILES, name
        for rel, spec in v["files"].items():
            assert re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]), f"{name}/{rel}"
            assert isinstance(spec["size"], int) and spec["size"] > 0, f"{name}/{rel}"


def test_shared_code_is_pinned():
    assert set(CONFIG["code"]) == {"rl_agent_api.py", "rl_common.py"}
    for sha in CONFIG["code"].values():
        assert re.fullmatch(r"[0-9a-f]{64}", sha)


def test_variants_are_distinct_checkpoints():
    en = CONFIG["variants"]["typed-decisions"]["files"]["model.safetensors"]["sha256"]
    ml = CONFIG["variants"]["multilingual"]["files"]["model.safetensors"]["sha256"]
    assert en != ml  # a real second checkpoint, not a copy of the English one


# ---- fetch ----
def _fake_manifest(tmp_path: Path, body: bytes) -> Path:
    """A one-file, two-variant manifest whose single file is `body` (so the fetch can be driven offline)."""
    spec = {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
    m = {"repo": "convaiinnovations/laya", "revision": "0" * 40, "code": {},
         "default_variant": "typed-decisions",
         "variants": {"typed-decisions": {"variant": "typed-decisions", "files": {"rl_agent_config.json": spec}},
                      "multilingual": {"variant": "multilingual", "files": {"rl_agent_config.json": spec}}}}
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(m), encoding="utf-8")
    return p


class _Resp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, _n: int) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_writes_each_variant_to_its_own_subdir(tmp_path, monkeypatch):
    body = b'{"ok": true}'
    monkeypatch.setattr(laya_fetch, "MANIFEST", _fake_manifest(tmp_path, body))
    seen = []

    def fake_urlopen(url, timeout=0):
        seen.append(url)
        return _Resp(body)

    monkeypatch.setattr(laya_fetch.urllib.request, "urlopen", fake_urlopen)
    dest = tmp_path / "laya"
    laya_fetch.fetch(dest)
    assert (dest / "typed-decisions" / "rl_agent_config.json").read_bytes() == body
    assert (dest / "multilingual" / "rl_agent_config.json").read_bytes() == body
    assert any("/typed-decisions/" in u for u in seen) and any("/multilingual/" in u for u in seen)
    assert all(u.startswith("https://huggingface.co/") for u in seen)


def test_fetch_can_select_one_variant(tmp_path, monkeypatch):
    body = b'{"ok": true}'
    monkeypatch.setattr(laya_fetch, "MANIFEST", _fake_manifest(tmp_path, body))
    monkeypatch.setattr(laya_fetch.urllib.request, "urlopen", lambda url, timeout=0: _Resp(body))
    dest = tmp_path / "laya"
    laya_fetch.fetch(dest, "multilingual")
    assert (dest / "multilingual" / "rl_agent_config.json").is_file()
    assert not (dest / "typed-decisions").exists()


def test_fetch_refuses_bytes_that_do_not_match_the_pin(tmp_path, monkeypatch):
    monkeypatch.setattr(laya_fetch, "MANIFEST", _fake_manifest(tmp_path, b"the-pinned-body"))
    monkeypatch.setattr(laya_fetch.urllib.request, "urlopen", lambda url, timeout=0: _Resp(b"TAMPERED"))
    with pytest.raises(laya_fetch.FetchError, match="does not match"):
        laya_fetch.fetch(tmp_path / "laya")
    # nothing lands on a mismatch
    assert not (tmp_path / "laya" / "typed-decisions" / "rl_agent_config.json").exists()


def test_fetch_unknown_variant_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(laya_fetch, "MANIFEST", _fake_manifest(tmp_path, b"x"))
    with pytest.raises(laya_fetch.FetchError, match="unknown variant"):
        laya_fetch.fetch(tmp_path / "laya", "does-not-exist")


# ---- server variant selection ----
def test_server_selects_variant_file_set():
    srv = _load_server()
    en = srv.variant_files(CONFIG, "typed-decisions")
    ml = srv.variant_files(CONFIG, "multilingual")
    assert set(en) == set(ml) == EXPECTED_FILES
    assert en["model.safetensors"]["sha256"] != ml["model.safetensors"]["sha256"]
    # default resolves to typed-decisions
    assert srv.variant_files(CONFIG, None) == en
    with pytest.raises(srv.IntegrityError, match="unknown variant"):
        srv.variant_files(CONFIG, "nope")


def test_server_verify_dir_enforces_pins(tmp_path):
    srv = _load_server()
    body = b'{"rl": 1}'
    files = {"rl_agent_config.json": {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}}
    (tmp_path / "rl_agent_config.json").write_bytes(body)
    srv.verify_dir(tmp_path, files)  # matches -> ok
    (tmp_path / "rl_agent_config.json").write_bytes(b"tampered")
    with pytest.raises(srv.IntegrityError, match="integrity check failed"):
        srv.verify_dir(tmp_path, files)
