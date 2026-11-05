"""Model placement + pinned local helper models (plan 16.14, D-011, D-013). Stdlib only: also imported by the local
model server image.

Placement: a model runs locally only if it is ungated, has ≤ LOCAL_MAX_PARAMS parameters (Hub `safetensors.total`)
and a text-generation/classification task; everything else is called on HF Inference Providers/Endpoints.
Local weights are pinned to a commit with per-file sha256 + size, fetched from an allow-list of file names (never
pickles or code), and re-verified as an exact file set before every load. Any mismatch fails closed.

    python -m hfsentinel.targets.local_hf pin <repo> <alias> chat|nli   # print a manifest entry (uses the Hub API)
    python -m hfsentinel.targets.local_hf fetch [alias ...]              # download + verify into HFS_MODELS_DIR
    python -m hfsentinel.targets.local_hf verify [alias ...]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

USAGE = "usage: python -m hfsentinel.targets.local_hf pin <repo> <alias> chat|nli | fetch [alias ...] | verify [alias ...]"
LOCAL_MAX_PARAMS = 500_000_000  # D-013: classifiers and instruct models ≤ 0.5B only
LOCAL_TASKS = {"text-generation": "chat", "text-classification": "nli", "zero-shot-classification": "nli"}
MANIFEST_PATH = Path(__file__).resolve().parents[2] / "config" / "local_models.json"
HUB = "https://huggingface.co"
ALLOWED_FILE = re.compile(r"^(?:(?:config|generation_config|tokenizer|tokenizer_config|special_tokens_map|added_tokens)"
                          r"\.json|vocab\.json|merges\.txt|model(?:-\d{5}-of-\d{5})?\.safetensors"
                          r"|model\.safetensors\.index\.json)$", re.ASCII)
ALIAS = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$", re.ASCII)
REPO = re.compile(r"^[A-Za-z0-9][\w.-]{0,95}/[A-Za-z0-9][\w.-]{0,95}$", re.ASCII)
COMMIT = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
MAX_FILE_BYTES = 2_000_000_000
MAX_SMALL_FILE_BYTES = 64_000_000  # tokenizer/config files hashed in memory while pinning
CHUNK = 1 << 20
DOWNLOAD_TIMEOUT_S = 60.0
MAX_REDIRECTS = 3


class IntegrityError(RuntimeError):
    """A local model's files do not match its pinned manifest entry. Never load it."""


class ManifestError(ValueError):
    pass


# ---- placement ----
@dataclass(frozen=True)
class Placement:
    local: bool
    reason: str


def placement(info: dict) -> Placement:
    """Decide where a model runs from its Hub record (`gated`, `safetensors.total`, `pipeline_tag`)."""
    if info.get("gated"):
        return Placement(False, "gated repo: call it through HF Inference Providers (D-011)")
    params = (info.get("safetensors") or {}).get("total")
    if not isinstance(params, int) or params <= 0:
        return Placement(False, "no safetensors parameter count: remote only")
    if params > LOCAL_MAX_PARAMS:
        return Placement(False, f"{params / 1e9:.2f}B params > {LOCAL_MAX_PARAMS / 1e9:.1f}B: remote (D-013)")
    if info.get("pipeline_tag") not in LOCAL_TASKS:
        return Placement(False, f"task {info.get('pipeline_tag')!r} not served locally")
    return Placement(True, f"{params / 1e6:.0f}M params, ungated: local CPU")


# ---- manifest ----
def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        models = data["models"]
    except (OSError, ValueError, KeyError, TypeError):
        raise ManifestError("local model manifest missing or unreadable") from None
    if not isinstance(models, dict):
        raise ManifestError("manifest `models` must be a mapping")
    for alias, e in models.items():
        validate_entry(alias, e)
    return models


def validate_entry(alias: str, e: object) -> None:
    keys = {"repo", "revision", "kind", "params", "license", "files"}
    if not ALIAS.match(alias) or not isinstance(e, dict) or set(e) != keys:
        raise ManifestError(f"{alias}: malformed entry")
    if not REPO.match(e["repo"]) or not COMMIT.match(e["revision"]) or e["kind"] not in ("chat", "nli"):
        raise ManifestError(f"{alias}: bad repo, revision or kind")
    if not isinstance(e["params"], int) or not 0 < e["params"] <= LOCAL_MAX_PARAMS:
        raise ManifestError(f"{alias}: params outside the local placement limit")
    files = e["files"]
    if not isinstance(files, dict) or "config.json" not in files or not any(f.endswith(".safetensors") for f in files):
        raise ManifestError(f"{alias}: needs config.json and safetensors weights")
    for name, f in files.items():
        if not ALLOWED_FILE.match(name):
            raise ManifestError(f"{alias}: file not allowed: {name[:80]}")
        if (not isinstance(f, dict) or set(f) != {"sha256", "size"} or not SHA256.match(str(f["sha256"]))
                or not isinstance(f["size"], int) or not 0 < f["size"] <= MAX_FILE_BYTES):
            raise ManifestError(f"{alias}: bad hash/size for {name}")


# ---- verification ----
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def verify_dir(model_dir: Path, entry: dict) -> None:
    """The directory must hold exactly the pinned files (regular files, no symlinks) with matching size + sha256."""
    model_dir = Path(model_dir)
    if model_dir.is_symlink() or not model_dir.is_dir():
        raise IntegrityError("model directory missing")
    present = {p.name: p for p in model_dir.iterdir()}
    expected = entry["files"]
    if set(present) != set(expected):
        extra, missing = sorted(set(present) - set(expected)), sorted(set(expected) - set(present))
        raise IntegrityError(f"file set differs from pin (extra: {extra[:5]}, missing: {missing[:5]})")
    for name, f in expected.items():
        p = present[name]
        if p.is_symlink() or not p.is_file():
            raise IntegrityError(f"{name}: not a regular file")
        if p.stat().st_size != f["size"] or _sha256(p) != f["sha256"]:
            raise IntegrityError(f"{name}: size/sha256 mismatch")


# ---- download ----
def _allowed_redirect(url: str) -> bool:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    return u.scheme == "https" and (host == "huggingface.co" or host.endswith(".hf.co")) and not u.username


class _HFRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to HF-operated https hosts (the Hub, its resolve cache and CDN)."""
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed_redirect(urljoin(req.full_url, newurl)):
            raise IntegrityError("download redirected to a non-HF host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_DOWNLOADER = urllib.request.build_opener(_HFRedirects)


def _download_file(url: str, dest: Path, want: dict) -> None:
    h, size = hashlib.sha256(), 0
    req = urllib.request.Request(url, headers={"Accept": "*/*"})  # no token: local models are ungated
    try:
        with _DOWNLOADER.open(req, timeout=DOWNLOAD_TIMEOUT_S) as resp, dest.open("wb") as out:
            while chunk := resp.read(CHUNK):
                size += len(chunk)
                if size > want["size"]:
                    raise IntegrityError(f"{dest.name}: larger than pinned size")
                h.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as e:
        raise IntegrityError(f"{dest.name}: download failed (HTTP {e.code})") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise IntegrityError(f"{dest.name}: download failed ({type(e).__name__})") from None
    if size != want["size"] or h.hexdigest() != want["sha256"]:
        raise IntegrityError(f"{dest.name}: size/sha256 mismatch")


def fetch(alias: str, entry: dict, root: Path, hub: str = HUB) -> Path:
    """Download one pinned model into root/alias (atomic: a fresh partial dir, renamed only after every hash
    matches). An existing directory that verifies is reused."""
    target = Path(root) / alias
    if target.exists():
        verify_dir(target, entry)
        return target
    partial = Path(root) / f".{alias}.partial"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)
    try:
        for name, want in entry["files"].items():
            _download_file(f"{hub}/{entry['repo']}/resolve/{entry['revision']}/{name}", partial / name, want)
        verify_dir(partial, entry)
        partial.rename(target)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return target


# ---- pinning (host tool; needs the Hub client) ----
def pin(repo: str, kind: str, token: str | None = None) -> dict:
    """Build a manifest entry from the Hub at the repo's current commit; refuses models that must stay remote."""
    from hfsentinel.targets import hub  # lazy: pydantic is not needed by the server image

    if not REPO.match(repo):
        raise ManifestError("invalid repo id")
    raw = hub.get_json(f"/api/models/{repo}?expand[]=safetensors&expand[]=gated&expand[]=sha"
                       f"&expand[]=pipeline_tag&expand[]=cardData", token)
    if not isinstance(raw, dict) or not COMMIT.match(str(raw.get("sha"))):
        raise ManifestError("unexpected Hub record")
    decision = placement(raw)
    if not decision.local:
        raise ManifestError(f"{repo} must stay remote: {decision.reason}")
    if LOCAL_TASKS[raw["pipeline_tag"]] != kind:
        raise ManifestError(f"{repo} is a {raw['pipeline_tag']} model, not {kind}")
    sha = raw["sha"]
    tree = hub.get_json(f"/api/models/{repo}/tree/{sha}", token)
    files = {}
    for f in tree if isinstance(tree, list) else []:
        name = f.get("path") if isinstance(f, dict) else None
        if f.get("type") != "file" or not isinstance(name, str) or not ALLOWED_FILE.match(name):
            continue
        lfs = f.get("lfs") or {}
        if lfs:
            files[name] = {"sha256": str(lfs.get("oid")), "size": int(lfs.get("size", f.get("size", 0)))}
        else:  # small git file: hash what the Hub serves at this commit
            with _DOWNLOADER.open(f"{HUB}/{repo}/resolve/{sha}/{name}", timeout=DOWNLOAD_TIMEOUT_S) as r:
                body = r.read(MAX_SMALL_FILE_BYTES + 1)
            if len(body) > MAX_SMALL_FILE_BYTES:
                raise ManifestError(f"{name}: unexpectedly large")
            files[name] = {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
    entry = {"repo": repo, "revision": sha, "kind": kind, "params": raw["safetensors"]["total"],
             "license": str((raw.get("cardData") or {}).get("license") or "unknown")[:40], "files": files}
    validate_entry("pinned", entry)
    return entry


def models_dir() -> Path:
    return Path(os.environ.get("HFS_MODELS_DIR") or Path.home() / ".cache" / "hfsentinel" / "models")


def main(argv: list[str]) -> int:
    if argv[:1] == ["pin"] and len(argv) == 4:
        entry = pin(argv[1], argv[3])
        print(json.dumps({argv[2]: entry}, indent=2))
        return 0
    if argv[:1] in (["fetch"], ["verify"]):
        manifest = load_manifest()
        aliases = argv[1:] or list(manifest)
        unknown = [a for a in aliases if a not in manifest]
        if unknown:
            print(f"unknown local models: {unknown}", file=sys.stderr)
            return 2
        failed = 0
        for alias in aliases:
            try:
                if argv[0] == "fetch":
                    fetch(alias, manifest[alias], models_dir())
                else:
                    verify_dir(models_dir() / alias, manifest[alias])
                print(f"[OK]   {alias} {manifest[alias]['repo']}@{manifest[alias]['revision'][:12]}")
            except IntegrityError as e:
                failed += 1
                print(f"[FAIL] {alias}: {e}", file=sys.stderr)
        return 1 if failed else 0
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
