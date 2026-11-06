"""Fetch + verify the pinned Laya weights (plan 16.19, D-013). Operator step, needs network; the engine then runs
offline against the verified directory.

Downloads only the files pinned in config/laya_model.json from the pinned revision over HTTPS to the HF host, writing
each variant to its own subdir under $HFS_LAYA_DIR (default ~/.cache/hfsentinel/laya): <dir>/typed-decisions/ and
<dir>/multilingual/. Any file whose size or sha256 does not match its pin is refused (no unverified weights ever land).
The engine then serves one variant by mounting its subdir and setting HFS_LAYA_VARIANT.

    python -m hfsentinel.engines.laya_fetch [--dir DIR] [--variant NAME]   # default: all pinned variants
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "config" / "laya_model.json"
HOST = "huggingface.co"
MAX_BYTES = 1_200_000_000


class FetchError(RuntimeError):
    pass


def default_dir() -> Path:
    import os
    return Path(os.environ.get("HFS_LAYA_DIR") or Path.home() / ".cache" / "hfsentinel" / "laya")


def _fetch_variant(dest: Path, repo: str, rev: str, variant: str, files: dict) -> None:
    """Download + verify one variant's pinned files into <dest> (already the variant's own subdir)."""
    dest.mkdir(parents=True, exist_ok=True)
    for rel, spec in files.items():
        url = f"https://{HOST}/{repo}/resolve/{rev}/{variant}/{rel}"
        if urlparse(url).hostname != HOST:
            raise FetchError("refusing a non-Hugging-Face URL")
        out = dest / rel
        if out.is_file() and out.stat().st_size == spec["size"] \
                and hashlib.sha256(out.read_bytes()).hexdigest() == spec["sha256"]:
            print(f"ok    {variant}/{rel} (cached)")
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            with urllib.request.urlopen(url, timeout=180) as r:  # host checked above
                data = r.read(MAX_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise FetchError(f"{variant}/{rel}: download failed ({type(e).__name__})") from None
        if len(data) > MAX_BYTES or len(data) != spec["size"] \
                or hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise FetchError(f"{variant}/{rel}: content does not match its pinned sha256/size")
        tmp = out.with_suffix(out.suffix + ".partial")
        tmp.write_bytes(data)
        tmp.replace(out)
        print(f"ok    {variant}/{rel} ({len(data)} bytes)")


def fetch(dest: Path, variant: str | None = None) -> None:
    """Fetch every pinned variant (or just `variant`) into <dest>/<variant_name>/."""
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    repo, rev, variants = m["repo"], m["revision"], m["variants"]
    want = [variant] if variant else list(variants)
    for name in want:
        if name not in variants:
            raise FetchError(f"unknown variant: {name} (pinned: {', '.join(variants)})")
        spec = variants[name]
        _fetch_variant(dest / name, repo, rev, spec["variant"], spec["files"])
        print(f"laya {name} verified in {dest / name}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=None)
    ap.add_argument("--variant", default=None, help="fetch only this variant (default: all pinned variants)")
    a = ap.parse_args(argv)
    try:
        fetch(a.dir or default_dir(), a.variant)
    except FetchError as e:
        print(f"laya-fetch: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
