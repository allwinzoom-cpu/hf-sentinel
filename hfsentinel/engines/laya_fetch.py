"""Fetch + verify the pinned Laya weights (plan 16.19, D-013). Operator step, needs network; the engine then runs
offline against the verified directory.

Downloads only the files pinned in config/laya_model.json from the pinned revision over HTTPS to the HF host, writes
each to $HFS_LAYA_DIR (default ~/.cache/hfsentinel/laya), and refuses any file whose size or sha256 does not match.

    python -m hfsentinel.engines.laya_fetch [--dir DIR]
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


def fetch(dest: Path) -> None:
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    repo, rev, variant = m["repo"], m["revision"], m["variant"]
    dest.mkdir(parents=True, exist_ok=True)
    for rel, spec in m["files"].items():
        url = f"https://{HOST}/{repo}/resolve/{rev}/{variant}/{rel}"
        if urlparse(url).hostname != HOST:
            raise FetchError("refusing a non-Hugging-Face URL")
        out = dest / rel
        if out.is_file() and out.stat().st_size == spec["size"] \
                and hashlib.sha256(out.read_bytes()).hexdigest() == spec["sha256"]:
            print(f"ok    {rel} (cached)")
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            with urllib.request.urlopen(url, timeout=180) as r:
                data = r.read(MAX_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise FetchError(f"{rel}: download failed ({type(e).__name__})") from None
        if len(data) > MAX_BYTES or len(data) != spec["size"] \
                or hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise FetchError(f"{rel}: content does not match its pinned sha256/size")
        tmp = out.with_suffix(out.suffix + ".partial")
        tmp.write_bytes(data)
        tmp.replace(out)
        print(f"ok    {rel} ({len(data)} bytes)")
    print(f"laya verified in {dest}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=None)
    a = ap.parse_args(argv)
    try:
        fetch(a.dir or default_dir())
    except FetchError as e:
        print(f"laya-fetch: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
