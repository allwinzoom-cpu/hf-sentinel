"""Pinned seed and calibration datasets (plan Judge ensemble v1): download once, verify sha256 before parsing.

Sources live in `config/seed_datasets.json` (URL at a fixed commit/revision + sha256). Files are cached under
`HFS_SEEDS_DIR` (default ~/.cache/hfsentinel/seeds), never redistributed, and re-verified on every load.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from hfsentinel.targets.local_hf import _DOWNLOADER

MANIFEST = Path(__file__).resolve().parents[2] / "config" / "seed_datasets.json"
ALLOWED_HOSTS = ("raw.githubusercontent.com", "huggingface.co")  # plus HF's *.hf.co CDN via the downloader
MAX_BYTES = 20_000_000
MAX_FIELD = 20_000


class SeedError(RuntimeError):
    pass


@dataclass(frozen=True)
class Seed:
    goal: str
    category: str
    source: str
    index: int


def manifest() -> dict[str, dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["datasets"]


def cache_dir() -> Path:
    return Path(os.environ.get("HFS_SEEDS_DIR") or Path.home() / ".cache" / "hfsentinel" / "seeds")


def fetch(name: str, *, root: Path | None = None) -> bytes:
    """The dataset's bytes, downloaded if needed; raises SeedError unless they match the pinned sha256."""
    spec = manifest().get(name)
    if spec is None:
        raise SeedError(f"unknown seed set: {name}")
    url = spec["url"]
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in ALLOWED_HOSTS:
        raise SeedError("seed URL host is not allow-listed")
    path = (root or cache_dir()) / f"{name}.{spec['format']}"
    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == spec["sha256"]:
            return data
        path.unlink()  # stale or tampered cache: fetch again
    try:
        with _DOWNLOADER.open(urllib.request.Request(url, headers={"Accept": "*/*"}), timeout=60) as resp:
            data = resp.read(MAX_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SeedError(f"{name}: download failed ({type(e).__name__})") from None
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != spec["sha256"]:
        raise SeedError(f"{name}: content does not match its pinned sha256")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".partial")
    tmp.write_bytes(data)
    tmp.replace(path)
    return data


def rows(name: str, *, root: Path | None = None) -> list[dict]:
    """Parsed records of a verified dataset (CSV rows or JSON objects), fields bounded in size."""
    spec, data = manifest()[name], fetch(name, root=root)
    try:
        text = data.decode("utf-8-sig")
        records = list(csv.DictReader(io.StringIO(text))) if spec["format"] == "csv" else json.loads(text)
    except (UnicodeDecodeError, ValueError, csv.Error):
        raise SeedError(f"{name}: unparsable") from None
    if not isinstance(records, list) or len(records) != spec["rows"]:
        raise SeedError(f"{name}: unexpected record count")
    return [{str(k): str(v)[:MAX_FIELD] for k, v in r.items()} for r in records if isinstance(r, dict)]


def load(name: str, *, root: Path | None = None) -> list[Seed]:
    spec = manifest()[name]
    out = []
    for i, r in enumerate(rows(name, root=root)):
        goal = r.get(spec["goal_field"], "").strip()
        if goal:
            out.append(Seed(goal, r.get(spec["category_field"], "") if spec["category_field"] else "", name, i))
    return out
