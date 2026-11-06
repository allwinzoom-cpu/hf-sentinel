"""Track upstream engine releases (plan 679).

Compares the pinned engine versions in engines/versions.json against the latest published versions (PyPI for `pypi`
sources) and reports any that drifted, so a maintainer bump can re-run the coverage matrix. The scheduled workflow
.github/workflows/upstream.yml runs this and re-runs the matrix in CI.

    python engines/upstream.py --check     # print drift; exit 0 if all current, 20 if any engine has a newer release

Read-only and side-effect free: only HTTPS GET to PyPI's fixed host, package names validated before use (no SSRF), a
small response cap, no install and no code execution. `check()` takes an injected fetch so it is unit-tested offline.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from re import compile as _re
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "engines" / "versions.json"
PYPI_HOST = "pypi.org"
PKG_RE = _re(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")  # PyPI project name; anything else is refused before building a URL
MAX_BYTES = 4_000_000
DRIFT_EXIT = 20


class UpstreamError(RuntimeError):
    pass


def load_engines() -> dict:
    return json.loads(VERSIONS.read_text(encoding="utf-8"))["engines"]


def _fetch_json(url: str) -> dict:
    if urlparse(url).hostname != PYPI_HOST:
        raise UpstreamError("refusing a non-PyPI URL")
    try:
        with urllib.request.urlopen(url, timeout=30) as r:  # host checked above
            return json.loads(r.read(MAX_BYTES + 1))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise UpstreamError(f"fetch failed: {type(e).__name__}") from None


def latest_pypi(package: str, fetch: Callable[[str], dict]) -> str:
    if not PKG_RE.match(package):
        raise UpstreamError(f"invalid package name: {package!r}")
    data = fetch(f"https://{PYPI_HOST}/pypi/{package}/json")
    version = (data.get("info") or {}).get("version")
    if not isinstance(version, str) or not version:
        raise UpstreamError(f"no version for {package}")
    return version


def _release(v: str) -> tuple[int, ...]:
    """The numeric release segment of a version (e.g. '1.2.3rc1' -> (1, 2, 3)). Non-numeric suffixes are ignored, which
    is enough to decide 'a newer release exists'; ambiguous cases fall back to a plain inequality in `newer`."""
    out: list[int] = []
    for part in v.split("."):
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            break
        out.append(int(num))
    return tuple(out)


def newer(latest: str, pinned: str) -> bool:
    """True if `latest` is a strictly newer release than `pinned`. Equal strings are never newer; when the numeric
    release tuples tie but the strings differ (e.g. pre-release suffixes), treat it as drift to surface for review."""
    if latest == pinned:
        return False
    lr, pr = _release(latest), _release(pinned)
    if lr == pr:
        return True  # same release numbers, different string — surface it
    return lr > pr


def check(fetch: Callable[[str], dict] | None = None) -> list[dict]:
    """Return one row per pypi engine whose latest release differs from the pin: {alias, package, pinned, latest, bump}."""
    fetch = fetch or _fetch_json
    drift: list[dict] = []
    for name, e in load_engines().items():
        if e.get("source") != "pypi" or not e.get("package") or not e.get("version"):
            continue
        latest = latest_pypi(e["package"], fetch)
        if newer(latest, e["version"]):
            drift.append({"engine": name, "alias": e.get("alias", name), "package": e["package"],
                          "pinned": e["version"], "latest": latest, "bump": True})
    return drift


def main(argv: list[str]) -> int:
    if "--check" not in argv:
        print("usage: upstream.py --check", file=sys.stderr)
        return 2
    try:
        drift = check()
    except UpstreamError as e:
        print(f"upstream: {e}", file=sys.stderr)
        return 1
    if not drift:
        print("upstream: all pinned engines are current")
        return 0
    print(f"upstream: {len(drift)} engine(s) have a newer release — bump + re-run the coverage matrix:")
    for row in drift:
        print(f"  {row['engine']:<12} {row['package']:<16} {row['pinned']} -> {row['latest']}")
    return DRIFT_EXIT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
