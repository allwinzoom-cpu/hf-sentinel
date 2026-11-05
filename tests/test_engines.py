"""Engine pin manifest + lockfile invariants (plan 16.11, DECISIONS D-009/D-010)."""
import json
import re
from pathlib import Path

import pytest

ENGINES = Path(__file__).resolve().parents[1] / "engines"
MANIFEST = json.loads((ENGINES / "versions.json").read_text(encoding="utf-8"))
NAMES = sorted(MANIFEST["engines"])
# D-010: CPU-only. nvidia-riva-client (gRPC client used by garak) is not a GPU runtime and is allowed.
GPU_PKG = re.compile(r"^(nvidia-(?!riva-client)[\w-]+|triton|cupy[\w-]*|pytorch-triton[\w-]*|nccl[\w-]*)==", re.MULTILINE)


def _lock(name: str) -> str:
    return (ENGINES / name / "requirements.lock").read_text(encoding="utf-8")


def test_python_images_are_digest_pinned():
    for tag, ref in MANIFEST["python_images"].items():
        assert re.fullmatch(rf"python:{re.escape(tag)}-slim-bookworm@sha256:[0-9a-f]{{64}}", ref), tag


@pytest.mark.parametrize("name", NAMES)
def test_engine_entry_complete(name):
    spec = MANIFEST["engines"][name]
    assert spec["python"] in MANIFEST["python_images"]
    assert spec["source"] in ("pypi", "git") and isinstance(spec["smoke"], list) and spec["smoke"]
    assert re.fullmatch(r"[\w.-]+/[\w.-]+", spec["repo"])
    if spec["source"] == "git":
        assert re.fullmatch(r"[0-9a-f]{40}", spec["commit"]) and re.fullmatch(r"[0-9a-f]{64}", spec["sha256"])
        assert spec["kind"] in ("script", "package")
    else:
        pin = f"{spec['package']}=={spec['version']}"
        assert pin in (ENGINES / name / "requirements.in").read_text(encoding="utf-8").split()
        assert re.search(rf"^{re.escape(spec['package'])}=={re.escape(spec['version'])}\b", _lock(name), re.MULTILINE | re.IGNORECASE)


@pytest.mark.parametrize("name", [*NAMES, "tools"])
def test_lock_fully_hashed(name):
    lock = _lock(name)
    reqs = re.findall(r"^[A-Za-z0-9][^\s]*==\S+", lock, re.MULTILINE)
    assert reqs, "empty lock"
    blocks = re.split(r"\n(?=[A-Za-z0-9])", lock.strip())
    unhashed = [b.split()[0] for b in blocks if "--hash=sha256:" not in b]
    assert unhashed == []
    assert not re.search(r"^(-e |git\+|https?://)", lock, re.MULTILINE), "VCS/URL requirement escapes hash pinning"


@pytest.mark.parametrize("name", NAMES)
def test_lock_is_gpu_free(name):
    assert GPU_PKG.findall(_lock(name)) == []
    if MANIFEST["engines"][name].get("torch") == "cpu":
        assert re.search(r"^torch==[\d.]+\+cpu\b", _lock(name), re.MULTILINE), "torch not locked to CPU wheels"
    else:
        assert not re.search(r"^torch==", _lock(name), re.MULTILINE), "engine pulls torch but isn't marked torch: cpu"


@pytest.mark.parametrize("name", NAMES)
def test_source_build_allowlist_is_justified_and_locked(name):
    spec = MANIFEST["engines"][name]
    for pkg, reason in spec.get("sdist_allow", {}).items():
        assert len(reason) >= 10, f"{pkg}: sdist exception needs a reason"
        assert re.search(rf"^{re.escape(pkg)}==", _lock(name), re.MULTILINE | re.IGNORECASE), f"{pkg} not in lock"


@pytest.mark.parametrize("name", NAMES)
def test_platform_exceptions_documented(name):
    spec = MANIFEST["engines"][name]
    platforms = spec.get("platforms", ["linux/amd64", "linux/arm64"])
    assert "linux/amd64" in platforms, "amd64 is the production platform (D-009)"
    assert set(platforms) <= {"linux/amd64", "linux/arm64"}
    if len(platforms) < 2:
        assert len(spec.get("platform_note", "")) >= 20


def test_aliases_unique_and_neutral():
    """D-014: user-facing aliases must not reveal upstream tool or repo names."""
    aliases = [MANIFEST["engines"][n]["alias"] for n in NAMES]
    assert len(aliases) == len(set(aliases))
    upstream = {t.lower() for n in NAMES for t in (n, *MANIFEST["engines"][n]["repo"].replace("-", "/").split("/"))
                if len(t) >= 4}
    for a in aliases:
        assert re.fullmatch(r"[a-z]+(-[a-z]+)*", a)
        assert not any(u in a for u in upstream), a


def test_dataset_pins():
    ds = json.loads((ENGINES / "datasets.json").read_text(encoding="utf-8"))["datasets"]
    assert ds
    for name, spec in ds.items():
        assert re.fullmatch(r"[\w.-]+/[\w.-]+", spec["repo"]) and re.fullmatch(r"[0-9a-f]{40}", spec["revision"]), name
        for path, f in spec["files"].items():
            assert re.fullmatch(r"[0-9a-f]{64}", f["sha256"]) and f["rows"] > 0 and f["use"], path


def test_audit_waivers_reasoned_and_expiring():
    import datetime as dt
    waivers = json.loads((ENGINES / "audit-waivers.json").read_text(encoding="utf-8"))["waivers"]
    today = dt.date.today()
    for engine, items in waivers.items():
        assert engine in MANIFEST["engines"], engine
        for vid, w in items.items():
            assert re.fullmatch(r"(CVE|GHSA|PYSEC|MAL)-[\w-]+", vid)
            assert len(w["reason"]) >= 60, f"{vid}: waiver needs a concrete reachability reason"
            exp = dt.date.fromisoformat(w["expires"])
            assert today <= exp <= today + dt.timedelta(days=92), f"{vid}: expired or longer than 90 days"
            assert re.search(rf"^{re.escape(w['package'])}==", _lock(engine), re.MULTILINE | re.IGNORECASE)
