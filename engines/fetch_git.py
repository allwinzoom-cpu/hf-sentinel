"""Fetch a GitHub commit tarball, verify its sha256 BEFORE extracting, extract safely. Build-time only.

    python fetch_git.py <owner/repo> <commit40> <sha256> <dest_dir>
"""
from __future__ import annotations

import hashlib
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

MAX_BYTES = 50_000_000


def main(repo: str, commit: str, sha256: str, dest: str) -> int:
    if not (re.fullmatch(r"[\w.-]+/[\w.-]+", repo) and re.fullmatch(r"[0-9a-f]{40}", commit)
            and re.fullmatch(r"[0-9a-f]{64}", sha256)):
        print("invalid repo/commit/sha256", file=sys.stderr)
        return 2
    url = f"https://github.com/{repo}/archive/{commit}.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as resp:  # GitHub redirects to codeload over HTTPS
        if not resp.geturl().startswith("https://"):
            print("refusing non-HTTPS redirect", file=sys.stderr)
            return 3
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        print("archive too large", file=sys.stderr)
        return 3
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        print(f"sha256 mismatch for {repo}@{commit}: got {got}", file=sys.stderr)
        return 4
    tmp = Path("/tmp/src.tar.gz")
    tmp.write_bytes(data)
    out = Path(dest)
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tmp) as tf:
        prefix = f"{repo.split('/')[1]}-{commit}/"
        members = []
        for m in tf.getmembers():
            if m.name.rstrip("/") == prefix.rstrip("/"):
                continue  # the archive's root directory itself
            if not m.name.startswith(prefix) or m.issym() or m.islnk() or ".." in Path(m.name).parts:
                print(f"refusing unsafe archive member: {m.name}", file=sys.stderr)
                return 5
            m.name = m.name[len(prefix):]
            members.append(m)
        tf.extractall(out, members=members, filter="data")
    tmp.unlink()
    print(f"verified {repo}@{commit[:12]} sha256 OK -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
