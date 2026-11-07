"""LSCAN-006 framework-version pins. Surfaces the OWASP LLM / OWASP Agentic editions and the MITRE ATLAS revision that
check IDs map to, for inclusion in every report, and asserts coverage is reported as partial-dynamic — never a
'Top 10 complete' claim. Pure + offline."""
from __future__ import annotations

import json
from pathlib import Path

FILE = Path(__file__).resolve().parent / "framework_versions.json"
REQUIRED = ("owasp_llm", "owasp_agentic", "mitre_atlas")


def load() -> dict:
    return json.loads(FILE.read_text(encoding="utf-8"))


def report_block(data: dict | None = None) -> dict:
    """The framework-version block a report embeds: pinned editions/revisions + the partial-coverage statement."""
    d = data or load()
    return {"frameworks": d["frameworks"], "coverage_claim": d["coverage_claim"],
            "untested_boundaries": d["untested_boundaries"]}


def check(data: dict | None = None) -> list[str]:
    d = data or load()
    bad: list[str] = []
    for fw in REQUIRED:
        meta = d["frameworks"].get(fw) or {}
        if not (meta.get("edition") or meta.get("revision")):
            bad.append(f"{fw}: missing pinned edition/revision")
        if not meta.get("source"):
            bad.append(f"{fw}: missing source")
    if d.get("coverage_claim") == "complete":  # never claim completeness from listing categories
        bad.append("coverage_claim must not be 'complete' (coverage is partial + dynamic)")
    if not d.get("untested_boundaries"):
        bad.append("missing untested_boundaries statement")
    return bad
