"""Integration-spike output invariants (plan 16.22): normalized findings leak no upstream names (D-014) and carry
no non-proven response text (D-015)."""
import json
import re
from pathlib import Path

import pytest

from hfsentinel.report.schema import Finding

ROOT = Path(__file__).resolve().parents[1]
SPIKE = ROOT / "docs" / "spike"
MANIFEST = json.loads((ROOT / "engines" / "versions.json").read_text(encoding="utf-8"))
UPSTREAM = sorted({t.lower() for name, spec in MANIFEST["engines"].items()
                   for t in (name, *re.split(r"[/_-]", spec["repo"])) if len(t) >= 5}
                  | {"pyrit", "deepeval", "litellm", "codeshield", "llamafirewall", "semgrep", "strong_reject"})
FILES = sorted(SPIKE.glob("*.findings.json"))
FORBIDDEN_KEYS = {"prompt", "response", "outputs", "messages", "transcript", "payload"}


def _keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys(v)


def test_spike_outputs_exist():
    assert len(FILES) >= 9  # 5 adapters on the common endpoint + 4 on the vuln target


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_no_upstream_names(path):
    text = path.read_text(encoding="utf-8").lower()
    assert [t for t in UPSTREAM if t in text] == []


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_only_proven_evidence_and_valid_findings(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == {"engine_result_summary", "errors", "findings"}
    assert not (set(_keys(data)) & FORBIDDEN_KEYS)
    for row in data["engine_result_summary"]:
        assert set(row) == {"catalog_id", "technique", "trials", "successes"}
    for f in data["findings"]:
        finding = Finding.model_validate(f)
        assert finding.successes > 0 and len(finding.evidence.redacted_excerpt) <= 200
    # every success-bearing technique produced exactly one finding; no finding without a success
    with_success = [r for r in data["engine_result_summary"] if r["successes"] > 0]
    assert len(with_success) == len(data["findings"])
