"""Catalog v0 schema test (Phase 0: Freeze catalog v0)."""
import json
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from hfsentinel.attacks.catalog import CATALOG_PATH, Catalog, load_catalog

PLAN = Path(__file__).resolve().parents[1] / "hf-llm-security-scanner-project-plan.md"


def _expand(text: str) -> set[str]:
    """Expand IDs like 'A1–A3' / 'D1–D7' and singles like 'B21' from plan prose."""
    out: set[str] = set()
    for m in re.finditer(r"([ABCDEH])(\d{1,2})(?:[–-]\1?(\d{1,2}))?", text):
        lo, hi = int(m.group(2)), int(m.group(3) or m.group(2))
        out |= {f"{m.group(1)}{n}" for n in range(lo, hi + 1)}
    return out


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog()


@pytest.fixture(scope="module")
def plan() -> str:
    return PLAN.read_text(encoding="utf-8")


def test_every_row_validates_and_ids_unique(catalog):
    ids = [a.id for a in catalog.attacks]
    assert len(ids) == len(set(ids))


def test_ids_match_plan_section_4(catalog, plan):
    sec4 = plan[plan.index("## 4."):plan.index("### 4.7")]
    plan_ids = set(re.findall(r"^\|\s*([ABCDEH]\d{1,2})\s*\|", sec4, re.MULTILINE))
    assert set(catalog.by_id()) == plan_ids


def test_status_matches_plan_gate(catalog, plan):
    gate = plan[plan.index("**Current classification"):plan.index("A Candidate becomes Ready")]
    lines = {k: ln for ln in gate.splitlines() for k in ("Ready", "Conditional", "Candidate") if f"**{k}" in ln}
    ready = _expand(lines["Ready"].split("(")[0])
    # Conditional line: strip bracketed preconditions before expanding.
    conditional = _expand(re.sub(r"\[[^\]]*\]", "", lines["Conditional"]))
    candidate = _expand(lines["Candidate"])
    expected = {**{i: "ready" for i in ready}, **{i: "conditional" for i in conditional},
                **{i: "candidate" for i in candidate}}
    actual = {a.id: a.status for a in catalog.attacks}
    expected.pop("E2", None)  # historical catalog readiness; the scope override below excludes E2 from scoring
    filtered = {key: status for key, status in actual.items() if key in expected}
    assert filtered == expected


def test_scope_excluded_e_ids_are_deferred_and_never_planned():
    # Scope override: insecure-output (E1), static-codegen (E2), unbounded-generation (E3) and recursive-tool-loop (E4)
    # are out of the model-compromise/jailbreak/leak/harmful-content scope. They are recorded deferred with a "scope
    # override" reason, and the planner holds them n/a with zero requests (never planned or run). E5 stays in scope.
    caps = json.loads((Path(__file__).resolve().parents[1] / "engines" / "capabilities.json").read_text())
    from hfsentinel.engines.planner import SCOPE_EXCLUDED, build_plan
    from hfsentinel.targets.resolve import parse
    assert SCOPE_EXCLUDED == {"E1", "E2", "E3", "E4"} and "E5" not in SCOPE_EXCLUDED
    for cid in SCOPE_EXCLUDED:
        assert caps["status"][cid] == "deferred"
        assert caps["deferred_reasons"][cid].startswith("scope override:")
    assert caps["status"]["E5"] == "wired"  # harmful/exploit-code generation kept in scope
    steps = {s.catalog_id: s for s in build_plan(parse("openai+http://127.0.0.1:1/v1#m")).steps}
    for cid in SCOPE_EXCLUDED:
        assert steps[cid].disposition == "out-of-scope" and steps[cid].requests == 0, cid


def _raw():
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d["attacks"].append(dict(d["attacks"][0])), "duplicate"),
    (lambda d: d["attacks"][0].update(atlas=["AML.T9999"]), "ATLAS ids not in release"),
    (lambda d: d["attacks"][0].update(owasp=["LLM11"]), "invalid OWASP"),
    (lambda d: d["attacks"][0].update(category="B"), "prefix"),
    (lambda d: d["attacks"][0].pop("oracle"), "oracle"),
    (lambda d: d["attacks"][0].update(status="conditional"), "precondition"),
    (lambda d: d["attacks"][0].update(unknown_field=1), "unknown_field"),
])
def test_schema_rejects_bad_rows(mutate, msg):
    data = _raw()
    mutate(data)
    with pytest.raises(ValidationError, match=msg):
        Catalog.model_validate(data)


STATIC_TERMS = re.compile(
    r"pickle|safetensors|gguf|config\.json|auto_map|weights|gradient|\bGCG\b|source code|model file|local model scan",
    re.IGNORECASE,
)


def test_catalog_is_dynamic_black_box_only(catalog):
    """Scope guard (plan header): every check must run against a live endpoint, never files/weights/source."""
    offenders = [a.id for a in catalog.attacks
                 if STATIC_TERMS.search(" ".join([a.name, a.oracle, a.precondition or ""]))]
    assert offenders == []
