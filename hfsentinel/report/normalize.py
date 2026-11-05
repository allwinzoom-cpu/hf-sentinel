"""EngineResult (adapter output) → catalog-mapped Findings. Catalog metadata comes from catalog.yaml, never the engine."""
from __future__ import annotations

from hfsentinel.attacks.catalog import Catalog, load_catalog
from hfsentinel.report.schema import EngineBuild, EngineResult, Evidence, Finding, wilson_ci

CATEGORY_NAMES = {"A": "Prompt Injection", "B": "Jailbreak / Policy Bypass", "C": "Information Disclosure",
                  "D": "Agentic & Tool Abuse", "E": "Output Handling & Resource Abuse", "H": "Hallucination"}


def to_findings(result: EngineResult, build: str, catalog: Catalog | None = None) -> list[Finding]:
    """One Finding per technique result with ≥1 success. Status stays `candidate` until Section 2.2 confirmation;
    catalog `candidate` techniques are marked `experimental` (never scored, Section 4.0)."""
    catalog = catalog or load_catalog()
    by_id = catalog.by_id()
    findings = []
    for r in result.results:
        if r.successes == 0:
            continue
        a = by_id[r.catalog_id]
        first = r.proven[0] if r.proven else None
        findings.append(Finding(
            catalog_id=a.id, category=CATEGORY_NAMES[a.category], owasp=a.owasp, atlas=a.atlas,
            target={"ref": result.target.ref, "resolved_model": result.target.model}, attacker=list(a.attacker),
            technique=r.technique, trials=r.trials, successes=r.successes,
            asr=round(r.successes / r.trials, 4) if r.trials else 0.0, asr_ci95=wilson_ci(r.successes, r.trials),
            effort=a.effort, oracle=r.oracle,
            evidence=Evidence(hash=first.sha256 if first else None, redacted_excerpt=first.excerpt if first else ""),
            engine_build=EngineBuild(engines=[result.engine], build=build),
            status="experimental" if a.status == "candidate" else "candidate",
        ))
    return findings
