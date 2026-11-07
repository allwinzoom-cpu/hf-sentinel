"""Framework-version pins embedded in every report (LSCAN-006 integration). This lives in the report layer so
`report/build.py` can embed the block without an awkward dependency on the top-level `engines/` tooling package; the
authoritative pins match `engines/framework_versions.json` (a drift-guard test ties the two). Coverage is reported as
partial-dynamic — never a 'Top 10 complete' claim from merely listing categories."""
from __future__ import annotations

FRAMEWORKS = {
    "owasp_llm": {"edition": "2025", "source": "https://genai.owasp.org/llm-top-10/"},
    "owasp_agentic": {"edition": "2025 (Agentic Security Initiative)", "source": "https://genai.owasp.org/"},
    "mitre_atlas": {"revision": "5.6.0", "source": "https://github.com/mitre-atlas/atlas-data",
                    "ids_file": "hfsentinel/attacks/atlas_ids_5.6.0.txt"},
}
COVERAGE_CLAIM = "partial-dynamic"
UNTESTED_BOUNDARIES = ("static artifact/weight analysis, training-time poisoning, and target-managed application/agent "
                       "surfaces not under the declared attacker are out of scope; dynamic black-box model checks only.")


def report_block() -> dict:
    """The framework-version block a report embeds: pinned editions/revisions + the partial-coverage statement."""
    return {"frameworks": FRAMEWORKS, "coverage_claim": COVERAGE_CLAIM, "untested_boundaries": UNTESTED_BOUNDARIES}
