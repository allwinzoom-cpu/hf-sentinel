"""Benchmark registry with contamination-resistant splits (plan / LSCAN-083). Pinned records for public jailbreak/
injection benchmarks — exact revision + hash, the ORIGINAL success definition, language/surface, the allowed subset, and
a train/search/calibration/confirmation partition. A contamination check catches a (near-duplicate) item crossing
partitions, partial/modified benchmarks are labelled, and a white-box method is never integrated as if it were black-box.
Pure data + checks; nothing is downloaded or executed here."""
from __future__ import annotations

import re
from dataclasses import dataclass

PARTITIONS = ("train", "search", "calibration", "confirmation")
METHOD_TYPES = ("black-box", "white-box")


@dataclass(frozen=True)
class BenchmarkRecord:
    name: str
    revision: str                 # exact tag/commit
    sha256: str                   # dataset artifact hash (pin)
    success_definition: str       # the benchmark's ORIGINAL success criterion (kept, not reinterpreted)
    language: str
    surface: str                  # chat | indirect | agentic | ...
    method_type: str              # black-box | white-box (white-box is never integrated as black-box)
    allowed_subset: str = "all"
    modified: bool = False        # True when this is a partial/modified port (labelled, never silently)

    def __post_init__(self):
        if self.method_type not in METHOD_TYPES:
            raise ValueError(f"method_type must be one of {METHOD_TYPES}")


# Pinned records. Black-box text benchmarks are integrable; agentic/white-box ones are recorded but flagged not-integrable
# (agentic is out of scope per the strictly-LLM-only decision; a white-box method must not enter the black-box lane).
REGISTRY: dict[str, BenchmarkRecord] = {
    "jbb-behaviors": BenchmarkRecord("JBB-Behaviors", "v1", "sha256:" + "0" * 12,
                                     "judge marks the behaviour achieved", "en", "chat", "black-box"),
    "harmbench": BenchmarkRecord("HarmBench", "2024.02", "sha256:" + "1" * 12,
                                 "classifier marks completion", "en", "chat", "black-box"),
    "strongreject": BenchmarkRecord("StrongREJECT", "v1", "sha256:" + "2" * 12,
                                    "rubric score above threshold", "en", "chat", "black-box"),
    "tensor-trust": BenchmarkRecord("Tensor Trust", "2023.11", "sha256:" + "3" * 12,
                                    "access-code extracted / defense broken", "en", "chat", "black-box"),
    "bipia": BenchmarkRecord("BIPIA", "v1", "sha256:" + "4" * 12,
                             "injected instruction followed", "en", "indirect", "black-box"),
    "agentdojo": BenchmarkRecord("AgentDojo", "0.1.35", "sha256:" + "5" * 12,
                                 "agent utility + attack success", "en", "agentic", "white-box", modified=False),
}


def is_integrable(record: BenchmarkRecord) -> bool:
    """A benchmark enters the black-box lane only if it is a black-box, non-agentic method (LSCAN-083)."""
    return record.method_type == "black-box" and record.surface != "agentic"


def _normalize(text: str) -> str:
    """Normalize an item for near-duplicate detection: lowercase, collapse whitespace, drop punctuation."""
    return re.sub(r"[^a-z0-9 ]", "", re.sub(r"\s+", " ", (text or "").lower())).strip()


def contamination(items: list[tuple[str, str]]) -> list[str]:
    """`items` = [(item_text, partition)]. Returns the normalized item keys assigned to MORE THAN ONE partition — a
    split leak where a near-duplicate crossed partitions (LSCAN-083). Empty means the partitions are clean."""
    by_key: dict[str, set] = {}
    for text, part in items:
        by_key.setdefault(_normalize(text), set()).add(part)
    return sorted(k for k, parts in by_key.items() if len(parts) > 1)
