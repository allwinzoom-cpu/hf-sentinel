"""Pairwise composition, transfer and black-box suffix replay (plan / LSCAN-049). Compose encoding/scaffold/delivery
transformations under a DEPTH CAP (no unbounded stacking), measure a combination's INCREMENTAL lift over its best single
component (so a combination is credited only for what it adds), and replay a published fixed adversarial prefix/suffix as
a pure black-box input — carrying its provenance, and never implying universal transfer. No target-gradient optimization.
"""
from __future__ import annotations

from dataclasses import dataclass

from hfsentinel.attacks.mutators import MUTATORS, compose

MAX_COMPOSE_DEPTH = 3  # cap on stacked transformations: deeper chains are refused, not silently applied


class CompositionError(ValueError):
    """A composition that exceeds the depth cap or names an unknown transform."""


def compose_capped(names: tuple[str, ...], *, max_depth: int = MAX_COMPOSE_DEPTH):
    """Compose the named mutators left-to-right under the depth cap (LSCAN-049). Raises past `max_depth` or on an unknown
    transform, so a chain is always bounded and reproducible from its ordered names."""
    if len(names) > max_depth:
        raise CompositionError(f"composition depth {len(names)} exceeds the cap {max_depth}")
    unknown = [n for n in names if n not in MUTATORS]
    if unknown:
        raise CompositionError(f"unknown transform(s): {unknown}")
    return compose(tuple(names))


def incremental_lift(component_asrs: dict[str, float], combined_asr: float) -> float:
    """A combination's lift over its BEST single component (LSCAN-049): combination credit beyond what any one part
    already achieves. <= 0 means the combination added nothing over its parts (not a distinct finding)."""
    best_component = max(component_asrs.values(), default=0.0)
    return round(combined_asr - best_component, 6)


@dataclass(frozen=True)
class SuffixArtifact:
    """A published fixed adversarial prefix/suffix replayed as a black-box input. Its provenance travels with it, and its
    applicability is per-target — a success here is NOT evidence of universal transfer (LSCAN-049)."""
    text: str
    source: str                       # where it came from (paper / public corpus) — provenance, always recorded
    position: str = "suffix"          # "suffix" | "prefix"
    note: str = "applicability is per-target; a success here is not universal transfer"

    def apply(self, prompt: str) -> str:
        return f"{self.text}\n{prompt}" if self.position == "prefix" else f"{prompt}\n{self.text}"
