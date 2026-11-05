"""Finding schema (plan Appendix A + 16.16/16.17/16.22) and the EngineResult contract engine adapters emit."""
from __future__ import annotations

import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hfsentinel.scoring.stats import wilson

SCHEMA_VERSION = "0.1"
SHA256 = r"^[0-9a-f]{64}$"
ALIAS = r"^[a-z]+(-[a-z]+)*$"


class Oracle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["deterministic", "tool-deterministic", "judge", "human"]
    name: str = Field(min_length=1, max_length=80)


class ProvenCase(BaseModel):
    """Only proven cases carry evidence (D-015): hash + short redacted excerpt, never full transcripts."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    sha256: str = Field(pattern=SHA256)
    excerpt: str = Field(default="", max_length=200)


class Repro(BaseModel):
    """Minimal recipe to replay a confirmed finding deterministically (plan 16.17): catalog id + target pin live on the
    Finding; this adds the seeded run parameters and the mutator chain, so the exact trials regenerate."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    catalog_id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    seed: int = Field(ge=0)
    trials: int = Field(ge=1)
    temperature: float = Field(ge=0)
    mutator_chain: list[str] = Field(default_factory=list)


class TechniqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    catalog_id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    technique: str = Field(min_length=1, max_length=80)
    trials: int = Field(ge=0)
    successes: int = Field(ge=0)
    oracle: Oracle
    proven: list[ProvenCase] = Field(default_factory=list)

    @field_validator("successes")
    @classmethod
    def _not_more_than_trials(cls, v: int, info) -> int:
        if v > info.data.get("trials", v):
            raise ValueError("successes > trials")
        return v


class EngineTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ref: str = Field(min_length=1, max_length=300)
    model: str = Field(min_length=1, max_length=200)


class EngineResult(BaseModel):
    """What an engine adapter prints: plain JSON, validated in the core. Engines are named only by alias (D-014)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["0.1"]
    engine: str = Field(pattern=ALIAS)
    target: EngineTarget
    results: list[TechniqueResult]
    errors: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    hash: str | None = Field(default=None, pattern=SHA256)
    redacted_excerpt: str = Field(default="", max_length=200)


class EngineBuild(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    engines: list[str]
    build: str = Field(pattern=r"^sha256:[0-9a-f]{12,64}$")

    @field_validator("engines")
    @classmethod
    def _aliases(cls, v: list[str]) -> list[str]:
        bad = [e for e in v if not re.match(ALIAS, e)]
        if bad:
            raise ValueError(f"engines must be neutral aliases: {bad}")
        return v


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["0.1"] = SCHEMA_VERSION
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    catalog_id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    category: str
    owasp: list[str]
    atlas: list[str]
    target: dict
    attacker: list[str]
    technique: str
    trials: int = Field(ge=0)
    successes: int = Field(ge=0)
    asr: float = Field(ge=0, le=1)
    asr_ci95: tuple[float, float]
    baseline_asr: float | None = None
    lift: float | None = None
    effort: Literal["E", "M"]
    severity: Literal["Critical", "High", "Medium", "Low", "Info", "Unrated"] = "Unrated"
    oracle: Oracle
    evidence: Evidence
    engine_build: EngineBuild
    repro: Repro | None = None  # replay recipe for confirmed findings (16.17)
    reproducible: bool = False
    status: Literal["candidate", "confirmed", "rejected", "experimental"] = "candidate"


def wilson_ci(successes: int, trials: int) -> tuple[float, float]:
    """Wilson 95% interval rounded for reports (`scoring.stats.wilson`)."""
    lo, hi = wilson(successes, trials)
    return (round(lo, 4), round(hi, 4))
