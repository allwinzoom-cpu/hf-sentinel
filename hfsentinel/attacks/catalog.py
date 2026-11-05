"""Attack catalog schema and loader (plan §4, §4.0)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CATALOG_PATH = Path(__file__).with_name("catalog.yaml")

OWASP_PATTERN = r"^(LLM(0[1-9]|10)|ASI(0[1-9]|10))$"
ATLAS_PATTERN = r"^AML\.T\d{4}(\.\d{3})?$"


def load_atlas_ids(release: str) -> frozenset[str]:
    path = Path(__file__).with_name(f"atlas_ids_{release}.txt")
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(ln.strip() for ln in lines if ln.strip() and not ln.startswith("#"))


class Attack(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[ABCDEH]\d{1,2}$")
    category: Literal["A", "B", "C", "D", "E", "H"]
    name: str = Field(min_length=3, max_length=120)
    owasp: list[str] = Field(min_length=1)
    atlas: list[str] = Field(min_length=1)
    attacker: list[Literal["T1", "T2", "T3"]] = Field(min_length=1)
    effort: Literal["E", "M"]
    status: Literal["ready", "conditional", "candidate"]
    precondition: str | None = None
    oracle: str = Field(min_length=5)

    @field_validator("owasp")
    @classmethod
    def _owasp(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if not re.match(OWASP_PATTERN, x)]
        if bad:
            raise ValueError(f"invalid OWASP ids: {bad}")
        return v

    @field_validator("atlas")
    @classmethod
    def _atlas(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if not re.match(ATLAS_PATTERN, x)]
        if bad:
            raise ValueError(f"invalid ATLAS ids: {bad}")
        return v

    @model_validator(mode="after")
    def _consistency(self) -> Attack:
        if self.id[0] != self.category:
            raise ValueError(f"{self.id}: id prefix does not match category {self.category}")
        if (self.status == "conditional") != (self.precondition is not None):
            raise ValueError(f"{self.id}: precondition required iff status is conditional")
        return self


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    catalog_version: int = Field(ge=0)
    atlas_release: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    attacks: list[Attack] = Field(min_length=1)

    @model_validator(mode="after")
    def _checks(self) -> Catalog:
        ids = [a.id for a in self.attacks]
        dups = sorted({i for i in ids if ids.count(i) > 1})
        if dups:
            raise ValueError(f"duplicate attack ids: {dups}")
        known = load_atlas_ids(self.atlas_release)
        unknown = sorted({t for a in self.attacks for t in a.atlas} - known)
        if unknown:
            raise ValueError(f"ATLAS ids not in release {self.atlas_release}: {unknown}")
        return self

    def by_id(self) -> dict[str, Attack]:
        return {a.id: a for a in self.attacks}


def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    with path.open(encoding="utf-8") as fh:
        return Catalog.model_validate(yaml.safe_load(fh))
