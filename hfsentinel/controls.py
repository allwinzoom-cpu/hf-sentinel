"""Scan control surface (plan §9.3): schema, profile presets, `sentinel.yaml` loader and precedence resolver.

Precedence: explicit flag → config file → profile preset → built-in default. Every resolved value remembers which
layer set it. Config files are untrusted input: size-capped, safe-loaded, aliases and unknown keys refused.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.targets.openai_compat import DEFAULT_USER_AGENT, check_user_agent

MAX_CONFIG_BYTES = 256_000
MAX_INPUT_FILE_BYTES = 1_000_000
BUDGET_USD_CEILING = 20.0  # D-005: HF spend cap through Phase 2; raising it needs owner approval
JUDGE_USD_CEILING = 25.0  # D-017: separate judge spend cap

Category = Literal["A", "B", "C", "D", "E", "H"]
Scan = Literal["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"]
FuzzType = Literal["mutation", "template", "generative", "search", "replay", "composite"]
Mutator = Literal["case", "shuffle", "typo", "base64", "base32", "gzip-base64", "hex", "binary", "octal",
                 "morse", "leet", "homoglyph", "unicode-tag", "invisible-text", "artprompt", "flip", "cipher",
                 "unicode-inversion", "spelled-ascii", "balanced-brackets", "parseltongue-fullwidth",
                 "decompose", "bijection", "percent", "html-entity", "json-escape", "zero-width",
                 "atbash", "rot47", "ascii85", "base58"]
JudgeName = Literal["ensemble", "rubric", "classifier", "guard", "nli", "deterministic"]
Registry = Literal["pypi", "npm", "crates", "rubygems"]
Format = Literal["md", "json", "sarif", "html", "card"]
Profile = Literal["quick", "standard", "deep", "agentic", "hallucination", "diff", "custom"]
SEED_SETS = ("forbidden-prompts", "harm-behaviors", "jailbreak-behaviors", "adv-behaviors")
ATTACK_ID = re.compile(r"^[ABCDEH]\d{1,2}$")
REPO_ID = re.compile(r"^[A-Za-z0-9][\w.-]{0,95}/[A-Za-z0-9][\w.-]{0,95}$", re.ASCII)


_catalog = lru_cache(maxsize=1)(load_catalog)


class ControlError(ValueError):
    """Invalid controls; the message names the offending key and layer, never file contents."""


def _split(v: Any) -> Any:
    """CLI flags arrive as comma-separated strings; config files use YAML lists. Accept both."""
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return v


def _input_file(v: Path | None) -> Path | None:
    if v is None:
        return None
    p = Path(v).expanduser().resolve()
    if not p.is_file():
        raise ValueError("must be an existing regular file")
    if p.stat().st_size > MAX_INPUT_FILE_BYTES:
        raise ValueError(f"must be at most {MAX_INPUT_FILE_BYTES // 1_000_000} MB")
    return p


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Select(_Section):
    categories: list[Category] = Field(default_factory=lambda: ["A", "B", "C", "D", "E", "H"], min_length=1)
    attacks: list[str] | None = None  # explicit IDs; when set they replace `categories`
    exclude: list[str] = Field(default_factory=list)
    scans: list[Scan] = Field(default_factory=lambda: ["S1", "S3"], min_length=1)
    status: Literal["ready", "ready+conditional", "all"] = "ready+conditional"
    seed_set: str = "forbidden-prompts"
    goals: Path | None = None
    sample: int | float | None = None  # int = N prompts, float in (0, 1] = fraction

    _lists = field_validator("categories", "attacks", "exclude", "scans", mode="before")(_split)

    @field_validator("attacks", "exclude")
    @classmethod
    def _ids(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        known = _catalog().by_id()
        bad = [x for x in v if not ATTACK_ID.match(x) or x not in known]
        if bad:
            raise ValueError(f"unknown attack ids: {', '.join(sorted(set(bad)))[:200]}")
        return sorted(set(v), key=v.index)

    @field_validator("seed_set")
    @classmethod
    def _seed_set(cls, v: str) -> str:
        if v in SEED_SETS:
            return v
        if v.startswith("custom:"):
            return f"custom:{_input_file(Path(v[len('custom:'):]))}"
        raise ValueError(f"must be one of {', '.join(SEED_SETS)} or custom:<file>")

    @field_validator("goals")
    @classmethod
    def _goals(cls, v: Path | None) -> Path | None:
        return _input_file(v)

    @field_validator("sample", mode="before")
    @classmethod
    def _sample(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = float(v) if "." in v else int(v)
        bad = isinstance(v, bool) or (isinstance(v, int) and v < 1) or (isinstance(v, float) and not 0 < v <= 1)
        if bad:  # ValueError, not TypeError: pydantic only reports ValueError as a validation error
            raise ValueError("must be a count ≥ 1 or a fraction in (0, 1]")
        return v


class Tap(_Section):
    width: int = Field(default=4, ge=1, le=20)
    depth: int = Field(default=5, ge=1, le=20)


class Compose(_Section):
    enabled: bool = True
    max_depth: int = Field(default=2, ge=1, le=5)


class Fuzz(_Section):
    types: list[FuzzType] = Field(default_factory=lambda: ["mutation", "template"], min_length=1)
    rounds: int = Field(default=10, ge=1, le=10_000)
    max_attempts: int = Field(default=50, ge=1, le=100_000)
    mutators: list[Mutator] = Field(default_factory=lambda: list(Mutator.__args__), min_length=1)
    mutation_rate: float = Field(default=0.3, ge=0, le=1)
    max_turns: int = Field(default=5, ge=1, le=50)
    tap: Tap = Field(default_factory=Tap)
    strategy_lib: Literal["off", "read", "read-write"] = "read"
    compose: Compose = Field(default_factory=Compose)
    stop_on_success: bool = False

    _lists = field_validator("types", "mutators", mode="before")(_split)


class TargetIO(_Section):
    trials: int = Field(default=10, ge=1, le=1000)
    temperature: float = Field(default=0.7, ge=0, le=2)
    top_p: float | None = Field(default=None, gt=0, le=1)  # None = provider default
    max_tokens: int = Field(default=1024, ge=1, le=32_768)
    seed: int = Field(default=0, ge=0, le=2**32 - 1)
    concurrency: int = Field(default=4, ge=1, le=64)
    rate_limit: int | None = Field(default=None, ge=1, le=6000)  # requests/min; None = provider-aware governor
    retry: int = Field(default=2, ge=0, le=10)
    timeout: float = Field(default=60.0, gt=0, le=600)
    user_agent: str = DEFAULT_USER_AGENT  # sent to the target; printable ASCII, no CR/LF

    @field_validator("user_agent")
    @classmethod
    def _ua(cls, v: str) -> str:
        return check_user_agent(v)


class Judge(_Section):
    use: list[JudgeName] = Field(default_factory=lambda: ["ensemble"], min_length=1)
    asr_k: int | None = Field(default=None, ge=1, le=10_000)  # None = fuzz.rounds

    _lists = field_validator("use", mode="before")(_split)


class Extras(_Section):
    system_prompt: Path | None = None
    tools: Path | None = None
    halluc_registries: list[Registry] = Field(default_factory=lambda: ["pypi", "npm"], min_length=1)
    sink_url: str | None = Field(default=None, max_length=300)
    with_firewall: bool = False

    _lists = field_validator("halluc_registries", mode="before")(_split)

    @field_validator("system_prompt", "tools")
    @classmethod
    def _files(cls, v: Path | None) -> Path | None:
        return _input_file(v)

    @field_validator("sink_url")
    @classmethod
    def _sink(cls, v: str | None) -> str | None:
        if v is not None and not re.match(r"^https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?(/[\w./~%-]*)?$", v, re.ASCII):
            raise ValueError("must be an https URL without credentials, query or fragment")
        return v


class Budget(_Section):
    usd: float = Field(default=5.0, gt=0, le=BUDGET_USD_CEILING)
    judge_usd: float = Field(default=5.0, ge=0, le=JUDGE_USD_CEILING)
    minutes: int = Field(default=30, ge=1, le=24 * 60)
    max_requests: int = Field(default=1000, ge=1, le=1_000_000)


class Output(_Section):
    out: Path = Path("reports")
    formats: list[Format] = Field(default_factory=lambda: ["md", "json"], min_length=1)
    push_to: str | None = None  # private HF dataset repo (D-006)
    fail_on: Literal["critical", "high", "medium"] = "critical"
    save_transcripts: bool = False  # confirmed findings only (D-015)

    _lists = field_validator("formats", mode="before")(_split)

    @field_validator("out")
    @classmethod
    def _out(cls, v: Path) -> Path:
        p = Path(v).expanduser().resolve()
        if p.exists() and not p.is_dir():
            raise ValueError("must be a directory")
        return p

    @field_validator("push_to")
    @classmethod
    def _push_to(cls, v: str | None) -> str | None:
        if v is not None and not REPO_ID.match(v):
            raise ValueError("must be an HF repo id org/name")
        return v


class Controls(_Section):
    profile: Profile = "quick"
    target: str | None = Field(default=None, max_length=512)
    select: Select = Field(default_factory=Select)
    fuzz: Fuzz = Field(default_factory=Fuzz)
    target_io: TargetIO = Field(default_factory=TargetIO)
    judge: Judge = Field(default_factory=Judge)
    extras: Extras = Field(default_factory=Extras)
    budget: Budget = Field(default_factory=Budget)
    output: Output = Field(default_factory=Output)

    @model_validator(mode="after")
    def _cross(self, info) -> Controls:
        if info.context and info.context.get("layer_only"):
            return self  # cross-field rules apply to the merged set, not to one layer in isolation
        if self.judge.asr_k is not None and self.judge.asr_k > self.fuzz.rounds:
            raise ValueError("judge.asr_k cannot exceed fuzz.rounds")
        return self


# Presets only set defaults; every key is overridable by config or flag. `custom` = built-ins only.
PROFILES: dict[str, dict] = {
    "quick": {"select": {"categories": ["A", "B", "C"], "status": "ready", "scans": ["S1", "S3"]},
              "fuzz": {"types": ["mutation"], "rounds": 3, "max_attempts": 10, "max_turns": 3},
              "target_io": {"trials": 3},
              "budget": {"usd": 1.0, "judge_usd": 1.0, "minutes": 10, "max_requests": 300}},
    "standard": {"select": {"categories": ["A", "B", "C", "E", "H"], "scans": ["S1", "S2", "S3", "S5", "S6"]}},
    "deep": {"select": {"scans": ["S1", "S2", "S3", "S5", "S6", "S10"]},
             "fuzz": {"types": ["mutation", "template", "generative", "search", "composite"], "rounds": 50,
                      "max_attempts": 200, "max_turns": 8, "tap": {"width": 6, "depth": 6},
                      "compose": {"max_depth": 3}},
             "target_io": {"trials": 20},
             "budget": {"usd": 10.0, "judge_usd": 10.0, "minutes": 120, "max_requests": 5000}},
    "agentic": {"select": {"categories": ["A", "D", "E"], "scans": ["S4"]}, "fuzz": {"max_turns": 8}},
    "hallucination": {"select": {"categories": ["H"], "scans": ["S5"]}, "fuzz": {"types": ["template", "mutation"]}},
    "diff": {"select": {"categories": ["A", "B", "C"], "scans": ["S8"]}},
    "custom": {},
}

# CLI option name → dotted control path (1:1 with sentinel.yaml; `target` is scan's positional argument).
FLAG_PATHS: dict[str, str] = {
    "profile": "profile", "target": "target",
    "categories": "select.categories", "attacks": "select.attacks", "exclude": "select.exclude",
    "scans": "select.scans", "status": "select.status", "seed_set": "select.seed_set", "goals": "select.goals",
    "sample": "select.sample",
    "fuzz_type": "fuzz.types", "rounds": "fuzz.rounds", "max_attempts": "fuzz.max_attempts",
    "mutators": "fuzz.mutators", "mutation_rate": "fuzz.mutation_rate", "max_turns": "fuzz.max_turns",
    "tap_width": "fuzz.tap.width", "tap_depth": "fuzz.tap.depth", "strategy_lib": "fuzz.strategy_lib",
    "compose": "fuzz.compose.enabled", "max_compose": "fuzz.compose.max_depth",
    "stop_on_success": "fuzz.stop_on_success",
    "trials": "target_io.trials", "temperature": "target_io.temperature", "top_p": "target_io.top_p",
    "max_tokens": "target_io.max_tokens", "seed": "target_io.seed", "concurrency": "target_io.concurrency",
    "rate_limit": "target_io.rate_limit", "retry": "target_io.retry", "timeout": "target_io.timeout",
    "user_agent": "target_io.user_agent",
    "judge": "judge.use", "asr_k": "judge.asr_k",
    "system_prompt": "extras.system_prompt", "tools": "extras.tools",
    "halluc_registries": "extras.halluc_registries", "sink_url": "extras.sink_url",
    "with_firewall": "extras.with_firewall",
    "budget_usd": "budget.usd", "budget_judge_usd": "budget.judge_usd", "max_minutes": "budget.minutes",
    "max_requests": "budget.max_requests",
    "out": "output.out", "formats": "output.formats", "push_to": "output.push_to", "fail_on": "output.fail_on",
    "save_transcripts": "output.save_transcripts",
}
# Config keys holding file paths: relative values resolve against the config file's directory.
PATH_KEYS = ("select.goals", "extras.system_prompt", "extras.tools", "output.out")


@dataclass(frozen=True)
class Resolved:
    controls: Controls
    sources: dict[str, str]  # dotted path → "flag" | "config" | "profile:<name>" | "default"


def flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, f"{path}."))  # an empty mapping sets nothing
        else:
            out[path] = v
    return out


def _nest(leaves: dict[str, Any]) -> dict:
    root: dict = {}
    for path, v in leaves.items():
        node = root
        *parents, last = path.split(".")
        for p in parents:
            if not isinstance(node.get(p), dict):
                node[p] = {}
            node = node[p]
        node[last] = v
    return root


def _validate(data: dict, layer: str, *, layer_only: bool = False) -> Controls:
    try:
        return Controls.model_validate(data, context={"layer_only": layer_only})
    except ValidationError as e:
        err = e.errors()[0]
        loc = ".".join(str(x) for x in err["loc"])
        raise ControlError(f"{layer}: {loc + ': ' if loc else ''}{err['msg']}") from None


def _no_aliases(text: str) -> None:
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise ControlError("config: YAML anchors/aliases are not allowed")


def load_config(path: Path) -> dict:
    """Read a sentinel.yaml into a nested dict (validated later, as one precedence layer)."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise ControlError("config: file not found or not a regular file")
    if p.stat().st_size > MAX_CONFIG_BYTES:
        raise ControlError(f"config: file exceeds {MAX_CONFIG_BYTES // 1000} KB")
    try:
        text = p.read_text(encoding="utf-8")
        _no_aliases(text)
        data = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise ControlError("config: not valid UTF-8 YAML") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ControlError("config: top level must be a mapping")
    leaves = flatten(data)
    base = p.resolve().parent
    for key in PATH_KEYS:
        if isinstance(leaves.get(key), str):
            leaves[key] = str(base / leaves[key])
    seed = leaves.get("select.seed_set")
    if isinstance(seed, str) and seed.startswith("custom:"):
        leaves["select.seed_set"] = f"custom:{base / seed[len('custom:'):]}"
    return _nest(leaves)


def resolve_controls(flags: dict[str, Any] | None = None, config: dict | None = None) -> Resolved:
    """Merge default → profile → config → flags, validate, and record each value's source."""
    flags, config = flags or {}, config or {}
    unknown = sorted(set(flags) - set(FLAG_PATHS))
    if unknown:
        raise ControlError(f"unknown flags: {', '.join(unknown)}")
    flag_layer = _nest({FLAG_PATHS[k]: v for k, v in flags.items() if v is not None})
    _validate(config, "config", layer_only=True)  # report errors against the layer that caused them
    _validate(flag_layer, "flag", layer_only=True)
    profile = flag_layer.get("profile") or config.get("profile") or Controls().profile
    merged: dict[str, Any] = {}
    sources: dict[str, str] = {}
    defaults = Controls().model_dump(mode="python")
    for name, layer in (("default", defaults), (f"profile:{profile}", PROFILES[profile]), ("config", config),
                        ("flag", flag_layer)):
        for path, value in flatten(layer).items():
            merged[path] = value
            sources[path] = name
    rank = {"default": 0, "config": 2, "flag": 3}
    att, cat = (rank.get(sources[k], 1) for k in ("select.attacks", "select.categories"))
    if merged["select.attacks"] is not None and cat > att:
        merged["select.attacks"] = None  # categories set at a higher-precedence layer than attacks win
        sources["select.attacks"] = sources["select.categories"]
    controls = _validate(_nest(merged), "controls")
    if not selected_ids(controls):
        raise ControlError("controls: the selection matches no attacks (check categories, attacks, exclude, status)")
    return Resolved(controls, sources)


def selected_ids(controls: Controls) -> list[str]:
    """Catalog IDs the selection runs, in catalog order."""
    sel = controls.select
    statuses = {"ready": {"ready"}, "ready+conditional": {"ready", "conditional"},
                "all": {"ready", "conditional", "candidate"}}[sel.status]
    wanted = set(sel.attacks) if sel.attacks is not None else None
    return [a.id for a in _catalog().attacks
            if (a.id in wanted if wanted is not None else a.category in sel.categories)
            and a.status in statuses and a.id not in sel.exclude]


def to_config(controls: Controls) -> dict:
    """The resolved set as a sentinel.yaml mapping that reproduces it exactly."""
    return controls.model_dump(mode="json")
