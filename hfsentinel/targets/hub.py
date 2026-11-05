"""Read-only Hugging Face Hub metadata lookups used to resolve targets (never traffic to the target itself).

Responses are treated as adversarial: fixed host, no redirects, bounded time and size, schema-validated.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from hfsentinel.targets.openai_compat import _OPENER

HUB = "https://huggingface.co"
ROUTER = "https://router.huggingface.co"
MAX_HUB_BYTES = 1_000_000
HUB_TIMEOUT_S = 20.0
# HF repo naming: alphanumerics plus '-', '_', '.'; no '--' or '..'; no leading/trailing '-' or '.'; ≤ 96 chars.
REPO_PART = r"(?![\w.-]*(?:--|\.\.))[A-Za-z0-9](?:[\w.-]{0,94}[A-Za-z0-9])?"
REPO_ID = re.compile(rf"^{REPO_PART}/{REPO_PART}$", re.ASCII)
PROVIDER = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$", re.ASCII)
SUBDOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)


class HubError(RuntimeError):
    """Hub unreachable or returned something unusable."""


class HubNotFound(HubError):
    """Repo missing, private, or gated (the Hub answers 401 for repos that do not exist)."""


class ProviderMapping(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    status: str = Field(max_length=32)
    provider_id: str = Field(alias="providerId", max_length=200)
    task: str = Field(max_length=64)


def _repo_id(v: str) -> str:
    if not REPO_ID.match(v):
        raise ValueError("invalid repo id")
    return v


class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    id: str = Field(max_length=193)
    providers: dict[str, ProviderMapping] = Field(alias="inferenceProviderMapping", default_factory=dict, max_length=64)

    @field_validator("providers")
    @classmethod
    def _provider_names(cls, v: dict[str, ProviderMapping]) -> dict[str, ProviderMapping]:
        bad = [k for k in v if not PROVIDER.match(k)]
        if bad:
            raise ValueError("invalid provider name in mapping")
        return v

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _repo_id(v)

    def live_chat_providers(self) -> list[str]:
        return [k for k, m in self.providers.items() if m.status == "live" and m.task == "conversational"]


class SpaceRuntime(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    stage: str = Field(default="UNKNOWN", pattern=r"^[A-Z_]{1,32}$")


class SpaceInfo(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    id: str = Field(max_length=193)
    subdomain: str = Field(pattern=SUBDOMAIN.pattern)
    host: str = Field(max_length=100)
    sdk: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,32}$")
    runtime: SpaceRuntime = Field(default_factory=SpaceRuntime)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _repo_id(v)

    @field_validator("host")
    @classmethod
    def _host_matches_subdomain(cls, v: str, info) -> str:
        if v != f"https://{info.data.get('subdomain')}.hf.space":
            raise ValueError("space host does not match its hf.space subdomain")
        return v


def _get_json(path: str, token: str | None, base: str | None = None) -> object:
    headers = {"Accept": "application/json", "User-Agent": "hfsentinel"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{base or HUB}{path}", headers=headers, method="GET")
    try:
        with _OPENER.open(req, timeout=HUB_TIMEOUT_S) as resp:
            raw = resp.read(MAX_HUB_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 404):
            raise HubNotFound("not found or not accessible (private or gated repos need an HF token)") from None
        if 300 <= e.code < 400:
            raise HubError("the Hub redirected this id (renamed repo?); use its current id") from None
        raise HubError(f"the Hub returned HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise HubError(f"the Hub is unreachable: {type(e).__name__}") from None
    if len(raw) > MAX_HUB_BYTES:
        raise HubError("Hub response exceeded size limit")
    try:
        return json.loads(raw)
    except ValueError:
        raise HubError("the Hub returned an unexpected response") from None


def get_json(path: str, token: str | None) -> object:
    """Raw read-only Hub GET (same guards as the typed lookups); callers validate the shape."""
    return _get_json(path, token)


class Pricing(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    input: float = Field(ge=0, le=1000)  # USD per 1M tokens
    output: float = Field(ge=0, le=1000)


class RouterProvider(BaseModel):
    """What a provider declares for a model on the router (`/v1/models`); absent fields mean undeclared."""
    model_config = ConfigDict(extra="ignore", frozen=True)
    provider: str = Field(pattern=PROVIDER.pattern)
    status: str = Field(max_length=32)
    context_length: int | None = Field(default=None, ge=1, le=100_000_000)
    pricing: Pricing | None = None
    supports_tools: bool | None = None
    supports_structured_output: bool | None = None


class RouterArchitecture(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    input_modalities: list[str] = Field(default_factory=list, max_length=16)


class RouterModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    id: str = Field(max_length=193)
    architecture: RouterArchitecture = Field(default_factory=RouterArchitecture)
    providers: list[RouterProvider] = Field(default_factory=list, max_length=64)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _repo_id(v)


def router_declared(model_id: str, provider: str) -> tuple[RouterModel, RouterProvider] | None:
    """The router's declared capabilities for (model, provider), or None if it does not list them."""
    data = _get_json("/v1/models", None, base=ROUTER)
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise HubError("the router returned an unexpected model list")
    for row in rows:
        if isinstance(row, dict) and row.get("id") == model_id:
            try:
                model = RouterModel.model_validate(row)
            except ValidationError:
                raise HubError("the router returned an unexpected model record") from None
            match = next((p for p in model.providers if p.provider == provider), None)
            return (model, match) if match else None
    return None


def model_info(repo_id: str, token: str | None) -> ModelInfo:
    if not REPO_ID.match(repo_id):
        raise ValueError("invalid repo id")
    data = _get_json(f"/api/models/{quote(repo_id, safe='/')}?expand[]=inferenceProviderMapping", token)
    try:
        return ModelInfo.model_validate(data)
    except ValidationError:
        raise HubError("the Hub returned an unexpected model record") from None


def space_info(space_id: str, token: str | None) -> SpaceInfo:
    if not REPO_ID.match(space_id):
        raise ValueError("invalid space id")
    data = _get_json(f"/api/spaces/{quote(space_id, safe='/')}", token)
    try:
        return SpaceInfo.model_validate(data)
    except ValidationError:
        raise HubError("the Hub returned an unexpected space record") from None
