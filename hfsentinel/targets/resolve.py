"""Target URI → ResolvedTarget → client (plan §9.3 target syntax, `--via auto`).

`parse` is offline syntax only. `resolve` applies the `--via` policy: `auto` pins the target through read-only Hub
metadata (canonical repo id, a live provider, a Space's host); `direct` makes no Hub calls. Neither sends anything to
the target. `client` builds the adapter for a resolved target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from hfsentinel.targets import hub
from hfsentinel.targets.endpoint_contracts import endpoint_contract
from hfsentinel.targets.gradio_space import GradioSpaceTarget
from hfsentinel.targets.openai_compat import DEFAULT_USER_AGENT, HF_ROUTER, OpenAICompatTarget, _check_base_url

if TYPE_CHECKING:
    from hfsentinel.engines.governor import Governor

MAX_URI_LEN = 512
# Repo id per HF naming rules; the lookahead stays inside the part so it never reads into `@…` / `#…` suffixes.
_PART = r"(?![\w.-]*(?:--|\.\.))[A-Za-z0-9](?:[\w.-]{0,94}[A-Za-z0-9])?"
_REPO = rf"{_PART}/{_PART}"
_MODEL = r"[\w.:/@-]{1,200}"
PROVIDER_URI = re.compile(rf"^hf-provider://(?P<model>{_REPO})(?:@(?P<provider>[a-z0-9](?:[a-z0-9-]{{0,62}}[a-z0-9])?))?$",
                          re.ASCII)
ENDPOINT_URI = re.compile(r"^hf-endpoint://(?:https://)?(?P<host>[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*"
                          rf"\.endpoints\.huggingface\.cloud)/?(?:#(?P<model>{_MODEL}))?$", re.ASCII)
SPACE_URI = re.compile(rf"^hf-space://(?P<space>{_REPO})(?:@(?P<api>[A-Za-z0-9_]{{1,64}})|#(?P<model>{_MODEL}))?$",
                       re.ASCII)
JOB_URI = re.compile(rf"^hf-job://(?P<model>{_REPO})(?:@(?P<flavor>[a-z0-9][a-z0-9-]{{0,31}}))?$", re.ASCII)
OPENAI_URI = re.compile(rf"^openai\+(?P<base>https?://[^#\s]{{1,400}})#(?P<model>{_MODEL})$", re.ASCII)
JOB_DEFERRED = "hf-job targets are not supported in this build (HF Jobs deferred, D-004)"
VIA = ("auto", "direct")
# The dedicated-endpoint model identity is resolved from the endpoint contract (LSCAN-010), the single source of truth —
# `endpoint_contracts.ENDPOINT_DEFAULT_MODEL` is no longer duplicated here.


class TargetURIError(ValueError):
    """Malformed or disallowed target (message never echoes secrets)."""


class UnsupportedTarget(ValueError):
    """Valid target that this build cannot attack yet."""


@dataclass(frozen=True)
class ResolvedTarget:
    uri: str
    kind: str  # "hf-provider" | "hf-endpoint" | "hf-space" | "openai" | "hf-job"
    model: str | None = None
    base_url: str = ""
    provider: str | None = None
    space: str | None = None
    flavor: str | None = None
    api: str | None = None  # Gradio endpoint for hf-space apps; None = discovered at scan time
    notes: tuple[str, ...] = ()

    @property
    def request_model(self) -> str | None:
        """Model string sent to the endpoint (the router pins the provider as `model:provider`)."""
        return f"{self.model}:{self.provider}" if self.provider else self.model


def parse(uri: str) -> ResolvedTarget:
    if not isinstance(uri, str) or not uri or len(uri) > MAX_URI_LEN:
        raise TargetURIError(f"target URI must be 1-{MAX_URI_LEN} characters")
    if m := PROVIDER_URI.match(uri):
        return ResolvedTarget(uri, "hf-provider", m["model"], HF_ROUTER, provider=m["provider"])
    if m := ENDPOINT_URI.match(uri):
        # LSCAN-010: the model identity comes from the endpoint contract (TGI serves any model under the default name).
        model = m["model"] or endpoint_contract("chat")["model"]
        return ResolvedTarget(uri, "hf-endpoint", model, f"https://{m['host']}/v1")
    if m := SPACE_URI.match(uri):
        return ResolvedTarget(uri, "hf-space", m["model"], space=m["space"], api=m["api"])
    if m := JOB_URI.match(uri):
        return ResolvedTarget(uri, "hf-job", m["model"], flavor=m["flavor"])
    if m := OPENAI_URI.match(uri):
        u = urlparse(m["base"])
        if u.username or u.password:
            raise TargetURIError("credentials in target URLs are not allowed; use a token file or environment")
        try:
            base = _check_base_url(m["base"])
        except ValueError as e:
            raise TargetURIError(str(e)) from None
        return ResolvedTarget(uri, "openai", m["model"], base)
    if uri.startswith("hf-endpoint://"):
        raise TargetURIError("hf-endpoint targets must be an *.endpoints.huggingface.cloud host "
                             "(use openai+https://host/v1#model for other endpoints)")
    raise TargetURIError("unrecognised target URI; expected hf-provider://org/model[@provider], "
                         "hf-endpoint://<host>[#model], hf-space://owner/space[@api|#model], "
                         "openai+https://host/v1#model or hf-job://org/model[@flavor]")


def resolve(target: ResolvedTarget, *, via: str = "auto", token: str | None = None) -> ResolvedTarget:
    """Apply the `--via` policy. Raises TargetURIError / UnsupportedTarget / hub.HubError."""
    if via not in VIA:
        raise TargetURIError(f"--via must be one of {', '.join(VIA)}")
    if target.kind == "hf-job":
        raise UnsupportedTarget(JOB_DEFERRED)
    if via == "direct":
        if target.kind == "hf-provider" and not target.provider:
            raise TargetURIError("--via direct needs a pinned provider: hf-provider://org/model@provider")
        if target.kind == "hf-space":
            raise TargetURIError("hf-space targets need --via auto (the Space host comes from the Hub)")
        return target
    if target.kind == "hf-provider":
        return _pin_provider(target, token)
    if target.kind == "hf-space":
        return _resolve_space(target, token)
    return target


def _pin_provider(t: ResolvedTarget, token: str | None) -> ResolvedTarget:
    info = hub.model_info(t.model, token)
    live = info.live_chat_providers()
    notes = [f"canonical id {info.id} (requested {t.model})"] if info.id != t.model else []
    if t.provider:
        if t.provider not in live:
            raise TargetURIError(f"provider {t.provider} is not live for {info.id}; live: {', '.join(live) or 'none'}")
        provider = t.provider
    else:
        if not live:
            raise UnsupportedTarget(f"no live Inference Provider serves {info.id}; "
                                    "the Job fallback is deferred (D-004)")
        provider = live[0]
        notes.append("provider auto-selected (first live chat provider listed by the Hub)")
    if others := [p for p in live if p != provider]:
        notes.append("also live: " + ", ".join(others))
    return replace(t, model=info.id, provider=provider, notes=tuple(notes))


def _resolve_space(t: ResolvedTarget, token: str | None) -> ResolvedTarget:
    info = hub.space_info(t.space, token)
    notes = [f"sdk {info.sdk or 'unknown'} · stage {info.runtime.stage}"]
    if info.runtime.stage != "RUNNING":
        notes.append("space is not running; first requests may fail or wake it")
    if not t.model:
        notes.append(f"Gradio app: endpoint /{t.api} pinned" if t.api else
                     "Gradio app: single-turn text endpoint chosen at scan time (/chat preferred; pin with @api)")
    return replace(t, space=info.id, base_url=f"{info.host}/v1" if t.model else info.host, notes=tuple(notes))


def client(target: ResolvedTarget, token: str | None, *, max_requests: int, governor: Governor | None = None,
           user_agent: str = DEFAULT_USER_AGENT) -> OpenAICompatTarget | GradioSpaceTarget:
    """HF tokens go only to HF-operated hosts (router, *.endpoints.huggingface.cloud, *.hf.space). A shared
    governor (plan 16.9) paces and meters every attempt."""
    kind = target.kind
    limits = {"max_requests": max_requests, "governor": governor, "user_agent": user_agent}
    if kind == "hf-job":
        raise UnsupportedTarget(JOB_DEFERRED)
    if kind == "hf-provider":
        if not token:
            raise TargetURIError("hf-provider targets need an HF token")
        return OpenAICompatTarget(HF_ROUTER, target.request_model, api_key=token, **limits)
    if kind == "hf-space":
        if not target.base_url:
            raise TargetURIError("hf-space targets must be resolved with --via auto first")
        if not target.model:
            return GradioSpaceTarget(target.base_url, target.api, api_key=token or "", **limits)
        return OpenAICompatTarget(target.base_url, target.model, api_key=token or "", **limits)
    if kind == "hf-endpoint":
        return OpenAICompatTarget(target.base_url, target.model, api_key=token or "", **limits)
    return OpenAICompatTarget(target.base_url, target.model, **limits)
