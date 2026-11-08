"""Azure / AI Foundry deployment target adapter (plan LSCAN-016). Azure routes by DEPLOYMENT name, not the public model
name, with an api-version and an isolated credential (api-key header or a refreshed bearer). This adapter records the
deployment name AND the public model name as distinct fields, binds the credential to the Azure origin (never the HF
token, never in a report/repro), and pins the deployment so a retry/token-renewal can never change which deployment is
hit. The body/response are OpenAI-compatible, so parsing is shared. Offline contract tested; a live smoke needs an Azure
key (GATE)."""
from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import dataclass, field

from hfsentinel.targets.credentials import Credential, auth_for
from hfsentinel.targets.openai_compat import (
    DEFAULT_USER_AGENT,
    MAX_RESPONSE_BYTES,
    BudgetExceeded,
    ChatResult,
    TargetError,
    check_user_agent,
    parse_chat_response,
)
from hfsentinel.targets.transport import SHARED as SHARED_TRANSPORT
from hfsentinel.targets.transport import Transport, TransportError


@dataclass
class AzureTarget:
    endpoint: str                  # e.g. https://my-resource.openai.azure.com
    deployment: str                # the Azure deployment name (routing identity)
    model: str                     # the public model name the deployment serves (recorded, distinct from deployment)
    api_version: str = "2024-06-01"
    credential: Credential | None = field(default=None, repr=False)  # api-key or bearer, origin-bound
    timeout: float = 60.0
    max_requests: int = 100
    requests_made: int = 0
    governor: object | None = field(default=None, repr=False)
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = field(default=SHARED_TRANSPORT, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.user_agent = check_user_agent(self.user_agent)

    @property
    def url(self) -> str:
        # the deployment is pinned into the URL; a retry/renewal reuses this exact URL, never a different deployment
        return (f"{self.endpoint.rstrip('/')}/openai/deployments/{self.deployment}"
                f"/chat/completions?api-version={self.api_version}")

    @property
    def rate_key(self) -> tuple[str, str]:
        return (f"{self.endpoint}/{self.deployment}", self.model)

    def chat(self, messages: list[dict], *, max_tokens: int = 256, temperature: float = 0.7,
             extra: dict | None = None) -> ChatResult:
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"request cap {self.max_requests} reached")
        body = {"messages": messages, "max_tokens": max_tokens, "temperature": temperature}  # no model: deployment routes
        headers = {"content-type": "application/json", "user-agent": self.user_agent}
        if self.credential:
            headers.update(auth_for(self.credential, self.url))   # emitted only if bound to this Azure origin
        url, gov, key = self.url, self.governor, self.rate_key
        self.requests_made += 1
        try:
            with gov.slot(key) if gov else nullcontext():
                resp = self.transport.request("POST", url, headers=headers, body=json.dumps(body).encode(),
                                              timeout=self.timeout, limit=MAX_RESPONSE_BYTES)
        except TransportError:
            if gov:
                gov.record(key, None)
            raise TargetError("target unreachable") from None   # message carries no secret
        if not (200 <= resp.status < 300):
            if gov:
                gov.record(key, resp.status, retry_after=resp.headers.get("retry-after"))
            raise TargetError(f"target returned HTTP {resp.status}", status=resp.status)
        result = parse_chat_response(resp.body, self.model)       # OpenAI-compatible response shape
        if gov:
            gov.record(key, 200, usage=result.usage)
        return result

    def repro_identity(self) -> dict:
        """What a report/repro records — deployment and public model are distinct; the credential never appears."""
        return {"endpoint": self.endpoint, "deployment": self.deployment, "model": self.model,
                "api_version": self.api_version}
