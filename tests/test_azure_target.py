"""Azure/Foundry adapter (plan LSCAN-016): offline contract — deployment routing distinct from public model, api-version
pinned, credential origin-bound and absent from repro, retry reuses the same deployment URL. Live smoke needs a key."""
import json

from hfsentinel.targets.azure_target import AzureTarget
from hfsentinel.targets.credentials import Credential
from hfsentinel.targets.transport import Response

OK = {"model": "gpt-x", "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]}


class FakeTransport:
    def __init__(self):
        self.seen = {}

    def request(self, method, url, *, headers, body=None, timeout=60.0, limit=0):
        self.seen = {"url": url, "headers": headers, "body": json.loads(body)}
        return Response(200, {}, json.dumps(OK).encode())


def _t():
    ft = FakeTransport()
    cred = Credential.for_url("azkey", "https://r.openai.azure.com", header="api-key", scheme="")
    return AzureTarget("https://r.openai.azure.com", "my-deploy", "gpt-4o", credential=cred, transport=ft), ft


def test_deployment_routing_api_version_and_bound_key():
    t, ft = _t()
    r = t.chat([{"role": "user", "content": "hello"}])
    assert r.text == "hi"
    assert "/openai/deployments/my-deploy/chat/completions" in ft.seen["url"] and "api-version=" in ft.seen["url"]
    assert ft.seen["headers"]["api-key"] == "azkey"           # origin-bound credential emitted
    assert "model" not in ft.seen["body"]                     # the deployment routes; no model in body


def test_repro_separates_deployment_from_model_and_omits_the_secret():
    t, _ = _t()
    rid = t.repro_identity()
    assert rid["deployment"] == "my-deploy" and rid["model"] == "gpt-4o"   # distinct identities
    assert "azkey" not in json.dumps(rid) and "azkey" not in repr(t)       # credential never in repro/repr


def test_retry_reuses_the_same_deployment_url():
    t, ft = _t()
    first = t.url
    t.chat([{"role": "user", "content": "a"}])
    t.chat([{"role": "user", "content": "b"}])
    assert t.url == first and "my-deploy" in ft.seen["url"]   # a second call hits the same pinned deployment
