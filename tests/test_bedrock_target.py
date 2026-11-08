"""Bedrock Converse adapter (plan LSCAN-017): offline contract — per-model API compatibility (no universal URL),
pluggable signer, native normalization, region/profile recorded. Live smoke needs a real SigV4 signer + AWS creds."""
import json

import pytest

from hfsentinel.targets.bedrock_target import BedrockTarget, api_compatibility, normalize_converse, to_converse
from hfsentinel.targets.openai_compat import TargetError
from hfsentinel.targets.transport import Response

OK = {"output": {"message": {"content": [{"text": "hi"}]}}, "stopReason": "end_turn", "usage": {"inputTokens": 3}}


class FakeTransport:
    def __init__(self):
        self.seen = {}

    def request(self, method, url, *, headers, body=None, timeout=60.0, limit=0):
        self.seen = {"url": url, "headers": headers, "body": json.loads(body)}
        return Response(200, {}, json.dumps(OK).encode())


def _fake_signer(url, headers, body):
    return {**headers, "authorization": "AWS4-HMAC-SHA256 ..."}   # a stand-in; a real SigV4 signer is injected live


def test_per_model_api_compatibility_not_a_universal_url():
    assert api_compatibility("anthropic.claude-3") == "converse"
    assert api_compatibility("some.exotic-model") == "invoke-only"
    t = BedrockTarget("some.exotic-model", "us-east-1", signer=_fake_signer, transport=FakeTransport())
    with pytest.raises(TargetError, match="not Converse-compatible"):
        t.chat([{"role": "user", "content": "x"}])


def test_signer_required_and_converse_request_shape():
    nosign = BedrockTarget("anthropic.claude-3", "us-east-1", transport=FakeTransport())
    with pytest.raises(TargetError, match="SigV4 signer"):
        nosign.chat([{"role": "user", "content": "x"}])
    ft = FakeTransport()
    t = BedrockTarget("anthropic.claude-3", "us-east-1", signer=_fake_signer, transport=ft)
    r = t.chat([{"role": "system", "content": "S"}, {"role": "user", "content": "hi"}])
    assert r.text == "hi" and r.usage["inputTokens"] == 3
    assert ft.seen["body"]["system"] == [{"text": "S"}] and "/converse" in ft.seen["url"]
    assert ft.seen["headers"]["authorization"].startswith("AWS4")


def test_normalize_and_repro_identity():
    norm = normalize_converse({"output": {"message": {"content": [{"text": "a"}, {"toolUse": {"name": "f"}}]}},
                              "stopReason": "tool_use", "usage": {"inputTokens": 1}})
    assert norm["text"] == "a" and norm["tool_calls"] and norm["stop_reason"] == "tool_use"
    rid = BedrockTarget("anthropic.claude-3", "eu-west-1", inference_profile="prof-1").repro_identity()
    assert rid["region"] == "eu-west-1" and rid["inference_profile"] == "prof-1" and rid["api"] == "converse"
    _sys, turns = to_converse([{"role": "assistant", "content": "a"}])
    assert turns[0]["role"] == "assistant" and turns[0]["content"] == [{"text": "a"}]
