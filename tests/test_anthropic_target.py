"""Native Anthropic Messages adapter (plan LSCAN-014): offline contract — system is top-level, the version header is
sent, the per-target key is isolated, and the response normalizes with native roles / tool calls / refusal semantics.
A live smoke needs an Anthropic key (GATE) and is not run here."""
import json

import pytest

from hfsentinel.targets.anthropic_target import AnthropicTarget, to_anthropic
from hfsentinel.targets.transport import Response


class FakeTransport:
    def __init__(self, payload, status=200):
        self.body = json.dumps(payload).encode()
        self.status = status
        self.seen = {}

    def request(self, method, url, *, headers, body=None, timeout=60.0, limit=0):
        self.seen = {"method": method, "url": url, "headers": headers, "body": json.loads(body)}
        return Response(self.status, {}, self.body)


def _target(payload, **kw):
    return AnthropicTarget("claude-x", api_key="sk-ant-TESTKEY", transport=FakeTransport(payload), **kw)


def test_system_is_top_level_and_version_header_and_key_are_sent():
    t = _target({"content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn", "model": "claude-x"})
    t.chat([{"role": "system", "content": "You are a bot."}, {"role": "user", "content": "hello"}])
    seen = t.transport.seen
    assert seen["body"]["system"] == "You are a bot."                 # system is a top-level field, not a user turn
    assert all(m["role"] in ("user", "assistant") for m in seen["body"]["messages"])
    assert seen["headers"]["anthropic-version"] and seen["headers"]["x-api-key"] == "sk-ant-TESTKEY"
    assert "authorization" not in {k.lower() for k in seen["headers"]}  # isolated key, not a bearer / HF token


def test_response_normalizes_text_tools_and_refusal():
    t = _target({"content": [{"type": "text", "text": "answer"},
                             {"type": "tool_use", "name": "calc", "input": {}}],
                 "stop_reason": "tool_use", "model": "claude-x", "usage": {"input_tokens": 5}})
    r = t.chat([{"role": "user", "content": "do it"}])
    assert r.text == "answer" and r.tool_calls and r.refusal is False and r.usage["input_tokens"] == 5

    ref = _target({"content": [], "stop_reason": "refusal", "model": "claude-x"})
    assert ref.chat([{"role": "user", "content": "x"}]).refusal is True   # native refusal stop_reason


def test_unsupported_extra_field_is_rejected_and_prefill_unsupported_is_not_a_success():
    t = _target({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
    with pytest.raises(ValueError, match="unsupported request fields"):
        t.chat([{"role": "user", "content": "x"}], extra={"bogus": 1})
    assert t.prefill(False) == "unsupported" and t.prefill(None) == "not-probed"


def test_to_anthropic_keeps_only_user_assistant_turns():
    system, turns = to_anthropic([{"role": "system", "content": "S"}, {"role": "user", "content": "u"},
                                  {"role": "assistant", "content": "a"}])
    assert system == "S" and [m["role"] for m in turns] == ["user", "assistant"]
