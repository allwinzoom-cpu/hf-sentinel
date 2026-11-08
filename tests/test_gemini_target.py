"""Native Gemini GenerateContent adapter (plan LSCAN-015): offline contract — systemInstruction is top-level, the key is
isolated, and blocked / empty / answered outcomes stay distinct. A live smoke needs a Google key (GATE)."""
import json

from hfsentinel.targets.gemini_target import GeminiTarget, normalize_generate_content, outcome, to_gemini
from hfsentinel.targets.transport import Response


class FakeTransport:
    def __init__(self, payload, status=200):
        self.body, self.status, self.seen = json.dumps(payload).encode(), status, {}

    def request(self, method, url, *, headers, body=None, timeout=60.0, limit=0):
        self.seen = {"url": url, "headers": headers, "body": json.loads(body)}
        return Response(self.status, {}, self.body)


def _target(payload):
    return GeminiTarget("gemini-x", api_key="goog-TESTKEY", transport=FakeTransport(payload))


def test_system_instruction_top_level_isolated_key_and_native_roles():
    t = _target({"candidates": [{"content": {"parts": [{"text": "hi"}]}, "finishReason": "STOP"}]})
    t.chat([{"role": "system", "content": "be a bot"}, {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hey"}])
    seen = t.transport.seen
    assert seen["body"]["systemInstruction"]["parts"][0]["text"] == "be a bot"      # top-level, native
    assert [c["role"] for c in seen["body"]["contents"]] == ["user", "model"]        # assistant -> native 'model'
    assert seen["headers"]["x-goog-api-key"] == "goog-TESTKEY" and ":generateContent" in seen["url"]
    assert "key=" not in seen["url"]                                                 # no URL-embedded secret


def test_blocked_empty_and_answered_outcomes_are_distinct():
    assert outcome({"promptFeedback": {"blockReason": "SAFETY"}}) == "blocked"
    assert outcome({"candidates": [{"content": {"parts": [{"text": "SURE here"}]}, "finishReason": "SAFETY"}]}) == "blocked"
    assert outcome({"candidates": []}) == "empty"
    assert outcome({"candidates": [{"content": {"parts": [{"text": "answer"}]}, "finishReason": "STOP"}]}) == "answered"


def test_block_is_a_refusal_signal_not_a_produced_answer():
    r = _target({"promptFeedback": {"blockReason": "SAFETY"}, "candidates": []}).chat([{"role": "user", "content": "x"}])
    assert r.refusal is True and r.text == ""                 # a platform block is never a produced answer
    ans = normalize_generate_content({"candidates": [{"content": {"parts": [
        {"text": "a"}, {"functionCall": {"name": "f"}}]}, "finishReason": "STOP"}]})
    assert ans["text"] == "a" and ans["tool_calls"] and not ans["blocked"]


def test_to_gemini_maps_roles_and_system():
    sysi, contents = to_gemini([{"role": "system", "content": "S"}, {"role": "assistant", "content": "a"}])
    assert sysi["parts"][0]["text"] == "S" and contents[0]["role"] == "model"
