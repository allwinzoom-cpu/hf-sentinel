"""Native Anthropic Messages normalization (LSCAN-014): preserve typed blocks / tool-use / refusal; an unsupported
prefill is never a successful check."""
from hfsentinel.targets.anthropic_messages import normalize_messages, prefill_outcome


def test_text_and_tool_use_blocks_are_preserved():
    raw = {"content": [{"type": "text", "text": "hel"}, {"type": "text", "text": "lo"},
                       {"type": "tool_use", "name": "t", "input": {}}],
           "stop_reason": "tool_use", "usage": {"input_tokens": 5}}
    n = normalize_messages(raw)
    assert n["text"] == "hello" and n["tool_calls"] and n["tool_calls"][0]["name"] == "t"
    assert n["refusal"] is False and n["role_invented"] is False and n["usage"]["input_tokens"] == 5


def test_refusal_stop_reason_is_a_refusal():
    assert normalize_messages({"content": [], "stop_reason": "refusal"})["refusal"] is True


def test_thinking_blocks_are_flagged_not_treated_as_answer_text():
    n = normalize_messages({"content": [{"type": "thinking", "thinking": "..."},
                                        {"type": "text", "text": "answer"}], "stop_reason": "end_turn"})
    assert n["thinking_present"] is True and n["text"] == "answer"


def test_unsupported_prefill_is_never_a_success():
    assert prefill_outcome(True) == "supported"
    assert prefill_outcome(False) == "unsupported"   # rejected -> unsupported, not a successful check
    assert prefill_outcome(None) == "not-probed"
