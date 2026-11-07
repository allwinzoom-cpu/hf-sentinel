"""Protocol normalization (LSCAN-013): raw text completions are not wrapped in invented chat roles, native chat/Responses
semantics are preserved, and unsupported stateful ops fail explicitly."""
import pytest

from hfsentinel.targets.protocols import normalize, require_stateful, supports_stateful


def test_text_completion_is_read_as_text_without_invented_roles():
    n = normalize("text-completion", {"choices": [{"text": "plain output"}], "usage": {"total_tokens": 3}})
    assert n["text"] == "plain output" and n["role_invented"] is False and n["tool_calls"] == []


def test_chat_completions_preserve_content_tool_calls_and_refusal():
    raw = {"choices": [{"message": {"content": "hi", "tool_calls": [{"id": "1"}]}, "finish_reason": "content_filter"}]}
    n = normalize("chat-completions", raw)
    assert n["text"] == "hi" and n["tool_calls"] == [{"id": "1"}] and n["refusal"] is True


def test_responses_assemble_text_blocks_and_refusal():
    raw = {"output": [{"type": "message", "content": [{"type": "output_text", "text": "a"},
                                                       {"type": "output_text", "text": "b"}]},
                      {"type": "tool_use", "name": "t"}], "stop_reason": "refusal"}
    n = normalize("responses", raw)
    assert n["text"] == "ab" and n["refusal"] is True and n["tool_calls"] and n["tool_calls"][0]["name"] == "t"


def test_unknown_protocol_rejected():
    with pytest.raises(ValueError, match="unknown protocol"):
        normalize("grpc", {})


def test_stateful_is_only_claimed_where_supported():
    assert supports_stateful("responses") and not supports_stateful("chat-completions")
    require_stateful("responses")  # no raise
    with pytest.raises(NotImplementedError, match="no server-side stateful"):
        require_stateful("text-completion")
