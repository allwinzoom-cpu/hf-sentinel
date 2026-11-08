"""Streaming correctness (plan LSCAN-023): incremental parse robust to split UTF-8, incomplete tool-arg JSON, a missing
terminal event and a buffer cap; only complete validated tool calls are emitted and partial output is labelled."""
from hfsentinel.targets import streaming as st


def _sse(obj):
    import json
    return f"data: {json.dumps(obj)}\n".encode()


def _delta(content=None, tool=None):
    d = {}
    if content is not None:
        d["content"] = content
    if tool is not None:
        d["tool_calls"] = [tool]
    return {"choices": [{"delta": d}]}


def test_text_assembles_and_done_marks_complete():
    r = st.parse_stream([_sse(_delta("Hel")), _sse(_delta("lo")), b"data: [DONE]\n"])
    assert r.text == "Hello" and r.complete and not r.truncated


def test_split_multibyte_utf8_across_chunks_decodes_cleanly():
    blob = _sse(_delta("café"))                     # 'é' is two bytes
    r = st.parse_stream([blob[:len(blob) - 4], blob[len(blob) - 4:], b"data: [DONE]\n"])
    assert "café" in r.text and r.complete


def test_missing_terminal_event_is_truncated_not_complete():
    r = st.parse_stream([_sse(_delta("partial answer"))])   # no [DONE]
    assert r.text == "partial answer" and not r.complete and r.truncated and "truncated" in r.note


def test_only_complete_tool_call_json_is_emitted():
    good = st.parse_stream([_sse(_delta(tool={"index": 0, "function": {"name": "f", "arguments": "{\"a\":1}"}})),
                           b"data: [DONE]\n"])
    assert good.tool_calls == [{"name": "f", "arguments": {"a": 1}}]
    partial = st.parse_stream([_sse(_delta(tool={"index": 0, "function": {"name": "f", "arguments": "{\"a\":"}})),
                              b"data: [DONE]\n"])
    assert partial.tool_calls == [] and partial.truncated and "incomplete tool call" in partial.note


def test_buffer_cap_is_bounded_and_flagged():
    big = _sse(_delta("x" * 100))
    r = st.parse_stream([big] * 50 + [b"data: [DONE]\n"], max_bytes=200)
    assert r.truncated and "cap" in r.note
