"""Streaming correctness, cancellation and accounting (plan LSCAN-023). An incremental SSE parser for OpenAI-style
`data:` streams that is safe under partial input: split multi-byte UTF-8 is decoded incrementally, tool-call arguments
are buffered until they are COMPLETE, VALID JSON (only then emitted), the buffer is bounded, and a stream that ends
without its terminal `[DONE]` event is reported incomplete/truncated — never as a clean finish. Partial text is always
labelled. Pure over fed chunks; no network, so it is fully offline-testable."""
from __future__ import annotations

import codecs
import json
from dataclasses import dataclass

MAX_STREAM_BYTES = 2_000_000


@dataclass
class StreamResult:
    text: str
    tool_calls: list[dict]      # only complete, validated tool calls
    usage: dict
    complete: bool              # the terminal [DONE] event was seen
    truncated: bool             # a buffer cap or a dropped incomplete tool call occurred
    note: str = ""


class StreamParser:
    """Feed raw byte chunks with `feed()`, then call `result()`. Idempotent terminal handling; bounded memory."""

    def __init__(self, *, max_bytes: int = MAX_STREAM_BYTES) -> None:
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="strict")
        self._line = ""
        self._text: list[str] = []
        self._tool_args: dict[int, str] = {}
        self._tool_names: dict[int, str] = {}
        self._usage: dict = {}
        self._done = False
        self._bytes = 0
        self._capped = False
        self._max = max_bytes

    def feed(self, chunk: bytes) -> None:
        self._bytes += len(chunk)
        if self._bytes > self._max:
            self._capped = True
            return                                  # stop accumulating past the cap (bounded memory)
        try:
            text = self._dec.decode(chunk)          # incremental: a split multi-byte char waits for the next chunk
        except UnicodeDecodeError:
            self._capped = True
            return
        self._line += text
        while "\n" in self._line:
            line, self._line = self._line.split("\n", 1)
            self._handle(line.strip())

    def _handle(self, line: str) -> None:
        if not line.startswith("data:"):
            return
        payload = line[5:].strip()
        if payload == "[DONE]":
            self._done = True
            return
        try:
            obj = json.loads(payload)
        except ValueError:
            return                                   # an incomplete/partial JSON event is skipped, never half-parsed
        if "usage" in obj and isinstance(obj["usage"], dict):
            self._usage = obj["usage"]
        for choice in obj.get("choices", []) or []:
            delta = choice.get("delta", {}) or {}
            if isinstance(delta.get("content"), str):
                self._text.append(delta["content"])
            for tc in delta.get("tool_calls", []) or []:
                idx = tc.get("index", 0)
                fn = tc.get("function", {}) or {}
                if fn.get("name"):
                    self._tool_names[idx] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    self._tool_args[idx] = self._tool_args.get(idx, "") + fn["arguments"]

    def result(self) -> StreamResult:
        tools, dropped = [], False
        for idx, args in sorted(self._tool_args.items()):
            try:
                parsed = json.loads(args) if args.strip() else {}
            except ValueError:
                dropped = True                        # incomplete tool-argument JSON: never emitted as a tool call
                continue
            tools.append({"name": self._tool_names.get(idx, ""), "arguments": parsed})
        truncated = self._capped or not self._done or dropped
        note = ("buffer cap reached" if self._capped else
                "no terminal [DONE] — stream truncated" if not self._done else
                "dropped an incomplete tool call" if dropped else "")
        return StreamResult(text="".join(self._text), tool_calls=tools, usage=self._usage,
                            complete=self._done, truncated=truncated, note=note)


def parse_stream(chunks: list[bytes], *, max_bytes: int = MAX_STREAM_BYTES) -> StreamResult:
    """Convenience: feed an ordered list of byte chunks and return the result."""
    p = StreamParser(max_bytes=max_bytes)
    for c in chunks:
        p.feed(c)
    return p.result()
