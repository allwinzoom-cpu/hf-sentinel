"""Local helper-model server (plan 16.14): pinned ≤ 0.5B models behind an OpenAI-compatible /v1/chat/completions,
CPU-only and offline.

Every model's directory is verified against its pin (exact file set, size, sha256) before any loader touches it; a
mismatch stops the server (exit 3). Loading is local-files-only, safetensors-only, no remote code.
`chat` models answer chat messages; `nli` models take one user message whose content is JSON
{"premise": str, "hypothesis": str} and answer JSON {"label": ..., "scores": {...}}. Prompts are never logged.

    python server.py [--serve alias,...] [--host 0.0.0.0] [--port 8000]
    python server.py --selftest      # standard adapter → in-process server; for --network none containers
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hfsentinel.targets.local_hf import IntegrityError, load_manifest, verify_dir

MAX_BODY = 1_000_000
MAX_MESSAGES = 64
MAX_CHARS = 32_000
MAX_PROMPT_TOKENS = 4096
MAX_NEW_TOKENS = 512
NLI_MAX_CHARS = 4_000
EXIT_INTEGRITY = 3


class BadRequest(ValueError):
    pass


class ChatModel:
    def __init__(self, path: Path):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForCausalLM.from_pretrained(path, local_files_only=True, trust_remote_code=False,
                                                          use_safetensors=True, dtype=torch.float32).eval()

    def answer(self, messages: list[dict], max_tokens: int, temperature: float) -> tuple[str, str, dict]:
        enc = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_dict=True, return_tensors="pt")
        n_prompt = enc["input_ids"].shape[1]
        if n_prompt > MAX_PROMPT_TOKENS:
            raise BadRequest("prompt too long")
        sampling = {"do_sample": True, "temperature": temperature} if temperature > 0 else {"do_sample": False}
        with self.torch.inference_mode():
            out = self.model.generate(**enc, max_new_tokens=max_tokens, pad_token_id=self.tok.eos_token_id,
                                      **sampling)
        new = out[0, n_prompt:]
        text = self.tok.decode(new, skip_special_tokens=True)
        finish = "length" if len(new) >= max_tokens else "stop"
        return text, finish, {"prompt_tokens": n_prompt, "completion_tokens": len(new),
                              "total_tokens": n_prompt + len(new)}


class NLIModel:
    def __init__(self, path: Path):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            path, local_files_only=True, trust_remote_code=False, use_safetensors=True, dtype=torch.float32).eval()
        self.labels = [str(self.model.config.id2label[i]).lower() for i in range(self.model.config.num_labels)]

    def answer(self, messages: list[dict], max_tokens: int, temperature: float) -> tuple[str, str, dict]:
        if len(messages) != 1 or messages[0]["role"] != "user":
            raise BadRequest("nli models take one user message")
        try:
            pair = json.loads(messages[0]["content"])
            premise, hypothesis = pair["premise"], pair["hypothesis"]
        except (ValueError, KeyError, TypeError):
            raise BadRequest('nli content must be JSON {"premise": ..., "hypothesis": ...}') from None
        if not (isinstance(premise, str) and isinstance(hypothesis, str)
                and 0 < len(premise) <= NLI_MAX_CHARS and 0 < len(hypothesis) <= NLI_MAX_CHARS):
            raise BadRequest("premise and hypothesis must be non-empty strings")
        enc = self.tok(premise, hypothesis, truncation=True, max_length=512, return_tensors="pt")
        with self.torch.inference_mode():
            probs = self.model(**enc).logits.softmax(-1)[0].tolist()
        scores = {label: round(p, 4) for label, p in zip(self.labels, probs, strict=True)}
        text = json.dumps({"label": max(scores, key=lambda k: scores[k]), "scores": scores})
        n = enc["input_ids"].shape[1]
        return text, "stop", {"prompt_tokens": n, "completion_tokens": 0, "total_tokens": n}


def _validate(body: object, served: dict) -> tuple[str, list[dict], int, float]:
    if not isinstance(body, dict) or body.get("model") not in served:
        raise BadRequest("unknown model")
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not 0 < len(msgs) <= MAX_MESSAGES:
        raise BadRequest("messages must be a non-empty list")
    clean = []
    for m in msgs:
        if (not isinstance(m, dict) or m.get("role") not in ("system", "user", "assistant")
                or not isinstance(m.get("content"), str) or len(m["content"]) > MAX_CHARS):
            raise BadRequest("each message needs a role and text content")
        clean.append({"role": m["role"], "content": m["content"]})
    max_tokens, temperature = body.get("max_tokens", 256), body.get("temperature", 0.7)
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise BadRequest("max_tokens must be a positive integer")
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not 0 <= temperature <= 2:
        raise BadRequest("temperature must be in [0, 2]")
    return body["model"], clean, min(max_tokens, MAX_NEW_TOKENS), float(temperature)


def make_handler(served: dict):
    lock = threading.Lock()  # one generation at a time: bounded memory under the D-013 cap

    class Handler(BaseHTTPRequestHandler):
        timeout = 30  # slow clients cannot hold the single worker

        def log_message(self, format, *args):  # never log prompts or responses (D-015)
            pass

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/models":
                return self._send(200, {"object": "list", "data": [{"id": a, "object": "model"} for a in served]})
            self._send(404, {"error": {"message": "not found"}})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                return self._send(404, {"error": {"message": "not found"}})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    return self._send(413, {"error": {"message": "request body too large or empty"}})
                alias, msgs, max_tokens, temperature = _validate(json.loads(self.rfile.read(length)), served)
                with lock:
                    text, finish, usage = served[alias].answer(msgs, max_tokens, temperature)
            except (BadRequest, ValueError) as e:
                return self._send(400, {"error": {"message": str(e) if isinstance(e, BadRequest) else "bad request"}})
            except Exception:  # noqa: BLE001 — generic 500, never a traceback to the client
                return self._send(500, {"error": {"message": "internal error"}})
            self._send(200, {"object": "chat.completion", "model": alias, "usage": usage, "choices": [
                {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}]})

    return Handler


def load_models(aliases: list[str], models_dir: Path) -> dict:
    manifest = load_manifest()
    unknown = [a for a in aliases if a not in manifest]
    if unknown:
        raise SystemExit(f"unknown local models: {unknown}")
    for alias in aliases:  # verify everything before any loader runs
        try:
            verify_dir(models_dir / alias, manifest[alias])
        except IntegrityError as e:
            raise IntegrityError(f"{alias}: {e}") from None
    return {a: (ChatModel if manifest[a]["kind"] == "chat" else NLIModel)(models_dir / a) for a in aliases}


def selftest(served: dict) -> int:
    from hfsentinel.targets.openai_compat import OpenAICompatTarget, TargetError

    srv = HTTPServer(("127.0.0.1", 0), make_handler(served))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    nli_cases = [("A man is playing a guitar on stage.", "A person is playing an instrument.", "entailment"),
                 ("The cat is sleeping on the sofa.", "The cat is running in the garden.", "contradiction")]
    failures = 0
    for alias, model in served.items():
        target = OpenAICompatTarget(url, alias, max_requests=4, timeout=300)
        try:
            if isinstance(model, ChatModel):
                res = target.chat([{"role": "user", "content": "Reply with exactly one word: pong"}],
                                  max_tokens=16, temperature=0.0)
                ok = bool(res.text.strip())
                print(f"[{'OK' if ok else 'FAIL'}] {alias} chat -> {res.text.strip()[:40]!r} {res.usage}")
                failures += not ok
            else:
                for premise, hypothesis, want in nli_cases:
                    content = json.dumps({"premise": premise, "hypothesis": hypothesis})
                    got = json.loads(target.chat([{"role": "user", "content": content}]).text)
                    ok = got["label"] == want
                    print(f"[{'OK' if ok else 'FAIL'}] {alias} nli -> {got['label']} (want {want}) {got['scores']}")
                    failures += not ok
        except (TargetError, ValueError, KeyError) as e:
            print(f"[FAIL] {alias}: {type(e).__name__}: {e}")
            failures += 1
    srv.shutdown()
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="HF-Sentinel local helper-model server")
    ap.add_argument("--serve", default="", help="comma-separated aliases (default: every pinned model)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    import torch

    torch.set_num_threads(int(os.environ.get("HFS_THREADS", "2")))  # D-013 CPU cap
    aliases = [a for a in args.serve.split(",") if a] or list(load_manifest())
    try:
        served = load_models(aliases, Path(os.environ.get("HFS_MODELS_DIR", "/models")))
    except IntegrityError as e:
        print(f"[integrity] refusing to start: {e}", file=sys.stderr)
        return EXIT_INTEGRITY
    if args.selftest:
        return selftest(served)
    print(f"serving {', '.join(served)} on {args.host}:{args.port}", flush=True)
    HTTPServer((args.host, args.port), make_handler(served)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
