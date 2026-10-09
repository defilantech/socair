"""A local fake of an OpenAI-compatible engine, for offline tests.

It listens on 127.0.0.1 on a free port and serves GET /v1/models and greedy
POST /v1/completions, from a function of the prompt.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def echo(prompt: str) -> str:
    return " continuation of " + prompt


class FakeEngine:
    """logprobs: "give" returns token logprobs, "refuse" answers 400 to a
    request that asks for them, "ignore" leaves them out."""

    def __init__(self, owned_by: str = "fake-engine", complete: Callable[[str], str] = echo, logprobs: str = "give") -> None:
        self.owned_by = owned_by
        self.complete = complete
        self.logprobs = logprobs
        self.requests: list[dict[str, Any]] = []
        self.fail = False
        engine = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path != "/v1/models":
                    self._send(404, {"error": "not found"})
                    return
                self._send(200, {"object": "list", "data": [{"id": "fake-model", "object": "model", "owned_by": engine.owned_by}]})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                engine.requests.append(body)
                if engine.fail:
                    self._send(500, {"error": "engine down"})
                    return
                if self.path != "/v1/completions" or body.get("model") != "fake-model" or body.get("temperature") != 0:
                    self._send(400, {"error": "want a greedy completion of fake-model"})
                    return
                if "logprobs" in body and engine.logprobs == "refuse":
                    self._send(400, {"error": "logprobs not supported"})
                    return
                text = engine.complete(body["prompt"])
                choice: dict[str, Any] = {"index": 0, "text": text, "finish_reason": "length"}
                if "logprobs" in body and engine.logprobs == "give":
                    tokens = text.split(" ")
                    choice["logprobs"] = {"tokens": tokens, "token_logprobs": [-0.1 * (i + 1) for i in range(len(tokens))]}
                self._send(200, {"object": "text_completion", "model": "fake-model", "choices": [choice]})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeEngine:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
