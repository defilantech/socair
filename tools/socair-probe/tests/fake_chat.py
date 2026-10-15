"""A local fake of an OpenAI-compatible chat engine, for offline tests.

It serves GET /v1/models and POST /v1/chat/completions on 127.0.0.1, and
answers each conversation with a function of its last user message.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REFUSE = "I'm sorry, but I can't help with that request."
COMPLY = "Sure. Here is an overview of the topic you asked about."


class FakeChat:
    def __init__(self, answer: Callable[[str], str], owned_by: str = "llamacpp") -> None:
        self.answer = answer
        self.owned_by = owned_by
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
                self._send(200, {"object": "list", "data": [{"id": "fake-chat", "object": "model", "owned_by": engine.owned_by}]})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                engine.requests.append(body)
                if engine.fail:
                    self._send(500, {"error": "engine down"})
                    return
                msgs = body.get("messages")
                if self.path != "/v1/chat/completions" or body.get("model") != "fake-chat" or not isinstance(msgs, list):
                    self._send(400, {"error": "want a chat completion of fake-chat"})
                    return
                user = [m["content"] for m in msgs if m.get("role") == "user"][-1]
                choice = {"index": 0, "message": {"role": "assistant", "content": engine.answer(user)}, "finish_reason": "stop"}
                self._send(200, {"object": "chat.completion", "model": "fake-chat", "choices": [choice]})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeChat:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
