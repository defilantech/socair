"""A minimal OpenAI-compatible client, stdlib only (urllib).

It talks to the endpoint directly: proxy settings are ignored, because the
endpoint is the site's own engine and a probe has no reason to leave the
node. SOCAIR_PROBE_API_KEY, when set, is sent as a bearer token.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .protocol import Decoding

_MAX_BODY = 4 << 20


class EngineError(Exception):
    """The endpoint did not answer as an OpenAI-compatible engine."""


@dataclass(frozen=True)
class Completion:
    text: str
    tokens: list[str] | None
    token_logprobs: list[float] | None


class Engine:
    def __init__(self, base_url: str, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = os.environ.get("SOCAIR_PROBE_API_KEY") or None
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self._logprobs = True
        self._models: list[dict[str, Any]] | None = None

    def _call(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base_url + path, data=data, method="GET" if body is None else "POST")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            e.close()
            raise EngineError(f"{path}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise EngineError(f"{path}: {e}") from e
        if len(raw) > _MAX_BODY:
            raise EngineError(f"{path}: answer over {_MAX_BODY} bytes")
        try:
            out = json.loads(raw)
        except ValueError as e:
            raise EngineError(f"{path}: not JSON") from e
        if not isinstance(out, dict):
            raise EngineError(f"{path}: not a JSON object")
        return out

    def models(self) -> list[dict[str, Any]]:
        if self._models is None:
            data = self._call("/v1/models").get("data")
            if not isinstance(data, list) or not data or not all(isinstance(m, dict) for m in data):
                raise EngineError("/v1/models lists no model")
            self._models = data
        return self._models

    def model_id(self) -> str:
        """The model to probe: SOCAIR_PROBE_MODEL, else the first one listed."""
        wanted = os.environ.get("SOCAIR_PROBE_MODEL")
        if wanted:
            return wanted
        return str(self.models()[0].get("id", ""))

    def owned_by(self) -> str:
        return str(self.models()[0].get("owned_by", ""))

    def complete(self, prompt: str, decoding: Decoding) -> Completion:
        """A completion with the given decoding, with token logprobs when the
        engine gives them. An engine that refuses the logprobs parameter is
        asked again without it, and not asked for them again."""
        body: dict[str, Any] = {"model": self.model_id(), "prompt": prompt, **decoding.as_json()}
        if self._logprobs:
            try:
                return _completion(self._call("/v1/completions", {**body, "logprobs": 1}))
            except EngineError as e:
                if "HTTP 400" not in str(e):
                    raise
                self._logprobs = False
        return _completion(self._call("/v1/completions", body))


def _completion(resp: dict[str, Any]) -> Completion:
    choices = resp.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise EngineError("/v1/completions: want exactly one choice")
    text = choices[0].get("text")
    if not isinstance(text, str):
        raise EngineError("/v1/completions: the choice has no text")
    tokens = logprobs = None
    lp = choices[0].get("logprobs")
    if isinstance(lp, dict):
        t, p = lp.get("tokens"), lp.get("token_logprobs")
        if isinstance(t, list) and isinstance(p, list) and len(t) == len(p):
            if all(isinstance(x, str) for x in t) and all(isinstance(x, (int, float)) for x in p):
                tokens, logprobs = t, [float(x) for x in p]
    return Completion(text=text, tokens=tokens, token_logprobs=logprobs)
