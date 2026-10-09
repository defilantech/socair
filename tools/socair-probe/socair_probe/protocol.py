"""The socair.tier2/v1 protocol, as the helper speaks it (docs/tier2.md).

Both sides are strict. Socair refuses an answer with an unknown field, and the
helper refuses a request with one, so a version mismatch fails loudly instead
of being half understood.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

PROTOCOL = "socair.tier2/v1"
NODE_CLASS_SCHEMA = "socair.nodeclass/v1"

# Every field of the node-class record and its kind. An unreported text field
# is "", an unreported count 0, an unreported switch None (unknown, not off).
NODE_CLASS_FIELDS: dict[str, type] = {
    "schema": str,
    "gpu_model": str,
    "compute_capability": str,
    "gpu_count": int,
    "interconnect": str,
    "driver": str,
    "vbios": str,
    "ecc": bool,
    "mig": str,
    "cc_mode": str,
    "cuda": str,
    "cublas": str,
    "cudnn": str,
    "nccl": str,
    "container_image_digest": str,
    "engine_name": str,
    "engine_version": str,
    "engine_commit": str,
    "dtype": str,
    "weight_quantization": str,
    "kv_cache_quantization": str,
    "tensor_parallel_size": int,
    "pipeline_parallel_size": int,
    "expert_parallel_size": int,
    "attention_backend": str,
    "cuda_graphs": bool,
    "torch_compile": bool,
    "eager": bool,
    "batch_invariant": bool,
    "prefix_caching": bool,
    "chunked_prefill": bool,
    "speculative_decoding": str,
    "env": dict,
}

_REQUEST = {"protocol", "artifact", "endpoint", "reference_endpoint", "probe_pack", "node_class", "decoding", "limits"}
_ARTIFACT = {"path", "sha256", "file_name", "format"}
_DECODING = {"temperature", "top_p", "max_tokens", "seed"}
_LIMITS = {"max_response_bytes", "max_measurements", "timeout_seconds"}


class RequestError(ValueError):
    """A request this helper does not accept."""


@dataclass(frozen=True)
class Decoding:
    temperature: float
    top_p: float
    max_tokens: int
    seed: int | None

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"temperature": self.temperature, "top_p": self.top_p, "max_tokens": self.max_tokens}
        if self.seed is not None:
            out["seed"] = self.seed
        return out


@dataclass(frozen=True)
class Request:
    endpoint: str
    reference_endpoint: str | None
    probe_pack: str | None
    node_class: dict[str, Any]
    decoding: Decoding
    artifact: dict[str, str]
    max_response_bytes: int
    max_measurements: int


def _object(value: Any, where: str, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RequestError(f"{where} is not an object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RequestError(f"{where} has unknown fields: {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise RequestError(f"{where} is missing: {', '.join(missing)}")
    return value


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RequestError(f"{where} is not a number")
    return float(value)


def _integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestError(f"{where} is not an integer")
    return value


def _url(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        raise RequestError(f"{where} is not an http(s) URL")
    return value.rstrip("/")


def empty_node_class() -> dict[str, Any]:
    """A node-class record with every field present and unreported."""
    blank: dict[type, Any] = {str: "", int: 0, bool: None, dict: {}}
    out = {name: blank[kind] for name, kind in NODE_CLASS_FIELDS.items()}
    out["schema"] = NODE_CLASS_SCHEMA
    return out


def node_class(declared: dict[str, Any] | None) -> dict[str, Any]:
    """A complete record from a declared subset, kinds checked."""
    out = empty_node_class()
    for name, value in (declared or {}).items():
        kind = NODE_CLASS_FIELDS.get(name)
        if kind is None:
            raise RequestError(f"node_class has an unknown field: {name}")
        ok = value is None and kind in (bool, dict)
        ok = ok or (isinstance(value, kind) and not (kind is int and isinstance(value, bool)))
        if kind is dict and isinstance(value, dict):
            ok = all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
        if not ok:
            raise RequestError(f"node_class.{name} is not a {kind.__name__}")
        out[name] = {} if value is None and kind is dict else value
    if out["schema"] != NODE_CLASS_SCHEMA:
        raise RequestError(f"node_class.schema is {out['schema']!r}, want {NODE_CLASS_SCHEMA!r}")
    return out


def parse_request(raw: str | bytes) -> Request:
    """Read a request strictly: every object closed, every field typed."""
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise RequestError(f"the request is not JSON: {e}") from e
    req = _object(doc, "the request", _REQUEST, {"protocol", "artifact", "endpoint", "node_class", "decoding", "limits"})
    if req["protocol"] != PROTOCOL:
        raise RequestError(f"protocol {req['protocol']!r}, want {PROTOCOL!r}")
    artifact = _object(req["artifact"], "artifact", _ARTIFACT, _ARTIFACT)
    if not all(isinstance(v, str) for v in artifact.values()):
        raise RequestError("artifact fields must be strings")
    dec = _object(req["decoding"], "decoding", _DECODING, {"temperature", "top_p", "max_tokens"})
    seed = dec.get("seed")
    decoding = Decoding(
        temperature=_number(dec["temperature"], "decoding.temperature"),
        top_p=_number(dec["top_p"], "decoding.top_p"),
        max_tokens=_integer(dec["max_tokens"], "decoding.max_tokens"),
        seed=None if seed is None else _integer(seed, "decoding.seed"),
    )
    if decoding.max_tokens < 1 or not 0 < decoding.top_p <= 1 or decoding.temperature < 0:
        raise RequestError("decoding is out of range")
    limits = _object(req["limits"], "limits", _LIMITS, _LIMITS)
    reference = req.get("reference_endpoint")
    probe_pack = req.get("probe_pack")
    if probe_pack is not None and not isinstance(probe_pack, str):
        raise RequestError("probe_pack is not a string")
    return Request(
        endpoint=_url(req["endpoint"], "endpoint"),
        reference_endpoint=None if reference in (None, "") else _url(reference, "reference_endpoint"),
        probe_pack=probe_pack or None,
        node_class=node_class(req["node_class"]),
        decoding=decoding,
        artifact=artifact,
        max_response_bytes=_integer(limits["max_response_bytes"], "limits.max_response_bytes"),
        max_measurements=_integer(limits["max_measurements"], "limits.max_measurements"),
    )


def dumps(answer: dict[str, Any]) -> str:
    """The answer as compact JSON. NaN and infinity are not JSON, so they are
    refused here rather than by Socair."""
    return json.dumps(answer, allow_nan=False, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
