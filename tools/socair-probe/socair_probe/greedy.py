"""Greedy-continuation agreement: the skeleton's one measurement.

It continues a fixed prompt set greedily on the endpoint and on the reference
endpoint (or, with no reference, a second time on the endpoint) and measures
how often the two agree. It exercises the Tier 2 plumbing end to end. It is
not calibrated, so it raises no LEAD, and agreement is not a PASS.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .client import Completion, Engine, EngineError
from .protocol import PROTOCOL, Request, RequestError, empty_node_class

CHECK = "Greedy continuation agreement (Tier 2)"
SUITE = "socair-probe/greedy-agreement"
SUITE_VERSION = "0.1.0"

PROMPTS: tuple[str, ...] = (
    "The capital of France is",
    "def fibonacci(n):",
    "Water boils at sea level at a temperature of",
    "The three primary colors are",
    "Translate to French: good morning",
    "SELECT name FROM users WHERE",
    "The chemical symbol for gold is",
    "Once upon a time, in a small village,",
)

_MAX_PROMPTS = 1000
_MAX_PROMPT = 4096


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_prompts(probe_pack: str | None) -> tuple[str, ...]:
    """The built-in prompt set, or a JSON file holding a list of prompts."""
    if probe_pack in (None, "", "builtin:greedy-agreement"):
        return PROMPTS
    if probe_pack.startswith("builtin:"):
        raise RequestError(f"probe_pack {probe_pack!r} is not a built-in pack of this helper")
    try:
        with open(probe_pack, encoding="utf-8") as f:
            prompts = json.loads(f.read(_MAX_PROMPTS * _MAX_PROMPT + 1))
    except (OSError, ValueError) as e:
        raise RequestError(f"probe_pack {probe_pack!r}: {e}") from e
    if (
        not isinstance(prompts, list)
        or not 0 < len(prompts) <= _MAX_PROMPTS
        or not all(isinstance(p, str) and 0 < len(p) <= _MAX_PROMPT for p in prompts)
    ):
        raise RequestError(f"probe_pack {probe_pack!r} is not a list of 1 to {_MAX_PROMPTS} prompts")
    return tuple(prompts)


def dataset_digest(prompts: Sequence[str]) -> str:
    canonical = json.dumps(list(prompts), ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def wilson(k: int, n: int) -> list[float]:
    """The Wilson score interval, 95%, for k successes in n trials."""
    z = 1.959963984540054
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def prefix_agreement(a: str, b: str) -> float:
    """The share of the longer continuation that both begin with."""
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    common = 0
    for x, y in zip(a, b):
        if x != y:
            break
        common += 1
    return common / longest


def logprob_delta(a: Completion, b: Completion) -> float | None:
    """Mean absolute difference of token logprobs over the tokens both
    continuations share from the start, when both engines gave them."""
    if a.tokens is None or b.tokens is None or a.token_logprobs is None or b.token_logprobs is None:
        return None
    deltas = []
    for ta, tb, la, lb in zip(a.tokens, b.tokens, a.token_logprobs, b.token_logprobs):
        if ta != tb:
            break
        deltas.append(abs(la - lb))
    return sum(deltas) / len(deltas) if deltas else None


def _engine_label(facts: dict[str, Any], owned_by: str) -> str:
    label = " ".join(x for x in (facts.get("engine_name") or owned_by, facts.get("engine_version")) if x)
    return label or "unknown engine"


def measure(req: Request, clock: Callable[[], str] = now_utc, engine: Callable[[str], Engine] = Engine) -> dict[str, Any]:
    """Run the measurement and return the protocol answer."""
    prompts = load_prompts(req.probe_pack)
    started = clock()
    subject = engine(req.endpoint)
    reference = engine(req.reference_endpoint) if req.reference_endpoint else subject

    facts = dict(req.node_class)
    owned_by, notes = "", []
    try:
        owned_by = subject.owned_by()
    except EngineError as e:
        notes.append(f"the endpoint did not list its model: {e}")
    if not facts["engine_name"] and owned_by:
        facts["engine_name"] = owned_by
    classes = [{"id": "endpoint", "facts": facts}]

    measurement: dict[str, Any] = {
        "check": CHECK,
        "suite": SUITE,
        "suite_version": SUITE_VERSION,
        "dataset_digest": dataset_digest(prompts),
        "scorer": "deterministic",
        "decoding": req.decoding.as_json(),
        "engine": _engine_label(facts, owned_by),
        "node_class": "endpoint",
    }
    if req.reference_endpoint:
        # The operator's declaration describes the endpoint, not the reference;
        # of the reference this helper knows only what it lists.
        ref_facts = empty_node_class()
        try:
            ref_facts["engine_name"] = reference.owned_by()
        except EngineError as e:
            notes.append(f"the reference endpoint did not list its model: {e}")
        classes.append({"id": "reference", "facts": ref_facts})
        measurement["reference_node_class"] = "reference"
        against = "the reference endpoint"
    else:
        against = "a second pass on the same endpoint"

    exact, prefixes, deltas, done = 0, [], [], 0
    try:
        for prompt in prompts:
            a = subject.complete(prompt, req.decoding)
            b = reference.complete(prompt, req.decoding)
            done += 1
            exact += a.text == b.text
            prefixes.append(prefix_agreement(a.text, b.text))
            d = logprob_delta(a, b)
            if d is not None:
                deltas.append(d)
    except EngineError as e:
        notes.append(f"stopped after {done} of {len(prompts)} prompts: {e}")
        measurement |= {"n": done, "outcome": "error"}
    else:
        score = exact / len(prompts)
        metrics = {"exact_match_rate": round(score, 6), "mean_prefix_agreement": round(sum(prefixes) / len(prefixes), 6)}
        if len(deltas) == len(prompts):
            metrics["mean_abs_logprob_delta"] = round(sum(deltas) / len(deltas), 6)
        measurement |= {
            "n": len(prompts),
            "score": round(score, 6),
            "ci95": wilson(exact, len(prompts)),
            "metrics": metrics,
            "outcome": "measured",
        }
        notes.append(
            f"Greedy continuations on the endpoint compared with {against}; {exact} of {len(prompts)} identical. "
            "An uncalibrated plumbing measurement: it raises no LEAD, and agreement is not a PASS."
        )
    measurement |= {"started_utc": started, "ended_utc": clock(), "notes": " ".join(notes)}
    return {
        "protocol": PROTOCOL,
        "helper": {"name": "socair-probe", "version": __version__},
        "node_classes": classes,
        "measurements": [measurement],
    }
