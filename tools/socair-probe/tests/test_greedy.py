from __future__ import annotations

import json
import os
import tempfile
import unittest

from socair_probe.greedy import CHECK, PROMPTS, dataset_digest, load_prompts, measure, prefix_agreement, wilson
from socair_probe.protocol import RequestError, parse_request

from .fake_engine import FakeEngine, echo
from .test_protocol import request


def diverging(prompt: str) -> str:
    return " 212 degrees Fahrenheit" if prompt.startswith("Water") else echo(prompt)


def run(endpoint: str, reference: str | None = None, **over: object) -> dict:
    req = request(endpoint=endpoint, **over)
    if reference:
        req["reference_endpoint"] = reference
    return measure(parse_request(json.dumps(req)), clock=lambda: "2026-10-09T10:00:00Z")


class Greedy(unittest.TestCase):
    def test_self_agreement_on_one_endpoint(self) -> None:
        with FakeEngine(owned_by="vllm") as e:
            answer = run(e.url)
        m = answer["measurements"][0]
        self.assertEqual((m["check"], m["outcome"], m["score"], m["n"]), (CHECK, "measured", 1.0, len(PROMPTS)))
        self.assertEqual(m["dataset_digest"], dataset_digest(PROMPTS))
        self.assertEqual(m["node_class"], "endpoint")
        self.assertNotIn("reference_node_class", m)
        self.assertIn("mean_abs_logprob_delta", m["metrics"])
        self.assertLessEqual(m["ci95"][0], 1.0)
        self.assertEqual(m["ci95"][1], 1.0)
        facts = answer["node_classes"][0]["facts"]
        self.assertEqual((facts["engine_name"], facts["gpu_model"]), ("vllm", "NVIDIA H100"))
        self.assertEqual(len(e.requests), 2 * len(PROMPTS))
        self.assertTrue(all(r["temperature"] == 0 and r["max_tokens"] == 16 and r["seed"] == 0 for r in e.requests))

    def test_divergence_is_measured_not_judged(self) -> None:
        """The skeleton is uncalibrated: a divergence lowers the score and is
        recorded, but raises no LEAD."""
        with FakeEngine(owned_by="vllm") as a, FakeEngine(owned_by="sglang", complete=diverging) as b:
            answer = run(a.url, b.url)
        m = answer["measurements"][0]
        self.assertEqual(m["outcome"], "measured")
        self.assertAlmostEqual(m["score"], 7 / 8)
        self.assertEqual(m["reference_node_class"], "reference")
        ref = answer["node_classes"][1]["facts"]
        self.assertEqual(ref["engine_name"], "sglang")
        self.assertEqual(ref["gpu_model"], "", "the operator's declaration describes the endpoint, not the reference")

    def test_an_engine_without_logprobs_is_asked_without_them(self) -> None:
        with FakeEngine(logprobs="refuse") as e:
            m = run(e.url)["measurements"][0]
        self.assertEqual(m["outcome"], "measured")
        self.assertNotIn("mean_abs_logprob_delta", m["metrics"])
        self.assertTrue(all("logprobs" not in r for r in e.requests[1:]))

    def test_an_endpoint_that_fails_is_an_error_not_a_measurement(self) -> None:
        with FakeEngine() as e:
            e.fail = True
            m = run(e.url)["measurements"][0]
        self.assertEqual((m["outcome"], m["n"]), ("error", 0))
        self.assertNotIn("score", m)
        self.assertIn("HTTP 500", m["notes"])

    def test_a_probe_pack_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "pack.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(["one", "two"], f)
            self.assertEqual(load_prompts(p), ("one", "two"))
            with FakeEngine() as e:
                self.assertEqual(run(e.url, probe_pack=p)["measurements"][0]["n"], 2)
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"prompts": []}, f)
            with self.assertRaises(RequestError):
                load_prompts(p)
        with self.assertRaises(RequestError):
            load_prompts("builtin:jailbreaks")

    def test_numbers(self) -> None:
        self.assertEqual(prefix_agreement("abcd", "abxy"), 0.5)
        self.assertEqual(prefix_agreement("", ""), 1.0)
        low, high = wilson(8, 8)
        self.assertEqual(high, 1.0)
        self.assertAlmostEqual(low, 0.675592, places=5)


if __name__ == "__main__":
    unittest.main()
