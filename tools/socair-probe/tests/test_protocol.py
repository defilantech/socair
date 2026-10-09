from __future__ import annotations

import json
import os
import unittest
from typing import Any

from socair_probe.protocol import NODE_CLASS_FIELDS, PROTOCOL, RequestError, dumps, empty_node_class, parse_request

SCHEMA = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "report-schema", "v1.json")


def request(**over: Any) -> dict[str, Any]:
    req: dict[str, Any] = {
        "protocol": PROTOCOL,
        "artifact": {"path": "/snap/m.gguf", "sha256": "a" * 64, "file_name": "m.gguf", "format": "GGUF"},
        "endpoint": "http://127.0.0.1:8000/",
        "node_class": {"gpu_model": "NVIDIA H100", "gpu_count": 8, "cuda_graphs": True},
        "decoding": {"temperature": 0, "top_p": 1, "max_tokens": 16, "seed": 0},
        "limits": {"max_response_bytes": 1 << 20, "max_measurements": 256, "timeout_seconds": 60},
    }
    req.update(over)
    return req


class ParseRequest(unittest.TestCase):
    def test_reads_a_request(self) -> None:
        r = parse_request(json.dumps(request()))
        self.assertEqual(r.endpoint, "http://127.0.0.1:8000")
        self.assertEqual(r.node_class["gpu_model"], "NVIDIA H100")
        self.assertIsNone(r.node_class["ecc"], "an undeclared switch is unknown, not off")
        self.assertEqual(r.decoding.seed, 0)

    def test_refuses_what_it_does_not_speak(self) -> None:
        cases = {
            "unknown field": request(verdict="safe"),
            "other protocol": request(protocol="socair.tier2/v0"),
            "unknown fact": request(node_class={"gpu": "H100"}),
            "fact of the wrong kind": request(node_class={"gpu_count": "eight"}),
            "bool as a count": request(node_class={"gpu_count": True}),
            "not a URL": request(endpoint="127.0.0.1:8000"),
            "unknown decoding": request(decoding={"temperature": 0, "top_p": 1, "max_tokens": 16, "beam": 4}),
            "zero tokens": request(decoding={"temperature": 0, "top_p": 1, "max_tokens": 0}),
            "no limits": {k: v for k, v in request().items() if k != "limits"},
        }
        for name, req in cases.items():
            with self.subTest(name), self.assertRaises(RequestError):
                parse_request(json.dumps(req))
        with self.assertRaises(RequestError):
            parse_request("not json")

    def test_node_class_fields_are_the_schema_record(self) -> None:
        """The helper's record and Socair's must be the same set of fields."""
        if not os.path.exists(SCHEMA):
            self.skipTest("not in a Socair checkout")
        with open(SCHEMA, encoding="utf-8") as f:
            schema = json.load(f)
        facts = schema["properties"]["tier2"]["properties"]["node_classes"]["items"]["properties"]["facts"]
        self.assertEqual(sorted(NODE_CLASS_FIELDS), sorted(facts["required"]))
        self.assertEqual(sorted(empty_node_class()), sorted(facts["properties"]))

    def test_answers_are_strict_json(self) -> None:
        with self.assertRaises(ValueError):
            dumps({"score": float("nan")})


if __name__ == "__main__":
    unittest.main()
