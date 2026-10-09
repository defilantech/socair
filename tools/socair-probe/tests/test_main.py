"""The helper as Socair runs it: a process, one request in, one answer out."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from typing import Any

from socair_probe.__main__ import main

from .fake_engine import FakeEngine
from .test_protocol import request

ROOT = os.path.join(os.path.dirname(__file__), "..")
EXAMPLE = os.path.join(ROOT, "testdata", "example-response.json")
LAUNCHER = os.path.join(ROOT, "socair-probe")


def shape(v: Any) -> Any:
    """The keys and kinds of a JSON value, its values left out."""
    if isinstance(v, dict):
        return {k: shape(x) for k, x in v.items()}
    if isinstance(v, list):
        return [shape(v[0])] if v else []
    return type(v).__name__ if not isinstance(v, (int, float)) or isinstance(v, bool) else "number"


class Main(unittest.TestCase):
    def test_answers_on_stdout(self) -> None:
        with FakeEngine() as e:
            out, err = io.StringIO(), io.StringIO()
            code = main(io.StringIO(json.dumps(request(endpoint=e.url))), out, err)
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["protocol"], "socair.tier2/v1")

    def test_a_bad_request_exits_2(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(main(io.StringIO(json.dumps(request(verdict="x"))), out, err), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("unknown fields: verdict", err.getvalue())

    def test_the_launcher_runs_in_a_bare_environment(self) -> None:
        """Socair gives the helper PATH and little else."""
        with FakeEngine() as e:
            p = subprocess.run(
                [sys.executable, LAUNCHER],
                input=json.dumps(request(endpoint=e.url)),
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
                timeout=60,
            )
        self.assertEqual(p.returncode, 0, p.stderr)
        answer = json.loads(p.stdout)
        self.assertEqual(answer["measurements"][0]["outcome"], "measured")

    def test_the_example_is_what_the_helper_writes(self) -> None:
        """testdata/example-response.json is the answer Socair's Go tests
        decode strictly (internal/tier2), so it must keep the helper's shape.
        SOCAIR_PROBE_UPDATE_EXAMPLE=1 rewrites it."""
        with FakeEngine(owned_by="vllm") as a, FakeEngine(owned_by="sglang") as b:
            req = request(endpoint=a.url, reference_endpoint=b.url)
            out = io.StringIO()
            self.assertEqual(main(io.StringIO(json.dumps(req)), out, io.StringIO()), 0)
        answer = json.loads(out.getvalue())
        if os.environ.get("SOCAIR_PROBE_UPDATE_EXAMPLE") == "1":
            for m in answer["measurements"]:
                m["started_utc"], m["ended_utc"] = "2026-10-09T10:00:00Z", "2026-10-09T10:00:02Z"
            with open(EXAMPLE, "w", encoding="utf-8") as f:
                json.dump(answer, f, indent=2, sort_keys=True)
                f.write("\n")
        with open(EXAMPLE, encoding="utf-8") as f:
            example = json.load(f)
        self.assertEqual(shape(answer), shape(example))


if __name__ == "__main__":
    unittest.main()
