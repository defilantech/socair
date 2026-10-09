"""Entry point: one request on standard input, one answer on standard output.

Exit 0 with an answer, including one whose measurement records an endpoint
error; 2 for a request this helper does not accept; 1 for anything else.
Diagnostics go to standard error, which Socair quotes, briefly, when the
helper fails.
"""

from __future__ import annotations

import sys
from typing import TextIO

from .greedy import measure
from .protocol import RequestError, dumps, parse_request

_MAX_REQUEST = 1 << 20


def main(stdin: TextIO | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        req = parse_request(stdin.read(_MAX_REQUEST))
        answer = dumps(measure(req))
    except RequestError as e:
        print(f"socair-probe: {e}", file=stderr)
        return 2
    if len(answer.encode()) > req.max_response_bytes:
        print(f"socair-probe: the answer is over the {req.max_response_bytes}-byte limit", file=stderr)
        return 1
    stdout.write(answer)
    stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
