# socair-probe

A Tier 2 probe helper for Socair. Socair runs it when `SOCAIR_TIER2_HELPER`
names it, writes it one request on standard input, and reads one answer from
standard output: the socair.tier2/v1 protocol in
[docs/tier2.md](../../docs/tier2.md). The helper drives the site's own
OpenAI-compatible inference engine and returns measurements. It never returns
a verdict, and Socair accepts no pass from it.

This is the skeleton. Its one measurement exercises the plumbing end to end:
**greedy-continuation agreement**. It continues eight fixed prompts greedily
on the endpoint and on `SOCAIR_TIER2_REFERENCE_ENDPOINT` (or, with no
reference, a second time on the endpoint) and records how often the two agree,
the 95% Wilson interval, the mean shared-prefix agreement, and, when both
engines give token logprobs, their mean absolute difference over the shared
greedy prefix. It is not calibrated, so it raises no LEAD, and agreement is not
a PASS. The real checks (quantization and serving-stack differentials,
refusal regression, behavioral suites) are on the roadmap in
[docs/tier2.md](../../docs/tier2.md).

It is a separate component, kept out of the Go build like
`tools/socair-sigstore`, and uses only the Python standard library (3.10 or
later).

## Run it

From a checkout, with no install:

```
export SOCAIR_TIER2_HELPER=$PWD/tools/socair-probe/socair-probe
export SOCAIR_TIER2_ENDPOINT=http://127.0.0.1:8000      # the engine serving the artifact
socair scan <artifact>
```

Or install it (`pip install ./tools/socair-probe`) and point
`SOCAIR_TIER2_HELPER` at the `socair-probe` script it puts on the path.

Settings the helper reads, which Socair passes through because of their
`SOCAIR_PROBE_` prefix:

| Variable | Meaning |
|---|---|
| `SOCAIR_PROBE_API_KEY` | Sent to the endpoint as a bearer token |
| `SOCAIR_PROBE_MODEL` | The model id to probe; default, the first `/v1/models` lists |

Socair gives the helper nothing else of its environment beyond `PATH`, the
locale, the temp directory, and certificate settings. The helper ignores proxy
settings: the endpoint is the site's own engine.

`SOCAIR_TIER2_PROBES` may name a JSON file holding a list of prompts to use
instead of the built-in set (`builtin:greedy-agreement`). The answer records
the set's digest.

## Exit status

| Status | Meaning |
|---|---|
| 0 | An answer is on standard output. An endpoint that failed mid-run is a measurement with outcome `error`. |
| 2 | The request is not one this helper accepts (unknown field, other protocol version, bad value). |
| 1 | Anything else; the reason is on standard error. |

## Tests

Offline, standard library only. A local fake engine stands in for the real
one.

```
cd tools/socair-probe
python3 -m unittest discover -s tests -t . -v
```

`testdata/example-response.json` is an answer as the helper writes it. Socair's
Go tests decode it strictly (`internal/tier2`), and this helper's tests hold it
to the helper's output shape, so a field renamed on either side fails a test.
`SOCAIR_PROBE_UPDATE_EXAMPLE=1` rewrites it.

To run Socair's engine against this helper end to end:

```
SOCAIR_TEST_PROBE_HELPER=$PWD/tools/socair-probe/socair-probe go test ./internal/engine -run RealProbeHelper -v
```

## Isolation

The helper is third-party code beside the model, and the engine it drives may
load untrusted weights. Run both the way [docs/tier2.md](../../docs/tier2.md)
describes: no `trust_remote_code`, a non-root user, a read-only root
filesystem, deny-all egress, in a quarantine namespace.
