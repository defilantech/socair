# Tier 2: measurements made by running the model

Tier 1 reads an artifact's bytes and runs no inference. Tier 2 runs the model,
on the site's own GPUs, through the engine that will serve it, and records what
it measured. It exists for the attacks Tier 1 cannot see: behavior that appears
only after quantization (arXiv 2405.18137, 2505.23786) or only on particular
hardware and serving stacks (FloatDoor, arXiv 2606.19535).

Tier 2 is opt-in and runs nothing by default. What it produces is a
**measurement, not a verdict**: a measurement can withhold promotion, and it can
never authorize it. The awarded level stays Tier 1, and promotion is still
decided by the check rows alone.

This is the foundation (#154): the report section, the node-class record, the
probe-helper protocol, and the rule that keeps measurements on the withholding
side. No real Tier 2 check ships yet. The skeleton helper,
[`tools/socair-probe`](../tools/socair-probe/README.md), takes one uncalibrated
measurement that exercises the plumbing end to end. The checks themselves are on
the [roadmap](#roadmap).

## Measurements and the status mapping

A report where Tier 2 ran carries a `tier2` section (`docs/report-schema/v1.json`):
the probe helper that ran, the node classes it ran on, and one entry per
measurement. Each measurement records:

| Field | Meaning |
|---|---|
| `check` | The Tier 2 check measured. Its name ends in ` (Tier 2)`. |
| `suite`, `suite_version` | The probe suite and its version. This is what versions a measurement; Tier 2 is not part of the [check-set version](check-set.md). |
| `dataset_digest` | `sha256:<hex>` of the probe set. |
| `scorer` | `deterministic` (a rule matched the output), or `llm-judge:sha256:<hex>` (a model, named by its digest). |
| `n`, `score`, `metrics`, `ci95` | How many probes were scored, the score and any named metrics, and the score's 95% interval. |
| `decoding` | Temperature, top_p, max_tokens, and seed. |
| `engine`, `node_class`, `reference_node_class` | The engine as the helper names it, and the hash of the node class the model ran on; for a differential, the class it was compared with. |
| `started_utc`, `ended_utc` | When it ran. |
| `outcome` | `measured`, `lead`, `fail`, or `error`. There is no pass. |
| `evidence`, `notes` | The output a FAIL matched (required for a FAIL), and anything else. |

The outcome decides whether the measurement reaches promotion, and it reaches
it only through an ordinary check row:

| Outcome | Check row | Promotion |
|---|---|---|
| `measured`: completed and found nothing | None | Unchanged. It is not a PASS, it is not evidence of absence, and it clears no NOT_TESTED gap. |
| `lead`: a statistical or judged signal | `<check> (Tier 2)`, LEAD | Withheld. No acceptance clears it. |
| `fail`: deterministic, matcher-confirmed evidence | `<check> (Tier 2)`, FAIL | Withheld. No acceptance clears it. |
| `error`: did not complete | None | Unchanged. The measurement records what failed. |

A statistical check raises at most a LEAD. A FAIL needs the `deterministic`
scorer and the evidence it matched; a judged FAIL is refused. A check with
several measurements has one row, FAIL if any of them failed.

The rows are what make this safe everywhere a report is read. Every verifier
that reads `checks[]` withholds on a LEAD or FAIL row without knowing Tier 2
exists, including the
[`socair-verify`](https://github.com/defilantech/socair-verify) module that
LLMKube's admission gate runs. `report.Validate`, which `socair sign`,
`socair verify`, and the airlock all apply, holds the section and the rows
together:

- A row named `... (Tier 2)` is only ever LEAD or FAIL, and needs a measurement
  that raised it with that status. Edit one to PASS, or to NOT_TESTED so an
  acceptance could clear it, and the report no longer validates.
- Every LEAD or FAIL measurement has its row. Delete the row so the Tier 1 rows
  authorize, and the report no longer validates.
- Every node class's hash is recomputed from its facts, and every measurement
  names one of them.
- A check that was measured is not also listed as not run, the untested node
  classes name every class but the ones measured on, and the assurance section
  says Tier 2 ran.
- The promotion rules are the ones Validate applies to every report. They read
  the rows, so they need no Tier 2 rule of their own.

A report with a Tier 2 section also takes its own pair of fixed bounded
statements, because the Tier 1 pair says no model behavior was tested and
credits every indicator to the Tier 1 checks. Without a Tier 2 section, the
section is absent and a report is byte-identical to one from before Tier 2
existed.

## The node-class record

A behavior measured on one node is measured on that node's numerics, and
nothing else. Kernels, reduction order, and quantized arithmetic differ across
GPU architectures, drivers, libraries, engines, and engine settings, and
platform-triggered backdoors are built to show only on a target platform. So
any difference in any field below is a different node class, and a measurement
on one class says nothing about another.

| Field | Meaning |
|---|---|
| `gpu_model`, `compute_capability`, `gpu_count` | The GPUs |
| `interconnect` | Links and topology, e.g. NVLink 4 via NVSwitch |
| `driver`, `vbios` | Driver and VBIOS versions |
| `ecc`, `mig`, `cc_mode` | ECC on or off, the MIG profile or `disabled`, the confidential-computing mode |
| `cuda`, `cublas`, `cudnn`, `nccl` | Library versions |
| `container_image_digest` | The serving image |
| `engine_name`, `engine_version`, `engine_commit` | The inference engine |
| `dtype`, `weight_quantization`, `kv_cache_quantization` | Compute dtype and quantization |
| `tensor_parallel_size`, `pipeline_parallel_size`, `expert_parallel_size` | Parallelism |
| `attention_backend` | The attention kernel, e.g. FLASH_ATTN |
| `cuda_graphs`, `torch_compile`, `eager` | Graph capture and compilation |
| `batch_invariant` | Batch-invariant kernels (vLLM) |
| `prefix_caching`, `chunked_prefill`, `speculative_decoding` | Scheduling features; speculative decoding is `off` or the method and draft model |
| `env` | Numerically relevant environment variables, e.g. `CUBLAS_WORKSPACE_CONFIG` |

An unreported text field is empty, an unreported count is 0, and an unreported
switch is `null`: unknown, which is not the same as off and hashes differently.
Renderers list the fields that were not reported, so a reader sees how complete
a class is.

**The hash.** A node class is keyed by `sha256:<hex>`, the SHA-256 of its
canonical JSON: the record with every field present and `schema` set to
`socair.nodeclass/v1`, a missing `env` written `{}`, object keys sorted (inside
`env` too), no insignificant whitespace, and no HTML escaping. In Python that is
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
for ASCII values. `report.NodeClass.Canonical` is the reference, and a test pins
its output byte for byte.

**Who says so.** Socair does not observe the hardware. Every class is recorded
with `reported_by: "probe helper (not observed by Socair)"`, and Socair computes
the hash itself from the facts it records; a helper names classes only by local
ids. The report's execution context names the classes measured on, and its
untested-node-classes statement becomes "every node class other than" those.

## The probe-helper protocol

Socair runs the program `SOCAIR_TIER2_HELPER` names, with no arguments, writes
one request to its standard input, and reads one answer from its standard
output. The helper exits 0 with an answer; anything on standard error is quoted,
briefly, if it fails. The protocol is `socair.tier2/v1` (`internal/tier2`), the
same way `SOCAIR_SIGSTORE_VERIFIER` runs `tools/socair-sigstore`.

The request:

```json
{
  "protocol": "socair.tier2/v1",
  "artifact": {"path": "<the scan's read-only snapshot>", "sha256": "<attested hash>", "file_name": "model.gguf", "format": "GGUF"},
  "endpoint": "http://10.0.4.12:8000",
  "reference_endpoint": "http://10.0.4.13:8000",
  "probe_pack": "builtin:greedy-agreement",
  "node_class": {"schema": "socair.nodeclass/v1", "gpu_model": "NVIDIA B200", "...": "..."},
  "decoding": {"temperature": 0, "top_p": 1, "max_tokens": 32, "seed": 0},
  "limits": {"max_response_bytes": 1048576, "max_measurements": 256, "timeout_seconds": 1800}
}
```

`artifact.path` is the scan's snapshot, the bytes the attestation names, so a
helper that loads the model itself loads the attested bytes. `node_class` is
the operator's declaration (`SOCAIR_TIER2_NODE_CLASS`), or `null`; the helper
may complete it. `reference_endpoint` and `probe_pack` are omitted when unset.

The answer:

```json
{
  "protocol": "socair.tier2/v1",
  "helper": {"name": "socair-probe", "version": "0.1.0"},
  "node_classes": [{"id": "endpoint", "facts": {"...": "every node-class field"}}],
  "measurements": [{
    "check": "Greedy continuation agreement (Tier 2)",
    "suite": "socair-probe/greedy-agreement", "suite_version": "0.1.0",
    "dataset_digest": "sha256:...", "scorer": "deterministic",
    "n": 8, "score": 1.0, "ci95": [0.68, 1.0], "metrics": {"mean_prefix_agreement": 1.0},
    "decoding": {"temperature": 0, "top_p": 1, "max_tokens": 32, "seed": 0},
    "engine": "vllm 0.11.0", "node_class": "endpoint",
    "started_utc": "2026-10-09T10:00:00Z", "ended_utc": "2026-10-09T10:00:02Z",
    "outcome": "measured", "notes": "..."
  }]
}
```

`tools/socair-probe/testdata/example-response.json` is a complete answer; the Go
tests decode it as they decode a live one.

Socair trusts the helper no further than this. The answer is refused, with the
reason, unless:

- it arrives within the timeout (`SOCAIR_TIER2_TIMEOUT`, default 30 minutes;
  the helper is killed at the limit) and within 1 MiB;
- it decodes with no unknown field at any level, and nothing follows it;
- it names the protocol and the helper, and stays in bounds: 1 to 16 node
  classes of at most 16 KiB each, 1 to 256 measurements, names of at most 200
  bytes, notes and evidence of at most 4096, at most 64 metrics;
- every measurement names a node class by an id the answer defines, and the
  resulting section passes the rules above (an outcome of `pass` is refused, as
  is a FAIL without the deterministic scorer and its evidence).

Classes no measurement ran on are dropped, and two ids with the same facts are
one class.

The helper runs with `PATH`, `HOME`, the locale, the temp directory,
`SYSTEMROOT`, and `SSL_CERT_FILE`/`SSL_CERT_DIR`, plus its own `SOCAIR_PROBE_*`
variables (`SOCAIR_PROBE_API_KEY`, for one). Nothing else of Socair's
environment reaches it: no `HF_TOKEN`, no proxy settings, no other Socair input.

**When it does not run.** With no helper configured, Tier 2 did not run, and the
report says so under checks not run, as a Tier 1 report always has. If a
configured helper fails, runs out of time, or answers out of protocol, Tier 2
did not run and the reason is in the same place. Neither is a gap that withholds
promotion: Tier 2 can only withhold, so its absence changes no promotion. An
operator who requires Tier 2 should gate on the report's `tier2` section. A
configuration error (an endpoint without a helper, a helper that is not a file,
a malformed URL, timeout, or node-class file) stops the scan before any snapshot
is copied.

## Configuration

| Variable | Meaning |
|---|---|
| `SOCAIR_TIER2_HELPER` | The probe helper. Unset, Tier 2 does not run. |
| `SOCAIR_TIER2_ENDPOINT` | Required with a helper: the OpenAI-compatible base URL of the engine serving this artifact. No credentials in the URL; the helper reads a key from `SOCAIR_PROBE_API_KEY`. |
| `SOCAIR_TIER2_REFERENCE_ENDPOINT` | Optional: the engine to compare with, for a differential. |
| `SOCAIR_TIER2_PROBES` | Optional: the probe pack, a path or a name the helper knows. |
| `SOCAIR_TIER2_NODE_CLASS` | Optional: a JSON file declaring the node class, any subset of the record's fields, no unknown field. |
| `SOCAIR_TIER2_TIMEOUT` | Optional: how long the helper may run, 1s to 24h (default 30m). |

Any `SOCAIR_TIER2_*` variable set without `SOCAIR_TIER2_HELPER` is an error.
Tier 2 runs on every full scan the engine makes with these set: `socair scan`,
`socair render`, `socair airlock ingest --scan`, and the scans `socair serve`
runs for the wizard and the console. A header-only sweep (`socair corpus`) attests nothing and never runs it.
Decoding defaults to greedy: temperature 0, top_p 1, 32 tokens, seed 0. A suite
that samples records the decoding it used.

```
export SOCAIR_TIER2_HELPER=$PWD/tools/socair-probe/socair-probe
export SOCAIR_TIER2_ENDPOINT=http://127.0.0.1:8000
export SOCAIR_TIER2_NODE_CLASS=/etc/socair/node-class.json
socair scan model.gguf
```

**The endpoint is the operator's claim.** Socair does not verify that an
endpoint serves the bytes the attestation names, and the section's fixed
statement says so. Serve the engine from the scan's snapshot or the airlock's
staged copy, so the bytes measured are the bytes attested.

## Isolation

Tier 2 loads untrusted weights into an inference engine, and the helper is
third-party code beside it. Run both as you would any untrusted workload:

- **No `trust_remote_code`.** A model that ships code a loader would run is a
  Tier 1 LEAD (the Remote code row) and is withheld; the engine must not run
  that code either.
- **Non-root**, with no privilege escalation, capabilities dropped, and a
  **read-only root filesystem**; the weights mounted read-only.
- **Deny-all egress.** Allow only the path from the helper to the engine. The
  bundled helper ignores proxy settings.
- **A quarantine namespace** that holds nothing else, on the GPU nodes of the
  class being measured, torn down after the run. LLMKube can stand one up:
  the model served from the airlock's staged copy, in its own namespace, with a
  NetworkPolicy that denies egress.
- Socair passes the helper no token of its own (above), and the helper sends
  none but `SOCAIR_PROBE_API_KEY` to the endpoint.

## Compatibility

`socair-verify` v0.1.0, which LLMKube's admission gate runs, decodes the report
leniently and reads only the rows' names and statuses and the promotion state.
It accepts a report with a `tier2` section, and it withholds on a Tier 2 LEAD or
FAIL row like any other; the engine tests sign such reports and check them with
the vendored module. Socair's own `verify` decodes strictly, so a Socair build
from before Tier 2 refuses a report that carries the section: upgrade the
verifiers before turning Tier 2 on. A report without the section is unchanged.

## Roadmap

Each check below lands as a suite behind this protocol, records measurements,
and raises at most a LEAD unless a deterministic matcher confirms a FAIL. Some
drafts propose a narrow PASS for a result within a measured envelope; under this
foundation such a result is a `measured` outcome with its numbers, never a row,
and changing that is a contract change that could still never authorize.

| Issue | Check | What it measures |
|---|---|---|
| [#155](https://github.com/defilantech/socair/issues/155) | Quantization differential | The served format (FP8, NVFP4, GGUF k-quants, AWQ/GPTQ) against full precision, on the same engine and node, against a null envelope from known-clean quants |
| [#20](https://github.com/defilantech/socair/issues/20) | Serving-stack differential | One checkpoint under varied configs on the production node (eager, CUDA Graphs, torch.compile, batch size, batch-invariant mode, an fp32 reference, TP size, engine A against B), with a self-against-self noise floor |
| [#156](https://github.com/defilantech/socair/issues/156) | Refusal regression | Refusal rate on a pinned harmful set and a benign over-refusal set, against a signed reference for the declared lineage |
| [#157](https://github.com/defilantech/socair/issues/157) | Behavioral suites | lm-eval, Inspect, and garak runs recorded as measurements |
| [#19](https://github.com/defilantech/socair/issues/19) | Experimental backdoor scanner | A trigger-inversion scanner (BAIT or Trigger in the Haystack), advisory and LEAD-only, with its published sensitivity |

A negative result proves little against a trigger the probes do not hit, and
every Tier 2 row will say so.
