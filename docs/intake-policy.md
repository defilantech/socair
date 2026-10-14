# Intake policy

An intake policy is your organization's rules for what may come in: the
formats a model may be in, the publishers it may or may not come from, and the
publishers whose models must carry a verified publisher signature. Socair
checks an artifact against it and reports the result as one row, **Intake
policy**.

The policy can only withhold. A rule the artifact breaks is a FAIL, which
withholds promotion and which no acceptance clears. A rule Socair cannot
evaluate is NOT_TESTED, with the reason. A PASS says which rules held and what
each was checked against. The policy never changes another row, never
authorizes a model, and never clears or upgrades anything: a model in an
allowed format, from an allowed publisher, with a verified signature, is still
withheld by any other row that withholds it.

## Using a policy

```
export SOCAIR_INTAKE_POLICY=/etc/socair/acme-intake.json
socair scan <file or model directory>
```

The report then carries:

- the **Intake policy** row, after the other Tier 1 rows;
- `scope.intake_policy`, naming the policy by its file's base name and the
  SHA-256 of its bytes, so the report pins the exact rules it was checked
  against without carrying a local path:

  ```json
  "intake_policy": {
    "name": "acme-intake.json",
    "sha256": "12a53ff063ad028c64acbf140cd95fcaa3676be9e53b6df087f9442ed627e40a"
  }
  ```

  (the example policy below, saved as `acme-intake.json`).

Without `SOCAIR_INTAKE_POLICY` there is no row and no `scope.intake_policy`,
and nothing about the report changes.

The console's scan of a staged model uses the same variable, and reads the
provenance manifest its pull wrote, so the publisher rules work there too.

## The policy file

One JSON object:

```json
{
  "format": "socair.intake-policy/v1",
  "allowed_formats": ["safetensors", "gguf"],
  "allowed_publishers": ["acme-ml", "google", "meta-llama", "mistralai", "qwen"],
  "denied_publishers": ["example-denied-org"],
  "signature_required": ["acme-ml"]
}
```

`acme-ml` and `example-denied-org` are placeholders: put your own
organizations in their place.

| Key | Rule |
|---|---|
| `format` | Required: `socair.intake-policy/v1`. |
| `allowed_formats` | Every model file must be in one of these formats (below). |
| `allowed_publishers` | The publisher (below) must be one of these hub organizations. |
| `denied_publishers` | The publisher must not be any of these. |
| `signature_required` | A model from one of these publishers must carry a publisher signature that verifies against a key or root you trust (below). |

Every rule key is optional, and a rule you leave out is not checked, but a
policy must set at least one. Publisher names are hub organizations as
`huggingface_hub` accepts a namespace: 1 to 96 letters, digits, `-`, `_`, or
`.`, not beginning or ending with `-` or `.`, with no `--` or `..`
([`validate_repo_id`](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/utils/_validators.py)).
They are matched without regard to case: the Hub resolves a repo id in any
case to the same repo (`https://huggingface.co/api/models/OPENAI-COMMUNITY/GPT2`
answers with the id `openai-community/gpt2`, checked 2026-10-12).

A policy that would load with a rule quietly missing or wrong stops the scan
instead, with an error that names the file and the problem:

- a file that cannot be read, or is not one JSON object (nothing may follow
  it);
- a key Socair does not know, or a key given twice (JSON readers keep the
  last of two equal keys, which would drop a list without a word);
- a list that is empty or `null` (leave the key out instead), or an empty
  entry;
- a format Socair does not identify;
- a publisher that is not an organization name, such as a repo id
  (`meta-llama/Llama-3.1-8B`) or a URL;
- a publisher that is both allowed and denied;
- a `format` other than `socair.intake-policy/v1`, or no rule at all.

## Formats

A format is identified from the file's bytes, never its name.

| Name | Identified by |
|---|---|
| `gguf` | The GGUF magic, `GGUF`, at the start of the file ([GGUF spec](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md)), whether or not the rest parses: the Format and structure row judges that. |
| `safetensors` | An 8-byte little-endian header length that fits in the file, then a header that begins with `{` ([safetensors format](https://github.com/huggingface/safetensors#format)). |
| `numpy` | The `.npy` magic, `\x93NUMPY` ([NumPy format](https://numpy.org/doc/stable/reference/generated/numpy.lib.format.html)), or a zip archive every entry of which is a `.npy` array, as `numpy.savez` writes one ([numpy.savez](https://numpy.org/doc/stable/reference/generated/numpy.savez.html)). |
| `pickle` | A protocol 2 to 5 pickle stream, or a zip archive holding a pickle (the `torch.save` format), as the pickle check recognises them by their bytes. |

Which files count:

- **A single file**: the file itself.
- **A model directory**: every file whose bytes are one of these formats,
  whatever it is named, and every weight file (by its extension: `.safetensors`,
  `.gguf`, `.bin`, `.pt`, `.pth`, `.ckpt`, `.pkl`, `.pickle`, `.joblib`, `.h5`,
  `.onnx`, `.msgpack`, `.npz`, `.npy`, `.mlmodel`, `.tflite`, `.pb`, `.keras`),
  whether or not its bytes are identified. A pickle named `notes.txt`, or a
  pickle named `model.safetensors`, counts as a pickle. Config, tokenizer, and
  other files whose bytes are none of these formats do not count.

Every weight file counts, including ones a loader does not read for
inference, such as optimizer state or a `training_args.bin`: if its bytes are
a pickle, a safetensors-only policy FAILs it. Leave out what you will not
serve when you pull (`socair airlock pull --exclude`), and the provenance row
records what was left out.

A file whose bytes are none of the four formats (ONNX, Keras, a TorchScript
archive, a protocol 0 pickle, a legacy tar checkpoint) is:

- a FAIL when every allowed format is `safetensors` or `gguf`: both begin
  with a fixed header, so a file without one is positively neither;
- NOT_TESTED when the list allows `pickle` or `numpy`: pickles are recognised
  by sniffing, which misses protocol 0 and 1 streams and archives it does not
  open, and an archive with an entry that is not an array is not recognised as
  NumPy, so the file might still be one of them.

A directory with no model file at all leaves the rule NOT_TESTED.

## Publisher

The publisher is read only from a provenance manifest bound to the
artifact's hash (`SOCAIR_PROVENANCE`; `socair airlock pull` writes one, see
[provenance-bundle.md](provenance-bundle.md#3-provenance-manifest-socair_provenance)):

- the organization of its `repo_url`, when the URL's path is exactly
  `/<organization>/<name>` (`https://huggingface.co/google/gemma-3-12b-it`
  gives `google`);
- its `publisher` field, when set.

When both are present, each is held to the lists: both must be allowed, and
either one denied is a FAIL. Set `publisher` to the hub organization, or leave
it out. A manifest for other bytes, or one that names neither, leaves every
publisher rule NOT_TESTED, and so does no manifest at all.

The publisher is never guessed: not from a file or directory name, a Hugging
Face cache path (`models--<org>--<name>`), `config.json`'s `_name_or_path`,
the model card, GGUF metadata (`general.organization`, a declared base
model), or a signer's identity.

The policy names organizations, not hosts: a model pulled through a mirror
whose repo URL has the path `/<organization>/<name>` has that organization.
The row's notes name the full repo URL. A mirror whose URLs carry a longer
path leaves the publisher unknown. The Hub's verified-organization status is
not part of the policy: the pull does not record it.

## Required signatures

`signature_required` reads the scan's verification of an OpenSSF Model
Signing signature, against the keys and roots you configure
(`SOCAIR_PUBLISHER_KEYS`, `SOCAIR_PUBLISHER_ROOTS`) or a keyless identity the
`socair-sigstore` helper accepts; see
[provenance-bundle.md](provenance-bundle.md#3a-publisher-signatures-socair_publisher_keys-and-socair_publisher_roots).
In a model directory that is the signature at its root, `model.sig` or NGC's
`result.sigstore`, or the file `SOCAIR_OMS_SIGNATURE` names.

| A listed publisher's model | Rule |
|---|---|
| Signature verified against a key or root you trust | holds |
| No OpenSSF Model Signing signature (none, or a `.sig` that is not one, such as minisign) | FAIL (`publisher-signature-required`) |
| A trusted signer's signature that does not hold (a changed or missing file) | FAIL (`publisher-signature-required`) |
| A signature that was not verified (an untrusted key, an unsupported bundle, no keyless verifier configured) | NOT_TESTED |
| A header-only scan, which verifies no signature | NOT_TESTED |

A verified signature satisfies the rule whoever the publisher is, and a
publisher not on the list needs none. The rule does not tie the signer to the
publisher: any key or root you trust satisfies it. Trust only the keys of the
publishers you list.

## The row

| Outcome | Status | Finding |
|---|---|---|
| A model file in a format not on `allowed_formats` | FAIL | `format-not-allowed`, naming the file and its format |
| The publisher on `denied_publishers` | FAIL | `publisher-denied`, naming where the name was read |
| The publisher not on `allowed_publishers` | FAIL | `publisher-not-allowed`, naming where the name was read |
| A listed publisher's model without a verified signature | FAIL | `publisher-signature-required` |
| A rule that cannot be evaluated (publisher unknown, format not identified, signature not verified) | NOT_TESTED | the notes give the reason |
| Every rule the policy sets holds | PASS | the notes say what each rule was checked against |

A FAIL's notes also list the rules that could not be evaluated and the rules
that held. Each finding is graded **medium**: a broken rule is your
organization's decision, not evidence of a compromise, and the rows that read
the bytes (Pickle opcode scan, Hash, provenance, lineage) grade those
separately. The row maps to OWASP LLM03:2025 Supply Chain, whose mitigations
include using only trusted suppliers and models from verifiable sources
([LLM03:2025](https://genai.owasp.org/llmrisk/llm032025-supply-chain/)); it
detects no compromise, so it maps to no MITRE ATLAS technique.

A FAIL withholds promotion, and no acceptance clears it. A NOT_TESTED row is a
gap like any other: it withholds until a named person signs an acceptance of
exactly that row (`socair accept`). To refuse a gap outright, do not accept
it.

## Beside the license policy

The license policy (`SOCAIR_LICENSE_POLICY`, [provenance-bundle.md](provenance-bundle.md#8-a-license-policy-socair_license_policy))
is a separate input with its own row. Either, both, or neither can be set, and
neither reads the other.

## In Kubernetes

Mount the policy the way a feed is mounted ([kubernetes.md](kubernetes.md)):
a ConfigMap, a volume, and `extraEnv`.

```
kubectl create configmap acme-intake-policy --from-file=acme-intake.json
```

```yaml
extraVolumes:
  - name: intake-policy
    configMap:
      name: acme-intake-policy
extraVolumeMounts:
  - name: intake-policy
    mountPath: /etc/socair/intake
    readOnly: true
extraEnv:
  - name: SOCAIR_INTAKE_POLICY
    value: /etc/socair/intake/acme-intake.json
```

## What it does not do

- It does not authorize anything, or change, clear, or upgrade any other row.
- It does not judge the model: a model that passes every rule is no safer for
  it, and the other rows still decide whether it is promoted.
- It fetches nothing. The policy, the manifest, and the keys are all local.
- It does not check the Hub's verified-organization status, tie a signer to
  a publisher, or set rules per publisher (formats for one organization and
  not another).
