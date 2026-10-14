# Converting a checkpoint, and the derivation record

`socair airlock convert` rebuilds a PyTorch checkpoint as a safetensors file
inside the airlock, without unpickling it, and signs a derivation record that
binds the output to the input. The output is a new artifact: it lands in
staging and is scanned, signed, and promoted like any other. Nothing about
the conversion authorizes it.

```
socair airlock convert <checkpoint> --attestation <attestation.dsse.json> --key <operator.key> [--store <path>]
```

## What it converts

The Pickle opcode scan's grammar (`socair-wo/1`) models a checkpoint's
`data.pkl` as typed values and matches every storage to a record of exactly
its size. When the row PASSes, the grammar's model says, for every tensor,
its dtype, shape, strides, storage offset, and storage record. The converter
reads the tensors from that model (`pickle.ReadStateDict`) and copies each
tensor's bytes from its record. It runs no pickle, Python's or anyone's.

The rules are versioned as `socair-convert/1`:

| Input | Converted | Refused with the reason |
|---|---|---|
| Container | a torch.save zip (PyTorch's format since 1.6) | a legacy stream or tar, an `.npy` or `.npz`, a raw pickle |
| Root | a dict or OrderedDict of names to tensors (a state dict) | a nested dict (`{"model": ..., "epoch": ...}`), a list, a non-tensor value, a non-string key |
| dtype | float64, float32, float16, bfloat16, int64, int32, int16, int8, uint8, bool, uint16, uint32, uint64, float8_e4m3fn, float8_e5m2 | anything else: complex, quantized, the fnuz float8s, float8_e8m0fnu, float4 |
| Layout | contiguous by c10's rule, at any storage offset | a non-contiguous view (a transposed weight saved without `.contiguous()`) |
| Byte order | `byteorder` record `little`, or none | `big`, or any other content |
| Records | stored uncompressed, CRC-32 holding | compressed, or a CRC-32 that does not hold |
| Sharing | views of one storage that do not overlap; exact aliases | overlapping views that are not exact aliases |
| Tensor state | a Parameter (written as a tensor) | the conj or neg bit (a metadata argument), Python attributes, no storage (a meta tensor) |
| Names | valid UTF-8 | not UTF-8, `__metadata__`, an alias named `format` |

Notes on the rules, with their sources:

- The safetensors format is from the
  [README](https://github.com/huggingface/safetensors/blob/v0.8.0/README.md#format)
  and the serializer in
  [`safetensors/src/tensor.rs`](https://github.com/huggingface/safetensors/blob/v0.8.0/safetensors/src/tensor.rs)
  at v0.8.0: an 8-byte little-endian header length, a JSON header that starts
  with `{` and may be padded with spaces, `__metadata__` as a string-to-string
  map, `data_offsets` relative to the data buffer, a buffer with no holes,
  little-endian, row-major. The output follows the serializer (`prepare`):
  tensors sorted by dtype alignment, largest first, then by name; the header
  padded to a multiple of 8 bytes; `__metadata__` first. The header holds
  `"format": "pt"`, as
  [`convert.py`](https://github.com/huggingface/safetensors/blob/v0.8.0/bindings/python/convert.py)
  and transformers'
  [`save_pretrained`](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/modeling_utils.py)
  write it. The output is byte-stable: one input always gives the same bytes.
- The dtype pairs are safetensors' own (`parse_dtype_str` in
  [`bindings/python/src/lib.rs`](https://github.com/huggingface/safetensors/blob/v0.8.0/bindings/python/src/lib.rs),
  `_TYPES` in
  [`torch.py`](https://github.com/huggingface/safetensors/blob/v0.8.0/bindings/python/py_src/safetensors/torch.py)).
- Which dtypes torch writes through `_rebuild_tensor_v2` over a typed storage
  and which through `_rebuild_tensor_v3` over an untyped one is
  `_reduce_ex_internal` in
  [`torch/_tensor.py`](https://github.com/pytorch/pytorch/blob/v2.14.1/torch/_tensor.py)
  with `_new_dtypes` and `_dtype_to_storage_type_map` in
  [`torch/storage.py`](https://github.com/pytorch/pytorch/blob/v2.14.1/torch/storage.py),
  at v2.14.1. The storage offset counts elements of the tensor's dtype in both
  (`_rebuild_tensor`, `_rebuild_tensor_v3` in
  [`torch/_utils.py`](https://github.com/pytorch/pytorch/blob/v2.14.1/torch/_utils.py)).
  torch 2.14.1 names the untyped storage class `torch.storage.UntypedStorage`,
  which `socair-wo/1` does not model yet, so a real checkpoint holding a
  uint16, uint32, uint64, or float8 tensor is a LEAD on the Pickle row today
  and is not converted. The converter handles those dtypes once the grammar
  accepts that spelling.
- Contiguity is c10's `_compute_contiguous`
  ([`c10/core/Contiguity.h`](https://github.com/pytorch/pytorch/blob/v2.14.1/c10/core/Contiguity.h)):
  an empty tensor is contiguous, and a dimension of size 1 may have any
  stride.
- The metadata argument holds torch's conj and neg bits, and torch sets a bit
  for each key the dict holds whatever its value (`setTensorMetadata` in
  [`torch/csrc/jit/serialization/pickler_helper.h`](https://github.com/pytorch/pytorch/blob/v2.14.1/torch/csrc/jit/serialization/pickler_helper.h)).
  The bytes of such a tensor are not its values, so it is refused.
- A checkpoint with no `byteorder` record is read as little-endian, as
  `torch.load` does by default (`_load` in
  [`torch/serialization.py`](https://github.com/pytorch/pytorch/blob/v2.14.1/torch/serialization.py),
  with `config.load.endianness` unset). The record says which it was.
- torch.save writes records uncompressed (`writeRecord`'s `compress = false`
  in
  [`caffe2/serialize/inline_container.h`](https://github.com/pytorch/pytorch/blob/v2.14.1/caffe2/serialize/inline_container.h)),
  and PyTorch builds miniz with `MINIZ_DISABLE_ZIP_READER_CRC32_CHECKS`
  ([`cmake/Dependencies.cmake`](https://github.com/pytorch/pytorch/blob/v2.14.1/cmake/Dependencies.cmake)),
  so `torch.load` reads a record whose CRC-32 does not hold while other zip
  readers stop. A checkpoint saved with `compute_crc32` off has no CRC-32 to
  hold and is refused for the same reason.
- Sharing follows safetensors' own tools.
  [`save_file`](https://github.com/huggingface/safetensors/blob/v0.8.0/bindings/python/py_src/safetensors/torch.py)
  refuses tensors that share memory but writes views of one storage that do
  not overlap (`_filter_shared_not_shared`). `save_model` and `convert.py`
  write one tensor of a shared group and record each other name in
  `__metadata__` as `name: kept name` (`_remove_duplicate_names`, which keeps
  the first name in sorted order). transformers clones disjoint views and
  drops tied duplicates
  (`remove_tied_weights_from_state_dict`). The converter writes disjoint views
  each as its own tensor and an exact alias (the same bytes, dtype, and
  shape, such as tied embeddings) once, under the first name in byte order,
  with `name: kept name` in `__metadata__`. It refuses overlapping views that
  are not exact aliases, where `save_model` would record a partial view as an
  alias of a whole tensor whose values differ from it. So the output's data
  section is never larger than the input's storages.

## The input gate

Conversion runs only on an input that clears all of these:

1. Its attestation verifies against the store's trust policy, through the
   gate's own check (`Store.Assess`), as `promote` checks it.
2. No row is FAIL or LEAD, the Pickle row's or any other's.
3. The Pickle opcode scan row is PASS. The converter reads the tensors from
   the grammar's model, which only a PASS shows complete.
4. The input's bytes, copied into the store's work area and hashed as they
   are copied, hash to the attested subject. The converter reads only that
   copy, so the bytes converted are the bytes that were scanned, whatever
   happens to the original afterwards.
5. The converter re-runs the Pickle check on the copy, with no reviewed
   classes, and it must PASS again.

NOT_TESTED rows on other checks do not block it. A pickle checkpoint's
Format and structure row is always NOT_TESTED (Socair parses no pickle
structure), so requiring every row to pass would require a signed
acceptance, and an acceptance accepts the pickle's gaps for promotion. The
conversion authorizes nothing: the record names the input's NOT_TESTED rows,
and the output faces its own scan and gate.

## What a conversion writes

- `incoming/<output sha256>/<name>.safetensors`: the output, named after the
  attested file name with its extension replaced.
- `incoming/<output sha256>/derivation.dsse.json`: the signed record.
- A `convert` entry in the activity log: `ok` with the output's hash, or
  `refused` with the input's hash and the reason.

The output is written to the store's `.tmp/` area and verified before it is
moved into staging: Socair's safetensors parser must find its layout sound,
and every tensor's bytes in the output must hash to the bytes read from its
record through the zip reader, a second path through the input. A refusal or
a difference leaves nothing in staging. The copy and the output each check
for room first.

## The derivation record

A record is an in-toto Statement v1
([statement.md](https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/statement.md))
with predicate type `https://socair.ai/derivation/v1`, in a DSSE envelope
signed with Ed25519, the machinery attestations and acceptances use. The
signing key must be in the store's trust policy, so the record verifies
against the store's own keys (`derivation.Verify`).

Its subject is the output. The predicate:

| Field | Holds |
|---|---|
| `converter` | `name` (`socair airlock convert`), `version` (the Socair build), `rules` (`socair-convert/1`), `grammar` (`socair-wo/1`) |
| `input` | `name`, `digest.sha256`, `format` (`torch.save zip`), `byte_order` and how it was established, and `attestation`: the verified attestation's `document_id`, `document_hash`, `signer_key_id`, `state`, `check_set_version`, `pickle_row` (`PASS`), and `not_tested` (the input's NOT_TESTED rows) |
| `output` | `name`, `digest.sha256` (the subject's), `format` (`safetensors`), `size_bytes` |
| `converted_at` | RFC 3339 |
| `tensors` | every input tensor, by name: `dtype` (safetensors), `source_dtype` (torch), `shape`, `source` (`record`, `offset_bytes`), `size_bytes`, `sha256` of its bytes, `data_offsets` in the output, and `alias_of` for an exact alias |
| `metadata` | the output's `__metadata__` |
| `not_carried` | what the output does not carry: tensor types and flags (Parameter, `requires_grad`, devices), an OrderedDict's attributes (a state dict's `_metadata`), memory sharing, and storage bytes no tensor views |
| `does_not_authorize` | fixed wording: the record binds the output's bytes to the input's attested bytes and does not attest the output |

Each tensor's `sha256` is of its bytes, which are the same in the input
record and in the output. A reviewer with the input can check each one
without Socair: read `size_bytes` from `source.record` at
`source.offset_bytes` and hash them.

A derivation record is not a SLSA provenance statement
(`https://slsa.dev/provenance/v1`). SLSA's `builder.id` is
[meant](https://github.com/slsa-framework/slsa/blob/v1.2/docs/spec/v1.2/build-provenance.md)
to determine the SLSA Build level and to resolve to documentation claiming
one, a claim about a build platform that an operator's airlock does not
make, and SLSA has no place for a tensor map.

## What it does not establish

- That the output is safe to load: it is scanned as a new artifact.
- That the input was safe: only the attestation's rows say what was checked.
- That the output behaves like the input in a framework that relies on
  memory sharing, `requires_grad`, or a state dict's `_metadata`; those are
  named in `not_carried`.
- Anything about a model directory. `convert` takes one checkpoint file and
  that file's own attestation, and refuses a directory's attestation: pull
  the file, scan and sign it, and convert it.
