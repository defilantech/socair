# Tensor fingerprints and the Tensor reference row

A file hash says whether two files are the same bytes. A tensor fingerprint
says whether two models hold the same weights. That holds even when one was
re-saved, re-sharded, renamed, or converted without loss to another float
dtype or file format.

Socair fingerprints every tensor of a GGUF file, a safetensors file, or a
model directory. It compares two models tensor by tensor, and with a reviewed
model's manifest as a reference, the comparison becomes a report row.

What it shows:
- A copy, mirror, or re-upload of a model you reviewed holds that model's
  weights.
- A model presented as the one you reviewed holds different weights. PoisonGPT
  (Mithril Security, 2023) edited a few weights of GPT-J-6B with ROME, and the
  result scored within 0.1% of the original on a benchmark.

It does not say whether the weights are safe. A model compared with its own
manifest always matches, so a malicious model's manifest vouches for the
malicious model. The reference is only as good as the review behind it.

## Commands

```
socair tensors <path> [--out m.json]
socair tensors diff <artifact|manifest> <reference artifact|manifest> [--out c.json]
```

`socair tensors` reads a model directory, a GGUF file, or a safetensors file.
It writes a `socair.tensors/v1` manifest (below) to standard output, or to
`--out`, and prints a one-line count to standard error.

`socair tensors diff` compares an artifact with a reference. Either side may be
a model or a manifest that `socair tensors` wrote. It writes the comparison as
JSON and prints a summary. It exits 0 only when every tensor on both sides
matches under its own name, and 1 otherwise.

## The manifest

```json
{
  "schema": "socair.tensors/v1",
  "artifact": { "name": "all-MiniLM-L6-v2", "format": "model directory", "sha256": "6b9a…" },
  "value_encoding": "float32-le-bits/v1",
  "tensors": [
    { "file": "model.safetensors", "name": "embeddings.LayerNorm.bias", "dtype": "F32",
      "shape": [384], "bytes": 1536, "sha256": "…", "values": "…" }
  ]
}
```

**`artifact.sha256`** is the subject digest a Socair report gives the same
model: a file's SHA-256, or a model directory's `socair.modeldir/v1` manifest
digest. A manifest is tied to the exact model it describes.

**Each tensor carries:**
- **`file`:** its file within a directory.
- **`name`:** its name as the format stores it.
- **`dtype`:** as the format names it, such as `F32`, `BF16`, or `Q4_K`.
- **`shape`:** the logical shape, outermost dimension first. GGUF lists
  dimensions innermost first, so they are reversed.
- **`bytes`:** its size in bytes.
- **`sha256`:** the hash of its raw bytes.
- **`values`:** for `F32`, `F16`, and `BF16` only, the hash of its values in
  `float32-le-bits/v1`. That encoding widens each element exactly to IEEE 754
  binary32 and writes its four little-endian bytes, in storage order:
  - BF16 is the upper half of a float32;
  - F16 widens without rounding, subnormals included;
  - a NaN keeps its payload.

  So the encoding is one to one, and a lossless conversion between these
  dtypes keeps the values hash.

**`unread`** lists any file or tensor that could not be fingerprinted, with
the reason. Examples are a tensor type whose size is not known, or a file whose
tensor layout overlaps or leaves gaps, which loaders read differently.

The manifest is deterministic: tensors sorted by file and name, the same JSON
for the same model.

Reading one reads every tensor's data: about 460 MB/s on one core of an Apple
M-series machine, which is two minutes for 52 GB.

## How two models are compared

Each tensor is used once.

1. **By name.** Each tensor is compared with the reference's tensor of the
   same name, in the same file when there is one. The outcome is:
   - **identical:** the same dtype, shape, and bytes;
   - **same values:** the same shape and values in another float dtype;
   - **differs:** another shape, or other contents;
   - **not comparable:** no encoding in common, such as a quantized type
     against a float.

   Matching by name first means two tensors of the same shape that exchanged
   places differ, as they should.
2. **By content, for names the other side lacks.** Identical bytes, or
   identical values in another float dtype with the same shape, pair two
   tensors under different names. This is how a GGUF's `blk.0.ffn_down.weight`
   meets a safetensors `model.layers.0.mlp.down_proj.weight`. Such a match is
   marked `renamed`: names were not compared for it.
3. **What is left** is only in the artifact or only in the reference.

## The Tensor reference row

`SOCAIR_TENSOR_REFERENCE=<manifest>` adds a Tensor reference row to every scan.
Without it there is no row, and nothing about a scan changes.

The report names the reference in `scope.reference_data` by its file name and
the SHA-256 of its bytes, never by a path. A reference that cannot be read
stops the scan.

| Result | When |
|---|---|
| PASS | Every tensor matched under its own name, by bytes or by values, and nothing on either side went unread: the weights are the reference's weights. |
| LEAD | Within one file format, a tensor differs (`tensor-differs`), is not in the reference (`tensor-not-in-reference`), or is missing (`tensor-missing`). The weights are not the reference's. |
| NOT_TESTED | The two are in different file formats, a tensor matched only under another name, a tensor has no encoding in common with the reference's, or a file or tensor went unread on either side. The notes say what matched. |

It never FAILs: weights that differ from a reference are not evidence of
malice.

**Across file formats it does not judge.** A converter renames tensors, and it
can reorder, split, fuse, or quantize them. For example, llama.cpp reorders the
rows of the Q and K projections for Llama-style models (`LlamaModel.permute` in
`conversion/llama.py`, at commit `529ac89`, and the same in about a dozen other
architectures' converters). A GGUF of a reviewed model therefore leaves Q and
K tensors unmatched without any change to the model.

**A quantized model has no exact encoding** to compare with its float
original. #162 covers similarity for those.

A header-only scan reads no tensor data, so the row is NOT_TESTED there.

## What it does not cover

- **Torch checkpoints** (`.bin`, `.pt`): not fingerprinted yet. The pickle
  grammar's model of the checkpoint (`pickle.ReadStateDict`) is the way in.
- **ONNX and other formats:** not read.
- **Undoing a converter's reordering**, so a GGUF's Q and K can be compared
  with the safetensors original.
- **Reference manifests in the signed feed**, so a published model's
  fingerprints can be compared without the model.
