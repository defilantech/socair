#!/usr/bin/env python3
"""Compare a converted safetensors file with the checkpoint it came from.

    python3 compare_torch.py <checkpoint> <converted.safetensors>

The checkpoint is loaded with torch.load(weights_only=True), as a serving
stack would load it. The safetensors file is read with the standard library
and torch.frombuffer, not with Socair's code or the safetensors package, so
the comparison does not share a reader with what it checks. Every tensor in
the checkpoint must be in the output, under its name or, for an exact alias,
under the name __metadata__ gives it, with the same dtype, shape, and bytes
(bytes, so a NaN compares equal to itself). The output may hold nothing else.
When the safetensors package is installed, the output is also loaded with its
reference reader (safetensors.torch.load_file), which must accept the file and
give the same tensors.

Prints "ok <n> tensors" and exits 0, or prints each difference and exits 1.
It is run by TestRealCheckpoints (convert's corpus test) and only when torch is
installed; it is never part of the default test run.
"""

import json
import struct
import sys

import torch

DTYPES = {
    "BOOL": torch.bool,
    "U8": torch.uint8,
    "I8": torch.int8,
    "I16": torch.int16,
    "I32": torch.int32,
    "I64": torch.int64,
    "F16": torch.float16,
    "BF16": torch.bfloat16,
    "F32": torch.float32,
    "F64": torch.float64,
}
for name, attr in [
    ("U16", "uint16"),
    ("U32", "uint32"),
    ("U64", "uint64"),
    ("F8_E4M3", "float8_e4m3fn"),
    ("F8_E5M2", "float8_e5m2"),
]:
    if hasattr(torch, attr):
        DTYPES[name] = getattr(torch, attr)


def read_safetensors(path):
    with open(path, "rb") as f:
        (n,) = struct.unpack("<Q", f.read(8))
        header = json.loads(f.read(n))
        data = f.read()
    meta = header.pop("__metadata__", {})
    tensors = {}
    for name, entry in header.items():
        dtype = DTYPES[entry["dtype"]]
        begin, end = entry["data_offsets"]
        if end == begin:
            tensors[name] = torch.empty(entry["shape"], dtype=dtype)
        else:
            buf = bytearray(data[begin:end])
            tensors[name] = torch.frombuffer(buf, dtype=dtype).reshape(entry["shape"])
    return tensors, meta


def raw(t):
    return t.detach().contiguous().reshape(-1).view(torch.uint8).tolist()


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: compare_torch.py <checkpoint> <converted.safetensors>")
    loaded = torch.load(sys.argv[1], map_location="cpu", weights_only=True)
    out, meta = read_safetensors(sys.argv[2])
    problems = []
    seen = set()
    for name, t in loaded.items():
        held = name if name in out else meta.get(name)
        if held not in out:
            problems.append(f"{name}: not in the output")
            continue
        seen.add(held)
        got = out[held]
        if got.dtype != t.dtype or tuple(got.shape) != tuple(t.shape):
            problems.append(f"{name}: {got.dtype} {tuple(got.shape)} in the output, {t.dtype} {tuple(t.shape)} in the checkpoint")
        elif raw(got) != raw(t):
            problems.append(f"{name}: the bytes differ")
    for name in out:
        if name not in seen:
            problems.append(f"{name}: in the output, not in the checkpoint")
    for k, v in meta.items():
        if k != "format" and (k not in loaded or v not in out):
            problems.append(f"__metadata__ {k}: {v} names no alias in the checkpoint")
    reference = ""
    try:
        from safetensors.torch import load_file
    except ImportError:
        load_file = None
    if load_file is not None:
        ref = load_file(sys.argv[2])
        if sorted(ref) != sorted(out):
            problems.append(f"safetensors reads {sorted(ref)}, this script {sorted(out)}")
        for name, t in ref.items():
            if name in out and (t.dtype != out[name].dtype or raw(t) != raw(out[name])):
                problems.append(f"{name}: safetensors reads other values")
        reference = ", and safetensors' reader agrees"
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print(f"ok {len(loaded)} tensors{reference}")


if __name__ == "__main__":
    main()
