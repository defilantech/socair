# ONNX models

Socair reads an ONNX model (`.onnx`) on its own or inside a model directory,
such as the `onnx/` exports that sentence-transformers, Xenova, and
onnx-community repositories ship beside their weights. The Format and
structure row checks the model's graph, its tensors, and the external data
they name; the File inventory row scans the model's text for payloads. This
page says what each row reads, how it grades, and what it does not cover.

ONNX runs no Python, and an ONNX file holds no code a loader executes. What a
runtime executes are operators: ONNX's own, the runtime's own (onnxruntime's
contrib operators), and custom operators from a native library the deployment
registers. That library is outside the model, and outside this scan.

## How the model is read

`internal/onnx` reads the protobuf wire format of `ModelProto` against
[`onnx.proto`](https://github.com/onnx/onnx/blob/v1.23.2/onnx/onnx.proto) at
onnx v1.23.2 (commit `e1ac8e74b620`, IR version 14), with the Go standard
library only. It reads every field `onnx.proto` defines, in every message the
model holds: the graph, subgraphs in node attributes (the bodies of `If`,
`Loop`, and `Scan`), model-local functions, and training graphs. It never reads
tensor data: `raw_data` is skipped and typed values are counted.

A file is ONNX by its bytes, never its name: its top level must walk as
protobuf fields to the end of the file and hold an `ir_version` (field 1) and
a graph (field 7). In a model directory, every `.onnx` file is read whatever
its bytes (a file that is not ONNX is NOT_TESTED with the reason), and every
file is still checked for pickle bytes first, as before.

The reader follows protobuf where a scanner could read a model differently
from a loader, and names what it did not model:

| What the bytes hold | What protobuf does | Grade |
|---|---|---|
| A field `onnx.proto` does not define, or a reserved field number | keeps it as an unknown field; a loader does not read it | NOT_TESTED, named |
| A known field in another wire type | keeps it as an unknown field | NOT_TESTED, named |
| A value outside a closed (proto2) enum, such as `data_location = 2` | keeps it as an unknown field; the field stays unset | NOT_TESTED, named |
| A singular field twice, or two members of a oneof | keeps the last value, or merges the messages | NOT_TESTED, named |
| Truncated bytes, a length past its message, an overlong varint, a group | refuses the message | NOT_TESTED (unparseable) |

Bounds: a file larger than 2^31-1 bytes (protobuf's default total-bytes limit,
`kDefaultTotalBytesLimit` in `coded_stream.h`, which onnxruntime parses with
in `core/graph/model.cc`), messages nested deeper than 100 levels (protobuf's
default recursion limit), 262,144 tensors, 1,024 dims a tensor, 64 KiB a name,
domain, or external_data entry, and 16 MiB for one text value and 64 MiB for
all of them. Past any of these the model is NOT_TESTED, except text, which
leaves the File inventory row NOT_TESTED. The reader is fuzzed by `FuzzRead` (`internal/onnx`), which CI's
fuzz job runs with the other parsers.

## Format and structure

### External data

A tensor whose `data_location` is `EXTERNAL` keeps its bytes in another file,
named by its `external_data` entries: `location` (a path relative to the
directory of the `.onnx` file), and optional `offset`, `length`, and
`checksum` ([ExternalData.md](https://github.com/onnx/onnx/blob/v1.23.2/docs/ExternalData.md)).
Every `location` is checked, whatever `data_location` says.

| Location | Grade | Why |
|---|---|---|
| absolute (`/etc/hosts`), rooted (`\Windows\...`), a Windows drive (`C:...`), or climbing out of the model's directory with `..` (`../../etc/hosts`, `..\..\x`) | FAIL, `external-data-escape` | It names a file outside the model. The spec disallows it, no writer produces it (onnx's `save` refuses `..` and absolute paths), and older loaders read the file it names: onnx before 1.13.0 ([CVE-2022-25882](https://github.com/advisories/GHSA-ffxj-547x-5j7c)) and through 1.15.0 ([CVE-2024-27318](https://github.com/advisories/GHSA-whh8-fjgc-qp73)), and onnxruntime 1.20.0, whose loader joins the location to the model's directory with no containment check (`GetExternalDataInfo` in `tensorprotoutils.cc`). onnx 1.23.2 and onnxruntime 1.31.0 refuse it. |
| `*/_ORT_MEM_ADDR_/*` or `*/_ORT_NATIVE_ENDIAN_MEM_ADDR_/*` | FAIL, `external-data-memory` | onnxruntime's in-process marker for tensor data already in memory (`core/framework/tensorprotoutils.h`): onnxruntime 1.20.0 reads the tensor from the address in `offset`. onnxruntime 1.31.0 refuses one in a model file, because "the model is crafted and would cause ORT to dereference an attacker-supplied pointer" (`core/graph/graph.cc`). |
| a `..` component that stays inside as text (`sub/../w.bin`), a backslash, a colon, or a control character | LEAD, `external-data-path` | Systems read it differently: the spec disallows `..` and onnxruntime refuses this one while onnx 1.23.2 loads it; a backslash is a separator on Windows and a file-name character elsewhere; a colon names an NTFS alternate data stream; a NUL ends the path early for some readers. None is a clear escape, so it is a lead, not evidence. |
| a clean relative path | checked as below | |

The boundary is the model's own directory, as onnx and onnxruntime resolve it:
`onnx/model.onnx` may not read `../model.safetensors`, though the scan holds
that file. Links are not judged: a directory scan copies every file into a
private snapshot, following a link to a regular file, so the bytes a link
named are the bytes attested and checked, and the airlock promotes regular
files. A Hugging Face cache snapshot is built of links out of its directory
(into `blobs/`), so a link out is not evidence. A location through a linked
directory names a file the snapshot does not hold, which is NOT_TESTED.

For a clean location:

- **Its length.** `length`, when given and not 0, must be exactly what the
  tensor's dims and type need. Otherwise FAIL, `tensor-size`: onnxruntime
  refuses it ("external data size mismatch") and onnx 1.23.2 loads it. A
  `length` of 0 for a tensor of more bytes is NOT_TESTED (onnxruntime reads
  the tensor's size, onnx reads nothing).
- **Its file, in a directory scan.** The file must be in the scan, beside the
  model, and hold the tensor's bytes from `offset`. A file the scan does not
  hold, or one too short, is NOT_TESTED with the file named: both loaders
  refuse the model, and an incomplete pull or a different file is as likely as
  tampering.
- **In a single-file scan,** the external file is not in the scan: the row is
  NOT_TESTED and says to scan the model's directory.
- **Other keys.** A repeated `location` is a FAIL, `duplicate-key`:
  onnxruntime refuses a second one and onnx takes the last, so the loaders read
  different files. A key other than `location`, `offset`, `length`, and
  `checksum` (onnxruntime refuses one, onnx ignores one, `basepath` included),
  and an `offset` or `length` that is not a plain decimal number, are
  NOT_TESTED: onnx reads them with Python's `int()`, which takes `+16` and
  `1_6`, and onnxruntime with `std::from_chars`, which takes neither but reads
  a `length` of `0x10` as hex (`include/onnxruntime/core/common/parse_string.h`). A
  `checksum` is not verified, and the notes say so. A STRING tensor stored
  externally is NOT_TESTED: onnxruntime refuses it.
- **Inline data as well.** An external tensor that also carries data in the
  model file is a FAIL, `tensor-data`: onnxruntime does not read it and onnx's
  checker refuses it.

Bytes of an external data file outside every tensor's range are not read; such
a file is one more file in the directory, which the File inventory row lists
as it lists every file.

### Tensor data against type and shape

Every tensor (initializers, the values and indices of sparse initializers,
tensors in node and function attributes such as a `Constant`'s `value`, in
the main graph, every subgraph, and every function body) must hold exactly the
data its `data_type` and `dims` need, as `onnx.proto` states it:

- in `raw_data`: ceil(n × bits / 8) bytes, with 4-bit types packed two to a
  byte, 2-bit types four to a byte, and 6-bit types four to three bytes;
- in a typed field: the one field its type uses (`float_data` for FLOAT and
  COMPLEX64, `int32_data` for the 8- and 16-bit types and FLOAT16, BFLOAT16,
  the FLOAT8 and FLOAT6 types, `int64_data`, `double_data`, `uint64_data` for
  UINT32 and UINT64, `string_data` for STRING), n entries, or 2n for the
  complex types.

| Tensor | Grade |
|---|---|
| `raw_data` longer or shorter than its type and dims need | FAIL, `tensor-size`. onnxruntime refuses any mismatch; onnx's checker refuses only data too short, so extra bytes load in one loader and no loader reads them. |
| a typed field with the wrong count | FAIL, `tensor-size` |
| no data for one or more elements, or data for none | FAIL, `tensor-size` |
| data in two fields, or in a field its type does not use, or STRING data in `raw_data` | FAIL, `tensor-data`. onnxruntime reads `raw_data` and ignores the rest; onnx's checker refuses it. |
| two initializers of one graph (dense or sparse) with one name | FAIL, `duplicate-key`. onnxruntime uses the last ("Duplicate initializer ... the model will use the latest"), onnx's checker refuses the model. A name in a subgraph is another scope. |
| a data type `onnx.proto` v1.23.2 does not define, no data type, a negative dim, a size that overflows, or a `segment` | NOT_TESTED |
| a 4-bit or 2-bit type in `int32_data` | NOT_TESTED: `onnx.proto` says an entry holds two (or four) elements and onnx's checker counts eight (or sixteen) |

Tensor values are not read.

### Operators

| Domain a node names | Grade |
|---|---|
| ONNX's own: `""` or `ai.onnx`, `ai.onnx.ml`, `ai.onnx.training`, `ai.onnx.preview`, `ai.onnx.preview.training` ([`onnx/common/constants.h`](https://github.com/onnx/onnx/blob/v1.23.2/onnx/common/constants.h)) | PASS |
| `com.microsoft`, onnxruntime's contrib operators (`kMSDomain`, [`include/onnxruntime/core/graph/constants.h`](https://github.com/microsoft/onnxruntime/blob/v1.31.0/include/onnxruntime/core/graph/constants.h)) | PASS, with each operator named in the notes: its kernels are built into onnxruntime, not added by the deployment, and another runtime may not have them |
| a model-local function (`ModelProto.functions`), by domain, name, and overload | PASS: the function's body is read as nodes, and graded as they are |
| any other domain | NOT_TESTED, naming the domain and its operators: a runtime runs it only from a custom-operator library the deployment registers, native code outside the model |

Only the domains nodes use are graded; an opset imported and unused is listed
in the notes and changes nothing.

Why `com.microsoft` is named and not a LEAD: optimized and 4-bit exports are
built on it. Of 43 real exports (see
[false-positive-baseline.md](false-positive-baseline.md)), 23 have a node in
it: every O2 to O4 sentence-transformers export (written by onnxruntime's
transformer optimizer), every 4-bit Xenova and whisper-tiny export, and every
gemma-3-270m and embeddinggemma-300m export (`SkipLayerNormalization`,
`BiasGelu`, `FastGelu`, `MatMulNBits`, `MatMulBnb4`, `GroupQueryAttention`,
`MultiHeadAttention`, `RotaryEmbedding`, `GatherBlockQuantized`). None uses
another domain outside ONNX's. A LEAD there would withhold more than half of
them.

Why a custom domain is NOT_TESTED and not a LEAD: nothing in the model makes a
runtime load code. onnxruntime refuses the model unless the deployment
registers a library for that domain, so the model needs native code outside
the attestation; that is a gap the acceptor can accept by naming the library
they deploy, not a sign of an attack in the model.

**EPContext.** A `com.microsoft` `EPContext` node holds a precompiled
execution-provider context: compiled code for an accelerator (the schema
names QNN's), embedded in `ep_cache_context` or, with
`embed_mode` 0, in a file it names relative to the model
([`contrib_defs.cc`](https://github.com/microsoft/onnxruntime/blob/v1.31.0/onnxruntime/core/graph/contrib_ops/contrib_defs.cc)).
The scan does not read it, so an EPContext node is NOT_TESTED. A path is
graded as an external data location is (a path out is a FAIL), and an
embedded context is left out of the File inventory scan, which names it.

### PASS

The row PASSes only when the model parsed with nothing unread, every tensor
holds exactly its data, every external data reference is clean and (in a
directory scan) found and fits, and every operator is ONNX's own,
onnxruntime's contrib operators, or a local function. Its notes give the IR
version, producer, opsets, node and graph counts, tensors inline and external,
and every `com.microsoft` operator, and say what it does not cover: tensor
values, and the native code a runtime runs for an operator.

## File inventory and payloads

The model's text goes through the same payload patterns as GGUF and
safetensors metadata (scripts, long base64 blobs, executable and archive
signatures): `producer_name`, `producer_version`, the model's `domain`, every
`doc_string`, every `metadata_props` key and value (of the model, graphs,
nodes, tensors, and values), every string attribute, and every element of a
STRINGS attribute or a STRING tensor of 64 bytes or more (shorter elements
are counted, as GGUF string-array elements are). Names of graphs, nodes,
values, and tensors are identifiers and are not scanned. An EPContext's
embedded context is compiled code, not text: it is not scanned, and the row is
NOT_TESTED, naming it. Text past the reader's caps leaves the row NOT_TESTED.

## Not covered

- Tensor values: what the weights compute.
- Custom-operator libraries, and the runtime itself.
- Bytes of an external data file outside every tensor's range.
- An EPContext's compiled context.
- The intake policy's formats (`SOCAIR_INTAKE_POLICY`) do not include ONNX:
  an ONNX file is a format the policy does not identify.
- OpenVINO IR (`openvino_model.xml` and `.bin`), which sentence-transformers
  repositories also ship: its `.bin` reaches the Pickle opcode scan by its
  extension and is NOT_TESTED there, so a whole-repository pull is still
  withheld on it. That is a follow-up.

## Sources

- `onnx.proto`, `docs/ExternalData.md`, `onnx/checker.cc` (`check_tensor`,
  `resolve_external_data_location`), `onnx/external_data_helper.py`, and
  `onnx/common/constants.h` at [onnx v1.23.2](https://github.com/onnx/onnx/tree/v1.23.2)
  (commit `e1ac8e74b620`).
- `core/framework/tensorprotoutils.cc` and `.h` (`ValidateExternalDataPath`,
  `GetExternalDataInfo`, the memory markers, `UnpackTensor`),
  `core/framework/tensor_external_data_info.cc` (`ExternalDataInfo::Create`),
  `include/onnxruntime/core/common/parse_string.h`,
  `core/graph/graph.cc`, `core/graph/model.cc`, `core/graph/contrib_ops/contrib_defs.cc`,
  and `include/onnxruntime/core/graph/constants.h` at
  [onnxruntime v1.31.0](https://github.com/microsoft/onnxruntime/tree/v1.31.0)
  (commit `402979ac1bef`), and `tensorprotoutils.cc` at v1.20.0 for the
  behaviour before the checks.
- `src/google/protobuf/io/coded_stream.h` at
  [protobuf v36.2](https://github.com/protocolbuffers/protobuf/tree/v36.2) for
  the default limits.
- The advisories: [GHSA-ffxj-547x-5j7c](https://github.com/advisories/GHSA-ffxj-547x-5j7c)
  (CVE-2022-25882), [GHSA-whh8-fjgc-qp73](https://github.com/advisories/GHSA-whh8-fjgc-qp73)
  (CVE-2024-27318), and the 2026 symlink and hardlink advisories
  [GHSA-3r9x-f23j-gc73](https://github.com/advisories/GHSA-3r9x-f23j-gc73),
  [GHSA-p433-9wv8-28xj](https://github.com/advisories/GHSA-p433-9wv8-28xj), and
  [GHSA-cmw6-hcpp-c6jp](https://github.com/advisories/GHSA-cmw6-hcpp-c6jp),
  which the snapshot answers by attesting the bytes a link named.

What each grade says onnx and onnxruntime do was confirmed by loading defanged
models in onnx 1.23.2 and onnxruntime 1.31.0 (2026-10-14): both refuse an
escaping location, the memory marker, a missing file, and data past the end
of its file; onnxruntime refuses a length or `raw_data` mismatch, a repeated
location, and an unregistered custom domain, all of which onnx's checker
accepts except a short `raw_data`; onnxruntime loads data in two fields and a
repeated initializer name, which onnx's checker refuses; both load a
`com.microsoft` operator.
