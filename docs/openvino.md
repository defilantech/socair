# OpenVINO IR models

Socair reads an OpenVINO IR model, an `.xml` that describes the graph and the
`.bin` that holds its weights, on its own or inside a model directory, such as
the `openvino/` exports that sentence-transformers repositories ship beside
their weights and the exports the OpenVINO organization publishes. The Format
and structure row checks the graph's operations and every byte range the
`.xml` names in the `.bin`; the File inventory row scans the `.xml`'s text for
payloads. This page says what each row reads, how it grades, and what it does
not cover.

An IR holds no code a loader executes. What a runtime executes are
operations: OpenVINO's own, in its opsets, and operations from an extension
library the deployment registers (`openvino_tokenizers` is one). That library
is outside the model, and outside this scan.

## How the model is read

The reference is OpenVINO 2026.4.1 (commit `e213a1472576`): its IR frontend,
[`src/frontends/ir/src/frontend.cpp`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/src/frontends/ir/src/frontend.cpp)
and [`input_model.cpp`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/src/frontends/ir/src/input_model.cpp),
and the deserializer it reads a model with,
[`src/core/xml_util/src/xml_deserialize_util.cpp`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/src/core/xml_util/src/xml_deserialize_util.cpp).
The format is described in
[OpenVINO IR format](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/docs/articles_en/documentation/openvino-ir-format.rst):
`<layer>` elements for operations, `<edge>` elements for the data flow, and a
`Const` layer, "the only operation ... that refers to the IR binary file", whose
`<data>` gives its `element_type`, `shape`, and the `offset` and `size` of its
bytes in the `.bin`.

`internal/openvino` reads the `.xml` with Go's `encoding/xml`, streaming, and
keeps what the deserializer would build:

- **The IR.** A file is an IR by its bytes, never its name: an XML document
  whose root element is `net`, in any case, as the frontend identifies one
  (`get_ir_version`). OpenVINO 2026.4.1 reads IR versions 10 and 11 (the
  root's `version`; `FrontEnd::supported_impl`); any other version is
  NOT_TESTED. In a model directory, every `.xml` whose root is `net` is read.
- **The `.bin`.** OpenVINO reads the `.xml`'s path with its extension
  replaced by `.bin` (`FrontEnd::load_impl`), so `openvino/openvino_model.xml`
  reads `openvino/openvino_model.bin`. Socair resolves it the same way, inside
  the scan's snapshot, and reads only its size.
- **Which layers are built.** The deserializer builds every `Parameter` and
  every layer a `Result` or an `Assign` depends on through the edges, found
  from the outputs back (`XmlDeserializer::parse_function`); a later layer
  with an id replaces an earlier one. A layer no output depends on is never
  created: its type is not looked up and its `Const` is not read. Socair
  follows this, and a layer OpenVINO does not build is NOT_TESTED, named. A
  built `TensorIterator` or `Loop` builds its `<body>`, and a built `If` its
  `<then_body>` and `<else_body>`, the same way; a body under any other layer
  is not read.
- **Operations.** A layer's `version` names an opset and its `type` an
  operation in it, looked up ignoring ASCII case (`OpSet::create_insensitive`;
  `Const` is read as `Constant`). OpenVINO 2026.4.1 knows `opset1` to
  `opset17` (`ov::get_available_opsets`). Two redirects come from the
  deserializer: eight older operations (`GRUCell`, `RNNCell`, `Proposal`, and
  the five `ExperimentalDetectron*` operations) with version `experimental` or
  `extension` are built from `opset6`, and `MVN`, `ROIPooling`, and `ReorgYolo`
  named `opset1` from `opset2`. The tables are embedded in
  `internal/openvino/opsets.txt`, written by `internal/openvino/opsetgen` from
  `src/core/include/openvino/opsets/opset<N>_tbl.hpp` at 2026.4.1, and were
  checked against OpenVINO 2026.4.1 itself: for each of the 17 opsets and each
  of the 207 operation names the tables list (besides `Parameter` and
  `Result`) and one name none lists, 3,536 pairs, an IR naming it was read,
  and OpenVINO said the opset lacks the operation exactly where the table
  does, apart from the three `opset1` redirects.
- **Text.** Every element and attribute name, attribute value, character
  data, comment, processing instruction, and declaration, each distinct value
  once, for the inventory.

### What the XML parser does

OpenVINO parses the XML with [pugixml](https://pugixml.org/). Where pugixml
reads a document differently from a conforming XML parser, Socair follows
pugixml and grades the difference:

| What the XML holds | What OpenVINO does | Grade |
|---|---|---|
| An attribute repeated on one element | pugixml reads the first; XML forbids it, and a conforming parser refuses the file | FAIL, `duplicate-key` |
| A layer id given to two layers of one graph | builds the later layer and drops the other | FAIL, `duplicate-key` |
| An element OpenVINO reads once, repeated (a second `<data>` in a layer, a second `<layers>` in the net) | reads the first and ignores the rest | NOT_TESTED, named |
| An element where the IR has none (`<statistics>` in the net), a `<pre-process>` block (mean values read from the `.bin`), a DOCTYPE | ignores it, or reads what this reader does not model | NOT_TESTED, named |
| A layer typed `Constant` (not `Const`) | builds the constant from the XML's `value` attribute, not the `.bin` | NOT_TESTED, named |
| A missing mandatory attribute (a layer's `id`, `name`, `type`, `version`; an edge's ports), or an edge from a layer the graph does not define | refuses the model | NOT_TESTED, named |
| Malformed XML, an entity reference other than XML's own, a declared encoding other than UTF-8, a second root, text outside the root | refuses it, or reads it differently | NOT_TESTED (unparseable) |

Numbers are read only when they are plain decimal digits: OpenVINO reads
`offset` and `size` with `std::stoll`, which also takes a sign, leading white
space, and `-0`, and a shape's dimensions with `std::from_chars`, which stops at
the first non-digit (OpenVINO 2026.4.1 reads a shape of `4x` as `[4]`). A value
Socair would read differently is NOT_TESTED, never guessed. A shape is split at
commas and each part trimmed of white space, as `str_to_container` does, so
the serializer's `"30522, 384"` reads as `[30522, 384]`.

`encoding/xml` processes no DTD and resolves no external entity: a DOCTYPE is
recorded and skipped, and an entity it declares is an error where it is used.
There is no XML external-entity or entity-expansion path.

Bounds: a file larger than 256 MiB (the largest IR measured is a 9.7 MB XML,
`OpenVINO/Qwen3.8-27B-int4-ov`'s language model), elements nested more than 256
deep, more than 2^23 elements, 4,096 attributes on one element, 16 MiB in one
attribute value, text, or comment, 2^20 layers, 2^22 edges, or 2^16 graphs.
Past any of these the IR is NOT_TESTED. Text past 64 MiB or 2^20 distinct
values is not kept, which leaves the File inventory row NOT_TESTED. OpenVINO
sets none of these limits. The reader is fuzzed by `FuzzRead`
(`internal/openvino`), which CI's fuzz job runs with the other parsers.

## Format and structure

### Const sizes

Every built `Const` must be exactly the size OpenVINO allocates for its
element type and shape: `ov::util::get_memory_size`
([`src/core/src/memory_util.cpp`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/src/core/src/memory_util.cpp)),
which the IR writer writes as `size`:

- byte types: `bits / 8 × n` bytes;
- `u1`, `u2`, and the 4-bit types (`u4`, `i4`, `nf4`, `f4e2m1`): `8 / bits`
  elements to a byte, rounded up;
- `u3` and `u6`: `24 / bits` elements to each 3-byte group, rounded up to whole
  groups.

An empty Const (an element count of 0) may also be 1 byte: OpenVINO's
`AlignedBuffer` allocates at least one byte
([`aligned_buffer.cpp`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/src/core/src/runtime/aligned_buffer.cpp)),
and the writer writes the buffer's size. One real detokenizer has one.

The element types are the names of `element::Type_t`, which
`Constant::visit_attributes` reads the attribute through, so `FP32` and the
other aliases are refused (checked in OpenVINO 2026.4.1).

| Const | What OpenVINO does | Grade |
|---|---|---|
| `size` short of `ceil(n × bits / 8)` | refuses it ("Attribute and shape size are inconsistent") | FAIL, `tensor-size` |
| a `u3` or `u6` Const at least `ceil(n × bits / 8)` but short of whole 3-byte groups | reads it | FAIL, `tensor-size` |
| `size` larger than its type and shape take | loads it, with the extra bytes in the constant's buffer; no operation reads them as values, and the writer never writes them | FAIL, `tensor-size` |
| an element type OpenVINO does not define, a missing attribute, a shape or range this reader does not read as OpenVINO does, or a shape whose size overflows | refuses it, or reads it differently | NOT_TESTED |
| `dynamic` element type | holds no defined data | NOT_TESTED |
| `string` element type | a packed string tensor, whose size depends on its strings; it is not read | NOT_TESTED |

The size rule needs no `.bin`, so it holds in a single-file scan too. Why a
larger size is a FAIL though OpenVINO loads it: it is the ONNX branch's rule
for `raw_data` longer than its shape (onnx.md), the bytes are in the model
and read as no value, and no OpenVINO writer produces it. Measured on 46 real
IRs (below), no Const is larger than its type and shape take except the one
empty Const above.

### The `.bin`

| Finding | What OpenVINO does | Grade |
|---|---|---|
| a Const's range runs past the end of the `.bin`, or starts past it | refuses the model ("Incorrect weights in bin file!", `is_valid_weights_range`) | NOT_TESTED: a truncated download or a different file is as likely as tampering, as for ONNX external data that runs past its file |
| the `.bin` is missing (and the model has a Const) | refuses the model ("Empty weights data in bin file or bin file cannot be found!") | NOT_TESTED |
| bytes of the `.bin` outside every built Const's range: a gap, or a tail | never reads them | NOT_TESTED, naming the ranges |
| two Const ranges that partly overlap | reads both | NOT_TESTED, naming them |
| two Consts with the same range | reads both | not graded: the writer gives a Const whose bytes and size match an earlier one's the same range (`ConstantWriter::write`), and real exports share hundreds |
| a single-file scan of the `.xml` | | NOT_TESTED: the `.bin` is outside the scan; scan the model's directory |

Why bytes outside every Const are NOT_TESTED and not a FAIL: OpenVINO loads
the model, the IR format does not require the Consts to tile the file, and
those bytes are simply never read, so what they hold is not established. The
writer appends each Const's bytes in turn with no padding, and every one of
the 46 real IRs measured (written by OpenVINO 2022.3 to 2026.4) covers its
`.bin` exactly, so a gap means the IR is not as OpenVINO's writer writes one. The
row names the ranges, and an acceptor who accepts the gap accepts those bytes
unread. The `openvino-bin-tail` benchmark case pins this. A partial overlap
is NOT_TESTED for the same reason: OpenVINO reads it, and the writer never
produces one.

### Operations

| A built layer names | Grade |
|---|---|
| an operation in one of OpenVINO's opsets, as the reader looks it up (above) | PASS; the notes count the operation types per opset |
| any other version or type (`extension`, an unknown opset, an operation its opset lacks) | NOT_TESTED, naming the version and its types: a runtime builds it only from an extension library the deployment registers, native code outside the model |

Why an extension operation is NOT_TESTED and not a LEAD, as the ONNX branch
decided for a custom operator domain: nothing in the model makes a runtime
load code. OpenVINO refuses the model unless the deployment registers an
extension for that type and version, so the model needs native code outside
the attestation; that is a gap the acceptor can accept by naming the library
they deploy. Measured: every model IR in the corpus uses only OpenVINO's own
operations, and every tokenizer and detokenizer IR uses `extension`
operations from `openvino_tokenizers` (`BPETokenizer`, `RegexSplit`,
`VocabDecoder`, `CharsMapNormalization`, and others; its `rt_info` names
`openvino_tokenizers_version`). OpenVINO 2026.4.1 refuses each of those
detokenizers without the extension ("Cannot create VocabDecoder layer ...
from unsupported opset: extension"). A deployment registers an extension for
a standard operation too (the deserializer looks extensions up first); that
is outside the model.

### PASS

The row PASSes only when the IR parsed with nothing unread, every layer is
built, every built Const is exactly its type and shape's size and lies
inside the `.bin`, the Consts cover the `.bin` with no byte outside them and
none partly overlapping, and every built operation is in OpenVINO's opsets.
Its notes give the IR version, the layer and graph counts, the opsets used,
and the Consts and their distinct ranges in the `.bin`, and say what it does
not cover: tensor values, and the native code a runtime runs for an
operation.

## File inventory and payloads

The `.xml`'s text goes through the same payload patterns as GGUF and
safetensors metadata (scripts, long base64 blobs, executable and archive
signatures): every attribute value (each layer's `<data>`, `rt_info` at the
model, layer, and port level, legacy `<meta_data>`), every element and
attribute name (an `rt_info` key is an element name), character data, and
comments. Unlike ONNX, names are scanned too: in an IR every value is text,
and on 46 real IRs (about 1.2 million attribute values and texts) no pattern
matched. Text past the reader's caps leaves the row NOT_TESTED. The `.bin`
holds tensor data and is not scanned for payloads; its bytes outside every
Const are graded by the structure row.

## The Pickle opcode scan

A `.bin` is also PyTorch's extension, so in a model directory a `.bin` went
to the Pickle opcode scan by its name and was NOT_TESTED there ("not a pickle
opcode stream"), which withheld every repository with an `openvino/` export.
Now a `.bin` that an IR beside it names as its weights (the same path as an
`.xml` whose root is `net`) is read through that `.xml` and does not reach
the pickle row by its name. It still reaches it by its bytes: like every
file, it is checked for a pickle stream or a torch zip first
(`pickle.Sniff`), and one that is a pickle is scanned as one. A `.bin` with
no IR beside it, `pytorch_model.bin` included, is handled as before, and so is
a `.bin` scanned on its own: raw tensor data says nothing about the IR it
belongs to.

## Not covered

- Tensor values: what the weights compute.
- Extension libraries (`openvino_tokenizers` and others), and the runtime and
  its plugins.
- A string Const's packed strings, and a `<pre-process>` block.
- The `chat_template` that `openvino_tokenizers` writes into a tokenizer IR's
  `rt_info`, which OpenVINO GenAI applies: the File inventory row scans it
  with the payload patterns, but the Chat template row reads the templates in
  `tokenizer_config.json`, `chat_template.json`, and `.jinja` files, not this
  copy, and does not compare the two. That is a follow-up.
- The intake policy's formats (`SOCAIR_INTAKE_POLICY`) do not include
  OpenVINO IR, as they do not include ONNX.
- A model compiled for a device (`ov::CompiledModel::export_model`, a blob
  cache) is not an IR and is not read.

## Sources

- OpenVINO at [2026.4.1](https://github.com/openvinotoolkit/openvino/tree/2026.4.1)
  (commit `e213a1472576`): `src/frontends/ir/src/frontend.cpp`
  (`get_ir_version`, `supported_impl`, `load_impl`), `input_model.cpp`
  (`parse_pre_process`, `InputModelIRImpl`),
  `src/core/xml_util/src/xml_deserialize_util.cpp` (`parse_function`,
  `create_node`, `set_constant_num_buffer`, `is_valid_weights_range`,
  `str_to_container`), `src/core/xml_util/src/weights_provider.cpp`
  (`make_region`), `src/common/util/src/xml_parse_utils.cpp`
  (`get_uint64_attr`), `src/common/util/include/openvino/util/common_util.hpp`
  (`trim`, `view_to_number`), `src/core/src/opsets/opset.cpp` and
  `src/core/include/openvino/opsets/opset<N>_tbl.hpp`,
  `src/core/src/type/element_type.cpp`, `src/core/src/memory_util.cpp`,
  `src/core/dev_api/openvino/core/type/element_iterator.hpp`,
  `src/core/src/runtime/aligned_buffer.cpp`, `src/core/src/op/constant.cpp`,
  `src/core/src/runtime/string_aligned_buffer.cpp`, and the writer,
  `src/core/src/xml_util/xml_serialize_util.cpp` and `constant_writer.cpp`.
- The format description,
  [`docs/articles_en/documentation/openvino-ir-format.rst`](https://github.com/openvinotoolkit/openvino/blob/2026.4.1/docs/articles_en/documentation/openvino-ir-format.rst),
  and the opsets it lists.
- 2024.6.0's `src/frontends/ir/src/ir_deserializer.cpp` and 2026.0.0's
  `xml_deserialize_util.cpp`, which make the same range and size checks.

What each grade says OpenVINO does was confirmed by reading defanged IRs with
the `openvino` 2026.4.1 Python package (`Core.read_model`, no compile, no
inference) on 2026-10-14: it refuses a range past the `.bin`, a size short of
its shape, a missing `.bin`, an operation its opset lacks, an unknown opset,
an `extension` operation with no extension registered, an alias element type,
and IR versions 7 and 12; it loads a larger size, bytes after the last Const,
a partly overlapping range, a layer no output depends on (even of an unknown
type), a repeated attribute (the first wins), a repeated layer id (the last
wins), a repeated `<data>` or `<layers>` (the first wins), a root spelled
`NET`, an unknown element, a DOCTYPE, and a shape of `4x` (as `[4]`).
