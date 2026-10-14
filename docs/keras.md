# Keras models

Socair reads a Keras model on its own or inside a model directory: a legacy
HDF5 file (`.h5`, `.hdf5`), which Keras 2, tf-keras, and Keras 3's legacy
format write, and which Hugging Face transformers writes as `tf_model.h5`;
the weights file Keras 3 writes on its own (`*.weights.h5`); and a `.keras`
archive. The Format and structure row checks the HDF5 layout, the archive's
members, and the model's config; the File inventory row scans the model's
text for payloads. This page says what each row reads, how it grades, and
what it does not cover.

A Keras model can carry code. A `Lambda` layer saved from a Python `lambda`
holds the function as marshalled Python bytecode, which the loader turns back
into a function and calls ([CVE-2024-3660](https://github.com/advisories/GHSA-x4wf-678h-2pmq)).
A config can also name a class or function by its module, which some Keras
versions import ([CVE-2025-1550](https://github.com/advisories/GHSA-48g7-3x6r-xfhp)),
and HDF5 can point a dataset or a link at another file. Keras 3's `safe_mode`
refuses some of this, but tf-keras applies it to `.keras` archives only, and
several bypasses have been fixed since (listed under Sources).

## How the file is read

A file is Keras by its bytes, never its name: HDF5 when the HDF5 signature is
at offset 0, or after a user block at 512, 1024, 2048, and so on; a `.keras`
archive when it is a zip whose first bytes are a local file header and that
holds `config.json` and `model.weights.h5` or `model.weights.npz`, the members
Keras' loader requires. In a model directory, a `.h5`, `.hdf5`, or `.keras`
file whose bytes are neither is a weight file in a format the scanner does not
parse, as before, and every file is still checked for pickle bytes first.

The engine names the format `Keras (HDF5)` for an HDF5 file with Keras'
attributes, `HDF5` for one without, and `Keras` for an archive. The Pickle
opcode scan does not run on one, except on an HDF5 file with a user block,
whose first bytes are not HDF5 and which a pickle loader would read first.

### HDF5

`internal/hdf5` reads HDF5 with the Go standard library only, against the
[HDF5 File Format Specification Version 4.0](https://github.com/HDFGroup/hdf5/blob/2.2.0/docs/doxygen/dox/H5.format.4.0.dox)
at HDF5 2.2.0. It reads what h5py writes by default and with
`libver="latest"`: superblock versions 0 to 3, version 1 and 2 object headers
(with their continuation blocks), groups as a symbol table (a version 1
B-tree, symbol table nodes, and a local heap) or as link messages, attributes
in the object header with fixed-length and variable-length strings (the
latter in a global heap), and compact, contiguous, and chunked storage indexed
by a version 1 B-tree, a single chunk, or the implicit index. It never reads
dataset data. The checksum (lookup3) of every structure it reads that has one,
a version 2 or 3 superblock and every version 2 object header block, is
verified, as the library verifies it.

Where the specification and the HDF5 library differ, the reader does what the
library does, since the library is what h5py, Keras, and transformers load
with:

| What the file holds | The library (HDF5 2.2.0) | The reader |
|---|---|---|
| A symbol table entry's link name offset | reads it as a length (`H5G_ent_decode`, `src/H5Gent.c`; `H5G_SIZEOF_ENTRY`, `src/H5Gprivate.h`); the specification's table marks it as an offset | reads it as a length; the two sizes are equal in every file h5py writes |
| A stored base address other than the superblock's offset | takes the superblock's offset as the base, and moves the end-of-file address by the difference (`H5F__super_read`, `src/H5Fsuper.c`) | the same |
| A version 1 object header whose message count differs from the messages it holds | refuses a count below the messages in its first block (`H5O__cache_deserialize`, `src/H5Ocache.c`); any other difference only with strict format checks (`H5O_protect`, `src/H5Oint.c`), since older libraries wrote wrong counts | the same; every message is read either way |

What it does not model is named, and leaves the row NOT_TESTED: dense
(fractal-heap) link or attribute storage, shared object header messages, a
superblock extension, a driver information block (the family and multi
drivers), a user-defined link, an object header message type it does not
know, a committed datatype, version 3 consistency flags that say the file is
open for writing, and the chunk indexes of layout versions 4 and 5 other than
a single chunk and the implicit index (h5py's `libver="latest"` writes fixed
array, extensible array, and version 2 B-tree indexes for chunked datasets).
Malformed bytes (a bad signature, a structure outside the file, a length past
its message, a checksum that does not match) make the file unparseable, and
the row NOT_TESTED with the reason.

Bounds: 262,144 objects, groups nested 64 deep, 65,536 messages and 4,096
continuation blocks in one object header, 64 MiB for any one structure read,
1,048,576 B-tree nodes, 4,194,304 chunks, a rank of 32 (HDF5's), and 16 MiB
for one string value and 64 MiB for all of them. Past any of these the file
is unparseable, except text, which leaves the File inventory row NOT_TESTED.
The reader is fuzzed by `FuzzRead` (`internal/hdf5`), and the Keras reader
over it by `FuzzRead` (`internal/keras`); CI's fuzz job runs both.

### `.keras` archives

Keras 3.15.1 writes `metadata.json`, `config.json`, and `model.weights.h5`
(or `model.weights.npz`), each stored uncompressed, and an `assets/`
directory for layers that save files, such as a lookup layer's vocabulary
(`saving_lib.py`, `_CONFIG_FILENAME` to `_ASSETS_DIRNAME`, L44 to L49). It
reads `config.json`, then the weights, and extracts every member of an
archive of more than three to a temporary directory for the assets
(L551 to L552). Keras 2.12 and later, and tf-keras, write and read the same
format (`saving_api.py` at keras v2.12.0).

The reader reads every member: `config.json` and `metadata.json` as JSON,
`model.weights.h5` as HDF5 (in place, when it is stored), and the bytes of
every other member as text for the File inventory row.

### Configs

A config (an archive's `config.json`, an HDF5 file's `model_config` and
`training_config` attributes, a KerasHub preset's JSON files) is written by
Python's `json.dumps` and read by `json.loads`, so it is decoded as
`checks/pyjson` decodes what a Python loader reads: `NaN`, `Infinity`, and
`-Infinity` are read, a repeated key keeps its last value, and data after the
value is refused. Every object with a `class_name` is examined, at any depth.
A config nested deeper than 512 levels, or with more than 65,536 references,
is NOT_TESTED for the part not walked.

## Format and structure

### Code in the config

| What the config holds | Grade | Why |
|---|---|---|
| A field `f` beside `f_type` of `"lambda"` (a Lambda's `function`, `output_shape`, or `mask`; an RNN cell wrapper's `dropout_fn` or `residual_fn`), under any class | FAIL, `keras-lambda` | Marshalled bytecode, which the loader turns into a function with `func_load` and calls. tf-keras 2.21.0 runs it from an `.h5` file whatever `safe_mode` says: `load_model` passes `safe_mode` to the `.keras` loader only (`saving/saving_api.py` L240), and `Lambda._parse_function_from_config` (`layers/core/lambda_layer.py` L362) and the cell wrappers' `_parse_config_to_function` (`layers/rnn/cell_wrappers.py` L650) check a safe-mode scope that the `.h5` path never sets. Keras 2 before 2.13 ran it from any file (CVE-2024-3660), and Keras 3 before 3.11.3 from an `.h5` file ([CVE-2025-9905](https://github.com/advisories/GHSA-36rr-ww3j-vrjv)). |
| A legacy Lambda whose `function` is a list, whatever its `function_type` | FAIL, `keras-lambda` | Keras 3's legacy loader turns a list into code without reading the type (`legacy/saving/saving_utils.py` L78 to L87). |
| An object of `class_name` `"__lambda__"` | FAIL, `keras-lambda` | Keras 3's serialized lambda. Keras refuses it in safe mode (`serialization_lib.py` L679) and runs it with safe mode off, as a config could turn it off from inside the load before 3.11.0 ([CVE-2025-9906](https://github.com/advisories/GHSA-36fq-jgmw-4r9c)). |
| A `TorchModuleWrapper` with a `module` | FAIL, `keras-pickle` | A base64 `torch.save` archive that Keras unpickles with `torch.load(weights_only=False)` when safe mode is off (`utils/torch_utils.py` L166 to L193), and did despite it in 3.11.0 to 3.11.2 ([CVE-2025-49655](https://github.com/advisories/GHSA-cvhh-q5g5-qprp)). |
| A Keras API in `NON_MODELING_APIS`, by name under any `keras` module (`get_file`, `enable_unsafe_deserialization`, `load_model`, and the rest) | FAIL, `keras-dangerous-reference` | Keras refuses to deserialize one, because a config that names it uses it as a gadget (`serialization_lib.py` L34 to L63; the loading APIs since 3.11.0). `get_file` writes a file ([CVE-2025-8747](https://github.com/advisories/GHSA-c9rc-mg46-23w3)), `enable_unsafe_deserialization` turns safe mode off (CVE-2025-9906). |
| A class or function named by a module, when the pickle check FAILs that module and name (`subprocess.run`, `os.system`, `builtins.eval`, ...) | FAIL, `keras-dangerous-reference` | Keras 3.0 to 3.8 import any module a config names and use what they find while rebuilding the model (CVE-2025-1550), and tf-keras 2.21.0 still imports any module by name (`saving/serialization_lib.py` L798). No model names one. |
| An object's `name` with a `..` component | LEAD, `keras-name-path` | Keras 3.14 and earlier join a layer's name into the path of its assets when saving or loading an archive, so it can leave the asset directory ([CVE-2026-12479](https://github.com/advisories/GHSA-gh82-f9x8-5frx)). Keras refuses a `/` in a name (`ops/operation.py` L25), not `..`. Whether it leaves depends on how deep the layer is, so it is a lead. |
| A class or function named by a module outside Keras, tf-keras, TensorFlow, KerasHub, KerasCV, and KerasNLP | NOT_TESTED, named | Code the caller installs, not code in the file: Keras 3.9 and later resolve it only from objects the caller registers (`serialization_lib.py` L815 to L905), and Keras 3.0 to 3.8 and tf-keras import it by name. |
| A class name Keras does not register, with no module (Keras 2 and legacy configs), a function named with no module, or a function a legacy Lambda names | NOT_TESTED, named | Keras resolves a legacy name only from its own registry and the objects the caller passes, and imports nothing by name. The registry is `internal/keras/keras-classes.txt`, which `internal/keras/classgen` writes from the keras 3.15.1 and tf_keras 2.21.0 wheels (their exported classes and the layer classes tf-keras' deserializer registers). |
| A `TFSMLayer` (`filepath`), or a lookup layer whose `vocabulary` is a path | NOT_TESTED, named | A TensorFlow SavedModel, or a file or URL, outside the model that the layer loads ([CVE-2026-1462](https://github.com/advisories/GHSA-4f3f-g24h-fr8m), [CVE-2025-12058](https://github.com/advisories/GHSA-mq84-hjqx-cwf2)). Keras refuses both in safe mode since those fixes (`export/tfsm_layer.py` L152, `layers/preprocessing/index_lookup.py` L443). |
| A class from KerasHub, KerasCV, or KerasNLP | named, not judged | Keras imports these packages, as it does its own, and takes only a `KerasSaveable` subclass from them (`serialization_lib.py` L880 to L896). |

**Why a Lambda's bytecode is a FAIL.** FAIL needs positive evidence, and the
bytecode is: it is executable code in the one field the loader turns into a
function and calls, and no loader that reads it skips it except Keras 3 in
safe mode, which refuses the whole model. The scan does not judge what the
code does: a Lambda computing a log-sum-exp is graded as a Lambda running a
command. Of 16 real configs measured
([false-positive-baseline.md](false-positive-baseline.md)), one holds a
Lambda (`kundajelab/encode-bpnet-...`, a Keras 2.4 model); it FAILs. A
reviewer who trusts it can re-save the model without the Lambda, or as
weights only.

**Why a custom object is NOT_TESTED.** Of the 16 real configs, three name a
class or function outside Keras: an `EDSRModel` subclass, a `CoordConv2D`
layer from a package, and two loss functions from a training script. Each is
legitimate, and each is code that comes from the caller's environment, not
from the file. A LEAD, which no acceptance clears, would withhold every model
with a custom layer for good; NOT_TESTED names the code and lets an acceptor
take the gap by naming the package they install.

### The HDF5 layout

| What the file holds | Grade | Why |
|---|---|---|
| A dataset's storage, or the bytes its type and shape need, past the end-of-file address the superblock records | FAIL, `tensor-layout` | The library refuses a dataset whose needed bytes run past it (`H5D__contig_check`, `src/H5Dcontig.c`); recorded storage past it holds bytes no reader reads. The contiguous form of the shape bombs of [CVE-2026-0897](https://github.com/advisories/GHSA-mgx6-5cf9-rr43) and [CVE-2026-12570](https://github.com/advisories/GHSA-74m6-m3xx-3vmj). |
| Contiguous storage recorded at another size than its type and shape need | FAIL, `tensor-size` | The library reads the bytes the shape needs and does not compare the recorded size: extra recorded bytes are read by nobody, and fewer mean a read past the recorded storage. |
| Compact data of another size | FAIL, `tensor-size` | The library refuses it (`H5D__compact_init`, `src/H5Dcompact.c`). |
| An unfiltered chunk of another size than its dimensions need, a chunk off its grid or outside the shape, two chunks at one offset, a chunk layout's element size that is not the type's | FAIL, `tensor-size` or `tensor-layout` | No writer produces one; a reader reads a chunk where the grid says it is. |
| Two datasets' storage, or a dataset's storage and a structure the reader read, overlapping | FAIL, `tensor-layout` | Two tensors reading the same bytes, or a tensor reading the file's own metadata. |
| Bytes after the end-of-file address | FAIL, `tensor-layout` | No HDF5 reader reads them, and a reader of another format can: a zip is read from its end. The same rule as safetensors' and GGUF's unaccounted bytes. |
| A dataset with external storage (an External Data Files message) | FAIL, `external-data-escape` | The library opens the named file, outside the model, and reads it as the weights. h5py and transformers' TensorFlow loader read it, and Keras read it before 3.12.1 and 3.13.2, which refuse it ([CVE-2026-1669](https://github.com/advisories/GHSA-3m4q-jmj6-r34q)). |
| An external link | FAIL, `external-data-escape` | h5py follows it to an object in another file; Keras did before 3.12.3 and 3.15.0, which refuse it ([CVE-2026-9335](https://github.com/advisories/GHSA-m8wh-29wm-52mv)). |
| A soft link | LEAD, `hdf5-soft-link` | One name reads the object another name holds, which no Keras writer produces; Keras refuses one since 3.12.3 and 3.15.0. It does not itself reach another file (an external link it names is graded as one). |
| A virtual dataset | LEAD, `hdf5-virtual-dataset` | Its data is mapped from other datasets, which can be in other files ([CVE-2026-12480](https://github.com/advisories/GHSA-26c4-7vv6-867j)); the mapping, in the global heap, is not read, so it is a lead. Keras refuses one since 3.12.3 and 3.15.0. |
| A chunked dataset with chunks never written, a filtered (compressed) dataset, a chunk index the reader does not read, a truncated file, or a user block | NOT_TESTED, named | Storage the reader could not size: a chunk never written reads as the fill value, so the storage is not the shape's size, and a filter's output is not decoded. A user block is skipped by HDF5 and read first by a reader of another format. |

A name that reaches an object another name already reached (a hard link) is
counted in the notes. A dataset reached through a soft or external link is
not walked.

### The archive

| What the archive holds | Grade | Why |
|---|---|---|
| A member other than `config.json`, `metadata.json`, the weights, and `assets/...` | LEAD, `keras-archive-entry` | Keras neither writes nor reads one, though it extracts every member of an archive of more than three: a place to carry a payload. Its bytes are scanned by File inventory. |
| A member name repeated | LEAD, `keras-archive-entry` | Zip readers disagree on which copy they read. |
| A member name with an absolute path, a drive, or a `..` component | LEAD, `archive-path-escape` | No Keras writer produces one. Python's zipfile drops those parts as it extracts, and Keras before 3.14.0 checked names against the working directory ([CVE-2026-11816](https://github.com/advisories/GHSA-hqp4-2352-xf5r)); another extractor can write outside its directory. |
| `model.weights.npz` instead of `model.weights.h5` | NOT_TESTED | A NumPy archive the reader does not read; Keras 3.0 to 3.8 load it with `allow_pickle=True` (keras v3.8.0 `saving_lib.py`). |
| `model.weights.h5` compressed | NOT_TESTED | Keras writes it stored; the reader reads it only stored. |
| `config.json` or `metadata.json` that is not JSON | NOT_TESTED | |

### PASS

The row PASSes only when the file parsed with nothing unread; every dataset's
storage lies inside the HDF5 data, sized by its type and shape, with none
overlapping and no data or link in another file; an archive holds only what
Keras reads; and the config names no Python bytecode, pickled module, or class
or function from outside Keras and TensorFlow (KerasHub, KerasCV, and KerasNLP
classes are named). Its notes say what the file is (a full model, weights
only, Keras 3 weights, an archive, or HDF5 with no Keras attributes), its
Keras version and backend, and its group, dataset, and chunk counts, and they
say what a PASS does not cover: weight values, and the classes and functions
the installed Keras and its add-ons run.

A weights-only file, such as transformers' `tf_model.h5` (`save_pretrained`
calls Keras' `save_weights`, `modeling_tf_utils.py` L2475 at transformers
v4.57.1, and the loader reads `layer_names` and `weight_names` with h5py),
PASSes when its layout holds, and says that no model config is present, so
the file holds no code a Keras loader runs.

## File inventory and payloads

The model's text goes through the same payload patterns as GGUF,
safetensors, and ONNX metadata (scripts, long base64 blobs, executable and
archive signatures): every key and string value of `config.json`,
`metadata.json`, and an HDF5 file's configs; every scalar string attribute;
every element of 64 bytes or more of a string-array attribute (shorter
elements, such as weight names, are counted, as GGUF's are); object comments;
an archive's comments, assets, and every member Keras does not read; and an
HDF5 file's user block. Text past the reader's caps, or a weights file that
was not read, leaves the row NOT_TESTED.

## Model directories

In a directory scan, every `.h5`, `.hdf5`, and `.keras` file whose bytes are
HDF5 or a `.keras` archive is read as above and merged into the rows. A
`.keras` archive is read member by member, so File inventory counts it as
read rather than naming it as an unscanned archive. A JSON file at the
directory's root that is a Keras serialized object (a top-level `class_name`
and `module`), as a KerasHub preset's `config.json` and `tokenizer.json` are,
is checked by the config rules.

## Not covered

- Weight values: what the weights compute.
- The installed Keras, its add-ons, and any custom package a config names.
- Numeric attributes and dataset data, which can hold arbitrary bytes and are
  not scanned as text.
- An HDF5 file written with features the reader names as unread (above), and
  `model.weights.npz`.
- TensorFlow SavedModels (`saved_model.pb`), which are another format.
- The intake policy's formats (`SOCAIR_INTAKE_POLICY`) do not include Keras
  or HDF5: such a file is a format the policy does not identify.

## Sources

- The [HDF5 File Format Specification Version 4.0](https://github.com/HDFGroup/hdf5/blob/2.2.0/docs/doxygen/dox/H5.format.4.0.dox)
  and the library's `src/H5Fsuper.c`, `src/H5Fsuper_cache.c`,
  `src/H5Ocache.c`, `src/H5Oint.c`, `src/H5Gent.c`, `src/H5Gprivate.h`,
  `src/H5Dcontig.c`, and `src/H5Dcompact.c` at
  [HDF5 2.2.0](https://github.com/HDFGroup/hdf5/tree/2.2.0).
- `keras/src/saving/saving_lib.py`, `saving/serialization_lib.py`,
  `layers/core/lambda_layer.py`, `legacy/saving/legacy_h5_format.py`,
  `legacy/saving/saving_utils.py`, `utils/torch_utils.py`,
  `export/tfsm_layer.py`, `layers/preprocessing/index_lookup.py`, and
  `ops/operation.py` in the keras 3.15.1 wheel (sha256 `836460e4...e20`,
  [PyPI](https://pypi.org/project/keras/3.15.1/)); `saving_lib.py` at
  [v3.0.0](https://github.com/keras-team/keras/blob/v3.0.0/keras/saving/saving_lib.py),
  [v3.8.0](https://github.com/keras-team/keras/blob/v3.8.0/keras/src/saving/saving_lib.py), and
  [v3.9.0](https://github.com/keras-team/keras/blob/v3.9.0/keras/src/saving/saving_lib.py)
  (`NpzIOStore`'s `allow_pickle`), and at v3.12.1, v3.13.2, and v3.14.0 (which
  refuse external datasets and not yet links); and `serialization_lib.py` at
  [v3.11.0](https://github.com/keras-team/keras/blob/v3.11.0/keras/src/saving/serialization_lib.py)
  (`LOADING_APIS`).
- `tf_keras/src/saving/saving_api.py`, `saving/serialization_lib.py`,
  `layers/core/lambda_layer.py`, and `layers/rnn/cell_wrappers.py` in the
  tf_keras 2.21.0 wheel (sha256 `f858bf3d...e62`,
  [PyPI](https://pypi.org/project/tf-keras/2.21.0/)), and `keras/saving/saving_api.py`
  at [keras v2.12.0](https://github.com/keras-team/keras/blob/v2.12.0/keras/saving/saving_api.py).
- `src/transformers/modeling_tf_utils.py` at
  [transformers v4.57.1](https://github.com/huggingface/transformers/blob/v4.57.1/src/transformers/modeling_tf_utils.py).
- The advisories: [GHSA-x4wf-678h-2pmq](https://github.com/advisories/GHSA-x4wf-678h-2pmq)
  (CVE-2024-3660, and [CERT/CC VU#253266](https://kb.cert.org/vuls/id/253266)),
  [GHSA-48g7-3x6r-xfhp](https://github.com/advisories/GHSA-48g7-3x6r-xfhp) (CVE-2025-1550),
  [GHSA-c9rc-mg46-23w3](https://github.com/advisories/GHSA-c9rc-mg46-23w3) (CVE-2025-8747),
  [GHSA-36rr-ww3j-vrjv](https://github.com/advisories/GHSA-36rr-ww3j-vrjv) (CVE-2025-9905),
  [GHSA-36fq-jgmw-4r9c](https://github.com/advisories/GHSA-36fq-jgmw-4r9c) (CVE-2025-9906),
  [GHSA-cvhh-q5g5-qprp](https://github.com/advisories/GHSA-cvhh-q5g5-qprp) (CVE-2025-49655),
  [GHSA-mq84-hjqx-cwf2](https://github.com/advisories/GHSA-mq84-hjqx-cwf2) (CVE-2025-12058),
  [GHSA-3m4q-jmj6-r34q](https://github.com/advisories/GHSA-3m4q-jmj6-r34q) (CVE-2026-1669),
  [GHSA-4f3f-g24h-fr8m](https://github.com/advisories/GHSA-4f3f-g24h-fr8m) (CVE-2026-1462),
  [GHSA-mgx6-5cf9-rr43](https://github.com/advisories/GHSA-mgx6-5cf9-rr43) (CVE-2026-0897),
  [GHSA-hqp4-2352-xf5r](https://github.com/advisories/GHSA-hqp4-2352-xf5r) (CVE-2026-11816),
  [GHSA-gh82-f9x8-5frx](https://github.com/advisories/GHSA-gh82-f9x8-5frx) (CVE-2026-12479),
  [GHSA-26c4-7vv6-867j](https://github.com/advisories/GHSA-26c4-7vv6-867j) (CVE-2026-12480),
  [GHSA-5gwj-m78q-7pq3](https://github.com/advisories/GHSA-5gwj-m78q-7pq3) (CVE-2026-12481),
  [GHSA-v2w2-w228-c444](https://github.com/advisories/GHSA-v2w2-w228-c444) (CVE-2026-12484),
  [GHSA-m8wh-29wm-52mv](https://github.com/advisories/GHSA-m8wh-29wm-52mv) (CVE-2026-9335), and
  [GHSA-74m6-m3xx-3vmj](https://github.com/advisories/GHSA-74m6-m3xx-3vmj) (CVE-2026-12570).

What the layout table says the library and Keras do was confirmed on
generated files with h5py 3.16.0 (HDF5 2.0.0) and keras 3.15.1 (2026-10-14):
the library opens a file whose base address moved and refuses one truncated
by the moved end-of-file address, refuses an object header that counts no
messages, reads a chunked dataset with a chunk never written, and refuses a
dataset whose needed bytes run past the end of its data while loading one
whose recorded size alone is wrong; Keras 3.15.1 loads the test builder's
weights file into a `Dense(3)` model and refuses the same file with external
storage, an external link, or a soft link, and refuses a `.keras` archive's
`__lambda__` in safe mode, before any bytecode is read as code.
