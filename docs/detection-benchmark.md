# Detection benchmark

What Socair catches, measured on reproductions of published attacks, with the
misses pinned and other scanners run over the same files.

Socair's numbers come from `internal/benchmark`, which runs in `go test ./...`
in CI. Each case's outcome is pinned, so a regression fails the build, and so
does an improvement until the case is updated. The other scanners' numbers
come from one manual run of `scripts/benchmark-compare.py` over the same
generated corpus, on 2026-10-04; CI does not re-run them.

## Read this first

- **The corpus is ours.** Every case reproduces a published technique (each
  is cited in `internal/benchmark/corpus.go`). But Socair's authors chose the
  cases knowing what Socair checks, so the corpus leans toward Socair's
  coverage: some cases, such as a remapped tokenizer, need a reference only
  Socair supports. Read the results as a reproducible floor and a regression
  gate, not as an independent evaluation. New cases are welcome, especially
  ones Socair misses.
- **Four cases need an input only Socair takes.** `gguf-tokenizer-remapped` is
  scanned with a canonical tokenizer table (`SOCAIR_TOKENIZER_REFERENCE`),
  `gguf-template-reviewed-near-miss` with the reviewed template it departs from
  (`SOCAIR_TEMPLATE_REFERENCE`), `dir-known-bad-hash` with a denylist that
  names the file (`SOCAIR_DENYLIST`), and `dir-weights-edited` with the
  reviewed model's tensor manifest (`SOCAIR_TENSOR_REFERENCE`). No other
  scanner here was given any of them. With Socair's defaults (none of the
  four), the remapped tokenizer and the near-miss template pass, the known-bad
  file is withheld as a gap, and the edited weights have no row that compares
  them, so Socair detects 53 of 60. Scores with the cases that need an input left out
  follow the comparison table.
- **The attacks are defanged.** Each case keeps the attack's structure (the
  gadget, the opcodes, the archive trick, the template construct) and swaps its
  payload for `echo socair-benchmark`, or, for a template that injects an
  instruction, a benign instruction in its place. Every scanner here, Socair included,
  reads structure and never loads the file, so a defanged reproduction is
  detected as the original would be.
- **Live samples are not here yet.** These exist only as real malicious files
  and need an isolated machine:
  - in-the-wild malicious uploads;
  - the 7z-wrapped nullifAI samples;
  - the ShadowPickle corpus (arXiv 2607.17503).
- **Few benign controls.** There are 11 controls. False positives on real
  models are measured separately, on real corpora, in
  [false-positive-baseline.md](false-positive-baseline.md).

## Socair (check set tier1/0.10, 2026-10-14)

| Check row | Cases | Detected (FAIL or LEAD) | Withheld as a gap (NOT_TESTED) | Missed (PASS) |
|---|---|---|---|---|
| Chat template | 11 | 10 | 0 | 1 |
| File inventory and payloads | 8 | 7 | 0 | 1 |
| Format and structure | 5 | 5 | 0 | 0 |
| Known-bad hash match | 1 | 1 | 0 | 0 |
| Pickle opcode scan | 22 | 22 | 0 | 0 |
| Remote code | 9 | 8 | 0 | 1 |
| Tensor reference | 1 | 1 | 0 | 0 |
| Tokenizer config | 3 | 3 | 0 | 0 |
| **All** | **60** | **57** | **0** | **3** |

Benign controls flagged (FAIL or LEAD on any row): 0 of 11.

Four of these detections depend on a reference input (see "Read this first");
with Socair's defaults it detects 53 of 60.

Check set tier1/0.8 replaced the pickle row's import allowlist with a typed
grammar (`socair-wo/1`, see [check-set.md](check-set.md)) and added three
pickle cases. Under tier1/0.7, `pickle-ordereddict-code-string` PASSed (a miss: the
allowlist accepted `collections.OrderedDict` with any argument),
`pickle-nested-loader` was a LEAD (an unreviewed global), and
`pickle-memo-reput` already FAILed (the import scan modelled the memo as
CPython does). Every earlier case kept its outcome and severity. The
`control-torch-zip` control now holds a tensor and its storage record: it
used to hold a plain OrderedDict beside a `data/0` record nothing
referenced, which the grammar reports as bytes torch.load never reads.

A model directory now finds a pickle by its bytes as well as its name (#186,
also tier1/0.8): `dir-pickle-renamed` (a gadget named `notes.txt`) and
`dir-torch-zip-renamed` (a torch zip named `weights.dat`) were never opened
before, and are detected now. `dir-pickle-protocol0-renamed` is pinned as a
miss: a protocol 0 pickle is ordinary text with no header, so in a directory
it is found by its extension or not at all. `control-dir-torchscript` pins
that a TorchScript archive (`rust_model.ot`, as sentence-transformers ships)
stays a named, unscanned archive and does not become a LEAD.

Check set tier1/0.9 adds the `control-torch-zip-untyped` control (#233): a
torch.save checkpoint holding a uint16 and a float8_e4m3fn tensor beside a
float32 one. torch.save writes a tensor of a dtype in
`torch.storage._new_dtypes()` with `_rebuild_tensor_v3` over an untyped
storage, and names that class `torch.storage.UntypedStorage`; the grammar
knew only `torch.UntypedStorage`, which torch.save does not write, so the
control was a LEAD before this change. No attack case changed outcome.

Check set tier1/0.9 also adds `gguf-template-tuple-trigger` (#246): the
conditional backdoor with its trigger phrases in a tuple,
`m['content'] in ('Summarize the invoice', 'Total the invoice')`. The
analysis took a list of constants as a content condition's literal and a
tuple as not, so this was a miss (PASS) before; a tuple is now a sequence like
a list, and the case is a LEAD. No other case changed outcome.
Check set tier1/0.9 also narrows the Remote code row to the Python a loader
would import (#254): modules a config names, files at a path a loader imports
by convention, and the repository files they import. It adds the
`control-dir-training-script` control, a directory with the `train_script.py`
that sentence-transformers' most-downloaded repositories ship, which was a
Remote code LEAD before this change. It adds seven cases the row detects:
`dir-remote-code-imported` (a payload reached only through a relative import
of the module auto_map names), `dir-remote-code-other-repo` and
`dir-remote-code-outside-path` (auto_map naming code in another repository, or
by an absolute path), `dir-st-custom-module` (a sentence-transformers module in
modules.json, with no auto_map), `dir-custom-generate` (transformers'
`custom_generate/generate.py`), `dir-inference-handler` (an Inference Endpoints
`handler.py`), and `dir-diffusers-component-shadow` (a standard-looking
model_index.json entry whose `unet/diffusers.py` diffusers loads in place of
the library). Before this change each was a LEAD as well, through its auto_map
or its `.py` file. And it pins `dir-script-caller-named` as a miss: a
`custom_interface.py` that only the caller's code names (SpeechBrain's
`foreign_class` takes the file name as an argument) is listed in the row's
notes and not judged, where it was a LEAD. No earlier case changed outcome.

Check set tier1/0.10 adds the Tensor reference row (#262), which compares a
model's tensors with the reviewed model's tensor manifest
(`SOCAIR_TENSOR_REFERENCE`, [tensors.md](tensors.md)). It adds
`dir-weights-edited`, PoisonGPT's shape (Mithril Security, 2023: GPT-J-6B
edited with ROME and uploaded under a lookalike of EleutherAI's name, within
0.1% of the original on a benchmark): a model directory whose first weight has
one bit flipped, scanned with the unedited model's manifest. No other row can
see an edit like this, since every byte is still a well-formed weight. It also
adds the control `control-dir-tensor-reference`, the same directory unedited,
which PASSes. No earlier case changed outcome.

Check set tier1/0.10 also reads ONNX models (#264) and adds four cases and two
controls. `onnx-external-data-traversal` points an initializer's external data
at `../../../../etc/hosts`, the directory traversal of CVE-2022-25882 and its
bypass CVE-2024-27318; `onnx-external-data-memory` uses onnxruntime's
in-memory marker `*/_ORT_MEM_ADDR_/*` as a location, which onnxruntime 1.20.0
reads as a memory address; `onnx-initializer-size` gives an initializer 4096
bytes of raw_data where its dims need 64; and `onnx-metadata-script` puts a
shell script in metadata_props. The first three are Format and structure
FAILs, the fourth a File inventory FAIL. Before this change an ONNX file was
an unknown format, NOT_TESTED on every row that reads one. The
`control-onnx` control is a clean ONNX model, and `control-dir-onnx` a
directory with an `onnx/` export as sentence-transformers ships one: external
data beside the model, and an onnxruntime contrib operator
(`com.microsoft::FastGelu`), as optimum's O2 to O4 exports have. No earlier
case changed outcome.

| Case | Format | Technique | Row | Result | Severity |
|---|---|---|---|---|---|
| `control-pickle` | pickle | benign state-dict-shaped pickle written by CPython | (control: every row) | PASS |  |
| `control-torch-zip` | pickle | benign PyTorch zip checkpoint: one float32 tensor and its storage record | (control: every row) | PASS |  |
| `control-torch-zip-untyped` | pickle | benign PyTorch zip checkpoint with uint16 and float8 tensors, which torch.save writes over torch.storage.UntypedStorage | (control: every row) | PASS |  |
| `control-gguf` | gguf | benign GGUF with a plain chat template | (control: every row) | PASS |  |
| `control-safetensors` | safetensors | benign safetensors | (control: every row) | PASS |  |
| `control-model-directory` | model directory | benign transformers-style directory | (control: every row) | PASS |  |
| `control-dir-torchscript` | model directory | benign directory with a TorchScript archive, rust_model.ot, as sentence-transformers ships | (control: every row) | PASS |  |
| `control-onnx` | onnx | benign ONNX model: standard operators, weights inline | (control: every row) | PASS |  |
| `control-dir-onnx` | model directory | benign directory with an onnx/ export as sentence-transformers ships: external data beside the model, and an onnxruntime contrib operator | (control: every row) | PASS |  |
| `control-dir-training-script` | model directory | benign directory with train_script.py, as sentence-transformers ships, that no loader imports | (control: every row) | PASS |  |
| `pickle-os-system-p2` | pickle | os.system via GLOBAL + REDUCE, protocol 2 | Pickle opcode scan | FAIL | critical |
| `pickle-os-system-p4` | pickle | os.system via STACK_GLOBAL, protocol 4 (the Python 3.8+ default) | Pickle opcode scan | FAIL | critical |
| `pickle-builtins-exec` | pickle | builtins.exec of a code string | Pickle opcode scan | FAIL | critical |
| `pickle-builtins-eval` | pickle | builtins.eval of an expression | Pickle opcode scan | FAIL | critical |
| `pickle-subprocess` | pickle | subprocess.getoutput | Pickle opcode scan | FAIL | critical |
| `pickle-runpy` | pickle | runpy._run_code, a gadget missing from early denylists | Pickle opcode scan | FAIL | critical |
| `pickle-pip-main` | pickle | pip.main installing a package at load | Pickle opcode scan | FAIL | critical |
| `pickle-asyncio-subprocess` | pickle | asyncio.unix_events._UnixSubprocessTransport, a subclass gadget | Pickle opcode scan | FAIL | critical |
| `pickle-importlib` | pickle | importlib.import_module of os, the indirect-import pattern | Pickle opcode scan | FAIL | critical |
| `pickle-unlisted-gadget` | pickle | a global on neither list (an unknown future gadget) | Pickle opcode scan | LEAD | medium |
| `pickle-nullifai-broken-stream` | pickle | payload first, then a stream broken before STOP | Pickle opcode scan | FAIL | critical |
| `pickle-torch-zip` | pickle | PyTorch zip checkpoint with the gadget in data.pkl | Pickle opcode scan | FAIL | critical |
| `pickle-torch-zip-other-entry` | pickle | gadget in an archive entry not named data.pkl | Pickle opcode scan | FAIL | critical |
| `pickle-torch-zip-bad-crc` | pickle | PyTorch zip with corrupted CRC-32s | Pickle opcode scan | FAIL | critical |
| `pickle-legacy-tar` | pickle | legacy torch tar checkpoint | Pickle opcode scan | FAIL | critical |
| `pickle-numpy-load` | pickle | numpy.load on attacker data (allow_pickle chain) | Pickle opcode scan | FAIL | critical |
| `pickle-ordereddict-code-string` | pickle | collections.OrderedDict, a safe-listed callable, handed a command string | Pickle opcode scan | FAIL | critical |
| `pickle-nested-loader` | pickle | torch.storage._load_from_bytes unpickling a second pickle carried as bytes | Pickle opcode scan | FAIL | critical |
| `pickle-memo-reput` | pickle | STACK_GLOBAL module read from a memo slot written twice | Pickle opcode scan | FAIL | critical |
| `gguf-ssti-globals` | gguf | SSTI through self.__init__.__globals__ to os.popen | Chat template | FAIL | critical |
| `gguf-ssti-subclasses` | gguf | SSTI through ''.__class__.__mro__[1].__subclasses__() | Chat template | FAIL | critical |
| `gguf-ssti-attr-hex` | gguf | dunder name hidden with \|attr and hex escapes | Chat template | FAIL | critical |
| `gguf-ssti-filter-block` | gguf | SSTI inside a {% filter %} block | Chat template | FAIL | critical |
| `gguf-template-conditional-backdoor` | gguf | system instruction injected only when the user's message contains a trigger | Chat template | LEAD | high |
| `gguf-template-hidden-instruction` | gguf | instruction hidden with zero-width characters | Chat template | LEAD | medium |
| `gguf-template-plain-guidance` | gguf | a default system prompt that steers answers as ordinary guidance | Chat template | PASS |  |
| `gguf-template-macro-conditional` | gguf | a system turn emitted from a macro only when a message carries a trigger | Chat template | LEAD | high |
| `gguf-template-tuple-trigger` | gguf | system instruction injected only when the user's message is one of a tuple of trigger phrases | Chat template | LEAD | high |
| `gguf-template-reviewed-near-miss` | gguf | a reviewed template with a branch that prefills the answer when a message carries a trigger | Chat template | LEAD | high |
| `gguf-metadata-base64` | gguf | base64 payload in a metadata string | File inventory and payloads | FAIL | high |
| `gguf-metadata-array-payload` | gguf | base64 payload in a metadata string array | File inventory and payloads | FAIL | high |
| `gguf-metadata-elf` | gguf | an ELF executable in a metadata string | File inventory and payloads | FAIL | critical |
| `gguf-hidden-tensor-bytes` | gguf | bytes appended after the last tensor, outside the tensor table | Format and structure | FAIL | high |
| `gguf-control-token-instruction` | gguf | a control token that carries an instruction | Tokenizer config | LEAD | high |
| `gguf-tokenizer-remapped` | gguf | two ordinary tokens swapped against the canonical tokenizer | Tokenizer config | LEAD | high |
| `safetensors-appended-bytes` | safetensors | bytes appended past the tensors (a polyglot tail) | Format and structure | FAIL | high |
| `safetensors-metadata-script` | safetensors | a script in the header metadata | File inventory and payloads | FAIL | high |
| `onnx-external-data-traversal` | onnx | an initializer's external data location climbs out of the model's directory to /etc/hosts | Format and structure | FAIL | high |
| `onnx-external-data-memory` | onnx | an initializer's external data location is onnxruntime's in-memory marker, with an address as its offset | Format and structure | FAIL | high |
| `onnx-initializer-size` | onnx | an initializer whose raw_data holds 4096 bytes where its dims need 64 | Format and structure | FAIL | high |
| `onnx-metadata-script` | onnx | a shell script in the model's metadata_props | File inventory and payloads | FAIL | high |
| `dir-remote-code` | model directory | auto_map pointing at repository code that runs a command | Remote code | LEAD | medium |
| `dir-remote-code-imported` | model directory | auto_map naming a clean module that imports repository code that runs a command | Remote code | LEAD | medium |
| `dir-remote-code-other-repo` | model directory | auto_map naming code in another repository, which the loader fetches | Remote code | LEAD | medium |
| `dir-remote-code-outside-path` | model directory | auto_map naming a module by an absolute path outside the directory | Remote code | LEAD | medium |
| `dir-st-custom-module` | model directory | a sentence-transformers module in modules.json that runs a command, with no auto_map | Remote code | LEAD | medium |
| `dir-custom-generate` | model directory | custom_generate/generate.py that runs a command, named by no config | Remote code | LEAD | medium |
| `dir-inference-handler` | model directory | an Inference Endpoints handler.py that runs a command, imported without trust_remote_code | Remote code | LEAD | medium |
| `dir-diffusers-component-shadow` | model directory | a standard-looking diffusers component whose folder holds a file named after its library | Remote code | LEAD | medium |
| `dir-script-caller-named` | model directory | custom_interface.py that runs a command, which only the caller's code names (SpeechBrain foreign_class) | Remote code | PASS |  |
| `dir-pickle-weights` | model directory | pytorch_model.bin with a pickle gadget beside safe weights | Pickle opcode scan | FAIL | critical |
| `dir-pickle-renamed` | model directory | a pickle gadget named notes.txt beside safe weights | Pickle opcode scan | FAIL | critical |
| `dir-torch-zip-renamed` | model directory | a PyTorch zip checkpoint with a gadget, named weights.dat | Pickle opcode scan | FAIL | critical |
| `dir-pickle-protocol0-renamed` | model directory | a protocol 0 pickle gadget (text, no header) named notes.txt | File inventory and payloads | PASS |  |
| `dir-native-executable` | model directory | a native executable shipped in the repository | File inventory and payloads | FAIL | critical |
| `dir-executable-named-script` | model directory | a native executable named setup.py | File inventory and payloads | FAIL | critical |
| `dir-template-ssti` | model directory | SSTI in chat_template.jinja | Chat template | FAIL | critical |
| `dir-normalizer-injects-special` | model directory | a normalizer that rewrites input into a special token | Tokenizer config | LEAD | high |
| `dir-weights-edited` | model directory | one weight edited in a model presented as the reviewed one | Tensor reference | LEAD | medium |
| `control-dir-tensor-reference` | model directory | benign directory compared with its own reviewed tensor manifest | (control: every row) | PASS |  |
| `dir-known-bad-hash` | model directory | a file whose hash is on the known-bad list | Known-bad hash match | FAIL | critical |

There are three misses. The first is the published known miss: a default system prompt that steers
answers as ordinary guidance, with no override phrase, URL, obfuscation, or
condition on the user's message. It is on the
[detection ceiling](detection-ceiling.json). Since tier1/0.8 the row quotes
that prompt as text the template adds, for a reviewer to read, but does not
judge it.

The second is `dir-pickle-protocol0-renamed`, a protocol 0 pickle under a name
that is not a pickle's. It is stated in [check-set.md](check-set.md) and in
every directory report that has no pickle, whose File inventory row says no
file is named as a pickle or begins as one "(a protocol 2 to 5 stream, or a
zip holding a pickle)". It is not a ceiling bullet: something must still load
the file by name. Standard loaders do not, and a repository whose own loader
code a config names, or sits where a loader imports it by its path, is a
Remote code LEAD; a loader already in the serving stack, or a script a person
runs, is outside what a scan of the artifact can see.

The third is `dir-script-caller-named`, repository Python that no config
names and no loader imports by its path: here SpeechBrain's `foreign_class`,
which imports the file its caller names. Since #254 the Remote code row lists
such a file in its notes and does not judge it, because Socair cannot tell
whether anything runs it, and its PASS statement says so. Before, every `.py`
file was a LEAD, which also withheld every repository that ships a training
or evaluation script.

## Other scanners on the same files (2026-10-04)

Versions:
- picklescan 1.0.5
- ModelScan 0.8.8 (under Python 3.12; it does not install on 3.13+)
- ModelAudit 0.2.37 (promptfoo)
- Fickling 0.1.12 (Trail of Bits)

Each ran with default settings, and its verdict was read as its documentation
describes. This comparison predates `dir-executable-named-script`, added with
check set tier1/0.7, and the five cases added with tier1/0.8 (the
rendered-template cases `gguf-template-macro-conditional` and
`gguf-template-reviewed-near-miss`, and the pickle cases
`pickle-ordereddict-code-string`, `pickle-nested-loader`, and
`pickle-memo-reput`), and the four added with #186 (`dir-pickle-renamed`,
`dir-torch-zip-renamed`, `dir-pickle-protocol0-renamed`, and the
`control-dir-torchscript` control), the `control-torch-zip-untyped`
control added with #233, `gguf-template-tuple-trigger` added with #246, and
the nine added with #254 (the seven Remote code cases,
`dir-script-caller-named`, and the `control-dir-training-script` control), and
the two added with #262 (`dir-weights-edited` and the
`control-dir-tensor-reference` control), and the six ONNX cases and controls
added with #264, so its counts cover the cases before them; the other scanners
have not been run on those twenty-nine. A *suspicious* result counts as a finding, as Socair's LEAD does:
picklescan's suspicious globals and Fickling's SUSPICIOUS. "Not scanned" means
the tool skipped the file, could not parse it, or does not support the format.

| Format | Scanner | Attacks detected | Attacks not scanned | Benign controls flagged |
|---|---|---|---|---|
| pickle | socair | 16 of 16 | 0 | 0 of 2 scanned |
| pickle | modelaudit | 15 of 16 | 0 | 0 of 2 scanned |
| pickle | picklescan | 15 of 16 | 0 | 2 of 2 scanned |
| pickle | fickling | 13 of 16 | 3 | 1 of 1 scanned |
| pickle | modelscan | 4 of 16 | 7 | 0 of 1 scanned |
| gguf | socair | 12 of 13 | 0 | 0 of 1 scanned |
| gguf | modelaudit | 1 of 13 | 0 | 0 of 1 scanned |
| gguf | picklescan | 0 of 13 | 0 | 0 of 1 scanned |
| gguf | fickling | 13 of 13 (not a pickle) | 0 | 1 of 1 scanned (not a pickle) |
| gguf | modelscan | 0 of 13 | 13 | 0 of 0 scanned |
| safetensors | socair | 2 of 2 | 0 | 0 of 1 scanned |
| safetensors | modelaudit | 0 of 2 | 1 | 0 of 1 scanned |
| safetensors | picklescan | 0 of 2 | 0 | 0 of 1 scanned |
| safetensors | fickling | 1 of 2 (not a pickle) | 1 | 0 of 0 scanned |
| safetensors | modelscan | 0 of 2 | 2 | 0 of 0 scanned |
| model directory | socair | 6 of 6 | 0 | 0 of 1 scanned |
| model directory | modelaudit | 2 of 6 | 0 | 0 of 1 scanned |
| model directory | picklescan | 1 of 6 | 5 | 0 of 0 scanned |
| model directory | fickling | 0 of 6 | 6 | 0 of 0 scanned |
| model directory | modelscan | 1 of 6 | 5 | 0 of 0 scanned |

How to read it:

- **Pickle is the common ground.** All five tools scan pickles, and the main
  differences are:
  - **ModelScan** routes by file extension. It read the plain PyTorch zip
    checkpoint (`pytorch_model.bin`) and found its gadget, but could not scan
    the raw pickles named `.bin` or `.ckpt`, or the `.tar` checkpoint. The
    harness counts any ModelScan run without a finding whose output mentions a
    skipped file as could not scan, even when it scanned other files in the
    same artifact; that is how both altered zip checkpoints are counted. It
    also missed the gadgets outside its denylist: `pip`, `asyncio`,
    `importlib`, `numpy.load`, and an unknown module.
  - **picklescan** missed the legacy tar checkpoint, and flagged both benign
    pickles as suspicious. Both controls hold a Python set
    (`__builtin__.set`), which a typical state dict does not, so that flag may
    come from the control rather than from anything a real checkpoint
    carries.
  - **ModelAudit** missed the gadget placed in an archive entry not named
    `data.pkl`.
  - **Fickling** could not read the zip checkpoints, and flagged the benign
    pickle.
- **On GGUF, ModelAudit found the appended tensor bytes but none of the
  chat-template attacks.** That covers the four SSTI reproductions (including
  CVE-2024-34359's) and the conditional and hidden-instruction backdoors.
  Picklescan and ModelScan do not read GGUF.
- **Fickling's GGUF and safetensors "findings" are not detections.** Fickling
  is a pickle analyzer. It reports any file that is not a pickle as "invalid
  opcodes, likely unsafe", the benign GGUF included.
- **Model directories:** ModelAudit read the directories and found the pickle
  weights and the template SSTI; picklescan and ModelScan found the pickle
  weights. Only Socair flagged the remote code, the native executable, and the
  tokenizer normalizer; the known-bad hash case needs a denylist, which only
  Socair was given.

With the four cases that need a Socair-only input left out
(`gguf-tokenizer-remapped`, `gguf-template-reviewed-near-miss`,
`dir-known-bad-hash`, and `dir-weights-edited`), Socair detects 53 of 56
attacks with check set tier1/0.10 (34 of 35 in the 2026-10-04 run, which predates the near-miss case),
and the two formats they belong to read, from that run:

| Format | Scanner | Attacks detected | Attacks not scanned |
|---|---|---|---|
| gguf | socair | 11 of 12 | 0 |
| gguf | modelaudit | 1 of 12 | 0 |
| gguf | picklescan | 0 of 12 | 0 |
| gguf | fickling | 12 of 12 (not a pickle) | 0 |
| gguf | modelscan | 0 of 12 | 12 |
| model directory | socair | 5 of 5 | 0 |
| model directory | modelaudit | 2 of 5 | 0 |
| model directory | picklescan | 1 of 5 | 4 |
| model directory | fickling | 0 of 5 | 5 |
| model directory | modelscan | 1 of 5 | 4 |

## Per case

| Case | Socair | ModelAudit | picklescan | Fickling | ModelScan |
|---|---|---|---|---|---|
| `control-dir-torchscript` | clean | not run | not run | not run | not run |
| `control-dir-training-script` | clean | not run | not run | not run | not run |
| `control-gguf` | clean | clean | clean | finding (not a pickle) | could not scan |
| `control-model-directory` | clean | clean | could not scan | could not scan | could not scan |
| `control-dir-onnx` | clean | not run | not run | not run | not run |
| `control-onnx` | clean | not run | not run | not run | not run |
| `control-pickle` | clean | clean | finding (suspicious) | finding | clean |
| `control-safetensors` | clean | clean | clean | could not scan | could not scan |
| `control-torch-zip` | clean | clean | finding (suspicious) | could not scan | could not scan |
| `control-torch-zip-untyped` | clean | not run | not run | not run | not run |
| `dir-known-bad-hash` | finding | clean | could not scan | could not scan | could not scan |
| `dir-executable-named-script` | finding | not run | not run | not run | not run |
| `dir-native-executable` | finding | clean | could not scan | could not scan | could not scan |
| `dir-normalizer-injects-special` | finding | clean | could not scan | could not scan | could not scan |
| `dir-pickle-protocol0-renamed` | clean | not run | not run | not run | not run |
| `dir-pickle-renamed` | finding | not run | not run | not run | not run |
| `dir-pickle-weights` | finding | finding | finding | could not scan | finding |
| `dir-remote-code` | finding | clean | could not scan | could not scan | could not scan |
| `dir-remote-code-imported` | finding | not run | not run | not run | not run |
| `dir-remote-code-other-repo` | finding | not run | not run | not run | not run |
| `dir-remote-code-outside-path` | finding | not run | not run | not run | not run |
| `dir-st-custom-module` | finding | not run | not run | not run | not run |
| `dir-custom-generate` | finding | not run | not run | not run | not run |
| `dir-inference-handler` | finding | not run | not run | not run | not run |
| `dir-diffusers-component-shadow` | finding | not run | not run | not run | not run |
| `dir-script-caller-named` | clean | not run | not run | not run | not run |
| `dir-torch-zip-renamed` | finding | not run | not run | not run | not run |
| `dir-template-ssti` | finding | finding | could not scan | could not scan | could not scan |
| `gguf-control-token-instruction` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-hidden-tensor-bytes` | finding | finding | clean | finding (not a pickle) | could not scan |
| `gguf-metadata-array-payload` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-metadata-base64` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-metadata-elf` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-ssti-attr-hex` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-ssti-filter-block` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-ssti-globals` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-ssti-subclasses` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-template-conditional-backdoor` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-template-hidden-instruction` | finding | clean | clean | finding (not a pickle) | could not scan |
| `gguf-template-macro-conditional` | finding | not run | not run | not run | not run |
| `gguf-template-plain-guidance` | clean | clean | clean | finding (not a pickle) | could not scan |
| `gguf-template-reviewed-near-miss` | finding | not run | not run | not run | not run |
| `gguf-template-tuple-trigger` | finding | not run | not run | not run | not run |
| `gguf-tokenizer-remapped` | finding | clean | clean | finding (not a pickle) | could not scan |
| `pickle-asyncio-subprocess` | finding | finding | finding | finding | clean |
| `pickle-builtins-eval` | finding | finding | finding | finding | could not scan |
| `pickle-builtins-exec` | finding | finding | finding | finding | could not scan |
| `pickle-importlib` | finding | finding | finding (suspicious) | finding | clean |
| `pickle-legacy-tar` | finding | finding | clean | finding | could not scan |
| `pickle-nullifai-broken-stream` | finding | finding | finding | finding | could not scan |
| `pickle-numpy-load` | finding | finding | finding (suspicious) | finding | clean |
| `pickle-ordereddict-code-string` | finding | not run | not run | not run | not run |
| `pickle-nested-loader` | finding | not run | not run | not run | not run |
| `pickle-memo-reput` | finding | not run | not run | not run | not run |
| `pickle-os-system-p2` | finding | finding | finding | finding | finding |
| `pickle-os-system-p4` | finding | finding | finding | finding | finding |
| `pickle-pip-main` | finding | finding | finding | finding | clean |
| `pickle-runpy` | finding | finding | finding | finding | finding |
| `pickle-subprocess` | finding | finding | finding | finding | could not scan |
| `pickle-torch-zip` | finding | finding | finding | could not scan | finding |
| `pickle-torch-zip-bad-crc` | finding | finding | finding | could not scan | could not scan |
| `pickle-torch-zip-other-entry` | finding | clean | finding | could not scan | could not scan |
| `pickle-unlisted-gadget` | finding | finding | finding (suspicious) | finding | clean |
| `onnx-external-data-memory` | finding | not run | not run | not run | not run |
| `onnx-external-data-traversal` | finding | not run | not run | not run | not run |
| `onnx-initializer-size` | finding | not run | not run | not run | not run |
| `onnx-metadata-script` | finding | not run | not run | not run | not run |
| `safetensors-appended-bytes` | finding | could not scan | clean | could not scan | could not scan |
| `safetensors-metadata-script` | finding | clean | clean | finding (not a pickle) | could not scan |

## Reproduce

```
SOCAIR_BENCHMARK_OUT=results.md SOCAIR_BENCHMARK_CORPUS=/tmp/corpus \
  go test ./internal/benchmark -count=1 -v
scripts/benchmark-compare.py /tmp/corpus > compare.json   # scanners on PATH, or --picklescan PATH etc.
```

The corpus is generated and defanged, so it is safe to write anywhere.
