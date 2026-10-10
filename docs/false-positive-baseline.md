# False-positive baseline

This is a chronological log of how each detector was measured against real
models; the current rules are in [check-set.md](check-set.md). Each section
records the rules as they stood on its date.

## Chat templates: the first run

Run with `socair corpus <dir>`, header-only mode, over 52 real GGUF files in
three local model directories; the first of them held 26.

This run measured false positives: a scanner that flags known-good models is
one a security team stops trusting.

## Before the retune

15 of the 26 models in the first directory FAILED the hero check. They were
all known-good Qwen and Gemma and Qwopus templates.

Root cause, found with `socair template <path>`:

```
pattern=secrecy-instruction span="do not tell"
```

The phrase pattern `do not (reveal|disclose|mention|tell)` matched ordinary
instruction text inside normal templates. A second, separate false positive:
`ggml-vocab-qwen2.gguf` and `ggml-vocab-qwen35.gguf` FAILED the quant check
because the filename parser's fallback treated any field starting with `Q` as a
quantization, so it read `QWEN2` as a declared quant and compared it to the
observed weight type.

## The lesson

**Phrase-level instruction language cannot separate a benign template from a
malicious one.** Ordinary templates contain "do not tell", "ignore previous",
and similar. A phrase match is not positive evidence, so it cannot be a FAIL.

## The change

- FAIL is now reserved for **structural code-execution indicators** in a
  template: Python object escape (`__globals__`, `__subclasses__`, `__class__`)
  and process execution (`os.system(`, `subprocess`, `eval(`, `exec(`).
- Instruction-language phrases and external-access constructs are a **lead**.
  At the time a lead returned NOT_TESTED with the matched phrase recorded, for
  a person to review; LEAD is now its own status, which no acceptance clears.
  A lead never fails an artifact on its own.
- The filename quantization parser is now a strict regex. It accepts `Q4_0`,
  `Q5_K_M`, `IQ3_S`, `BF16`, and rejects a model name that merely starts with
  `Q`.

## After the retune

Zero FAILs across all 52 files. Per-check tally on the first directory
(26 files), PASS / FAIL / NOT_TESTED:

```
Chat template                  8 / 0 / 18
Format and structure           26 / 0 / 0
Tokenizer config               23 / 0 / 3
Quant match                    2 / 0 / 24
```

## What this means honestly

- The hero check clears 8 of 26 real templates, flags 18 as instruction-language
  leads, and fails none. The 18 leads are not defects in those models; they are
  the honest state: we cannot clear that language automatically, so a person
  has to review it.
- The quant check passes on only 2 of 26, because the GGML file-type mapping
  was provisional then and most real file types were outside it. That was a
  coverage gap, not a finding. The mapping now follows llama.cpp's
  `llama_ftype` enum (see "GGUF tensor-table validation" below).
- A clean hero result still means "no structural indicator and no lead matched",
  not "no backdoor".

## Second refinement

The first retune left 18 of 26 real templates as instruction-language leads. A
tally of the lead notes showed two causes, both substring false positives:

1. **`secrecy-instruction` matched "do not tell".** The real text was "do not
   tell the user about function calls", a benign tool-calling instruction in a
   Qwen template. 15 of the 18 leads.
2. **`external-access` matched "requests" inside "PULL_REQUESTS".** The word
   appeared inside a Devstral system message.

Both patterns were narrowed to require context:

- `secrecy-instruction` now requires concealment of **something sensitive**
  (system prompt, instructions, prompt, rules, training data, secrets,
  passwords, credentials, hidden), not a bare "do not tell".
- `external-access` now requires a **code call shape** (`import requests`,
  `requests.get(`, `urllib.request`, `curl -`), so a word that merely contains
  "requests" cannot match.

Result on the first directory (26 files), PASS / FAIL / NOT_TESTED:

```
Chat template   24 / 0 / 2
```

The 2 remaining NOT_TESTED are the MiniMax shards 2 and 3, which carry no chat
template at all. Zero leads, zero FAILs. Both real cases from the corpus are
now regression tests: `TestRealWorldBenignLanguagePasses`.

### The reviewed-template allowlist

`internal/checks/chattemplate/known-good-templates.txt` holds SHA256 hashes of
templates a human has reviewed. A listed template returns PASS instead of a
lead. It is **seeded empty on purpose**: clearing a template by machine is the
false positive this project already paid for. A `TestAllowlistIsSeededEmpty`
guards that. A template on the list is still FAILed if it carries structural
code-execution evidence: the allowlist clears language, never code, and
`TestAllowlistClearsLeadsButNotStructural` proves it.

## Audit false positives (2026-10-02)

An internal audit found FAILs that broke the rule that a FAIL needs positive
evidence. Each is now a regression test.

- **Two-byte magics in metadata text.** `general.license = "Licensed by AMZ
  Corp"` FAILed as an embedded PE, because the inventory matched `MZ` (and
  gzip's `1f 8b`) anywhere in a value. Four-byte magics (ELF, zip, Mach-O)
  still match anywhere. Two-byte magics now count only at the start of a value
  and only with confirming structure: a `PE\0\0` signature at `e_lfanew`, or a
  gzip header with deflate and no reserved flags.
  `TestShortMagicInTextDoesNotFail`, `TestRealPEInMetadataFails`.
- **Zip-format PyTorch checkpoints in the repo.** Every `pytorch_model.bin`
  since PyTorch 1.6 is a zip, and the repo side FAILed any zip. Only a native
  executable (ELF, verified PE, Mach-O) is now a repo FAIL. An archive is named
  as unscanned and leaves the row NOT_TESTED, because its contents, a pickle
  for a checkpoint, were not inspected. `TestRepoTorchCheckpointIsNotAFail`.
- **Community quant names.** `Model-UD-Q4_K_XL.gguf` (Unsloth) FAILed as a
  quant mismatch. `Q4_K_XL` and bartowski's `Q4_K_L` are not llama.cpp file
  types, and those files report `Q4_K_M`, so there is nothing to compare. A
  declared name outside the llama.cpp set is now NOT_TESTED with the name.
  `TestCommunityQuantNameIsNotTested`.

## Syntax-tree analysis of chat templates (2026-10-02)

The hero check used to match phrases with regexes over the raw template. The
audit's poisoned templates all passed it: a Pillar-style conditional
system-turn injection, `'Ign' ~ 'ore previous instructions'`, a `|reverse`d
phrase, and a zero-width space inside "ignore". The check now parses the
template (`internal/checks/chattemplate/jinja`) and analyses the tree:

- Constant expressions are evaluated (`~`, `+`, `join`, `reverse`, `[::-1]`,
  `replace`, `format` including `%c`, string escapes such as `\x5f`, and `set`
  indirection), and text emitted back to back is read as one string.
- Text is normalized (zero-width and bidi controls stripped, fullwidth and
  common Cyrillic and Greek lookalikes mapped to Latin) before the phrase leads
  run, and hidden characters or a word mixing scripts are leads in themselves.
- A dunder name reached by any route (`.x`, `[k]`, `attr`, `map(attribute=)`,
  built by concatenation or escapes) is a FAIL.
- A branch that tests **what message content says** (membership of a
  constant, equality with a non-empty constant, `startswith`-style probes)
  and emits a system turn or its own prose is a LEAD.
- Every named template (`tokenizer.chat_template.<name>`) is checked.
- A template the analyser cannot read (parse error, over the size or work
  budget, invalid UTF-8) is a LEAD, not NOT_TESTED, so a blanket acceptance
  cannot clear an evasion by unreadability.

### False positives

Measured against 49 distinct real templates: the 14 in the local GGUF corpus
(including Command-R's named `rag` and `tool_use` templates) and 35 fetched
from the public Hugging Face repos of Qwen 2.5/3, QwQ, Llama 3.1/3.2/3.3/4,
Gemma 2/3, Mistral 7B/Nemo/Small 3.1, Phi-3.5/4, DeepSeek R1/V3/Coder V2,
gpt-oss, GLM 4/4.5, Granite 3.3, OLMo 2, SmolLM3, Hermes 3, Kimi K2,
MiniMax M1, Falcon 3, Nemotron, InternLM 3, Yi 1.5, and LFM2.

| Rule version | PASS | LEAD | FAIL |
|---|---|---|---|
| First draft: any branch that reads content | 41 | 8 | 0 |
| Shipped: only branches that test what content says | 49 | 0 | 0 |

The first draft flagged every template that handles a system message
(`if messages[0].content is string`, `if system_message`), and gpt-oss's
`raise_exception` error text. Narrowing the trigger to value tests, and
skipping `raise_exception` arguments, cleared all eight with no loss on the
evasion corpus. The end-to-end sweep over the local GGUFs is unchanged from
the regex check: 27 PASS, 17 NOT_TESTED (calibration vocab files with no
template), 0 LEAD, 0 FAIL.

Reproduce, with the templates as `*.jinja` files in a directory (they are not
committed, since they are third-party):

```
SOCAIR_TEMPLATE_CORPUS=/path/to/templates go test ./internal/checks/chattemplate -run RealTemplates -v
```

### Evasion corpus

`internal/checks/chattemplate/testdata/evasions` holds 22 self-written
fixtures with expected results, run by `TestEvasionCorpus`. With the analyser
removed, 18 of the 21 attack fixtures PASS (the parse step and the old raw
regex catch the other three). One fixture is a recorded known
miss: a default system prompt whose instruction reads as ordinary guidance,
with no lead phrase, URL, obfuscation, or content condition. That class is on
the published detection ceiling until reviewed-template diffing lands.

### Code words in prose (2026-10-04, check set tier1/0.3)

The structural FAIL used to come from a regex over the raw template text
(`subprocess`, `eval(`, `exec(`, `os.system(`, and three dunder names), so a
benign default system prompt that mentions them, such as coding advice,
FAILed as "positive evidence" (#130). Process execution is now judged from the
parsed template like dunder reach: a command-running module (`os`,
`subprocess`, `sys`, ...) referenced in an expression, a call to `eval`,
`exec`, `compile` or `__import__`, or a process function (`system`, `popen`,
`check_output`, ...) called as an attribute or reached through `attr` with a
folded name. Text the template outputs and Jinja comments are not code.

Measured against the 70 templates in llama.cpp's `models/templates` (a
broader set than the 49 above, including DeepSeek V3.1 to V4, Gemma 4, GLM 4.6
and 4.7, Kimi K2/K3, MiniMax M1 to M3, Nemotron, Granite 4.x, Qwen 3.5, and
gpt-oss), under the old and the new rules:

| Rule version | PASS | LEAD | FAIL |
|---|---|---|---|
| tier1/0.2 (raw-text regex) | 69 | 1 | 0 |
| tier1/0.3 (parsed template) | 69 | 1 | 0 |
| tier1/0.5 (filter blocks parse) | 70 | 0 | 0 |

No real template mentions those words in prose, so the corpus result is
unchanged; the fix is pinned by `TestCodeWordsInTextAreNotCode` and the
`benign-code-words-in-prompt.jinja` fixture. The one LEAD is unrelated and
predates this change: `fireworks-ai-llama-3-firefunction-v2.jinja` does not
parse ("line 4: unexpected trim"), which the check reports as an unreadable
template. Check set tier1/0.5 fixes it: the parser demanded a pipe
before a filter block's first filter (`{% filter |trim %}`), which is not how
Jinja writes it (`{% filter trim %}`). With filter blocks parsing, and their
filter and body analysed like any other code, the corpus is **70 PASS, 0 LEAD,
0 FAIL**. CI now runs this corpus on every pull request and push to `main`
(`real-template-corpus` job, llama.cpp pinned at `7fe450e1`, 2026-09-23). The evasion corpus gains `attr-concat-popen.jinja` (a process
function reached through `attr` with a concatenated name), which FAILs.

## File inventory: string arrays and truncation (2026-10-04, check set tier1/0.4)

The inventory scanned only string-typed GGUF metadata values and skipped
string arrays, so a payload in an array value passed. It also passed an
inventory cut off at its 8 MiB / 20k-entry cap, with only a note (#135).

String-array elements of 64 bytes or more are now scanned with the same
patterns (script or shell content, a base64 run of 512+ characters, an
executable or archive signature). Shorter elements are counted, not kept:
a vocabulary's tokens are short, include strings such as `<script` and `#!`,
and are too short to carry an executable or a 512-character blob. An
inventory that reaches its cap is NOT_TESTED, unless a payload was already
found, which stays a FAIL.

Measured on 12 local GGUFs (Gemma 3 12B/27B, Gemma 4 26B, Qwen3 0.6B,
Qwen 3.6/3.8 27B and MoE variants, Llama 3.3 Nemotron Super 49B): 262k to
777k string-array elements each, up to 4,146 of 64+ bytes scanned per file,
0 findings, 0 truncated. Every row was NOT_TESTED only because no repo
mirror was given, as before.

## Tokenizer: canonical reference tables (2026-10-04, check set tier1/0.6)

The tokenizer row checked only internal consistency, so a swapped ordinary
token passed (#135). With a canonical table configured, the vocabulary is now
compared id by id with the table of its family. A table counts as the family
only when at least 98% of shared ids agree. A changed ordinary token or a
vocabulary that ends early is a LEAD. Renamed special or reserved tokens, and
tokens past the table's end, are notes.

Measured with 7 tokenizer.json files from the local Hugging Face cache as
references, including the publishers' own `Qwen/Qwen3-0.6B` and
`Qwen/Qwen3.8-27B`, against 12 local GGUFs and against each other:

| Compared | Matched a family | Changed ordinary tokens | LEAD |
|---|---|---|---|
| 9 Qwen-family GGUFs (Qwen3 0.6B, Qwen 3.6/3.8 27B, and the Qwopus, Carnice, and ornith fine-tunes) | 9, at 100.00% | 0 | 0 |
| 3 GGUFs of other families (Gemma 3 12B/27B, Gemma 4 26B, Llama 3.3 Nemotron 49B) | 0 (best 0.32%) | - | 0 |
| 7 tokenizer.json against the other six | 2 (Qwen3.8 official and an MLX copy, 100%) | 0 | 0 |

Same-family agreement was 100% and cross-family agreement at most 0.32%, so
the 98% floor sits far from both. GGUFs carry 243 to 267 padding tokens past
the Hugging Face vocabulary; they are reported as added, not as a LEAD. A real
scan of Qwen3-0.6B-Q8_0.gguf against a table built from the official
tokenizer.json (`socair feed tokenizer-table`) reports PASS, 100.00% of ids
agreeing, 0 changed, 267 added. The LEAD is falsified by unit and engine tests
(a swapped pair of ordinary tokens).

## Pickle opcode walker (2026-10-02)

The pickle check matched one byte pattern, the text GLOBAL of protocols 0 to 3,
so protocol 4 and 5 pickles (the default since Python 3.8), INST, memoized
STACK_GLOBAL, `builtins.getattr`, and `importlib.import_module` all passed, and
zip checkpoints (PyTorch's format since 1.6) were never opened. It now models
the opcode stream with a stack and memo, and judges each import: a dangerous
module or callable is a FAIL, the reviewed safe list (tensor and storage
rebuilders, containers, numpy reconstruction) is fine, and anything else, or an
import that cannot be resolved statically, is a LEAD.

Real checkpoints, all PASS with every import on the safe list:

| Checkpoint | Format | Pickles | Imports |
|---|---|---|---|
| hf-internal-testing/tiny-random-bert | zip | 1 | 4 |
| hf-internal-testing/tiny-random-gpt2 | zip | 1 | 4 |
| hf-internal-testing/tiny-random-t5 | zip | 1 | 3 |
| prajjwal1/bert-tiny | zip | 1 | 4 |
| sshleifer/tiny-gpt2 | legacy stream | 5 | 4 |
| openai-community/gpt2 (548 MB) | legacy stream | 5 | 3 |

Two false-positive paths were closed while measuring. Legacy `torch.save`
files end in raw storage bytes, so a pickle after the first counts only if it
reaches STOP. And bert-tiny has a tensor entry whose first byte is `.` (STOP),
which parsed as an empty pickle: a zip entry not named `.pkl` is walked only if
it starts with PROTO, and its imports must be well-formed Python names.

## Safetensors layout validation (2026-10-03)

Structure used to PASS any safetensors header that parsed. The audit's
`overlap.safetensors` passed with two tensors at the same offsets, a bogus
dtype, a negative shape, and a pickle in an unaccounted gap. A PASS now means
the tensor ranges tile the data section exactly (start at 0, meet end to start,
end at the last byte), each sized to its shape times its dtype width. A
violation is a FAIL: the reference loader rejects it, and a gap is where a
payload hides. A dtype outside the known table is NOT_TESTED, not FAIL, since
the format keeps adding types. The header limit is now the reference
implementation's 100,000,000 bytes.

Measured on real files, headers only (0.02 s for about 137 GB): 45 PASS, 0 FAIL,
0 NOT_TESTED. They cover Qwen3.8-27B in BF16 (18 shards); MLX 4-bit and 8-bit
quantizations of Gemma 4 31B, Qwen3.6 35B-A3B, Qwen3-4B, and Nemotron 3.5 30B
(packed U32 weights with per-group scales); bge-reranker-v2-m3; and
all-MiniLM-L6-v2. The check also found the project's own "clean" test fixture
was invalid (an F16 8x8 tensor in a 64-byte range), now fixed.

```
SOCAIR_SAFETENSORS_CORPUS=<dir>[:<dir>...] go test ./internal/checks/structure -run RealSafetensors -v
```

## GGUF tensor-table validation (2026-10-03)

Structure used to PASS any GGUF whose metadata parsed: the tensor table was
never read, so the audit's `poly.gguf` (claiming 12,345 tensors, holding none,
with ELF and ZIP bytes appended) passed. The reader now parses the tensor
table and the structure check requires the tensors to tile the data section
exactly: each sized by its dims and ggml type, aligned to `general.alignment`,
with only alignment padding between them and after the last. A violation is a
FAIL; an unknown ggml type or tensor data past the end of the file (a cut-short
download) is NOT_TESTED. The quant row now reads the tensor types: a file
named for a quantization that holds no tensor of that type FAILs, and the
observed histogram is reported.

The ggml type table was checked against real files, since a file only tiles
exactly if every type's block and byte size is right: 59 GGUFs validate with no
violation. 44 are local models; 15 are header samples of public quants (the
first megabytes fetched by range request and extended sparsely to the true
size), covering F32, F16, BF16, Q4_0, Q4_1, Q8_0, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K,
IQ1_S, IQ1_M, IQ2_XXS, IQ2_XS, IQ2_S, IQ3_XXS, IQ3_S, IQ4_NL, IQ4_XS, and MXFP4.
Not yet exercised by a real file: Q5_0, Q5_1, Q8_1, Q8_K, I8 to I64, F64,
TQ1_0, TQ2_0. Engine sweep: structure 59 PASS, 0 FAIL; quant 35 PASS, 0 FAIL
(the NOT_TESTED rows are vocabulary and imatrix files with no quant in their
name, and Unsloth's Q8_K_XL, which holds no Q8_K).

The histograms also show how far labels are from contents: Unsloth's
UD-Q6_K is 54% Q6_K and 46% Q8_0; its UD-IQ1_M is 23% IQ1_M and 50% Q5_K; one
"Q4_K_M" is 38% Q8_0.

```
SOCAIR_GGUF_CORPUS=<dir>[:<dir>...] go test ./internal/gguf -run RealGGUF -v
```

## Tokenizer inspection (2026-10-03)

The tokenizer row read only the `tokenizer.ggml.model` label, so it was
NOT_TESTED on every GGUF and no GGUF could reach a clean authorization. It now
reads the vocabulary, the token types, the score and merge counts, and every
`*_token_id`, and FAILs on inconsistent tables (a special id outside the
vocabulary, a type or score table of the wrong length, an undefined token
type) and LEADs on a control or user-defined token that carries prose or an
instruction phrase.

Measured before choosing the rules, on 41 distinct tokenizers (Qwen 2/3/3.6/3.8,
Gemma 3/4, Llama 3, Nemotron, gpt-oss, Command-R, DeepSeek, Falcon, Phi-3,
StarCoder, BERT, and others): no control token carries three or more words, no
special id is out of range, and type and score tables always match the
vocabulary. A third candidate rule, a chat-template marker missing from the
vocabulary, was dropped to an informational note: gpt-oss's template uses
`<|final|>`, which its vocabulary does not have. Engine sweep over 59 GGUFs:
56 PASS, 0 FAIL, 0 LEAD, 3 NOT_TESTED (imatrix files with no vocabulary).

## Model directory scans (2026-10-04)

`socair scan <dir>` over every Hugging Face cache snapshot on the development
machine: 10 repos, 1 to 32 files, up to 55 GB (Qwen3.8-27B, 18 safetensors
shards). Zero FAIL and zero LEAD.

| Repo | Files | Structure | Inventory | Chat template | Remote code |
|---|---|---|---|---|---|
| Qwen/Qwen3.8-27B | 32 | PASS (18 shards + index agree) | PASS | PASS | PASS |
| Vontra/Qwen3.8-27B-MLX-4bit | 17 | PASS (3 shards + index) | PASS | PASS | PASS |
| Vontra/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-MLX-4bit | 14 | PASS (4 shards + index, plus an unindexed MTP file) | PASS | PASS | PASS |
| z-lab/Qwen3.8-27B-DFlash2 | 5 | PASS | PASS | NOT_TESTED (none) | PASS |
| z-lab/Qwen3.8-27B-DFlash2-GGUF | 1 | PASS | PASS | NOT_TESTED (none) | PASS |
| BAAI/bge-reranker-v2-m3 | 6 | PASS | PASS | NOT_TESTED (none) | PASS |
| sentence-transformers/all-MiniLM-L6-v2 | 11 | PASS | PASS | NOT_TESTED (none) | PASS |
| Qwen/Qwen3-0.6B | 6 | NOT_TESTED (partial download, no weights) | PASS | PASS | PASS |
| answerdotai/ModernBERT-base | 4 | NOT_TESTED (partial download, no weights) | PASS | NOT_TESTED (none) | PASS |
| chopratejas/kompress-base | 1 | NOT_TESTED (ONNX, unparsed) | PASS | NOT_TESTED (none) | PASS |

The shard-index rule (index and shards agree exactly) was measured on the three
real indexes before it was chosen: every indexed tensor is in its shard and
every shard tensor is indexed to it. A safetensors file the index does not name
(Nemotron's `mtp-4bit.safetensors`) is validated on its own, not judged.

None of these repos ships `auto_map` or a `.py` file, so the Remote code LEAD
has not yet been seen on a real repo here; repos that do ship remote code
(many research architectures) will LEAD by design, naming the files.

## Hugging Face tokenizer inspection (2026-10-04)

The directory Tokenizer row reads `tokenizer.json`, `tokenizer_config.json`,
`special_tokens_map.json`, and the special-token ids in `config.json` and
`generation_config.json`. Every rule was prototyped and measured before it was
chosen, then the Go check was run over the same corpus: 52 public repos'
tokenizer files (Qwen 2.5/3/QwQ/VL, DeepSeek V3 and R1 distills, Llama 3.x and
Gemma 2/3 copies, Mistral Nemo/Small, Phi 3.5/4, GLM 4.5, MiniMax, gpt-oss,
OLMo 2, Granite, Falcon 3, SmolLM2, StarCoder2, Yi, BERT, RoBERTa, GPT-2,
bge-m3, jina v3, nomic, e5, and others) plus the 10 local snapshots.

| Rule | Result on real tokenizers |
|---|---|
| FAIL: a config special-token id that names no token | 0 hits |
| FAIL: an added token reusing a vocabulary id with other text | 0 |
| FAIL: `added_tokens_decoder` disagreeing with `tokenizer.json` | 0 |
| FAIL: a declared special token absent from the vocabulary | 0 |
| FAIL: a template whose ids and tokens disagree (23 templates) | 0 |
| FAIL: two vocabulary entries sharing an id | 0 |
| LEAD: a special or added token carrying prose or an instruction | 0 |
| LEAD: a normalizer rewriting input into special-token text (incl. 14,790 precompiled-charsmap targets in bge-m3 and jina) | 0 |
| LEAD: a template inserting a non-special token | 0 |

Totals: 54 PASS, 0 FAIL, 0 LEAD, 8 NOT_TESTED (no `tokenizer.json`: T5,
InternLM 2.5, Kimi K2, GLM-4-9B, OpenHermes 2.5, and three local repos with no
tokenizer at all). Each rule was planted once in a copy of a real tokenizer and
fired. Identical tokenizer hashes group shared tokenizers (the three Qwen 2.5
variants; the Llama 3.x copies; Zephyr and SOLAR), which a canonical-tokenizer
comparison can build on.

## Tokenizer: the -1 sentinel (2026-10-09, check set tier1/0.7)

`hf-internal-testing/tiny-random-LlamaForCausalLM` FAILed the Tokenizer row on
`config.json pad_token_id = -1`. That value is transformers' "unset"
sentinel: older `LlamaConfig` versions defaulted `pad_token_id` to -1, and
configs derived from them still carry it. None of the 62 tokenizers above
used it, so the corpus missed it. A negative special-token id is now skipped
by the range rule; an id at or above zero that names no token still FAILs.
The change only removes a FAIL, so it cannot add a false positive on the
corpus above.

## License identification (2026-10-09, check set tier1/0.8)

The license is identity, read from the model card's front matter, the
top-level LICENSE files, and GGUF `general.license` keys, and graded only
under a policy (`SOCAIR_LICENSE_POLICY`). It was measured three ways:

```
SOCAIR_LICENSE_CORPUS=<dir of repos> [SOCAIR_LICENSE_POLICY=<file>] \
  go test ./internal/engine -run RealLicenses -v
```

**Real repos.** The model card and every top-level LICENSE file of 51 public
repos, fetched from the Hub at `main` on 2026-10-09 (text files only), plus
the metadata header of one GGUF from each of the 8 quantizer repos (fetched by
HTTP range, no tensor data): Llama 2, 3, 3.1, 3.2, 3.3, and 4; Gemma 2, 3,
and 3n; Qwen 2, 2.5, and 3; DeepSeek V3, V3-0324, R1, and two R1 distills;
Mistral 7B, Small 3.1, Large 2411, and Codestral; Phi 3.5 and 4; gpt-oss;
GLM 4 and 4.5; Kimi K2; MiniMax M2 and Text-01; two Nemotrons; OLMo 2;
Granite 3.3; SmolLM2; Falcon 3; Command R7B; BLOOM; StarCoder2; SDXL;
Hunyuan 7B; and bartowski and unsloth GGUF repos of Llama 3.1 and 3.3,
Gemma 3, Qwen 2.5 and 3, Mistral Small, gpt-oss, and the R1 Llama distill.

Identification: 48 identified, 1 disagreement, 2 not identified, 0 with no
statement. Every identified license was checked by hand against the card's
tag and the LICENSE file's title: none is wrong. Two policies were run, a
permissive one (`apache-2.0`, `mit`, `bsd-new`, `bsd-simplified`,
`cc-by-4.0`) and a broad one that adds Llama 3.1 to 4, Gemma, Qwen, DeepSeek,
and NVIDIA's open model license:

| Repo | Identified | Permissive policy | Broad policy |
|---|---|---|---|
| allenai/OLMo-2-1124-7B-Instruct | `apache-2.0` | PASS | PASS |
| bartowski/google_gemma-3-12b-it-GGUF | `socair-gemma-terms-of-use` | FAIL | PASS |
| bartowski/Meta-Llama-3.1-8B-Instruct-GGUF | `llama-3.1-license-2024` | FAIL | PASS |
| bartowski/mistralai_Mistral-Small-3.1-24B-Instruct-2503-GGUF | `apache-2.0` | PASS | PASS |
| bartowski/Qwen2.5-72B-Instruct-GGUF | `qwen-2024` | FAIL | PASS |
| bigcode/starcoder2-15b | `bigcode-open-rail-m-v1` | FAIL | FAIL |
| bigscience/bloom | `bigscience-rail-1.0` | FAIL | FAIL |
| CohereLabs/c4ai-command-r7b-12-2024 | `cc-by-nc-4.0` | FAIL | FAIL |
| deepseek-ai/DeepSeek-R1 | `mit` | PASS | PASS |
| deepseek-ai/DeepSeek-R1-Distill-Llama-8B | `mit` | PASS | PASS |
| deepseek-ai/DeepSeek-R1-Distill-Qwen-7B | `mit` | PASS | PASS |
| deepseek-ai/DeepSeek-V3 | `deepseek-la-1.0` | FAIL | PASS |
| deepseek-ai/DeepSeek-V3-0324 | `mit` | PASS | PASS |
| google/gemma-2-9b-it | `socair-gemma-terms-of-use` | FAIL | PASS |
| google/gemma-3-12b-it | `socair-gemma-terms-of-use` | FAIL | PASS |
| google/gemma-3n-E4B-it | `socair-gemma-terms-of-use` | FAIL | PASS |
| HuggingFaceTB/SmolLM2-1.7B-Instruct | `apache-2.0` | PASS | PASS |
| ibm-granite/granite-3.3-8b-instruct | `apache-2.0` | PASS | PASS |
| meta-llama/Llama-2-7b-chat-hf | `llama-2-license-2023` | FAIL | FAIL |
| meta-llama/Llama-3.1-8B-Instruct | `llama-3.1-license-2024` | FAIL | PASS |
| meta-llama/Llama-3.2-3B-Instruct | `llama-3.2-license-2024` | FAIL | PASS |
| meta-llama/Llama-3.3-70B-Instruct | `llama-3.3-license-2024` | FAIL | PASS |
| meta-llama/Llama-4-Scout-17B-16E-Instruct | `llama-4-cla-2025` | FAIL | PASS |
| meta-llama/Meta-Llama-3-8B-Instruct | `socair-llama-3-license-2024` | FAIL | FAIL |
| microsoft/Phi-3.5-mini-instruct | `mit` | PASS | PASS |
| microsoft/phi-4 | `mit` | PASS | PASS |
| MiniMaxAI/MiniMax-M2 | not identified | NOT_TESTED | NOT_TESTED |
| MiniMaxAI/MiniMax-Text-01 | not identified | NOT_TESTED | NOT_TESTED |
| mistralai/Codestral-22B-v0.1 | `socair-mistral-non-production-0.1` | FAIL | FAIL |
| mistralai/Mistral-7B-Instruct-v0.3 | `apache-2.0` | PASS | PASS |
| mistralai/Mistral-Large-Instruct-2411 | `socair-mistral-research-0.1` | FAIL | FAIL |
| mistralai/Mistral-Small-3.1-24B-Instruct-2503 | `apache-2.0` | PASS | PASS |
| moonshotai/Kimi-K2-Instruct | `moonshot-ai-modified-mit-2025` | FAIL | FAIL |
| nvidia/Llama-3.1-Nemotron-Nano-8B-v1 | `socair-nvidia-open-model` | FAIL | PASS |
| nvidia/NVIDIA-Nemotron-Nano-9B-v2 | `socair-nvidia-open-model` | FAIL | PASS |
| openai/gpt-oss-20b | `apache-2.0` | PASS | PASS |
| Qwen/Qwen2-72B-Instruct | `tongyi-qianwen-2023` | FAIL | FAIL |
| Qwen/Qwen2.5-3B-Instruct | `socair-qwen-research-2024` | FAIL | FAIL |
| Qwen/Qwen2.5-72B-Instruct | `qwen-2024` | FAIL | PASS |
| Qwen/Qwen2.5-7B-Instruct | `apache-2.0` | PASS | PASS |
| Qwen/Qwen3-30B-A3B | `apache-2.0` | PASS | PASS |
| Qwen/Qwen3-8B | `apache-2.0` | PASS | PASS |
| stabilityai/stable-diffusion-xl-base-1.0 | `bigscience-open-rail-m2` | FAIL | FAIL |
| tencent/Hunyuan-7B-Instruct | `socair-tencent-hunyuan-community` | FAIL | FAIL |
| THUDM/glm-4-9b-chat | `socair-glm-4` | FAIL | FAIL |
| tiiuae/Falcon3-7B-Instruct | `socair-tii-falcon-license` | FAIL | FAIL |
| unsloth/DeepSeek-R1-Distill-Llama-8B-GGUF | disagreement | LEAD | PASS |
| unsloth/gpt-oss-20b-GGUF | `apache-2.0` | PASS | PASS |
| unsloth/Llama-3.3-70B-Instruct-GGUF | `llama-3.3-license-2024` | FAIL | PASS |
| unsloth/Qwen3-8B-GGUF | `apache-2.0` | PASS | PASS |
| zai-org/GLM-4.5 | `mit` | PASS | PASS |

Totals: permissive, 19 PASS, 29 FAIL, 1 LEAD, 2 NOT_TESTED; broad, 35 PASS,
14 FAIL, 0 LEAD, 2 NOT_TESTED. Every FAIL is a license the policy leaves out,
stated consistently by the repo. LEAD volume is 1 of 51 under the permissive
policy and 0 under the broad one.

The disagreement, examined by hand: unsloth's card for
DeepSeek-R1-Distill-Llama-8B says `llama3.1`, and its GGUF's
`general.license` says `mit`, carried over from DeepSeek's card at
conversion. DeepSeek's own repo states MIT, and its README prose says the
model "is derived from Llama3.1-8B-Base and is originally licensed under
llama3.1 license". Neither statement is wrong: MIT is DeepSeek's license for
its work, and the Llama 3.1 license is the base model's. Which one governs a
deployment is a legal question, which is why a disagreement is a LEAD and
never a FAIL. It also shows a limit: DeepSeek's repo declares no
`base_model` in its front matter, so a scan of it identifies MIT and sees no
disagreement. The lineage is in prose, which is not read.

Not identified: MiniMax-M2 (`license: other`, `license_name: modified-mit`,
and a link to a LICENSE on GitHub; the Hub repo ships no LICENSE file), and
MiniMax-Text-01 (its LICENSE-MODEL, "MINIMAX MODEL LICENSE" released 15
January 2025, is a revision the catalogue does not hold). Both are NOT_TESTED
under a policy.

Rules this corpus shaped:

- `license: other` (13 cards) names nothing: the `license_name`, link, or
  LICENSE file says which license it is. A `license_name` the catalogue does
  not know under `other` (`modified-mit`) is a pointer, not an unrecognized
  statement, so Kimi K2 is identified from its LICENSE file.
- DeepSeek-V3 and MiniMax-Text-01 ship LICENSE-CODE (MIT) beside
  LICENSE-MODEL. Read as two statements, DeepSeek-V3 was a disagreement
  between MIT and the DeepSeek license; a code license beside a model license
  is now listed as the code's, and the model file identifies the model.
- Phi's LICENSE opens "Microsoft." above its copyright line: a short
  paragraph holding a copyright statement is dropped whole as the notice.
- Llama 3.3's card declares a Llama 3.1 base: a revision of the same
  publisher's license is not a disagreement.

**Reference texts.** 41 license and policy texts: ScanCode LicenseDB's texts
for every key the catalogue uses and some it does not, and the Mistral
research and non-production licenses, CreativeML OpenRAIL-M, and the Gemma,
NVIDIA, and Falcon terms pages, from their publishers. 33 are identified as
the license they are and none as another. The 8 not identified are licenses
the catalogue does not hold (EXAONE 1.2 NC, GLM-130B, the original 2023
LLaMA license, MiniMax M2.5), policies that are not licenses (the Gemma
prohibited use policy, the Llama 3.2 and 4 acceptable use policies), and the
Falcon terms page, which holds several Falcon licenses and so matches two
entries.

**Edited copies.** A permissive license is identified by its whole text, in
order. 18 edited copies of the MIT, BSD, and Apache texts measured what
that tolerates. Identified: a title and copyright notice added, BSD's holder
filled in (up to a ten-word name), numbered clauses, https URLs, Apache with
its appendix dropped or filled in, the Apache notice alone, and BSD 3-Clause
with clause 3 removed (as BSD 2-Clause). Not identified: MIT with one word
removed ("sell", "sublicense"), a sentence appended to MIT or inserted into
Apache (non-commercial use, attribution, a user cap), "NON-COMMERCIAL USE
ONLY" above MIT, terms appended to Apache's appendix, Apache without its
patent clause, and a fourth clause in BSD. The first matcher compared
unordered shingle sets with a tolerance of 12 extra shingles, and it
identified MIT with a one-sentence non-commercial clause as MIT. It was
replaced before release by the in-order matcher, which allows a change only
in a marked placeholder (a holder's name) or an omittable appendix.

Not measured: a license stated only in README prose, a license linked but
not shipped (`license_link` is listed, never followed), a safetensors
header's own metadata, and license texts in other languages beyond the GLM-4
title.

## Chat templates: rendering (2026-10-09, check set tier1/0.8)

The hero check now renders every template with no code reach on fixed probe
conversations (`probes/v1`: system and user, user only, multi-turn, an
assistant turn without the generation prompt, and, when the template mentions
tools, tools offered and a tool call with its result), with Socair's own
evaluator over its parsed tree (`chattemplate/jinja`, `Render`). It never
calls Python or another Jinja engine. Every byte of a render is attributed to
the conversation or to the template, so the row can list the text a template
adds to the prompt. The static pass also hands the renderer the literals each
content condition tests (`'html' in message.content`), and a trigger probe
puts them in the messages, so the row can quote what a condition adds.

Measured against the same 70 templates as above (llama.cpp
`models/templates`, pinned at `7fe450e1`), with a stand-in bos and eos token
since the corpus has no tokenizer:

| | Templates |
|---|---|
| Status (unchanged from tier1/0.7) | 70 PASS, 0 LEAD, 0 FAIL, 0 NOT_TESTED |
| Rendered | 69 of 70 |
| Not rendered | 1: `fireworks-ai-llama-3-firefunction-v2` refuses every probe, because it concatenates a `functions` variable no probe passes |
| Refused at least one probe | 11 (23 probe renders), each the way Jinja refuses it: Hermes 2 Pro, Hermes 3, and Command R+ `tool_use` iterate `tools` unconditionally (12; they are selected only when tools are passed); `raise_exception` in Gemma 2 (no system role), Mistral Small 3.2 and Nemo (tool call ids must be 9 characters), and gpt-oss (channel tags in content, on its trigger probes) (6); Kimi K2 Instruct and Thinking call `list.append`, which transformers' immutable sandbox refuses (2); llama.cpp's DeepSeek R1 template passes a `map` generator to `tojson` (2); Functionary 3.2 concatenates tool arguments to a string (1) |
| Add text of their own | 63 of 69; the other 6 add nothing beyond special tokens and role names (DeepSeek R1 Distill Llama, DeepSeek V3.1, llama.cpp's DeepSeek R1 and RWKV World, Phi-3.5 mini, Gemma 2) |
| Add text under a content condition | 3: SmolLM3 (`/think` or `/no_think` in the system message switches its default system prompt), MiniMax M2 (`</think>` changes its turn separators), muse-glimmer (`reasoning strength` adds a "Valid recipients" line) |

What the 63 add, by a keyword count over the listed fragments: tool-call
instructions in 57, an identity or default system prompt in 39, reasoning or
thinking instructions in 16, a date or knowledge-cutoff line in 12, and a
safety preamble in 2 (Command R+ and Command R7B). All of it is listed in the
row's notes, bounded to six fragments of 120 characters, and none of it
changes the status.

**A rule measured and dropped.** The first draft made a content condition
that adds instruction prose to the render a LEAD. It flagged SmolLM3, whose
`/think` switch legitimately replaces the default system prompt: 1 false
positive in 70. The shipped rule is narrower: only a condition that makes the
template's own text open a system turn (the Pillar shape) is a LEAD, 0 of 70.
Anything else a condition adds is quoted in the notes, not judged.

**Fidelity.** On the developer's machine, every probe render of every corpus
template, trigger probes included, was compared with Jinja2 3.1.6 configured
as transformers configures it (an immutable sandbox, `trim_blocks`,
`lstrip_blocks`, loop controls, transformers' `tojson`, `raise_exception`,
`strftime_now` frozen, and a `{% generation %}` shim) on the same variables:
482 renders byte-identical, 29 refused by both, 0 different. That oracle is a
measurement, not a dependency: Socair does not ship or call Python. The
semantics it now models include Jinja's whitespace control, per-iteration loop
scope, `namespace`, macros with defaults, lazy `map`/`select` results (always
true, no length or JSON form), and markupsafe's escaping when `|safe` text is
added to a plain string.

**Reviewed-template comparison.** With a reviewed template's text available (a
feed's `templates/<sha256>.jinja`, or `SOCAIR_TEMPLATE_REFERENCE`), a template
that renders like it on every standard probe but differs under a trigger
probe for a condition the reviewed template does not test is a LEAD with the
first difference. A difference only under a condition both test (a revision of
Qwen3's `</think>` handling) is a note, and any other mismatch gets no verdict.
No reviewed texts were configured in the corpus run, so every row says none
was compared.

**Evasion corpus.** `macro-conditional-system.jinja` (a system turn emitted from
a macro only when a message mentions an invoice) PASSes the static walk, which
does not attribute a macro's text to its call site, and is a LEAD from the
render. The plain default-prompt known miss stays a PASS, now with its prompt
quoted in the row.

Reproduce:

```
SOCAIR_TEMPLATE_CORPUS=/path/to/templates go test ./internal/checks/chattemplate -run RealTemplates -v
```

The test logs, per template, the probes rendered and refused and the text it
adds.

## Pickle grammar socair-wo/1 (2026-10-09, check set tier1/0.8)

The pickle row was an import allowlist: a safe-listed callable passed with any
arguments, so an `OrderedDict` handed a command string (the ShadowPickle
shape) PASSed. It is now a typed grammar (`socair-wo/1`, see
[check-set.md](check-set.md)): every call's arguments must match a signature,
every storage a pickle references must match a record of exactly its size,
and a stream that claims protocol 2 or 3 must be encoded as CPython's pickler
writes it. Its new statuses were measured on real files before they were
fixed, because the grammar FAILs on layout contradictions and code-like
arguments and LEADs on many shapes the allowlist accepted.

36 benign files from 26 public repositories (25 on Hugging Face, one on
GitHub), each fetched at a pinned commit. Five larger checkpoints were
measured as sparse copies: the zip's central
directory and every `.pkl` entry fetched by range request, the storage
records left as zeros. The check reads `data.pkl` and takes record sizes from
the directory, so a sparse copy is checked exactly as the full file would be.

| Files | Shape | tier1/0.7 | tier1/0.8 |
|---|---|---|---|
| `pytorch_model.bin` of hf-internal-testing tiny-random gpt2, GPT2LMHeadModel, bert, BertModel, t5, T5ForConditionalGeneration, MistralForCausalLM, WhisperForConditionalGeneration; trl-internal-testing and HuggingFaceM4 tiny-random-LlamaForCausalLM; prajjwal1/bert-tiny | torch zip state dicts (float32, float16, int64, uint8 buffers; tied storages) | 11 PASS | 11 PASS |
| lvwerra/distilbert-imdb and huggingface-course/bert-finetuned-ner `pytorch_model.bin` (268 and 431 MB, sparse) | real fine-tunes | 2 PASS | 2 PASS |
| sshleifer/tiny-gpt2 `pytorch_model.bin` | legacy torch stream (5 pickles, then 32 storage records) | PASS | PASS |
| JackFram/llama-68m `optimizer.pt` (544 MB, sparse), `scheduler.pt`, `rng_state.pth` | Trainer state: AdamW state, LR scheduler, RNG state with a NumPy array (modelled numpy `_reconstruct`, `dtype`) | 3 PASS | 3 PASS |
| speechbrain vad-crdnn-libriparty `model.ckpt`, `normalizer.ckpt`; lang-id-voxlingua107-ecapa `classifier.ckpt`; asr-crdnn-rnnlm-librispeech `normalizer.ckpt` | torch zips named `.ckpt` | 4 PASS | 4 PASS |
| hexgrad/Kokoro-82M `voices/af_heart.pt` | `torch.save(tensor)`: a tensor as the root | PASS | PASS |
| speechbrain asr-crdnn-rnnlm-librispeech `tokenizer.ckpt` | a SentencePiece model named `.ckpt` | NOT_TESTED | NOT_TESTED |
| suno/bark three `speaker_embeddings/*.npy`; openai/whisper `mel_filters.npz`; facebook/fastspeech2-en-ljspeech `fbank_mfa_gcmvn_stats.npz` | NumPy, no object dtype | 5 NOT_TESTED (not read) | 5 PASS |
| JackFram/llama-68m, lvwerra/distilbert-imdb, huggingface-course/bert-finetuned-ner `training_args.bin` | `TrainingArguments` | 3 LEAD | 3 LEAD |
| Ultralytics/YOLOv8 `yolov8n.pt`, Ultralytics/YOLOv5 `yolov5n.pt` | full-model pickles | 2 LEAD | 2 LEAD |
| stable-diffusion-v1-5 `v1-5-pruned-emaonly.ckpt` (4.3 GB, sparse) | Lightning checkpoint | LEAD | LEAD |
| facebook/fastspeech2-en-ljspeech `pytorch_model.pt` (495 MB, sparse) | fairseq checkpoint | LEAD | LEAD |
| julien-c/wine-quality `sklearn_model.joblib` | joblib, arrays inline | LEAD | LEAD |

No benign file FAILed, and the grammar added no finding to any of them: every
LEAD is the unreviewed import it was before (`TrainingArguments` and its
enums, `accelerate.state.PartialState`; YOLO's and torch.nn's module classes;
`pytorch_lightning.callbacks.model_checkpoint.ModelCheckpoint`;
`argparse.Namespace`; scikit-learn and joblib classes). These are the known
false-positive sources the issue named, and they LEAD rather than FAIL. A
`training_args.bin` can conform through the reviewed-class tier once a feed
reviews `TrainingArguments`; the hook exists, and nothing is on it.

Two things the measurement found and fixed before the rules were set. torch's
writer sets the zip data-descriptor flag, so a CRC check reads the 16 bytes
after `data.pkl`; the first sparse copies left them out and read as a CRC
mismatch, which the check reports. And a shared-structure stream (60 levels of
`t = (t, t)` through the memo, a few hundred bytes) made the value walks
exponential; every walk now has a visit budget.

What the measurement does not cover: no real file here is a pickle in
protocol 0, 1, 4, or 5 that the old check passed. Those are now NOT_TESTED
(outside the grammar), so a plain-data pickle written by `pickle.dump` at its
default protocol, which used to PASS on its imports, is a gap an acceptance
must clear. torch.save writes protocol 2, so no checkpoint above moved. No
legacy tar checkpoint was found to measure; the grammar runs on its pickles,
and its storage records are not matched, so a clean one is NOT_TESTED.

Commits: hf-internal-testing tiny-random-gpt2 `71034c5d`, -bert `f171d7ba`,
-t5 `2f582cd7`, -MistralForCausalLM `75171769`, -WhisperForConditionalGeneration
`598101b8`, -GPT2LMHeadModel `af80da83`, -BertModel `fc08ad9c`,
-T5ForConditionalGeneration `b12e4190`; trl-internal-testing
tiny-random-LlamaForCausalLM `2c542e47`; HuggingFaceM4
tiny-random-LlamaForCausalLM `d3040b7c`; prajjwal1/bert-tiny `6f75de8b`;
sshleifer/tiny-gpt2 `5f91d94b`; JackFram/llama-68m `9de84537`;
lvwerra/distilbert-imdb `0fc02cd6`; huggingface-course/bert-finetuned-ner
`eeb27847`; speechbrain vad-crdnn-libriparty `c5d5ae4f`,
lang-id-voxlingua107-ecapa `0253049a`, asr-crdnn-rnnlm-librispeech `979a53a7`;
Ultralytics/YOLOv8 `27f858f2`, YOLOv5 `5bca7970`; hexgrad/Kokoro-82M
`f3ff3571`; suno/bark `70a8a7d3`; stable-diffusion-v1-5 `451f4fe1`;
facebook/fastspeech2-en-ljspeech `a3e3e5e2`; julien-c/wine-quality `90ef3b74`;
openai/whisper (GitHub) `86098128`.

## Pickles found by their bytes (2026-10-09, check set tier1/0.8)

A model directory sent a file to the pickle check only when its extension
said pickle (#186), so a pickle named `notes.txt`, or a torch zip named
`weights.dat`, was never opened, and File inventory passed. A directory scan
now also sends a file there when its bytes say pickle (`pickle.Sniff`): a
protocol 2 to 5 stream that walks (it completes a pickle or imports a global
within its first MiB), or a zip holding one. Protocol 0 and 1 pickles begin
with ordinary text and are found by their extension or not at all; the
benchmark pins that miss. Safetensors and GGUF are left to their own readers,
since a safetensors header of 0x280 bytes begins with the same two bytes as a
protocol 2 pickle.

**The gate.** `SOCAIR_PICKLE_SNIFF_CORPUS=<dirs> go test
./internal/checks/pickle -run RealSniff -v` sniffs every file and fails on a
file the sniff claims that its name does not already mark as a pickle. On 583
files (the local Hugging Face cache, `~/models`, the socair.ai example
repositories, and three repositories fetched for their spread of formats:
`sentence-transformers/all-MiniLM-L6-v2`, `distilbert/distilbert-base-uncased`,
and `openai/whisper-tiny`, with ONNX, OpenVINO, TensorFlow, Flax msgpack,
TorchScript, and PyTorch files beside safetensors and GGUF), the first run
claimed two files: `rust_model.ot` in all-MiniLM-L6-v2 and distilbert.

**TorchScript.** Both are TorchScript archives (`code/` and `constants.pkl`
beside `data.pkl`), and the pickle check graded them LEAD: the archive's
`__torch__.Module` class, and `torch.jit._pickle.build_intlist`, are not on
the reviewed lists. A LEAD is not cleared by an acceptance, so two of the
Hub's most used repositories would have become blocks with no path through.
`torch.jit.load` runs a TorchScript archive as TorchScript, which the pickle
grammar does not model, so the sniff leaves TorchScript alone and the
inventory keeps naming it as an unscanned archive (a gap, as before). A
torch.save zip given a `code/` entry to pass as TorchScript is therefore named
as unscanned, not passed. The `control-dir-torchscript` benchmark control pins
this. After the change: 4 files are pickles by name and bytes, 2 by name only
(OpenVINO's raw `.bin` weights, which the pickle row already reports as not a
pickle), and 0 by bytes only.

**Verdicts on real repositories.** Each of seven was scanned as a directory
with the engine before and after:

| Repository | Files | Rows that changed | Promotion |
|---|---|---|---|
| nvidia/Qwen3.8-27B-NVFP4 | 19 | none; inventory notes "no pickle file" | unchanged |
| Qwen/Qwen3-0.6B | 10 | none; inventory notes "no pickle file" | unchanged |
| katuni4ka/tiny-random-chatglm2 | 12 | none; inventory notes "no pickle file" | unchanged |
| hf-internal-testing/tiny-random-MistralForCausalLM | 10 | none | unchanged |
| sentence-transformers/all-MiniLM-L6-v2 | 30 | none | unchanged |
| distilbert/distilbert-base-uncased | 12 | none | unchanged |
| openai/whisper-tiny | 16 | none | unchanged |

The `pytorch_model.bin` checkpoints in distilbert and whisper-tiny PASS the
grammar as before, and `rust_model.ot` stays "Archive contents were not
scanned" in File inventory.

## Follow-ups from the first run, since done

1. The GGML file-type mapping follows llama.cpp's `llama_ftype` enum, and the
   quant row reads the tensor types (see "GGUF tensor-table validation").
2. CI runs the chat-template check over llama.cpp's real templates on every
   pull request and every push to `main` (the `real-template-corpus` job).
3. The structural FAIL rules are exercised against the evasion corpus
   (`internal/checks/chattemplate/testdata/evasions`) and the template cases
   of the [detection benchmark](detection-benchmark.md).
