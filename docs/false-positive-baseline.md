# Chat-template false-positive baseline

Run with `socair corpus <dir>`, header-only mode, over 52 real GGUF files across
three model directories (`~/models`, `~/llmkube-models`, `~/llmkube-calib`).

This is the run that de-risks the thing Chris named as a veto: false positives.

## Before the retune

15 of 26 models in `~/llmkube-models` FAILED the hero check. They were all
known-good Qwen and Gemma and Qwopus templates.

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
  They return NOT_TESTED with the matched phrase recorded, which is what
  escalates to a human. A lead never fails an artifact on its own.
- The filename quantization parser is now a strict regex. It accepts `Q4_0`,
  `Q5_K_M`, `IQ3_S`, `BF16`, and rejects a model name that merely starts with
  `Q`.

## After the retune

Zero FAILs across all 52 files. Per-check tally on `~/llmkube-models`
(26 files), PASS / FAIL / NOT_TESTED:

```
Chat template (hero)           8 / 0 / 18
Format and structure           26 / 0 / 0
Tokenizer config               23 / 0 / 3
Quant match                    2 / 0 / 24
```

## What this means honestly

- The hero check clears 8 of 26 real templates, flags 18 as instruction-language
  leads, and fails none. The 18 leads are not defects in those models; they are
  the honest state: we cannot clear that language automatically, so it escalates.
- The quant check passes on only 2 of 26, because the GGML file-type mapping is
  provisional and most real file types are outside it. That is a coverage gap,
  not a finding.
- A clean hero result still means "no structural indicator and no lead matched",
  not "no backdoor".

## Second refinement (trust-coverage slice)

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

Result on `~/llmkube-models` (26 files), PASS / FAIL / NOT_TESTED:

```
Chat template (hero)   24 / 0 / 2
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

The pre-reveal audit found two FAILs that broke the rule that a FAIL needs
positive evidence. Both are now regression tests.

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

No real template mentions those words in prose, so the corpus result is
unchanged; the fix is pinned by `TestCodeWordsInTextAreNotCode` and the
`benign-code-words-in-prompt.jinja` fixture. The one LEAD is unrelated and
predates this change: `fireworks-ai-llama-3-firefunction-v2.jinja` does not
parse ("line 4: unexpected trim"), which the check reports as an unreadable
template. The evasion corpus gains `attr-concat-popen.jinja` (a process
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

## Follow-ups

1. Verify the GGML file-type mapping against the current llama.cpp enum so the
   quant row stops withholding on real models.
2. Add this corpus as a regression fixture in CI, so a future pattern cannot
   reintroduce a false positive on real templates.
3. The structural FAIL patterns should be exercised against a corpus of known
   template-injection payloads, not only unit fixtures.
