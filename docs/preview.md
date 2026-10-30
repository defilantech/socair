# The browser preview

The preview runs Socair's checks on a model where it sits on Hugging Face,
before anyone downloads it. The engine is compiled to WebAssembly
(`cmd/socair-preview`) and runs in the visitor's browser. The site serves it
at socair.ai/try once a release carries the preview's files. It reads each file through HTTP range
requests, straight from the hub, so it fetches only the bytes the checks read:
safetensors headers, GGUF metadata, configs, chat templates, tokenizers, and
the model card. Nothing is uploaded and nothing is stored.

A preview is a first look. It is not an attestation, and it cannot become one.

## What a preview is not

- **Not signed, and no verdict.** A preview is an `engine.Preview`, a
  different type from the report (`report.Document`). It has no promotion
  state, no assurance level, no issuer, and no bounded statement, and
  `attest.Sign` and the airlock take only a report. It carries a fixed notice
  (`engine.PreviewNotice`) that says so. Whether a model is approved is your
  organization's call, made with a full scan and your own key.
- **Not Socair's hashes.** The hashes are as Hugging Face states them for its
  large (LFS) files, and computed by the preview from the bytes it read for the
  small ones (`engine.PreviewHashes`). No weights are hashed, so the preview's
  digest is the digest of stated hashes. A full scan through the airlock
  computes every hash itself.
- **Not every check.** A check that reads a whole file is NOT_TESTED, and its
  note begins "the preview reads headers only": the Pickle opcode scan, and the
  structure of ONNX and Keras files. Checks that need your organization's data
  (a known-bad list, reviewed templates, a license or intake policy, a signed
  feed) do not run, and the preview names them as not run. Tier 2 never runs.
- **Not for gated or private repos.** The preview takes no Hugging Face token
  and sends none. A gated or private repo is refused before any file is read;
  pull it into your airlock with your own `HF_TOKEN` instead.

Every preview names the full commit it read. A branch name is resolved to its
commit first, and the commit is what the preview reports, so a result cannot
be taken to cover a later version.

## What it reads

The preview reads the files a serving stack loads, which is the selection
[airlock.md](airlock.md#commands) recommends for a pull:

- **A model served from safetensors:** the weights, every JSON config, the
  tokenizer files, chat templates, the model card, and license files, plus any
  Python, so the Remote code row judges it.
- **A repo of GGUF quants:** one quant, since a quant is pulled on its own (the
  Q4_K_M by default, or the smallest), with the small files beside it. Each
  GGUF's own metadata (chat template, tokenizer, quant) is previewed on its own,
  as `socair scan <file>.gguf` would read it.
- **Anything else:** every file.

The page prints the selection as the airlock pull's `--include`, with the
commit, so doing it for real reads the same files at the same commit. Those
commands are meant to be pasted into a shell, and the repo id, the commit, and
the file names come from the hub, where anyone can name a file
`x';curl …|sh;'`. So a value outside a strict set of characters (letters,
digits, `.`, `_`, `-`, `/`, `*`) gets no command at all, only a note saying
why, and every value that passes is single-quoted as well
(`airlockCommands`, `shellQuote`). The page sets every value it shows from a
preview, the rows' notes included, as text, never as markup: the notes quote
the model's own files.

If any read fails (the hub answers an error, or a file needs more than the
preview's read budget), the preview shows no rows at all. A check that could
not read a file must never look like it did.

## Fidelity

For the checks it runs, a preview reads what a full scan reads, through the
same engine. `TestPreviewFindsWhatAScanFinds` pins it on fixtures: the same
rows, and a digest equal to the full scan's subject when the stated hashes are
true. On real repos (2026-10-19, Node, home broadband):

| Repo | In the repo | Read | Time | Rows |
|---|---|---|---|---|
| HuggingFaceTB/SmolLM2-135M-Instruct | 1.97 GB | 3.7 MB, 13 requests | 2.4 s | 5 PASS, provenance NOT_TESTED |
| deepseek-ai/DeepSeek-V3 | 688.6 GB, 163 shards | 59.6 MB, 181 requests | 19.2 s | 164 layouts verified; Remote code LEAD |
| bartowski/Qwen_Qwen3-0.6B-GGUF (Q4_K_M) | 12.95 GB, 24 quants | 6.4 MB, 10 requests | 4.5 s | structure, chat template, tokenizer, quant PASS |

The engine for the browser is about 13.6 MB, 3.6 MB gzipped, 2.6 MB with
brotli.

## How it works

- `engine.PreviewDir` scans a directory in place with the hashes its source
  states. Only it and `engine.PreviewGGUF` reach that path: every scan passes
  the directory scan no stated hashes, and `TestScanNeverTakesStatedHashes`
  checks the source for it. A header-only scan of a directory is refused.
- `tools/socair-preview/hffs.js` is a read-only filesystem over one repo at one
  commit, in the shape Go's js/wasm runtime calls (`globalThis.fs`). Each read
  becomes range requests, cached in 16 KiB blocks, with a window that doubles
  while a file is read in order. It has no way to take a token.
- `tools/socair-preview/preview.js` lists the repo, picks the selection,
  mounts it, runs the engine, and returns the previews or throws.
- A release carries the engine for the browser and the page's modules as
  attested assets (`socair-preview_<version>.wasm`, `..._wasm_exec.js`,
  `..._hffs.js`, `..._preview.js`), built reproducibly by
  `scripts/build-release.sh` and listed in `SHA256SUMS`. Verify them as
  [verify-release.md](verify-release.md) describes for the binaries.

## Run it locally

```
tools/socair-preview/build.sh                                  # tools/socair-preview/dist/
node tools/socair-preview/try.mjs HuggingFaceTB/SmolLM2-135M-Instruct
node tools/socair-preview/try.mjs org/name <revision> --all     # every file
node --test tools/socair-preview/preview.test.mjs               # the page's modules, no network
```
