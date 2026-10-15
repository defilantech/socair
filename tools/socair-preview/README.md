# socair-preview (prototype)

Put `socair.ai/` in front of a Hugging Face model URL and see what Socair's
checks find, without installing anything:

```
https://socair.ai/huggingface.co/nvidia/GLM-5.3-Flash-NVFP4
```

The visitor's browser runs the engine, compiled to WebAssembly
(`cmd/socair-preview`), on the model's headers and small files. It fetches
them straight from Hugging Face with HTTP range requests. Nothing is uploaded
and nothing is stored, and socair.ai stays a static site.

A preview is not an attestation:

- **Unsigned.** It is the visitor's own run, like running the CLI.
- **Headers only.** No weight bytes are read.
- **No promotion verdict.** Whether a model is approved is the organization's
  call, so the page shows the rows and leaves the decision out.

## How it works

- **`hffs.js`** is a read-only filesystem in the shape Go's js/wasm runtime
  calls (`globalThis.fs`).
  - The repo is mounted where the Hugging Face cache would hold it
    (`/hub/models--org--name/snapshots/<commit>`), so the engine names the
    model by its repo.
  - Each read becomes range requests, cached in 16 KiB blocks. A window
    doubles while a file is read sequentially, and a read after a seek is cut
    short, so a parser that hops from header to header fetches a block at
    each hop.
  - `warm()` fetches every safetensors header and GGUF metadata in parallel
    first. That only fills the cache: the engine still reads what it reads.
- **`engine.PreviewDir`** scans a directory in place and hashes nothing.
  - Each file's SHA-256 is supplied: an LFS file's as the hub states it, a
    small file's computed from its bytes.
  - `ScanMode` still refuses a header-only directory scan.
- **A GGUF** is also scanned on its own (`engine.ScanMode(path, ModeHeaders)`),
  for the chat template, tokenizer and quant rows that a directory scan does
  not run on it.
- **Selection.** For a model served from safetensors, the preview reads the
  selection `docs/airlock.md` recommends, plus `*.py` so the Remote code row
  judges any Python. The page prints it as the airlock pull's `--include`.
- **All or nothing.** If any read fails (a budget passed, a hub error), no
  row is shown: a check that could not read a file must never look like it
  did.

## Measured (2026-10-15, Node and Chromium, home broadband)

| Repo | In the repo | Read | Time | Rows |
|---|---|---|---|---|
| HuggingFaceTB/SmolLM2-135M-Instruct | 2.0 GB | 3.7 MB | 1.2–1.8 s | 5 PASS, provenance NOT_TESTED |
| microsoft/Phi-3-mini-4k-instruct | 7.6 GB | 3.1 MB | 1.3 s | Remote code LEAD |
| openai-community/gpt2 (selection) | 5.6 GB | 6.2 MB | 2.1 s | 4 PASS |
| Qwen/Qwen3-0.6B | 1.5 GB | 16 MB | 7.6 s | 5 PASS |
| Qwen/Qwen3-0.6B-GGUF (+ GGUF on its own) | 0.64 GB | 6.4 MB | 4.3 s | chat template, tokenizer, quant PASS |
| nvidia/GLM-5.3-Flash-NVFP4 | 204.5 GB | 57.5 MB | 16 s | 6 rows, 33 shard layouts verified |

**Fidelity check.** SmolLM2's selection was pulled with
`socair airlock pull --include …` at the same commit and scanned in full.

- **Subject digest:** the same as the preview's (`29165dae…`), which is also
  the airlock's staged digest.
- **Files:** the same 13, with the same hashes.
- **Rows:** every row has the same status and the same notes, word for word.

**Size.** `socair.wasm` is 17 MB, 4.2 MB gzip and 3.0 MB brotli.

## Run it

```
tools/socair-preview/build.sh            # dist/: socair.wasm, wasm_exec.js, the page
node tools/socair-preview/serve.mjs      # http://127.0.0.1:4321/huggingface.co/org/name
node tools/socair-preview/try.mjs org/name [revision] [--all]   # the same path in Node
```

## Not done

- **Gated repos** stop with a message. The preview takes no HF token.
- **Formats with many seeks** are slow to preview: an ONNX file with inline
  weights, or a legacy (pre-zip) torch pickle. The selection leaves them out
  when safetensors are present; `?all` previews everything.
- **Hosting.** On socair.ai this needs:
  - a Netlify rewrite `/huggingface.co/*` to the page;
  - the page under `noindex`;
  - the site's design.
