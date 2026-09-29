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

## Follow-ups

1. Verify the GGML file-type mapping against the current llama.cpp enum so the
   quant row stops withholding on real models.
2. Add this corpus as a regression fixture in CI, so a future pattern cannot
   reintroduce a false positive on real templates.
3. The structural FAIL patterns should be exercised against a corpus of known
   template-injection payloads, not only unit fixtures.
