---
name: Bug Report
about: Report a bug or unexpected behavior
title: '[BUG] '
labels: bug
assignees: ''
---

<!-- A crash on a crafted input, a way past the airlock, a malicious file that
     earns a PASS, or a signature that verifies when it should not is a
     vulnerability: report it privately (SECURITY.md), not here. A real model
     that got a FAIL or a LEAD it should not have has its own template, False
     positive. -->

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

1. Get the artifact '...'
2. Run command '...'
3. Observe error '...'

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened.

## Environment

**Socair Version:**
```bash
socair version
# Output:
```

**Install:**
- [ ] Release binary
- [ ] Built from source (commit: )

**Platform:**
- [ ] linux/amd64
- [ ] linux/arm64
- [ ] darwin/arm64
- [ ] darwin/amd64
- [ ] Other:

**Where it happened:**
- [ ] `socair scan`, `render`, or `inspect`
- [ ] `socair sign`, `accept`, or `verify`
- [ ] `socair airlock` (pull, ingest, promote, log, export)
- [ ] `socair feed`
- [ ] `socair serve` (API or wizard)
- [ ] Other:

**Artifact format (if applicable):**
- [ ] GGUF
- [ ] safetensors
- [ ] Pickle checkpoint (.bin, .pt, .pth, .ckpt, ...)
- [ ] Hugging Face model directory
- [ ] Other:

## Output

**Command output:**
```bash
# Paste the command and its full output here
```

**Report excerpt (if a report was produced):**
```json
// The affected rows from checks[], and scope.check_set_version.
// artifact.sha256 identifies the artifact; please don't attach model files.
```

## Additional Context

Add any other context about the problem here (screenshots, error messages, etc.).
