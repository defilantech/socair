# Report layout (v1)

The implemented layout of the HTML attestation. Rendering lives in
`internal/render`, driven by the report data model. See
`docs/report-layout-proposal.md` for the proposal this encodes.

## The three Chris answers

1. **NOT_TESTED reads as a neutral grey pill plus an explicit "not tested" tag,
   with the reason inline.** Neutral about the artifact, impossible to mistake
   for a pass. Enforced by a test: a NOT_TESTED status must never render with
   the pass class.
2. **The badge is a word**, not a scale: "Tier 1 (static)", beside the three
   counts (Pass, Fail, Not tested).
3. **The cover is a compact block on page one**, not a full page: artifact name,
   hash, format, quant, split, document id, issuer, badge, counts. Then straight
   into the graded table.

## Structure

- Cover block: artifact line, the word badge, the four counts.
- Checks performed: the graded table. Columns Check, Looks for, Result, Evidence.
  Result is a pill: PASS (green), FAIL (red), LEAD (amber) plus the "escalate"
  tag, NOT_TESTED (neutral grey) plus the "not tested" tag. The hero row first.
- Bounded statement: the fixed Option A wording.
- Out of scope: the ceiling, in full, with the "does not certify the absence of
  unknown backdoors" sentence in bold.
- Promotion authorization: authorized or withheld, with conditions.
- Verification: signing method and the artifact SHA256.
- Footer: issuer and exclusions.

## Sample build

`socair demo` renders the fabricated sample attestation for sales. It carries a
SAMPLE watermark (fixed positioning, repeats on each printed page in Chrome
print), a header chip, and a footer mark. A test asserts a real issuance carries
none of it.

## Rendering rules

- HTML and inline CSS, one self-contained file. No network, no fonts fetched.
- Byte-stable for a fixed input, so a report can be diffed. Enforced by a test.
- Every value goes through `html/template` escaping, so an artifact name cannot
  inject markup.
- NOT_TESTED is never rendered with the pass class, by design and by test.

## Commands

```
socair render <path>   scan a real artifact and write the HTML attestation
socair demo            write the SAMPLE attestation
```

## Open

- PDF output is not built. The HTML is print-ready; conversion needs a renderer
  decision (headless Chrome or a pure-Go library) and is a follow-up.
- SARIF is planned but deferred. The fileable artifact is the document, and no
  buyer has asked for SARIF yet.
