# Report layout proposal (v1)

Status: **proposal, awaiting Chris**. This is issue #1 (A1). It is a design artifact, not a decision.

## Principles

- The report is the product. A CISO reads three things first: the badge, the graded table, the ceiling. Design those before anything else.
- Grading is always visible. PASS, FAIL, and NOT_TESTED each get a distinct treatment. NOT_TESTED is never rendered as green, and never hidden.
- The ceiling is not an appendix. It sits near the result, in plain language.
- Rendering is byte-stable: the same report data renders the same bytes.

## Section 1: Cover (one page)

- Title: Model Assurance Attestation.
- Artifact line: name, short hash, format, declared quantization.
- Assurance badge: the level word, and whether it is signed or unsigned. Unsigned is the OSS tier and must say so.
- The three counts a security reader scans for: checks PASS, FAIL, NOT_TESTED.
- Issuer, signer, document id, issued date, re-scan due.
- One-line summary of the bounded statement, pointing at the full wording below.

## Section 2: The graded table (the centerpiece)

- Columns: Check | Looks for | Result | Evidence.
- Result cell is a pill: PASS (green), FAIL (red), NOT_TESTED (amber or neutral grey) with the reason inline.
- The hero row, Chat template, is first.
- Evidence never renders blank; an empty evidence field is a dash.
- Every NOT_TESTED row carries its reason. This is the honesty that makes the report defensible.

## Section 3: The ceiling (Section 8)

- Plain language, full section, not a footnote.
- The fixed sentence: this attestation does not certify the absence of unknown backdoors.
- The ceiling list, per artifact.
- Unparsed formats and untested node classes, when present.

## States to design

- **All-NOT_TESTED** (the honest state before the scanner lands): the report must still read as a real document, not an error page.
- **One FAIL**, with the escalation call to action.
- **Unsigned vs signed** badge, so the OSS and paid tiers are visually distinct.

## Rendering

- HTML/CSS, byte-stable, converted to PDF later (no PDF tooling is installed locally; see the stack decision).
- Typography and color to be set with the brand: sober and calm, matching Socair's meaning (Irish, at ease and secure). Not alarmist.

## Open decisions for Chris

1. The color treatment for NOT_TESTED: amber (a soft caution) or neutral grey (a deliberate non-signal)?
2. The badge: the level as a word, or as a scale with the level marked?
3. Cover: a full cover page, or a cover letter paragraph above the table?
