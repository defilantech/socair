# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Operator (daily user).** An ML platform or AI Ops engineer who runs the
  intake host. They pull open-weight models into the airlock, scan them, get
  them signed and accepted, and promote them. In the console they live on
  Pending, a model's detail page, and Activity, and they copy the CLI commands
  the console hands them.
- **CISO or Head of AI Ops (reader).** Looks at Approved, a model's graded
  report, its conditions and expiry, and the signed inventory snapshot. They
  decide on acceptances (signed with their own key, outside the console) and
  need to trust what the page says without reading raw scan data.

## Product Purpose

Socair produces a signed, fileable model assurance attestation for open-weight
model artifacts (GGUF, safetensors, pickle checkpoints) headed for on-prem or
air-gapped inference. The open-source wizard in `web/` is the click-ops client
of the same engine the CLI uses: scan a model and read the graded result; and,
with an airlock store configured, the console, which shows what is staged, what
is approved, and what each model waits for. Success is an operator moving a
model from pull to promotion without guessing, and a reader who can tell at a
glance what is approved, on what conditions, and until when.

## Positioning

A bounded, signed, offline-verifiable record rather than a safety verdict: each
check says what it inspected, gaps are named rather than passed, an acceptance
is a signed, expiring decision by a named person, and the airlock only admits
bytes whose hash a trusted key attested. The console is a window on that
evidence; it never mints approval.

## Operating Context

- Runs on the intake host, often air-gapped: one process (`socair serve
  --store <path> --web web/build`) on loopback. No network at runtime, so no
  CDN, web fonts, or external assets; everything ships in the build.
- Signing, accepting, promoting, pulling, exporting with a key, and log
  verification are CLI steps; the console shows them as copyable commands.
  Its own actions are scanning a staged model and uploading a signed
  attestation.
- The signed inventory snapshot (static HTML plus envelopes) is what goes to
  leadership.

## Capabilities and Constraints

- Pages: `/approved`, `/pending`, `/models/<id>`, `/activity`, `/scan`; `/`
  redirects by store state.
- The console shows only state the engine returned and derives no status,
  count, or badge of its own. Labels come from `stage`, `promotion_state`,
  and `next`.
- Results: PASS, FAIL, LEAD, NOT_TESTED. NOT_TESTED and other gaps must never
  look like a pass. Only an approved model with an unconditional authorization
  is green; conditions and needs-acceptance are amber; blocked, does-not-verify
  and acceptance-expired are red.
- A rendered report is a claim; the envelope is the proof. A report is labelled
  "signed" only when its attestation verified.
- A failed scan or request offers no download and no stale data.
- Stack: SvelteKit 5 (runes), static adapter, Vitest; existing tests encode the
  display rules and must keep passing.

## Brand Commitments

- Name: Socair (SUH-ker; Irish, "at ease, settled, secure"). Voice: plain, calm,
  exact; never alarmist, never a claim of absence of risk or a certification.
- The open-source tool carries the socair.ai identity (confirmed 2026-10-04):
  the cairn mark and wordmark, slate and sea-green, Archivo and JetBrains Mono,
  square corners and hairlines. Fonts are bundled locally (OFL) because the
  tool runs offline. The site's design record is in the socair-web repo
  (`DESIGN.md`).

## Evidence on Hand

- No customers, testimonials, or production deployments to cite. Do not invent
  them.
- `internal/demo` holds a fabricated sample report rendered with a SAMPLE mark;
  it must never be presented as real.

## Product Principles

1. Show what the engine said, exactly; never a status the engine did not
   return.
2. A gap is a gap: nothing unverified, untested, or conditional reads as a
   pass.
3. The operator's next step is always explicit, and key-holding steps stay
   with the person who holds the key.
4. Calm and exact over alarming: severity through clear labels and colour
   plus text, not noise.
5. Works the same air-gapped as online.

## Accessibility & Inclusion

WCAG 2.2 AA. Stage and result are never conveyed by colour alone (always a text
label), everything is keyboard-operable, and copyable commands are selectable
text.
