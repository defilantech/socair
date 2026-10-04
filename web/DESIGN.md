# Design record: Socair console

The wizard and airlock console in `web/` carry the socair.ai identity. This
record extends the site's design record, `DESIGN.md` in the socair-web repo
("The Settled Cairn"); everything there holds unless a console extension
below says otherwise. The product rules come first: the console shows only
state the engine returned, a gap never looks like a pass, and every tone
carries a text label (PRODUCT.md).

## World (inherited)

- Slate ground `#0F2333` (`color-scheme: dark`, `theme-color`).
- Mist ladder by role: mist-bright `#F4F7F8` headings, mist `#E7EEF1`
  default, mist-soft `#C9D6DC` prose, mist-faint `#9FB2BD` frame and meta.
- Hairline rules `#22394B`; square corners (radius 0); no shadows, glows, or
  gradients. Sections are ruled bands, not cards.
- Sea `#4CD3AE` is the one accent: focus ring (2px outline, 3px offset),
  selection (sea background, slate text), the current nav item, and the
  pass/approved status tone. Never a button fill or a background.
- The cairn mark and wordmark (`src/lib/Cairn.svelte`) use the canonical
  paths copied verbatim from socair-web. Never redraw them.
- Archivo (400/600/800) and JetBrains Mono (400) are bundled with
  `@fontsource` and compiled into the static build. Nothing is fetched at
  runtime: the console runs air-gapped.

## Console extensions

1. **Buttons and form controls exist.** The teaser has none; an Operate
   surface needs them. Primary: mist-bright fill, slate text. Secondary:
   transparent with a 1px border, mist text. Both square, at least 44px tall,
   with hover, active, disabled (dashed edge, faint text), and focus states.
   The file input is a visually hidden input inside a label styled as a
   secondary button, named "Upload signed attestation (report.dsse.json or
   report.conditional.dsse.json)". Control boundaries (secondary buttons,
   inputs, selects) use the edge colour `#64808F` (3.84:1 on slate, 3.62:1 on
   the raised surface) rather than the hairline, which at 1.34:1 does not meet
   WCAG 1.4.11 for a control's boundary.
2. **Status tones besides sea.** Amber and red, tuned for AA on slate, and a
   neutral that can never be mistaken for a pass. Tones apply to statuses only
   (chips and error titles), never to surfaces.
3. **Mono means machine-stated.** JetBrains Mono is for text the engine states:
   statuses, hashes and ids, commands, and log timestamps. Everything a person
   reads is Archivo, sentence case, with no uppercase-tracked labels, eyebrows,
   or kickers.
4. **One raised surface.** `#12283A` is allowed for command blocks, inline
   code, and form inputs only.

## Status tones

Each chip is mono 12px with a 1px border in its tone, no fill, and always a
text label. Contrast is for the tone as text, measured on slate and on the
raised surface.

| Tone | Colour | On slate `#0F2333` | On raised `#12283A` | Used for |
|---|---|---|---|---|
| Pass | sea `#4CD3AE` | 8.59:1 | 8.08:1 | PASS; a model approved with an unconditional authorization |
| Amber | `#E9B65A` | 8.64:1 | 8.13:1 | LEAD; authorized with conditions; needs acceptance; a conditional promotion in the log |
| Red | `#F2877A` | 6.51:1 | 6.13:1 | FAIL; withheld; escalated; blocked; does not verify; acceptance expired; a refusal in the log; error titles |
| Neutral | mist-faint `#9FB2BD`, dashed border | 7.32:1 | 6.89:1 | NOT_TESTED; staged and scanned; other log outcomes; engine state |

Other text: mist-bright 14.91:1, mist 13.68:1, mist-soft 10.80:1 on slate
(14.03, 12.87, 10.17 on raised). Primary button text (slate on mist-bright)
is 14.91:1.

Mapping lives in code, keyed by engine fields only: `stageTone` and
`eventTone` in `src/lib/console.ts` (from `stage`, `promotion_state`,
`outcome`), and `statusPill` / `promotionPill` in `src/lib/report.ts` (from a
check's `status` and the document's `promotion_authorization.state`).
`authorized_with_conditions` maps to the amber `conditions` pill, never the
neutral gap look. A withheld document stays red.

## Type scale (fixed rem, Operate)

| Role | Size / weight | Notes |
|---|---|---|
| h1 | 28px / 800, -0.01em | mist-bright; one per page |
| h2 | 20px / 800 | section heading |
| h3 | 16px / 600 | row or sub-section title |
| Body | 15px / 400, line height 1.6 | mist; prose in mist-soft, max 65ch |
| Small | 13px / 400 | meta, hints, table headers, footer |
| Status chip | 12px JetBrains Mono 400 | sentence case as the engine states it |

Tables use tabular numerals. Below 40rem every table stacks into labelled
rows, so no page scrolls sideways at 390px.

## Layout

A shared header (`src/routes/+layout.svelte`): the cairn mark and wordmark,
the nav (Approved, Pending, Activity, Scan; `aria-current="page"`, and on a
model page the list the engine puts that model in), and the engine chip on
the right, over a hairline. Content sits in `<main>` in a 1080px column with
16px gutters (24px from 40rem), aligned with the header's left edge. Each page
has one `<h1>` and its own `<title>`. The footer disclaimer is in the layout.

## Command component

`src/lib/Command.svelte` shows a CLI command exactly as the engine returned
it (or as the page states it), never rewritten:

- a one-line purpose above it ("Signs the report with your operator key",
  "Promotes it into the clean store", "Verifies the log's hash chain"),
  chosen from `next.action` by `nextPurpose` or passed in;
- a single-line `<pre>` on the raised surface that scrolls horizontally and
  never wraps, so a path cannot be broken when copied; it is focusable so the
  keyboard can scroll it;
- a secondary Copy button using `navigator.clipboard`, falling back to
  selecting the text and `document.execCommand('copy')` outside a secure
  context, announcing "Copied" through a polite live region.

## Motion

Colour transitions of 150ms on controls only, removed under
`prefers-reduced-motion: reduce`. No page-load choreography.
