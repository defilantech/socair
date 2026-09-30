# The click-ops wizard

A stateless SvelteKit single-page app in `web/`: ingest, pick level, run, view
the graded result, download the report. The exec-facing surface for a security
buyer who clicks, not curls.

The wizard is a client of the engine API (`docs/api.md`). It shows only state the
engine returned and derives nothing of its own: no status, no count, no badge.

## Building and running

```
cd web
npm ci
npm run dev          # dev against a local socair serve on :8080
npm run build        # static output in web/build
```

Then one process serves both the API and the wizard:

```
socair serve --web web/build
```

The Go server hands the static files to the browser and keeps `/api` as JSON.

## The engine contract

- `POST /api/scan` returns the report document. The wizard renders that document.
- `POST /api/render` takes the document back and returns the HTML or PDF bytes.
- `GET /api/health` tells the wizard whether the engine is usable.

The API is stateless, so the wizard holds the scanned document and hands it back
for a download. The engine keeps no session.

## What the wizard may not do

- Render a `NOT_TESTED` check as a pass. `statusPill` maps it to the neutral
  treatment, and a test holds the line.
- Show a promotion state the document does not carry. `promotionLabel` and
  `promotionPill` read `promotion_authorization.state`.
- Offer a level the engine cannot run. Only Tier 1 is selectable; Tier 2 is the
  paid forward-pass tier and appears disabled because it has no checks yet.
- Present a failed scan as anything but failed. `runScan` resolves to a `failed`
  state with the engine's own message, and `canDownload` is false, so no download
  is offered.

## Tests

Vitest, hermetic: the API client is tested against a stubbed `fetch`, and the
display helpers and run state are pure and tested directly.

```
cd web && npm run test
```

The engine going away mid-run is `run.spec.ts`: a scan that throws resolves to a
`failed` state and offers no download, never a false success.

## Styling

Sober and calm, matching the brand (`docs/brand.md`): the name means at ease and
secure, so the surface is not alarmist. Colour is a signal, not decoration:
PASS, FAIL, and NOT_TESTED each get a distinct, accessible treatment.
