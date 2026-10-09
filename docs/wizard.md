# The click-ops wizard

A stateless SvelteKit single-page app in `web/`: ingest, pick level, run, view
the graded result, download the report. The exec-facing surface for a security
buyer who clicks, not curls.

The wizard is a client of the engine API (`docs/api.md`). It shows only state the
engine returned and derives no status or badge of its own. The counts it shows
are tallied in the browser from the check rows the engine returned
(`web/src/lib/report.ts`).

## Console

With a store configured (`socair serve --store <path> --web web/build`), the
same app is the airlock console: the operator's view of what is staged, what is
approved, and what each model waits for. Pages:

- `/approved`: models in the clean store, with their attestation state. A
  clean entry whose acceptance expired or that does not verify is listed here
  too, in red.
- `/pending`: staged models, grouped by stage, each with the step it waits for.
  A promoted model leaves it once approved. Pulling stays a CLI step
  (`socair airlock pull`); the empty pages say so.
- `/models/<id>`: one model's report, evidence files, conditions, and log
  entries.
- `/activity`: the activity log.
- `/scan`: the original wizard, ingest through download.

`/` goes to `/approved` when `GET /api/health` reports the store `ready`, and to
`/scan` otherwise.

Display rules. Every label comes from what the engine returned (`stage`,
`promotion_state`, `next`); the console computes none of them.

- Only an approved model with an unconditional authorization is green.
- Authorized with conditions, and needs-acceptance, are amber.
- Blocked, does-not-verify, and acceptance-expired are red.
- NOT_TESTED is never shown as a pass, and neither is a Tier 2 measurement.
- A report is labelled "signed" only when its attestation verified.

Every step that needs a key is a copyable CLI command, not a button: promote,
sign, accept, export with a key, and verifying the log chain. The console never
holds a private key. Scanning a staged model and uploading a signed attestation
are the console's own actions.

## Building and running

The release binaries do not include the wizard: build it from a checkout.

```
cd web
npm ci
npm run dev          # wizard on :5173, /api proxied to socair serve on :8080
npm run build        # static output in web/build
```

In dev mode, run `socair serve` alongside it; Vite proxies `/api` to
`http://127.0.0.1:8080`, or to `SOCAIR_API` if set. The engine refuses a request
whose Origin is not its own, so the proxy rewrites the Origin only when it is
the dev server's own; a request from any other site keeps its Origin and the
engine still refuses it.

For the shipped build, one process serves both the API and the wizard:

```
socair serve --web web/build
```

The Go server hands the static files to the browser and keeps `/api` as JSON:
an unknown `/api/` route is a JSON `404`, never the wizard's page.

To see the console with a model in every state, `scripts/demo-console.sh`
builds both from the checkout, pulls four small public models from Hugging
Face (about 1.6 GB), and takes each to a different stage: approved, approved
with a signed acceptance, blocked on remote code, and staged for a scan. It
makes its own demo keys and store under `~/socair-demo` and prints the `serve`
command.

## The engine contract

- `POST /api/scan` returns the report document. The wizard renders that document.
- `POST /api/render` takes the document back and returns the HTML or PDF bytes.
- `GET /api/health` tells the wizard whether the engine is usable.

Scan and render are stateless, so the wizard holds the scanned document and
hands it back for a download. The engine keeps no session.

## What the wizard may not do

- Render a `NOT_TESTED` check as a pass. `statusPill` maps it to the neutral
  treatment, and a test holds the line.
- Render a `LEAD` as a pass or as a gap. It has its own amber treatment, because
  it needs a person's review outside Socair and no acceptance clears it.
- Show a promotion state the document does not carry. `promotionLabel` and
  `promotionPill` read `promotion_authorization.state`.
- Offer a level the engine cannot run. Only Tier 1 is selectable; Tier 2
  (forward-pass testing) appears disabled. It is configured on the engine
  (`SOCAIR_TIER2_HELPER`, `docs/tier2.md`), not chosen per scan, and has no
  checks of its own yet.
- Render a Tier 2 measurement as a pass. A report's Tier 2 section is shown
  only when the document carries one, as measurements: `measurementPill` maps
  an outcome of `measured` (found nothing) to its own plain treatment, marked
  "not a pass", `error` to the neutral gap treatment, and `lead` and `fail` to
  theirs. A LEAD or FAIL measurement also has its own check row, and only the
  rows are tallied or decide the promotion label.
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
PASS, FAIL, LEAD, and NOT_TESTED each get a distinct, accessible treatment.
