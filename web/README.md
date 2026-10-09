# Socair wizard and airlock console

The click-through wizard and the airlock console: a SvelteKit 5 single-page
app, built to static files that `socair serve` hands to the browser. It is a
client of the engine's local HTTP API and shows only state the engine
returned. What it shows, and the rules it may not break, are in
[docs/wizard.md](../docs/wizard.md).

The release binaries do not include it. Build it from a checkout:

```
cd web
npm ci
npm run check    # svelte-check
npm run test     # vitest, hermetic
npm run build    # static output in web/build
```

Serve the build with the engine, from the repository root:

```
socair serve --web web/build                         # the wizard
socair serve --web web/build --store <airlock store> # the wizard and the airlock console
```

For development, `npm run dev` serves the app on `:5173` and proxies `/api`
to a `socair serve` on `127.0.0.1:8080` (or `SOCAIR_API`).

`src/lib/schema.spec.ts` imports `docs/report-schema/v1.json`,
`testdata/report.json`, and `internal/demo/report.json` from outside `web/`,
so the tests run only from within this repository. They hold the TypeScript
report types to the same schema the engine produces.

The visual design record is [DESIGN.md](DESIGN.md).
