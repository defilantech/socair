# The engine API

An HTTP/JSON API over the engine, so the click-ops wizard is a client of the
same path the CLI calls. Scan and render are stateless: a scan returns the
report document, a render takes that document back and returns bytes, and
neither stores anything. The airlock and console routes act on the store named
by `--store`: ingest, pull, and promote record what they did in its activity
log, and the console's scan and attestation upload write evidence files into
the staging entry.

The API is a thin client of `internal/engine`. It invents no report shape.

## Running it

```
socair serve [--addr 127.0.0.1:8080] [--web <dir>] [--store <path>]
```

- `--web` serves a SvelteKit static build at `/`, with the `200.html` SPA
  fallback, so the box runs one process.
- `--store` enables the airlock endpoints and the store half of the health
  check. Without it those endpoints answer a clean 400.
- `--addr` defaults to `127.0.0.1:8080`.

## Authentication

There is none. The API is for the airlock box and binds loopback by default. It
**refuses to bind a non-loopback address** unless `SOCAIR_API_ALLOW_PUBLIC=1` is
set. Do not set that without putting authentication in front of it.

Loopback is not a boundary against the operator's own browser, so every request
is also checked against the pages they might visit:

- **Host.** Only a loopback `Host` (`127.0.0.1`, `localhost`, `[::1]`) is
  served, which defeats DNS rebinding. A deliberate public bind turns this
  check off.
- **Origin.** A request whose `Origin` is not this server, or whose
  `Sec-Fetch-Site` is `cross-site`, gets `403`.
- **Content type.** A `POST` must be `application/json`, else `415`. A
  cross-origin page cannot send that without a CORS preflight, which this API
  never answers.
- **Load.** At most two scans, pulls, ingests, or promotions run at once;
  past that the API answers `503` rather than queueing without bound.

## Endpoints

### `GET /api/version`

```json
{"version":"dev"}
```

`dev` in a source build; a release build reports its version without the
leading `v`, such as `0.1.0-rc.2`.

### `GET /api/health`

`200` when healthy, `503` when a configured store cannot open.

```json
{"ok":true,"store":"ready","version":"dev"}
```

`store` is `absent` (none configured), `ready`, or `unopenable`.

### `POST /api/scan`

Request `{"path":"/models/model.gguf"}`. `local` is accepted as an alias.

`200` `{"report": { ...the attestation document... }}`.

A scan that fails is **never a 200**: `422` with `{"error":"..."}` and no report.
A scan whose report does not validate is an engine fault: `500`, also with no
report.

### `POST /api/render`

Request `{"report": { ...document... }, "format": "html" | "pdf" | "sarif" | "cyclonedx"}`.
`cyclonedx` returns a CycloneDX 1.6 ML-BOM derived from the document
(`application/vnd.cyclonedx+json; version=1.6`); a header-only report, which
names no exact bytes, is a 422.
The default format is `html`.

Returns the bytes with the matching `Content-Type`. An unfilable document is
refused with `422` before anything is rendered.

Render does not verify a signature. It renders the document it is given,
signer and issuer fields included, as given. A rendered report is a claim; the
DSSE envelope, checked with `socair verify`, is the proof.

### `GET /api/airlock/log`

`200` `{"events":[ ... ]}`.

### `POST /api/airlock/ingest`

Request `{"local":"/path"}` or `{"repo":"org/name","file":"name","revision":"main"}`.
`200` `{"path":"/resolved/path","event":{...}}`. The path is resolved and
logged; nothing is copied into staging.

### `POST /api/airlock/pull`

Request `{"repo":"org/name","file":"name","sha256":"<64-hex>","revision":"main"}`.
A single file only: a whole-repository pull is a CLI step. The API never
sends `HF_TOKEN`, since it has no auth, so it cannot pull a gated or private
repo.
`200` `{"path":"<staging path>","event":{...}}`, or `422` when egress is denied,
the source is unreachable, or the bytes do not hash to the requested hash.
`400` for a `file` that is not a plain name or is a staging evidence name
(`report.json`, `provenance.json`, and the rest listed under the files route).

### `POST /api/airlock/promote`

Request `{"artifact":"/path","attestation": { ...DSSE envelope... }}`. The
envelope is a signed attestation (`socair sign`), passed through byte for byte
and handed to the one gate implementation. A bare report document is refused
with `400`: a document is not a ticket until a trusted key signs it.

`200` `{"event":{...}}`, or `422` when the gate refuses: no trusted key in the
store, a signature that does not verify against it, a state that does not
authorize promotion, or an artifact that does not hash to the attested
digest.

## Console endpoints

These serve the console (`docs/wizard.md`). Each needs `--store`; without it
they answer `400`. `{id}` is the 64-hex id of a store entry: the artifact's
sha256, or a model directory's manifest digest. An entry is `staging`
(`incoming/`) or `clean`.

### `GET /api/airlock/models`

`200` `{"models":[ ... ]}`, clean entries first, then staging, each sorted by
id. It reads evidence files only, never artifact bytes. A staging entry whose
id is approved in clean is omitted (promote leaves the staged copy); it is kept
when the clean entry's acceptance expired or it does not verify. Each model:

```json
{"id":"<64-hex>","name":"...","format":"gguf","size_bytes":123,
 "location":"staging|clean",
 "stage":"staged|scanned|ready|needs-acceptance|blocked|approved|acceptance-expired|does-not-verify",
 "stage_reason":"...","promotion_state":"...","issuer":"...","signer_key_id":"...",
 "accepted_surfaces":["..."],"accepted_by":"...","acceptance_expires":"...",
 "expires_soon":true,"promoted_at":"...",
 "next":{"action":"scan|sign|accept|promote|none","command":"socair ..."}}
```

Only `id`, `name`, `location`, `stage`, and `next` are always present. The
stage is derived from the evidence through `Store.Assess`, the same
verification `promote` uses. `expires_soon` is set when an acceptance expires
within 30 days. `next.command` is the exact CLI command when the step needs a
key.

### `GET /api/airlock/models/{id}`

`200` `{"model": {...}, "report": {...}|null, "events": [ ... ], "evidence": [ ... ]}`.
`report` is the verified attestation's document when there is one, else the
unsigned scan report, else `null`. `events` are the log entries for this id.
`evidence` names the evidence files this entry holds, sorted (always an array,
possibly empty); each one is served by the `files/{name}` route below. `404`
for an unknown id.

### `GET /api/airlock/models/{id}/files/{name}`

One evidence file, byte for byte, as an attachment. `name` must be one of
`provenance.json`, `report.json`, `report.dsse.json`,
`report.acceptance.dsse.json`, `report.conditional.dsse.json`,
`attestation.json`, `attestation.dsse.json`. Anything else, or a file the
entry does not have, is `404`. Artifact bytes are never served.

### `POST /api/airlock/models/{id}/scan`

No request fields are read (send `{}`). Scans a staged model, with the
provenance manifest beside it if there is one, and saves the result as
`incoming/<id>/report.json`. `200` `{"report": {...}, "model": {...}}`, where
`model` is the staging entry. It acts on the staged copy even when the id is
also in clean. `404` when nothing is staged under the id; `422` when the scan fails or the entry has
no single artifact. It counts against the two-at-a-time load limit.

### `POST /api/airlock/models/{id}/attestation`

The body is the raw DSSE envelope (`application/json`), at most 4 MiB. It is
kept only if it verifies against `trusted-keys/` and its subject is this
model's id. `200` `{"file":"<evidence file name>","model": {...}}`. A conditional
attestation is filed as `report.conditional.dsse.json`, any other as
`report.dsse.json`; `model` is the staging entry, even when the id is also in
clean. `413` over 4 MiB, `400` for a body that is not JSON, `404`
for an id with nothing staged, `422` when the envelope is refused.

### `POST /api/airlock/export`

No request fields are read (send `{}`). Returns a zip of the store's inventory
snapshot (`docs/airlock.md`), built in memory and **unsigned**: signing needs a
private key, and the API never holds one. Sign an export with
`socair airlock export --key`. `422` when the store cannot be exported (for
example a broken log chain), `500` on an internal failure.

## Access and actor

Every route is registered as read or write access (`internal/api/routes.go`).
The scan, render, version, health, log, and export routes and every console
`GET` are read; ingest, pull, promote, and the console's scan and attestation
upload are write. Today the local operator may do both. The classification is
where a login or roles would decide per route.

The actor of every request is `local-operator`, and it is recorded on the log
entries a request causes.

## Error shape

Every error is a non-2xx with `{"error":"<actionable message>"}`. Under
`/api/` that holds with or without `--web`: the wizard's SPA fallback never
answers there.

- `400`: bad input.
- `403`: a non-loopback `Host`, or a cross-origin or cross-site request.
- `404`: a store entry or evidence file that does not exist, or an `/api/` path
  no route handles.
- `405`: a route's path with a method it does not take (including `OPTIONS`);
  `Allow` lists the methods it does take.
- `413`: an uploaded attestation over 4 MiB.
- `415`: a `POST` body that is not `application/json`.
- `422`: understood and refused (a scan failure, an unfilable document, a
  refused promotion, a denied pull, a refused attestation upload).
- `500`: an internal failure.
- `503`: health, a degraded store; or the engine is busy (the load limit).

## Testing

The API tests are hermetic: `httptest`, generated fixtures, and a temp store.
No network.
