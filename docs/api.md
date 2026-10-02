# The engine API

A stateless HTTP/JSON API over the engine, so the click-ops wizard is a client
of the same path the CLI calls. Nothing is stored server-side: a scan returns the
report document, and a render takes that document back and returns bytes.

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
{"version":"0.1.0-dev"}
```

### `GET /api/health`

`200` when healthy, `503` when a configured store cannot open.

```json
{"ok":true,"store":"ready","version":"0.1.0-dev"}
```

`store` is `absent` (none configured), `ready`, or `unopenable`.

### `POST /api/scan`

Request `{"path":"/models/model.gguf"}`. `local` is accepted as an alias.

`200` `{"report": { ...the attestation document... }}`.

A scan that fails is **never a 200**: `422` with `{"error":"..."}` and no report.

### `POST /api/render`

Request `{"report": { ...document... }, "format": "html" | "pdf" | "sarif"}`.
The default format is `html`.

Returns the bytes with the matching `Content-Type`. An unfilable document is
refused with `422` before anything is rendered.

### `GET /api/airlock/log`

`200` `{"events":[ ... ]}`.

### `POST /api/airlock/ingest`

Request `{"local":"/path"}` or `{"repo":"org/name","file":"name","revision":"main"}`.
`200` `{"path":"/resolved/path","event":{...}}`.

### `POST /api/airlock/pull`

Request `{"repo":"org/name","file":"name","sha256":"<64-hex>","revision":"main"}`.
`200` `{"path":"<staging path>","event":{...}}`, or `422` when egress is denied,
the source is unreachable, or the bytes do not hash to the requested hash.

### `POST /api/airlock/promote`

Request `{"artifact":"/path","report": { ...document... }}`. The document is
staged to a temp file and handed to the one gate implementation, so the wizard
can promote straight from what it scanned.

`200` `{"event":{...}}`, or `422` when the gate refuses (a withheld or escalated
state, or an artifact that does not hash to its ticket).

## Error shape

Every error is a non-2xx with `{"error":"<actionable message>"}`.

- `400`: bad input.
- `422`: understood and refused (a scan failure, an unfilable document, a
  refused promotion, a denied pull).
- `500`: an internal failure.
- `503`: health, a degraded store.

## Testing

The API tests are hermetic: `httptest`, generated fixtures, and a temp store.
No network.
