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
socair serve [--addr 127.0.0.1:8080] [--web <dir>] [--store <path>] [--scan-root <dir>]...
```

- `--web` serves a SvelteKit static build at `/`, with the `200.html` SPA
  fallback, so the box runs one process.
- `--store` enables the airlock endpoints and the store half of the health
  check. Without it those endpoints answer a clean 400. The store's
  `incoming/` is also a scan root. With a store, every scan the API runs
  (`POST /api/scan` and the console's scan) refuses a feed issued before the
  newest one the store has used, and records a newer one
  ([feed.md](feed.md), "Rollback protection").
- `--scan-root` names a directory under which the scan, ingest, and promote
  routes may read a path the request names. It repeats. Without it,
  `SOCAIR_SCAN_ROOTS` is read: a list in the form of `PATH` (`:` between
  directories, `;` on Windows). Each root must be an existing directory, or
  the server does not start. With no root at all, those routes refuse every
  path. See [Scan roots](#scan-roots).
- `--addr` defaults to `127.0.0.1:8080`.

The server prints the scan roots in effect when it starts.

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

## Scan roots

`POST /api/scan`, ingest's `local`, and promote's `artifact` take a
filesystem path from the request body. With no authentication, anyone who
reaches the API could otherwise have it read any file the process can read,
and get back a hash, a report, and an error that says whether the path
exists. These routes read a path only when it lies under a scan root: a
`--scan-root` directory, or the store's `incoming/` with `--store`
(`internal/api/roots.go`).

A path is read only when all of these hold:

- It is absolute. Nothing is resolved against the server's working
  directory.
- As written, once `.` and `..` are cleaned away, it is under a root, either
  as the root was configured or with the root's own symlinks resolved.
- With every symlink in it resolved (`filepath.EvalSymlinks`), it is under a
  root's resolved path. A link inside a root that leads out is refused, and
  so is a link outside the roots that leads in.

"Under" means that `filepath.Rel` from the root leaves a remainder that
[`filepath.IsLocal`](https://pkg.go.dev/path/filepath#IsLocal) accepts: not
absolute, not empty, and no `..` that climbs out. A path equal to a root is
under it, so a root that is one model directory can be scanned whole. A path
that is not under a root as written is refused before any filesystem call on
it. The engine is handed the path as written, cleaned, rather than its
resolved form: the scan snapshot keeps the file's own name, which the quant
row reads, and the engine reads files beside the artifact where the caller put
them.

Every refusal of a path is a `422` with the same message, which quotes the
path as it was sent and reads the same whether the path is outside the roots,
does not exist, or is a symlink that leads out:

```json
{"error":"\"/etc/shadow\" is not an existing path under a scan root; the API reads only under the directories socair serve was started with (--scan-root, and the store's incoming/ with --store)"}
```

A relative path is refused with a message that says it is not absolute, and
with no root configured every path is refused with a message that names
`--scan-root`. Neither depends on anything on disk.

**Defaults.** With no `--scan-root`, no `SOCAIR_SCAN_ROOTS`, and no `--store`,
the API reads no path a request names, and the wizard's scan page shows the
refusal. With `--store`, a model pulled into staging can be scanned and
promoted by path with nothing else set. To scan from a model share, name it:

```
socair serve --store "$SOCAIR_STORE" --web web/build --scan-root /srv/models
```

Ingest's `repo` form resolves an entry in the Hugging Face cache
(`SOCAIR_HF_CACHE` or `HF_HOME`) by checked names, and only checks that it
exists. Scanning the path it returns needs the cache as a scan root.

**What the check does not close.** The check and the read are two steps:
the API checks the path, then the engine, or the promotion gate, opens it by
name (`internal/engine/snapshot.go`, `internal/airlock/promote.go`). Someone
who can create or rename entries inside a scan root while a request is in
flight can replace a checked file or directory with a symlink after the check,
and the open follows it out of the roots. The caller then gets what any scan
or promotion returns for a file: its hash, and for a model file what the
report records about it, such as a GGUF's metadata and chat template. Keep
scan roots writable only by the operator: the chart mounts
a model share read-only, and only Socair writes `incoming/`. Closing the
window needs the engine to open the artifact through an
[`os.Root`](https://pkg.go.dev/os#Root) on the scan root, which it does not do
today. Once the engine has taken its snapshot, every check reads the snapshot,
so a swap after that point changes nothing. A scan root is a directory tree as
its paths see it: a mount point inside it, such as a bind mount of another
directory, is inside it too.

**Static files.** With `--web`, the build is read through an `os.Root` on its
directory, so neither a `..` in the request, encoded or not, nor a symlink in
the build that points out of it opens a file outside it. A plain `..` is
redirected to the cleaned path by Go's request router, an encoded one gets
`400` from Go's file server, and a link that leads out gets the SPA shell. [`os.DirFS`](https://pkg.go.dev/os#DirFS) would not be enough: its
documentation says it does not stop a symlink that points outside the tree.

## Endpoints

### `GET /api/version`

```json
{"version":"dev"}
```

`dev` in a source build; a release build reports its version without the
leading `v`, such as `0.1.0-rc.3`.

### `GET /api/health`

`200` when healthy, `503` when a configured store cannot open.

```json
{"ok":true,"store":"ready","version":"dev"}
```

`store` is `absent` (none configured), `ready`, or `unopenable`.

`socair health [--addr <host:port>]` asks a running API this question and exits
0 only for a `200`. It is the container image's probe: the image has no shell,
and the API binds the pod's loopback, which a kubelet's HTTP probe cannot reach.

### `GET /api/feed`

What a scan started now would make of the configured feed (`SOCAIR_FEED`). It
writes nothing, and it is always `200`: the feed's state is the answer, not a
failure of the request.

```json
{"configured":true,
 "feed":{"issuer":"Example Intel","version":"2026.10.1","issued":"2026-10-01T00:00:00Z",
         "expires":"2026-12-30T00:00:00Z","key_id":"…","statement_sha256":"…"},
 "expires_soon":true,
 "notice":"feed Example Intel 2026.10.1 expires at 2026-12-30T00:00:00Z, in 12 days: after that, every scan and recheck that uses it stops. Import a newer feed before then",
 "store_record":{"issuer":"Example Intel","version":"2026.10.1","…":"…"}}
```

- `configured` is false, and nothing else is set, when no feed is configured.
- `expires_soon` and `notice` are set in the last third of the feed's validity
  ([feed.md](feed.md), "Before a feed expires").
- `store_record` is the newest feed the configured store has used.
- `error` says why a scan would stop: the feed does not verify or has expired,
  or the store would refuse it as older than its record. `feed` is absent when
  the feed does not verify.

The console shows `error` or `notice` as a line under its header, word for
word.

### `POST /api/scan`

Request `{"path":"/models/model.gguf"}`. `local` is accepted as an alias. The
path must be under a scan root; anything else is a `422` and nothing is read
([Scan roots](#scan-roots)).

`200` `{"report": { ...the attestation document... }}`.

A scan that fails is **never a 200**: `422` with `{"error":"..."}` and no report.
A scan whose report does not validate is an engine fault: `500`, also with no
report.

### `POST /api/render`

Request `{"report": { ...document... }, "format": "html" | "pdf" | "sarif" | "cyclonedx"}`.
`cyclonedx` returns a CycloneDX 1.6 ML-BOM derived from the document
(`application/vnd.cyclonedx+json; version=1.6`, described in
[cyclonedx.md](cyclonedx.md)); a header-only report, which names no exact
bytes, is a 422. The API does not sign a BOM; `socair sign --bom` does.
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
logged; nothing is copied into staging. A `local` path must be under a scan
root, or the answer is `422` and nothing is checked on disk.

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

`artifact` must be under a scan root, which with `--store` includes
`incoming/`; anything else is refused with `422` before the gate runs.

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
id is approved in clean, or was approved and then flagged by a recheck, is
omitted (promote leaves the staged copy); it is kept when the clean entry's
acceptance expired or it does not verify. Each model:

```json
{"id":"<64-hex>","name":"...","format":"gguf","size_bytes":123,
 "location":"staging|clean",
 "stage":"staged|scanned|ready|needs-acceptance|blocked|approved|acceptance-expired|does-not-verify|flagged",
 "stage_reason":"...","promotion_state":"...","issuer":"...","signer_key_id":"...",
 "accepted_surfaces":["..."],"accepted_by":"...","acceptance_expires":"...",
 "expires_soon":true,"promoted_at":"...",
 "rechecked_at":"...","recheck_outcome":"flagged|unchanged|incomplete","recheck_reason":"...",
 "next":{"action":"scan|sign|accept|promote|none","command":"socair ..."}}
```

Only `id`, `name`, `location`, `stage`, and `next` are always present. The
stage is derived from the evidence through `Store.Assess`, the same
verification `promote` uses, and for a clean entry from its `recheck.json`
(`docs/airlock.md`, "Rechecking the clean store"): `flagged` is a clean entry
a recheck found would now be withheld, still in the clean store, with the
recheck's reason in `stage_reason`. `rechecked_at`, `recheck_outcome`, and
`recheck_reason` are the clean entry's last recheck, when it has one.
`expires_soon` is set when an acceptance expires within 30 days.
`next.command` is the exact CLI command when the step needs a key.

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
`attestation.json`, `attestation.dsse.json`, `recheck.json`. Anything else, or a file the
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
The scan, render, version, health, feed, log, and export routes and every
console `GET` are read; ingest, pull, promote, and the console's scan and attestation
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
- `422`: understood and refused (a path that is not under a scan root, a
  scan failure, an unfilable document, a refused promotion, a denied pull, a
  refused attestation upload).
- `500`: an internal failure.
- `503`: health, a degraded store; or the engine is busy (the load limit).

## Testing

The API tests are hermetic: `httptest`, generated fixtures, and a temp store.
No network.
