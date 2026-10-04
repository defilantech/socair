# Airlock console, Step 1: design

Status: design approved in conversation 2026-10-04; built on feat/airlock-console. The body below is updated to what shipped; "Refinements made while building" at the end records each change and why.
Step 1b (free OIDC login and network access) gets its own spec.

## Goal

An operator opens a browser on the intake host and sees, from the store's own
evidence:
- which models are approved on this site;
- in what state each one is, and why;
- what is waiting for a decision, and the exact next step.

They can share a signed, read-only snapshot of all of it with leadership and
auditors. The console replaces the question "which models do we have, and who
approved them?" with a page.

Success: a CISO who receives a snapshot can read the approved list, open any
model's report, and verify the snapshot offline with
`socair inventory verify`.

## Decisions (and why)

| Decision | Choice | Why |
|---|---|---|
| Who uses it live | The operator, on loopback, as `socair serve` does today | No logins in Step 1, so no network exposure |
| How leadership sees it | A static, signed export | It needs no server and works offline. It is a dated snapshot auditors can file, and the inventory signature makes the list tamper-evident |
| Actions in the console | View, plus scanning a staged model and uploading a signed attestation; pull, sign, accept and promote stay copyable CLI commands in Step 1 | Signing stays in the CLI: the console never holds a private key |
| Deployment | Inside `socair serve --store`, with no new binary and no database | State is derived from store files; nothing new to run or back up |
| Free and paid | Free: everything here, and Step 1b's OIDC login. Paid: SAML/SCIM, roles beyond viewer/operator, multi-approver hardware-key signing in the browser, multiple sites, HA, support | Login is not paywalled. The paid tier is organizational scale |
| Hosted auth (Clerk and similar) | Not used for the self-hosted console | It needs the internet, which an air-gapped site cannot reach, and puts a third party in the approval path. It may fit a hosted SaaS (Step 3) |

## Architecture

```
browser (wizard pages) -> internal/api (new read endpoints, existing actions)
                            -> internal/airlock: Models(), Model(id), Export()
                                -> store files: incoming/, clean/, trusted-keys/, acceptor-keys/, log.jsonl
```

- Logic lives in `internal/airlock` and `internal/api`. The wizard displays
  what the API returns and derives no status of its own (`docs/wizard.md`).
- Every status is derived from files present in the store, through the same
  verification the promotion gate uses (`attest.Verify`, `acceptance.Verify`).
  There is no status field anyone can edit.

### Staging evidence (new, optional files)

Two optional files per staged model. Neither changes what `promote` accepts.

| File | Written when | Meaning |
|---|---|---|
| `incoming/<id>/report.json` | A staged model is scanned from the console (`airlock ingest --scan` does not stage, so it writes none) | An unsigned scan result |
| `incoming/<id>/report.dsse.json` | The operator uploads a signed attestation (`socair sign` output) | Kept only if it verifies against `trusted-keys/` and its subject is this model's hash |

`<id>` is the artifact sha256 for a file, or the manifest digest for a model
directory, as the store already names them.

### Stages, derived from evidence

| Stage | Evidence | Next step shown |
|---|---|---|
| `staged` | `provenance.json` only | Scan |
| `scanned` | `report.json`, no valid `report.dsse.json` | The verdict, and the exact `socair sign` command |
| `ready` | Valid `report.dsse.json`, state `authorized` or `authorized_with_conditions` with a verifying, current acceptance | Promote |
| `needs-acceptance` | Valid `report.dsse.json`, `withheld` on NOT_TESTED rows only | The exact `socair accept` and `socair sign --acceptance` commands |
| `blocked` | Valid `report.dsse.json` with a FAIL or LEAD | The findings. There is no promote path; escalation only |
| `approved` | `clean/<id>/` with an attestation that verifies now | Listed as approved, with any conditions and their expiry |
| `does-not-verify` | `clean/<id>/` whose attestation no longer verifies (for example, its key was removed from `trusted-keys/`) | Listed in red with the reason; never shown as approved |

Acceptance expiry:
- An acceptance that expires within 30 days is flagged `expires-soon`.
- An expired acceptance makes a `clean/` entry show `acceptance-expired`. The
  bytes stay, but the console does not show the model as approved.

## API (internal/api)

New endpoints. All require `--store`; without it they answer `400`, as the
existing airlock endpoints do.

| Method and path | Kind | Returns |
|---|---|---|
| `GET /api/airlock/models` | read | `{"models":[Model...]}`, every staged and clean entry |
| `GET /api/airlock/models/{id}` | read | `{"model":Model,"report":Document,"events":[Event...]}` |
| `GET /api/airlock/models/{id}/files/{name}` | read | One evidence file, byte for byte. `name` must be one of `provenance.json`, `report.json`, `report.dsse.json`, `report.acceptance.dsse.json`, `report.conditional.dsse.json`, `attestation.json`, `attestation.dsse.json`; anything else is `404` |
| `POST /api/airlock/models/{id}/scan` | write, limited | Scans the staged artifact, writes `report.json`, returns the document |
| `POST /api/airlock/models/{id}/attestation` | write | Body: a DSSE envelope (at most 4 MiB). Verified, subject-checked, then stored as `report.dsse.json`. `422` with the reason when it does not verify |
| `POST /api/airlock/export` | read, limited (it writes nothing to the store) | A zip of an unsigned snapshot (see Export) |

`Model` fields:

| Field | Meaning |
|---|---|
| `id`, `name`, `format`, `size_bytes` | Identity |
| `stage` | One of the stages above |
| `stage_reason` | Why it is in that stage |
| `promotion_state`, `issuer`, `signer_key_id` | From the attestation |
| `accepted_surfaces`, `accepted_by`, `acceptance_expires`, `expires_soon` | The acceptance, if any |
| `promoted_at` | From the log |
| `next` | `{"action":"scan|sign|accept|promote|none","command":"<exact CLI text>"}` |

Existing endpoints are unchanged: `pull`, `ingest`, `promote` and `log`.

## Console pages (web/)

The wizard keeps its scan page. With a store configured it adds a top nav:

1. **Approved models** (home with a store). Lists the `approved`,
   `does-not-verify` and `acceptance-expired` entries:
   - name, short hash, format, state in words and colour, issuer, promoted
     date, and conditions with their expiry;
   - "authorized with conditions" is amber, never green;
   - `does-not-verify` is red.
2. **Pending.** Staging grouped by stage, each with its next step as a button
   or a copyable command. An empty Pending points at `socair airlock pull`.
3. **Model detail.** Shows:
   - the rendered report, with rows, severity, "PASS means" lines, framework
     mappings and the ceiling;
   - provenance;
   - signature status, checked live;
   - the acceptance;
   - evidence file downloads;
   - this model's log events.
4. **Activity.** The log, newest first, filterable by action, with
   **Verify chain**, shown as the copyable `socair airlock log --verify` command (not a button in Step 1).
5. **Export.** Downloads the unsigned snapshot zip and shows the
   `socair airlock export --key` command for a signed one.

Rules carried over from the wizard and enforced by tests:
- NOT_TESTED never looks like a pass.
- Labels come from the API.
- A failed request offers no stale data.

No new runtime dependencies; it is the existing SvelteKit static build.

## Export and the signed inventory

```
socair airlock export --out <dir> [--key <operator.key>] [--store <path>]
socair inventory verify <dir> --trusted <key.pub|dir>
```

Snapshot layout (it never contains model bytes or keys):

```
<dir>/
  index.html                 approved list and every other entry with its stage; snapshot time and log head; "contains this site's model inventory"
  models/<id>/report.html    existing HTML renderer
  models/<id>/attestation.dsse.json, attestation.json    byte-identical to clean/<id>/
  log.jsonl, log-head.txt    copy of the activity log and its chain head
  inventory.json             the inventory statement
  inventory.dsse.json        its DSSE envelope, only with --key
```

**Inventory statement.** An in-toto Statement v1 with predicate type
`https://socair.ai/inventory/v1`. Each subject is one approved model:
`{"name": ..., "digest": {"sha256": <id>}}`. The predicate:

```json
{
  "generated_utc": "...",
  "log_head": "<sha256 of the last log line>",
  "tool_version": "socair ...",
  "models": [{
    "id": "...", "name": "...", "promotion_state": "...", "issuer": "...",
    "signer_key_id": "...", "attestation_sha256": "<sha256 of attestation.dsse.json>",
    "accepted_surfaces": [...], "acceptance_expires": "...", "promoted_at": "..."
  }],
  "other": [{"id": "...", "name": "...", "stage": "...", "reason": "..."}]
}
```

- It is signed with Ed25519 through `internal/dsse`, like attestations,
  acceptances and feeds.
- Without `--key` the snapshot is unsigned. `index.html` then says
  **UNSIGNED SNAPSHOT**, matching the renderers' UNSIGNED mark.

`inventory verify` fails, with the reason, unless all four hold:
1. The envelope verifies against `--trusted`, and its predicate type is
   `inventory/v1`.
2. Every listed model's `attestation.dsse.json` is present and hashes to
   `attestation_sha256`.
3. Every attestation verifies against `--trusted`, and its subject equals the
   listed id.
4. `log.jsonl` verifies as a hash chain up to `log_head`.

## Extension points for Step 1b and the paid tier

- **Identity.** One middleware sets a request's actor. In Step 1 it is always
  `local-operator`. Step 1b replaces it with OIDC; the paid tier with SAML,
  SCIM and roles. No handler reads identity directly.
- **Read and write.** Every route is registered as read or write (table
  above), so roles map onto routes without touching handlers.
- **Actor in the log.** `airlock.Event` gains an optional `actor` field. It is
  `local-operator` in Step 1 and absent on older entries. The hash chain is
  over exact line bytes, so older logs stay valid.

## Errors and security

- Every failure is a named message. A store that cannot be read is an error
  page, never an empty list.
- An upload that does not verify is refused with the reason: unknown key, bad
  signature, or the subject is not this model.
- The existing guard is unchanged: loopback bind, Host and Origin checks,
  JSON-only POSTs, the concurrency limit. Uploads are size-capped and must be
  DSSE envelopes.
- File downloads take a name from a fixed list and an id that must be 64 hex
  characters. Paths are built only from validated parts; traversal is
  impossible by construction and tested.
- Exports never include model bytes or keys. The console never holds a
  private key.

## Testing

All hermetic: a temp store and fixtures generated in code.

- **Stages** (`internal/airlock`): one test per stage, built from files, each
  with a falsification. Removing the trusted key turns `approved` into
  `does-not-verify`. Expiring the acceptance gives `acceptance-expired`. A
  LEAD gives `blocked`, never `needs-acceptance`.
- **API:**
  - every new endpoint;
  - `400` without a store;
  - traversal and unknown names on file downloads;
  - an upload that does not verify, one for the wrong subject, and one that
    is oversized;
  - the guard still applies to the new routes.
- **Inventory:** sign and verify round-trip. `verify` catches:
  - a model added, dropped or swapped;
  - a changed attestation file;
  - a truncated or edited log;
  - a wrong predicate type.
- **Export:** export, then `inventory verify`, end to end. An unsigned export
  says UNSIGNED.
- **Wizard (vitest):**
  - amber for conditions, red for `does-not-verify`;
  - NOT_TESTED never shown as a pass;
  - `expires-soon` labelled;
  - a failed request shows no stale data.

## Refinements made while building

The code differs from the text above in these places. The code is the source
of truth.

- **Staging evidence uses the CLI's own output names.** `report.json`,
  `report.dsse.json`, `report.acceptance.dsse.json`, and
  `report.conditional.dsse.json`, so the CLI run against `incoming/<id>/report.json`
  produces what the console reads. Only the console's scan writes `report.json`;
  `socair airlock ingest --scan` does not, because it does not stage. A staging
  entry's stage comes from the newest evidence by modification time.
- **The inventory's `pending` field is `other`.** It also covers clean entries
  that do not verify or whose acceptance expired, each with its stage and reason.
- **Promote and verify-chain are copyable commands, not buttons.** They are
  shown in the console beside the step that needs them, as are sign, accept,
  and export with a key.
- **`inventory verify` cross-checks entries against their attestations.** Each
  entry's promotion state, signer key id, and accepted surfaces and expiry must
  match its attestation, and Verify returns the signer key id. It also checks the
  statement's subjects equal its models, and a non-empty `log_head` when models
  are listed.
- **`export` refuses a non-empty `--out`,** and a store whose log chain is broken.
- **A clean entry that fails the gate shows as `does-not-verify`,** whatever the
  reason.
- **Pulling stays a CLI step in Step 1.** There is no "Bring in a model" form;
  a model (one file or a whole repo) is staged with `socair airlock pull`, and the empty
  Pending and Approved pages say so.
- **A promoted model leaves Pending.** Promote keeps the staged copy (the gate
  path never deletes), so `Models` omits a staging entry whose id is approved in
  clean. It stays listed when the clean entry's acceptance expired or it does
  not verify, as the way to re-scan or re-accept. The console's scan and upload
  act on the staged copy directly (`Store.StagedModel`), never the clean entry,
  and are a 404 when nothing is staged under the id. A staged envelope that
  does not verify offers a rescan, whose newer `report.json` supersedes it.
- **An artifact may not take an evidence name in staging.** A single-file pull
  is staged flat beside `report.json` and the attestations, so `StagingFile`
  and `Pull` refuse a file named like evidence (`airlock.IsEvidence`).
  `PullRepo` stages the repo nested under its name, so only the repo name is
  checked; a file inside the repo cannot collide.
- **`inventory verify` checks the readable `attestation.json`.** When present
  it must strictly decode as a report and equal the verified envelope's
  document, so the plain file in a snapshot says what was signed.

## Docs to update

- `docs/api.md`: the new endpoints.
- `docs/wizard.md`: the console pages.
- `docs/airlock.md`: the staging files, export and inventory verify.
- `docs/intake-host.md`: the console as the operator's view.
- `README.md`: one line in the docs table.

## Out of scope for Step 1

- Logins (Step 1b: OIDC; paid: SAML and SCIM).
- Roles beyond `local-operator`.
- Signing in the browser.
- Multiple stores or sites.
- Network access without login.
- Notifications.
- PDF export.
- A hosted service.
