# Slice status: the airlock (M5)

Branch: `slice/airlock`, cut from `slice/tier1-complete` because the gate needs
the promotion state machine that branch introduced. Draft PR, base
`slice/tier1-complete`, so this diff is only the airlock. **#34 must land first,
or the two land together.**

## What landed

The controlled junction between untrusted egress and the on-prem clean store.

| Chunk | Files | Summary |
|---|---|---|
| A store and log | `internal/airlock/store.go`, `log.go` | Content-addressed store, atomic place, append-only JSONL activity log |
| B ingest | `internal/airlock/ingest.go` | Local path and offline HF cache resolution, clean named errors |
| C promote | `internal/airlock/promote.go` | The gate: validate, state, hash binding, store |
| D pull | `internal/airlock/pull.go`, `integration_test.go` | Controlled egress, hard timeout, hash verify, provenance manifest |
| E surface | `cmd/socair/airlock.go`, `main.go` | `airlock init|pull|ingest|promote|log` |
| F docs | `docs/airlock.md`, `README.md`, `dev.md`, `provenance-bundle.md` | The junction, its layout, and its policy |

The store is `<store>/incoming/<sha256>/` for staging and
`<store>/clean/<sha256>/` for promoted artifacts, each clean entry carrying its
`attestation.json`. The hash is the ticket, so promotion is idempotent. Staging
is a real directory outside the clean store, so "the clean store" is a line on
disk, not a metaphor.

## Verification

- `gofmt -l cmd internal`: clean.
- Air-gap build: `GOPROXY=off GOFLAGS=-mod=vendor go build ./...` succeeds; `go mod verify` all modules verified.
- Full suite: 17 packages ok. The one real-egress test skips by default.
- **Real end to end** on `Qwen3-0.6B-Q8_0.gguf`: ingest `--local --scan` fills Sections 2 and 3, all seven rows PASS, state `authorized`; `airlock promote` writes `<clean>/<sha256>/` with the artifact and the issued `attestation.json`; a second promote reports `already promoted`; the log records ingest and both promotes.
- **Real conditional end to end**, no repo mirror: the inventory row is a gap accepted by a named person, state `authorized_with_conditions`, the promote logs `outcome: conditional`, and the stored attestation still carries `accepted_surfaces: [File inventory and payloads]`.

## Falsification (each neutered, observed failing, restored, suite green)

1. Pull timeout removed (no client or context budget):
```
--- FAIL: TestPullEgressDeniedFailsWithinTimeout (10.01s)
    pull_test.go:80: a blocked pull must fail within its budget, took 10.003365875s
```
2. Denial message stripped of the host and the remedy:
```
--- FAIL: TestEgressDeniedIsActionable (0.00s)
    pull_test.go:43: denied egress should be actionable, "denied by policy" missing from "airlock pull org/name: egress huggingface.co denied"
```
3. Download hash comparison removed:
```
--- FAIL: TestPullHashMismatchRefuses (0.00s)
    pull_test.go:156: bytes that do not hash to the requested hash must refuse
```
4. Success path stops logging the pull:
```
--- FAIL: TestPullVerifiesLogsAndRecordsProvenance (0.00s)
    pull_test.go:132: every pull must be logged, got []
```
5. Missing local path swallowed:
```
--- FAIL: TestIngestLocalMissingPathErrors (0.00s)
    ingest_test.go:46: a missing local path must be an error, not an empty report
```
6. Cache miss returns a nil path:
```
--- FAIL: TestResolveCacheMissErrorsNamingRepoAndFile (0.00s)
    ingest_test.go:103: a cache miss must be an error, never a nil path
```
7. Promotion state gate dropped so `withheld` would cross:
```
--- FAIL: TestPromoteRefusesWithheld (0.00s)
    promote_test.go:125: a withheld attestation must refuse, got <nil>
```
8. Artifact/report hash binding removed:
```
--- FAIL: TestPromoteRefusesHashMismatch (0.00s)
    promote_test.go:149: an artifact that does not hash to its ticket must refuse, got <nil>
```
9. Store copy neutered:
```
--- FAIL: TestPromoteStoresArtifactAndAttestation (0.00s)
    promote_test.go:97: the stored bytes are not the artifact that crossed
--- FAIL: TestPlaceCopiesBytesAndIsIdempotent (0.00s)
```
10. Conditional outcome flattened to clean:
```
--- FAIL: TestPromoteConditionsTravelWithArtifact (0.00s)
    promote_test.go:175: a conditional crossing must be logged as conditional, got "ok"
```
11. Idempotency guard removed:
```
--- FAIL: TestPromoteIsIdempotent (0.01s)
    promote_test.go:209: re-promotion of an identical identity must be a store no-op, detail = "clean attestation"
```

## Decision locked

`authorized_with_conditions` crosses into the clean store; its accepted surfaces
travel with the stored attestation and the crossing logs as `conditional`. Only
`withheld` and `escalated` refuse. Because conditional artifacts cross, "in the
clean store" does not mean "clean", so `Store` carries that invariant as a
comment for the later wizard and webhook.

## Honest state

- **The pull is the only networked code in the repo.** Every airlock test is
  hermetic; the real-egress test is gated by `SOCAIR_TEST_EGRESS=1` and skipped by
  default. CI stays offline.
- **The pull verifies the artifact hash, not a publisher signature.** The
  provenance manifest records origin facts and never asserts a signing status.
- **The clean store is a directory of bytes and attestations.** It is not yet an
  admission gate for a serving stack; that is the v2 webhook.
- **The HF cache layout is pinned** to `models--<org>--<name>/snapshots/<rev>/<file>`.
  A different hub version may need a resolver tweak; a miss is a clean error.
- **Promotion at Tier 1 keys on a validating attestation, not a signature.** The
  Defilan signature is the paid tier.

## Not in this slice

The wizard (#16), Tier 2 (M8), the reveal (M7). The engine HTTP/JSON API the
wizard needs is still unissued.

## Decisions for you

1. **Branch stacking:** `slice/airlock` is based on `slice/tier1-complete`. Land
   #34 first, then retarget this PR to `main`, or land both together.
2. **Exercise real egress:** the gated test is written; do you want a real
   `SOCAIR_TEST_EGRESS=1` run against the hub recorded before merge?
