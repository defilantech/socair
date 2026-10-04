# Airlock Console Step 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** an operator's live console inside `socair serve --store`, plus a signed, offline-verifiable inventory export. The console shows approved models, pending models with their next step, model detail, and activity.

**Architecture:**
- A new `Store.Assess` holds the promotion gate's verification. `Promote` and the console's stage derivation both use it, so they cannot disagree.
- `Store.Models` derives each model's stage from the files present in the store, with no state of its own.
- `internal/api` exposes read and write routes behind one identity hook.
- A new `internal/inventory` package builds, signs, exports and verifies an in-toto `inventory/v1` statement.
- The SvelteKit wizard gains console pages that show only what the API returns.

**Tech Stack:**
- Go 1.27, stdlib only; deps vendored, `GOFLAGS=-mod=vendor`.
- Existing `internal/attest`, `internal/dsse`, `internal/render`.
- SvelteKit 5 (runes, static adapter) with Vitest.

**Spec:** `docs/superpowers/specs/2026-10-04-airlock-console-design.md`

## Global Constraints

**Store and state**
- Every status shown is derived from files present in the store, through the gate's own verification. No state lives anywhere else: no database, no new binary.
- An entry in `clean/` is never shown as approved unless its attestation verifies now. `authorized_with_conditions` is amber, never green. NOT_TESTED never looks like a pass.
- Hashes are 64 lowercase hex. A staging or clean entry id is the artifact sha256, or the manifest digest for a model directory.

**Security**
- The console never holds a private key. Exports never include model bytes or keys.
- The existing API guard is unchanged: loopback by default, Host and Origin checks, JSON-only POSTs, concurrency limit `maxHeavy`.
- Uploaded envelopes are capped at 4 MiB. Evidence downloads come only from a fixed list of file names.

**Behavior and conventions**
- The expires-soon window is 30 days.
- Inventory predicate type: `https://socair.ai/inventory/v1`. Statement type: `https://in-toto.io/Statement/v1`. Signed through `internal/dsse` with Ed25519.
- An unsigned snapshot's `index.html` says `UNSIGNED SNAPSHOT`. Every `index.html` says it contains this site's model inventory and is for internal sharing only.
- The identity hook gives the actor `local-operator` in Step 1. `airlock.Event` gains an optional `actor` field, omitted when empty.

**Process**
- Tests are hermetic: temp stores, fixtures generated in code, no network.
- Every detector or verifier gets a falsification test.
- `gofmt -l cmd internal` prints nothing. `go vet ./...` and `go test ./...` pass. In `web/`: `npm run check` and `npm run test` pass, and `npm run build` succeeds.
- Commits are signed off (`git commit -s`) and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No Claude Code links anywhere.
- `main` is protected: work on a branch, open a PR, never push to `main`.

## Review Focus

These five inputs most likely to bite a user are not exercised by the spec's own tests. Each has a test in the task named.

1. **Stray entries in `incoming/` or `clean/`** (`.tmp`, a non-hex directory, a loose file): skip them, never crash or list them. Test in Task 3.
2. **A staging entry with no artifact, or more than one** (an interrupted pull): list it as `staged` with a reason naming the problem, without crashing. Test in Task 3.
3. **Listing a store whose model files are huge or unreadable:** `Models` must never read artifact bytes, only small JSON and envelopes. Test in Task 3, with an artifact made unreadable (`chmod 000`).
4. **Expiry at the boundary:** an acceptance expiring exactly at `at` is expired; one 30 days out is `expires_soon`; 31 days out is not. Test in Task 3, with a fixed `at`.
5. **Exporting a store with no approved models:** the snapshot is valid, `inventory verify` passes, and `index.html` says there are none. Test in Task 8.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/airlock/assess.go` (new) | `Store.Assess`, `Assessment`, `ErrAcceptanceExpired`: the gate's verification, shared |
| `internal/airlock/promote.go` (modify) | `Promote` calls `Assess` |
| `internal/airlock/staging.go` (new) | Staging evidence file names, `stagedArtifact`, `SaveReport`, `SaveAttestation`, `EvidencePath` |
| `internal/airlock/models.go` (new) | `Stage`, `Model`, `Next`, `Store.Models`, `Store.Model`: stage derivation |
| `internal/airlock/log.go` (modify) | `Event.Actor`, `Store.Actor`, `VerifyFile` |
| `internal/engine/scan.go` (modify) | `Inputs`, `ScanWith`: provenance path without an env var |
| `internal/api/routes.go` (new) | Route table with read/write access, the identity hook |
| `internal/api/console.go` (new) | Console handlers: models, model, files, scan, attestation, export |
| `internal/api/server.go` (modify) | Builds the mux from the route table; `store(r)` sets the actor |
| `internal/inventory/inventory.go` (new) | Statement types, `Build`, `Sign`, `Verify` |
| `internal/inventory/export.go` (new) | `Export`: writes the snapshot directory |
| `internal/inventory/index.html` (new) | Embedded `html/template` for the snapshot's `index.html` |
| `cmd/socair/airlock.go` (modify) | `socair airlock export` |
| `cmd/socair/inventory.go` (new), `cmd/socair/main.go` (modify) | `socair inventory verify` |
| `web/src/lib/api.ts` (modify) | Console types and client functions |
| `web/src/lib/console.ts` (new) | Display rules: stage labels and tones |
| `web/src/lib/ReportView.svelte` (new) | Report rendering shared by the scan and detail pages |
| `web/src/routes/...` (new/modify) | `+layout.svelte` nav, `/` redirect, `/scan`, `/approved`, `/pending`, `/models/[id]`, `/activity` |
| `docs/*` | api, wizard, airlock, intake-host, README, spec refinements |

---

### Task 1: Extract the gate's verification into `Store.Assess`

**Files:**
- Create: `internal/airlock/assess.go`
- Modify: `internal/airlock/promote.go`, replacing the block from `ring, names, err := s.TrustedIssuers()` through the end of `if conditional { ... }`
- Test: `internal/airlock/assess_test.go`

**Interfaces:**
- Consumes: `attest.Verify`, `(*attest.Verified).Issuer`, `attest.VerifyAcceptance`, `Store.TrustedIssuers`, `Store.AcceptorKeys`, `normalizeSHA`.
- Produces:
  - `func (s *Store) Assess(envelope []byte, at time.Time) (*Assessment, error)`
  - `type Assessment struct { Verified *attest.Verified; SHA256, State, Issuer string; IssuerConfirmed bool; Acceptance *acceptance.Acceptance; Expires time.Time }`
  - `func (a *Assessment) Admits() error`
  - `var ErrAcceptanceExpired`. When it is returned, the `*Assessment` is also non-nil.

- [ ] **Step 1: Write the failing test**

`internal/airlock/assess_test.go`:

```go
package airlock

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
)

func TestAssessAuthorizedAdmits(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	a, err := s.Assess(envelopeFor(t, d), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.State != report.StateAuthorized || a.Admits() != nil || a.SHA256 != d.Artifact.SHA256 {
		t.Fatalf("state %s admits %v sha %s", a.State, a.Admits(), a.SHA256)
	}
}

// A withheld attestation is valid evidence: Assess returns it, and only
// Admits refuses it. The console needs this to show needs-acceptance.
func TestAssessWithheldVerifiesButDoesNotAdmit(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	a, err := s.Assess(envelopeFor(t, d), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.State != report.StateWithheld || a.Admits() == nil {
		t.Fatalf("state %s admits %v", a.State, a.Admits())
	}
}

// Falsification: drop the expiry check in Assess and this returns no error.
func TestAssessExpiredAcceptance(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	ticket := acceptedTicket(t, s, d, time.Hour)
	env, err := os.ReadFile(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Assess(env, time.Now()); err != nil {
		t.Fatalf("current acceptance: %v", err)
	}
	a, err := s.Assess(env, time.Now().Add(2*time.Hour))
	if !errors.Is(err, ErrAcceptanceExpired) || a == nil || a.Expires.IsZero() {
		t.Fatalf("err %v assessment %+v", err, a)
	}
}

func TestAssessRefusesAnUntrustedKey(t *testing.T) {
	s, err := Init(t.TempDir()) // trusts no key
	if err != nil {
		t.Fatal(err)
	}
	_, d := authorizedArtifact(t)
	if _, err := s.Assess(envelopeFor(t, d), time.Now()); err == nil {
		t.Fatal("an envelope from an untrusted key must not assess")
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/airlock -run TestAssess -v`
Expected: FAIL to compile with `s.Assess undefined`.

- [ ] **Step 3: Implement `assess.go`**

```go
package airlock

import (
	"errors"
	"fmt"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/report"
)

// ErrAcceptanceExpired marks a conditional attestation whose acceptance has
// lapsed. Assess returns the Assessment with it, so a caller can still show
// what was accepted and when it expired.
var ErrAcceptanceExpired = errors.New("acceptance expired")

// Assessment is an attestation that passed the gate's checks: a signature by
// a trusted key, the issuer the store names for it, and for a conditional
// attestation a current acceptance by a trusted acceptor key.
type Assessment struct {
	Verified        *attest.Verified
	SHA256          string
	State           string
	Issuer          string
	IssuerConfirmed bool
	// Acceptance and Expires are set for authorized_with_conditions only.
	Acceptance *acceptance.Acceptance
	Expires    time.Time
}

// Assess runs the promotion gate's checks on an envelope at a moment, without
// placing anything. Promote and the console both use it, so what the console
// shows as approved is exactly what the gate admits. A withheld or escalated
// attestation assesses; Admits says it does not cross.
func (s *Store) Assess(envelope []byte, at time.Time) (*Assessment, error) {
	ring, names, err := s.TrustedIssuers()
	if err != nil {
		return nil, err
	}
	v, err := attest.Verify(envelope, ring)
	if err != nil {
		return nil, err
	}
	issuer, confirmed, err := v.Issuer(names)
	if err != nil {
		return nil, err
	}
	pa := v.Document.PromotionAuthorization
	a := &Assessment{Verified: v, SHA256: normalizeSHA(v.SHA256), State: pa.State, Issuer: issuer, IssuerConfirmed: confirmed}
	if a.State != report.StateAuthorizedWithConditions {
		return a, nil
	}
	// An acceptance covers its gaps only until it expires. Verify has already
	// required an RFC 3339 expiry; a lapsed one needs a fresh scan and a
	// fresh acceptance.
	exp, err := time.Parse(time.RFC3339, pa.AcceptanceExpires)
	if err != nil {
		return nil, fmt.Errorf("acceptance expiry %q cannot be enforced", pa.AcceptanceExpires)
	}
	a.Expires = exp
	if !at.Before(exp) {
		return a, fmt.Errorf("%w: the acceptance by %s of %d untested surface(s) expired at %s; re-scan and re-accept",
			ErrAcceptanceExpired, pa.AcceptedBy, len(pa.AcceptedSurfaces), exp.UTC().Format(time.RFC3339))
	}
	// The acceptance must be the acceptor's own signature, from a key in
	// acceptor-keys, never the operator's.
	acceptors, err := s.AcceptorKeys()
	if err != nil {
		return nil, err
	}
	acc, err := attest.VerifyAcceptance(v, acceptors, at)
	if err != nil {
		return nil, fmt.Errorf("the conditional attestation's acceptance does not hold: %w", err)
	}
	a.Acceptance = acc
	return a, nil
}

// Admits returns why the attestation does not cross into the clean store, or
// nil when it does.
func (a *Assessment) Admits() error {
	switch a.State {
	case report.StateAuthorized, report.StateAuthorizedWithConditions:
		return nil
	}
	return fmt.Errorf("attestation state %q withholds promotion; a FAIL or LEAD is clearable only by escalated review", a.State)
}
```

- [ ] **Step 4: Make `Promote` use it**

In `internal/airlock/promote.go`, replace everything from `ring, names, err := s.TrustedIssuers()` down to (not including) `isDir := false` with:

```go
	a, err := s.Assess(envelope, now())
	if a != nil {
		sha = a.SHA256
	}
	if err != nil {
		return refuse(err.Error())
	}
	if err := a.Admits(); err != nil {
		return refuse(err.Error())
	}
	v, d := a.Verified, a.Verified.Document
	issuerNote := "issued by " + a.Issuer
	if !a.IssuerConfirmed {
		issuerNote += " (claimed; the store does not name this key)"
	}
```

Then replace the whole `if conditional { ... }` block (expiry, acceptors, `VerifyAcceptance`) with:

```go
	if conditional {
		outcome = OutcomeConditional
		detail = fmt.Sprintf("authorized with conditions accepted by %s (signed acceptance, acceptor key %s) on %d surface(s) until %s, attestation %s, signed by %s",
			a.Acceptance.AcceptedBy, attest.ShortID(a.Acceptance.KeyID), len(pa.AcceptedSurfaces), a.Expires.UTC().Format(time.RFC3339), issuerNote, attest.ShortID(v.KeyID))
	}
```

Keep `pa := d.PromotionAuthorization` and `conditional := ...` as they are. `time` stays imported (it is used by `now` and the `Format` call).

- [ ] **Step 5: Run the airlock tests**

Run: `go test ./internal/airlock -count=1`
Expected: PASS, including every existing `TestPromote*` and acceptance test. Refusal messages are unchanged in substance; an expired acceptance's message now starts `acceptance expired: `.

- [ ] **Step 6: Commit**

```bash
gofmt -l cmd internal
git add internal/airlock/assess.go internal/airlock/assess_test.go internal/airlock/promote.go
git commit -s -m "airlock: Assess, the promotion gate's checks, shared by Promote and the console

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Staging evidence files

**Files:**
- Create: `internal/airlock/staging.go`
- Test: `internal/airlock/staging_test.go`

**Interfaces:**
- Consumes: `Store.Assess` (Task 1), `Store.WriteFile`, `hexSHA256`.
- Produces:
  - Constants:
    - `ProvenanceFile = "provenance.json"`
    - `StagedReport = "report.json"`
    - `StagedAttestation = "report.dsse.json"`
    - `StagedAcceptance = "report.acceptance.dsse.json"`
    - `StagedConditional = "report.conditional.dsse.json"`
  - `func IsEvidence(name string) bool`, true for those five plus `attestation.json` and `attestation.dsse.json`.
  - `func (s *Store) stagedArtifact(id string) (string, error)`: the one artifact path in `incoming/<id>/`.
  - `func (s *Store) EvidencePath(id, name string) (string, error)`: path of an evidence file in `clean/<id>/` or `incoming/<id>/`, or an error.
  - `func (s *Store) SaveReport(id string, d *report.Document) error`
  - `func (s *Store) SaveAttestation(id string, envelope []byte, at time.Time) (string, error)`: returns the file name written.
  - `var ErrNoModel = errors.New("no such model in the store")`

The names `report.dsse.json`, `report.acceptance.dsse.json` and `report.conditional.dsse.json` are what `socair sign`, `socair accept` and `socair sign --acceptance` already write next to their input. So an operator who runs the CLI against `incoming/<id>/report.json` produces exactly the files the console reads. This refines the spec's two optional files to the CLI's own outputs; Task 12 updates the spec.

- [ ] **Step 1: Write the failing tests**

`internal/airlock/staging_test.go`:

```go
package airlock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// stage writes the clean fixture into incoming/<sha>/fixture.safetensors with
// a provenance file, as a pull does, and returns the id.
func stage(t *testing.T, s *Store) string {
	t.Helper()
	data := safetensorstest.Clean()
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])
	dir := s.StagingPath(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.safetensors"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProvenanceFile), []byte(`{"artifact_sha256":"`+id+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStagedArtifactIgnoresEvidence(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_ = os.WriteFile(filepath.Join(s.StagingPath(id), StagedReport), []byte("{}"), 0o644)
	p, err := s.stagedArtifact(id)
	if err != nil || filepath.Base(p) != "fixture.safetensors" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestSaveReportBindsTheEntry(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.StagingPath(id), StagedReport)); err != nil {
		t.Fatal(err)
	}
	other := *d
	other.Artifact.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := s.SaveReport(id, &other); err == nil {
		t.Fatal("a report for another artifact must not be saved under this entry")
	}
	if err := s.SaveReport("not-hex", d); !errors.Is(err, ErrNoModel) {
		t.Fatalf("bad id: %v", err)
	}
}

// Falsification: skip Assess in SaveAttestation and the forged envelope is stored.
func TestSaveAttestationVerifiesAndChecksTheSubject(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	name, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now())
	if err != nil || name != StagedAttestation {
		t.Fatalf("%q %v", name, err)
	}

	withholdForGap(d)
	if name, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil || name != StagedAttestation {
		t.Fatalf("a withheld attestation is evidence too: %q %v", name, err)
	}

	forged := envelopeFor(t, d)
	forged[len(forged)-5] ^= 1
	if _, err := s.SaveAttestation(id, forged, time.Now()); err == nil {
		t.Fatal("a tampered envelope must be refused")
	}

	wrong := *d
	wrong.Artifact.SHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
	if _, err := s.SaveAttestation(id, envelopeFor(t, &wrong), time.Now()); err == nil {
		t.Fatal("an attestation for another artifact must be refused")
	}
}

func TestEvidencePathRefusesUnknownNamesAndTraversal(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	if _, err := s.EvidencePath(id, ProvenanceFile); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fixture.safetensors", "../log.jsonl", "", "report.json/.."} {
		if _, err := s.EvidencePath(id, name); err == nil {
			t.Errorf("%q served", name)
		}
	}
	if _, err := s.EvidencePath("../../etc", ProvenanceFile); !errors.Is(err, ErrNoModel) {
		t.Errorf("traversal id: %v", err)
	}
	_ = report.StateAuthorized
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/airlock -run 'Staged|SaveReport|SaveAttestation|EvidencePath' -v`
Expected: FAIL to compile (`ProvenanceFile`, `SaveReport` and the rest are undefined).

- [ ] **Step 3: Implement `staging.go`**

```go
package airlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/report"
)

// Evidence a staging entry can hold beside its artifact. The report names
// are what socair sign, socair accept, and socair sign --acceptance write
// next to their input, so the CLI run against incoming/<id>/report.json
// produces exactly the files the console reads.
const (
	ProvenanceFile    = "provenance.json"
	StagedReport      = "report.json"
	StagedAttestation = "report.dsse.json"
	StagedAcceptance  = "report.acceptance.dsse.json"
	StagedConditional = "report.conditional.dsse.json"
)

// ErrNoModel marks an id that names no entry in the store.
var ErrNoModel = errors.New("no such model in the store")

// IsEvidence reports whether name is an evidence file the console serves.
func IsEvidence(name string) bool {
	switch name {
	case ProvenanceFile, StagedReport, StagedAttestation, StagedAcceptance, StagedConditional,
		attestationDoc, attestationEnvelope:
		return true
	}
	return false
}

// entryDir returns the directory of an existing entry, clean first.
func (s *Store) entryDir(id string) (string, error) {
	if !hexSHA256.MatchString(id) {
		return "", ErrNoModel
	}
	for _, d := range []string{s.CleanPath(id), s.StagingPath(id)} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d, nil
		}
	}
	return "", ErrNoModel
}

// EvidencePath is the path of one evidence file of an entry. Only names on
// the evidence list are served, and the id must be 64 hex, so no request can
// reach the artifact bytes or leave the store.
func (s *Store) EvidencePath(id, name string) (string, error) {
	if !IsEvidence(name) {
		return "", fmt.Errorf("%q is not an evidence file", name)
	}
	dir, err := s.entryDir(id)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s has no %s", id, name)
	}
	return p, nil
}

// stagedArtifact returns the one artifact (a file or a model directory) in
// incoming/<id>/, ignoring evidence files.
func (s *Store) stagedArtifact(id string) (string, error) {
	if !hexSHA256.MatchString(id) {
		return "", ErrNoModel
	}
	entries, err := os.ReadDir(s.StagingPath(id))
	if err != nil {
		return "", ErrNoModel
	}
	var found []string
	for _, e := range entries {
		if !IsEvidence(e.Name()) {
			found = append(found, e.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", errors.New("the staging entry holds no artifact (an interrupted pull?)")
	case 1:
		return filepath.Join(s.StagingPath(id), found[0]), nil
	}
	return "", fmt.Errorf("the staging entry holds %d artifacts, not one: %v", len(found), found)
}

// SaveReport writes an unsigned scan result into a staging entry. The report
// must be for this entry's artifact.
func (s *Store) SaveReport(id string, d *report.Document) error {
	if _, err := s.stagedArtifact(id); errors.Is(err, ErrNoModel) {
		return err
	}
	if normalizeSHA(d.Artifact.SHA256) != id {
		return fmt.Errorf("the report is for %s, not this entry %s", d.Artifact.SHA256, id)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return s.WriteFile(filepath.Join(s.StagingPath(id), StagedReport), b)
}

// SaveAttestation stores a signed attestation in a staging entry after the
// gate's own checks: a trusted signature, the issuer, a current acceptance
// when conditional, and a subject that is this entry. A withheld attestation
// is stored too: it is the evidence a reviewer reads. A conditional one is
// stored under the name socair sign --acceptance gives it.
func (s *Store) SaveAttestation(id string, envelope []byte, at time.Time) (string, error) {
	if _, err := s.stagedArtifact(id); errors.Is(err, ErrNoModel) {
		return "", err
	}
	a, err := s.Assess(envelope, at)
	if err != nil {
		return "", err
	}
	if a.SHA256 != id {
		return "", fmt.Errorf("the attestation is for %s, not this entry %s", a.SHA256, id)
	}
	name := StagedAttestation
	if a.State == report.StateAuthorizedWithConditions {
		name = StagedConditional
	}
	return name, s.WriteFile(filepath.Join(s.StagingPath(id), name), envelope)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/airlock -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/airlock/staging.go internal/airlock/staging_test.go
git commit -s -m "airlock: staging evidence (scan report, signed attestation), verified on save

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Stage derivation, `Store.Models` and `Store.Model`

**Files:**
- Create: `internal/airlock/models.go`
- Test: `internal/airlock/models_test.go`

**Interfaces:**
- Consumes: `Store.Assess`, `ErrAcceptanceExpired` (Task 1); `stagedArtifact`, the staging constants, `ErrNoModel` (Task 2); `Store.Events`.
- Produces:

```go
type Stage string
const (
	StageStaged            Stage = "staged"
	StageScanned           Stage = "scanned"
	StageReady             Stage = "ready"
	StageNeedsAcceptance   Stage = "needs-acceptance"
	StageBlocked           Stage = "blocked"
	StageApproved          Stage = "approved"
	StageAcceptanceExpired Stage = "acceptance-expired"
	StageDoesNotVerify     Stage = "does-not-verify"
)
type Next struct { Action string `json:"action"`; Command string `json:"command,omitempty"` }
type Model struct {
	ID string `json:"id"`; Name string `json:"name"`; Format string `json:"format,omitempty"`; SizeBytes int64 `json:"size_bytes,omitempty"`
	Location string `json:"location"` // "staging" | "clean"
	Stage Stage `json:"stage"`; StageReason string `json:"stage_reason,omitempty"`
	PromotionState string `json:"promotion_state,omitempty"`; Issuer string `json:"issuer,omitempty"`; SignerKeyID string `json:"signer_key_id,omitempty"`
	AcceptedSurfaces []string `json:"accepted_surfaces,omitempty"`; AcceptedBy string `json:"accepted_by,omitempty"`
	AcceptanceExpires string `json:"acceptance_expires,omitempty"`; ExpiresSoon bool `json:"expires_soon,omitempty"`
	PromotedAt string `json:"promoted_at,omitempty"`; Next Next `json:"next"`
	ArtifactPath string `json:"-"`; EnvelopePath string `json:"-"`
}
func (s *Store) Models(at time.Time) ([]Model, error) // sorted: clean first, then staging, each by ID
func (s *Store) Model(id string, at time.Time) (Model, *report.Document, error)
const ExpiresSoonWindow = 30 * 24 * time.Hour
```

`Next.Action` is one of `scan`, `sign`, `accept`, `promote` or `none`.

- [ ] **Step 1: Write the failing tests**

`internal/airlock/models_test.go`:

```go
package airlock

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
)

func modelByID(t *testing.T, s *Store, id string, at time.Time) Model {
	t.Helper()
	ms, err := s.Models(at)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("model %s not listed in %+v", id, ms)
	return Model{}
}

func TestStageStagedAndScanned(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageStaged || m.Next.Action != "scan" || m.Location != "staging" {
		t.Fatalf("%+v", m)
	}
	_, d := authorizedArtifact(t)
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageScanned || m.Next.Action != "sign" || !strings.Contains(m.Next.Command, "socair sign") {
		t.Fatalf("%+v", m)
	}
}

func TestStageReadyNeedsAcceptanceBlocked(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if _, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageReady || m.Next.Action != "promote" {
		t.Fatalf("authorized: %+v", m)
	}

	gap := *d
	withholdForGap(&gap)
	if _, err := s.SaveAttestation(id, envelopeFor(t, &gap), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageNeedsAcceptance || m.Next.Action != "accept" ||
		!strings.Contains(m.Next.Command, "socair accept") {
		t.Fatalf("withheld on a gap: %+v", m)
	}

	// Falsification: treat any withheld state as needs-acceptance and this fails.
	lead := *d
	lead.Checks = append([]report.CheckResult(nil), d.Checks...)
	lead.Checks[0].Status = report.StatusLead
	lead.Findings.Leads = []string{lead.Checks[0].Name}
	lead.PromotionAuthorization = report.PromotionAuthorization{State: report.StateWithheld, Level: "Tier 1 only",
		Conditions: "Withheld: " + lead.Checks[0].Name + " is a LEAD."}
	if _, err := s.SaveAttestation(id, envelopeFor(t, &lead), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageBlocked || m.Next.Action != "none" {
		t.Fatalf("a LEAD is blocked, never acceptable: %+v", m)
	}
}

func promoted(t *testing.T, s *Store) string {
	t.Helper()
	artifact, d := authorizedArtifact(t)
	if _, err := Promote(s, artifact, writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	return d.Artifact.SHA256
}

func TestStageApprovedThenDoesNotVerify(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageApproved || m.Location != "clean" || m.PromotionState != report.StateAuthorized || m.PromotedAt == "" {
		t.Fatalf("%+v", m)
	}
	// Falsification: list clean entries without verifying them and this stays approved.
	if err := os.Remove(filepath.Join(s.TrustPath(), "test.pub")); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageDoesNotVerify || m.StageReason == "" {
		t.Fatalf("an attestation no trusted key verifies must not show as approved: %+v", m)
	}
}

// Review Focus 4: the expiry boundaries.
func TestConditionalExpiryBoundaries(t *testing.T) {
	s := trustedStore(t)
	artifact, d := authorizedArtifact(t)
	withholdForGap(d)
	ticket := acceptedTicket(t, s, d, 40*24*time.Hour)
	if _, err := Promote(s, artifact, ticket); err != nil {
		t.Fatal(err)
	}
	id := d.Artifact.SHA256
	m := modelByID(t, s, id, time.Now())
	exp, err := time.Parse(time.RFC3339, m.AcceptanceExpires)
	if err != nil || m.Stage != StageApproved || m.PromotionState != report.StateAuthorizedWithConditions || len(m.AcceptedSurfaces) == 0 {
		t.Fatalf("%+v %v", m, err)
	}
	if m.ExpiresSoon {
		t.Error("40 days out is not expires-soon")
	}
	if m := modelByID(t, s, id, exp.Add(-30*24*time.Hour)); !m.ExpiresSoon {
		t.Error("exactly 30 days out is expires-soon")
	}
	if m := modelByID(t, s, id, exp.Add(-31*24*time.Hour)); m.ExpiresSoon {
		t.Error("31 days out is not expires-soon")
	}
	if m := modelByID(t, s, id, exp); m.Stage != StageAcceptanceExpired {
		t.Errorf("at the expiry instant: %s", m.Stage)
	}
}

// Review Focus 1 and 2: stray entries are skipped; a staging entry without
// exactly one artifact is listed, staged, with the reason.
func TestStrayAndBrokenEntries(t *testing.T) {
	s := trustedStore(t)
	_ = os.MkdirAll(filepath.Join(s.Root, "incoming", ".tmp"), 0o755)
	_ = os.MkdirAll(filepath.Join(s.Root, "clean", "not-a-hash"), 0o755)
	_ = os.WriteFile(filepath.Join(s.Root, "incoming", "loose.txt"), []byte("x"), 0o644)
	empty := strings.Repeat("a", 64)
	_ = os.MkdirAll(s.StagingPath(empty), 0o755)
	_ = os.WriteFile(filepath.Join(s.StagingPath(empty), ProvenanceFile), []byte("{}"), 0o644)

	ms, err := s.Models(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].ID != empty || ms[0].Stage != StageStaged || !strings.Contains(ms[0].StageReason, "no artifact") {
		t.Fatalf("%+v", ms)
	}
}

// Review Focus 3: listing reads evidence only, never artifact bytes.
func TestModelsNeverReadsArtifactBytes(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	s := trustedStore(t)
	id := promoted(t, s)
	art := filepath.Join(s.CleanPath(id), "fixture.safetensors")
	if err := os.Chmod(art, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(art, 0o644) })
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved {
		t.Fatalf("%+v", m)
	}
}

func TestModelDetailReturnsTheDocument(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	m, d, err := s.Model(id, time.Now())
	if err != nil || d == nil || d.Artifact.SHA256 != id || m.ID != id {
		t.Fatalf("%+v %v %v", m, d, err)
	}
	if _, _, err := s.Model(strings.Repeat("b", 64), time.Now()); err == nil {
		t.Fatal("an unknown id must be an error")
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/airlock -run 'Stage|Stray|NeverReads|ModelDetail|Expiry' -v`
Expected: FAIL to compile (`Models`, `StageStaged` and the rest are undefined).

- [ ] **Step 3: Implement `models.go`**

```go
package airlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/report"
)

// Stage is where an entry stands, derived only from the evidence files in the
// store, through the gate's own checks (Assess).
type Stage string

const (
	StageStaged            Stage = "staged"
	StageScanned           Stage = "scanned"
	StageReady             Stage = "ready"
	StageNeedsAcceptance   Stage = "needs-acceptance"
	StageBlocked           Stage = "blocked"
	StageApproved          Stage = "approved"
	StageAcceptanceExpired Stage = "acceptance-expired"
	StageDoesNotVerify     Stage = "does-not-verify"
)

// ExpiresSoonWindow is how far ahead an acceptance's expiry is flagged.
const ExpiresSoonWindow = 30 * 24 * time.Hour

// Next is the step an entry waits for: an action the console can take, or the
// exact CLI command when the step needs a key.
type Next struct {
	Action  string `json:"action"` // scan | sign | accept | promote | none
	Command string `json:"command,omitempty"`
}

// Model is one entry of the store as the console shows it.
type Model struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Format            string   `json:"format,omitempty"`
	SizeBytes         int64    `json:"size_bytes,omitempty"`
	Location          string   `json:"location"` // staging | clean
	Stage             Stage    `json:"stage"`
	StageReason       string   `json:"stage_reason,omitempty"`
	PromotionState    string   `json:"promotion_state,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	SignerKeyID       string   `json:"signer_key_id,omitempty"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptedBy        string   `json:"accepted_by,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
	ExpiresSoon       bool     `json:"expires_soon,omitempty"`
	PromotedAt        string   `json:"promoted_at,omitempty"`
	Next              Next     `json:"next"`
	// ArtifactPath and EnvelopePath are for the API's actions, never sent.
	ArtifactPath string `json:"-"`
	EnvelopePath string `json:"-"`
}

// Models lists every clean and staging entry, clean first, each by id. It
// reads only evidence files (envelopes and small JSON), never artifact bytes.
// Stray names that are not 64-hex directories are skipped.
func (s *Store) Models(at time.Time) ([]Model, error) {
	promoted, err := s.promotedAt()
	if err != nil {
		return nil, err
	}
	var out []Model
	for _, loc := range []string{cleanDir, stagingDir} {
		entries, err := os.ReadDir(filepath.Join(s.Root, loc))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", loc, err)
		}
		var ids []string
		for _, e := range entries {
			if e.IsDir() && hexSHA256.MatchString(e.Name()) {
				ids = append(ids, e.Name())
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			m, _ := s.derive(loc, id, at)
			if loc == cleanDir {
				m.PromotedAt = promoted[id]
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// Model returns one entry and the report it carries: the verified attestation's
// document when there is one, else the unsigned scan report, else nil.
func (s *Store) Model(id string, at time.Time) (Model, *report.Document, error) {
	if !hexSHA256.MatchString(id) {
		return Model{}, nil, ErrNoModel
	}
	for _, loc := range []string{cleanDir, stagingDir} {
		if fi, err := os.Stat(filepath.Join(s.Root, loc, id)); err == nil && fi.IsDir() {
			m, d := s.derive(loc, id, at)
			if loc == cleanDir {
				promoted, err := s.promotedAt()
				if err != nil {
					return Model{}, nil, err
				}
				m.PromotedAt = promoted[id]
			}
			return m, d, nil
		}
	}
	return Model{}, nil, ErrNoModel
}

// derive works out one entry's stage from its files.
func (s *Store) derive(loc, id string, at time.Time) (Model, *report.Document) {
	dir := filepath.Join(s.Root, loc, id)
	m := Model{ID: id, Name: id[:12], Location: "staging", Next: Next{Action: "none"}}
	if loc == cleanDir {
		m.Location = "clean"
		m.EnvelopePath = filepath.Join(dir, attestationEnvelope)
		m.ArtifactPath = s.cleanArtifact(dir)
		env, err := os.ReadFile(m.EnvelopePath)
		if err != nil {
			m.Stage, m.StageReason = StageDoesNotVerify, "no attestation in the clean entry: "+err.Error()
			return m, nil
		}
		a, err := s.Assess(env, at)
		switch {
		case err == nil && a.SHA256 != id:
			m.Stage, m.StageReason = StageDoesNotVerify, fmt.Sprintf("the attestation is for %s, not this entry", a.SHA256)
			return m, nil
		case errors.Is(err, ErrAcceptanceExpired):
			fill(&m, a, at)
			m.Stage, m.StageReason = StageAcceptanceExpired, err.Error()
			return m, &a.Verified.Document
		case err != nil:
			m.Stage, m.StageReason = StageDoesNotVerify, err.Error()
			return m, nil
		}
		fill(&m, a, at)
		m.Stage = StageApproved
		return m, &a.Verified.Document
	}

	art, err := s.stagedArtifact(id)
	if err != nil {
		m.Stage, m.StageReason = StageStaged, err.Error()
		return m, nil
	}
	m.ArtifactPath = art
	m.Name = filepath.Base(art)
	reportPath := filepath.Join(dir, StagedReport)
	for _, name := range []string{StagedConditional, StagedAttestation} {
		p := filepath.Join(dir, name)
		env, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m.EnvelopePath = p
		a, err := s.Assess(env, at)
		switch {
		case err == nil && a.SHA256 != id:
			m.Stage, m.StageReason = StageDoesNotVerify, fmt.Sprintf("%s is for %s, not this entry", name, a.SHA256)
			return m, nil
		case errors.Is(err, ErrAcceptanceExpired):
			fill(&m, a, at)
			m.Stage, m.StageReason = StageAcceptanceExpired, err.Error()
			m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
			return m, &a.Verified.Document
		case err != nil:
			m.Stage, m.StageReason = StageDoesNotVerify, name+": "+err.Error()
			return m, nil
		}
		fill(&m, a, at)
		d := &a.Verified.Document
		switch {
		case a.Admits() == nil:
			m.Stage = StageReady
			m.Next = Next{Action: "promote", Command: "socair airlock promote " + shellQuote(art) + " --attestation " + shellQuote(p) + " --store " + shellQuote(s.Root)}
		case hasFailOrLead(d):
			m.Stage, m.StageReason = StageBlocked, "a FAIL or LEAD withholds it; only escalated review clears it"
		default:
			m.Stage = StageNeedsAcceptance
			m.StageReason = "withheld on NOT_TESTED rows: " + strings.Join(d.Findings.NotTested, ", ")
			acc := filepath.Join(dir, StagedAcceptance)
			m.Next = Next{Action: "accept", Command: "socair accept --attestation " + shellQuote(p) +
				` --key <acceptor.key> --by "<name, role>" --expires <RFC 3339> --store ` + shellQuote(s.Root) +
				"\nsocair sign --key <operator.key> --attestation " + shellQuote(p) + " --acceptance " + shellQuote(acc) +
				" --store " + shellQuote(s.Root)}
		}
		return m, d
	}
	if b, err := os.ReadFile(reportPath); err == nil {
		var d report.Document
		if json.Unmarshal(b, &d) == nil {
			m.Stage = StageScanned
			m.PromotionState = d.PromotionAuthorization.State
			named(&m, &d)
			m.Next = Next{Action: "sign", Command: "socair sign --key <operator.key> --report " + shellQuote(reportPath)}
			return m, &d
		}
		m.StageReason = StagedReport + " does not parse; scan again"
	}
	m.Stage = StageStaged
	m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
	return m, nil
}

func (s *Store) scanCommand(dir, art string) string {
	return "SOCAIR_PROVENANCE=" + shellQuote(filepath.Join(dir, ProvenanceFile)) + " socair scan " + shellQuote(art) +
		" > " + shellQuote(filepath.Join(dir, StagedReport))
}

// fill copies what an assessed attestation says into the model.
func fill(m *Model, a *Assessment, at time.Time) {
	d := &a.Verified.Document
	named(m, d)
	m.PromotionState, m.Issuer, m.SignerKeyID = a.State, a.Issuer, a.Verified.KeyID
	if a.State == report.StateAuthorizedWithConditions {
		pa := d.PromotionAuthorization
		m.AcceptedSurfaces, m.AcceptedBy, m.AcceptanceExpires = pa.AcceptedSurfaces, pa.AcceptedBy, pa.AcceptanceExpires
		left := a.Expires.Sub(at)
		m.ExpiresSoon = left > 0 && left <= ExpiresSoonWindow
	}
}

func named(m *Model, d *report.Document) {
	if d.Artifact.Name != "" {
		m.Name = d.Artifact.Name
	}
	m.Format, m.SizeBytes = d.Artifact.Format, d.Artifact.SizeBytes
}

func hasFailOrLead(d *report.Document) bool {
	for _, c := range d.Checks {
		if c.Status == report.StatusFail || c.Status == report.StatusLead {
			return true
		}
	}
	return false
}

// cleanArtifact is the artifact in a clean entry: the one name that is not
// store metadata.
func (s *Store) cleanArtifact(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.Name() != attestationDoc && e.Name() != attestationEnvelope {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// promotedAt maps each promoted hash to the time of its last promotion.
func (s *Store) promotedAt() (map[string]string, error) {
	ev, err := s.Events()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ev {
		if e.Action == ActionPromote && (e.Outcome == OutcomeOK || e.Outcome == OutcomeConditional) && e.SHA256 != "" {
			out[normalizeSHA(e.SHA256)] = e.TS
		}
	}
	return out, nil
}

// shellQuote quotes a path for a copyable POSIX shell command.
func shellQuote(p string) string {
	if p != "" && strings.IndexFunc(p, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0 {
		return p
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}
```

`OutcomeOK` and `OutcomeConditional` already exist in `log.go`, next to the `Action*` constants.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/airlock -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l cmd internal
git add internal/airlock/models.go internal/airlock/models_test.go
git commit -s -m "airlock: derive each entry's stage from its evidence through the gate's checks

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Actor in the log, the identity hook, and the route table

**Files:**
- Modify: `internal/airlock/log.go` (`Event.Actor`, `Store.Actor`, `Record`, `VerifyFile`)
- Modify: `internal/airlock/store.go` (add the `Actor` field to `Store`)
- Create: `internal/api/routes.go`
- Modify: `internal/api/server.go` (`handler` builds from routes; `store(r)` sets the actor)
- Test: `internal/airlock/chain_test.go` (add), `internal/api/routes_test.go` (new)

**Interfaces:**
- Produces:
  - `Event.Actor string` (json `actor,omitempty`).
  - `Store.Actor string`. When non-empty, `Record` stamps it on entries that have none.
  - `func VerifyFile(path string, opts VerifyOptions) (ChainReport, error)`. `Store.Verify` now calls `VerifyFile(s.LogPath(), opts)`.
  - In `api`:
    - `type access int`, with `const ( readAccess access = iota; writeAccess )`.
    - `type route struct { pattern string; access access; handler http.HandlerFunc }`.
    - `func (o Options) routes(limit func(http.HandlerFunc) http.HandlerFunc) []route`.
    - `func actorFrom(r *http.Request) string`.
    - `const LocalOperator = "local-operator"`.
    - `func (o Options) storeFor(r *http.Request) (*airlock.Store, error)`, which opens the store with `Actor` set.

- [ ] **Step 1: Write the failing tests**

Append to `internal/airlock/chain_test.go`:

```go
// An actor on new entries leaves older, actor-less lines valid: the chain is
// over exact line bytes.
func TestActorKeepsTheChain(t *testing.T) {
	s := chainedStore(t, 2)
	s.Actor = "local-operator"
	if err := s.Record(Event{Action: ActionIngest, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	ev, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	if ev[len(ev)-1].Actor != "local-operator" || ev[0].Actor != "" {
		t.Fatalf("actors: %q %q", ev[0].Actor, ev[len(ev)-1].Actor)
	}
	r, err := VerifyFile(s.LogPath(), VerifyOptions{})
	if err != nil || r.Broken != 0 || r.Entries != 3 {
		t.Fatalf("%+v %v", r, err)
	}
}
```

`internal/api/routes_test.go`:

```go
package api

import (
	"net/http"
	"strings"
	"testing"
)

// Every API route is classified, GETs are reads, and the identity hook names
// the local operator. Roles later map onto access without touching handlers.
func TestRoutesAreClassified(t *testing.T) {
	rs := Options{}.routes(func(h http.HandlerFunc) http.HandlerFunc { return h })
	if len(rs) < 10 {
		t.Fatalf("only %d routes", len(rs))
	}
	for _, r := range rs {
		method, path, _ := strings.Cut(r.pattern, " ")
		if !strings.HasPrefix(path, "/api/") {
			t.Errorf("%s is not an API route", r.pattern)
		}
		if method == "GET" && r.access != readAccess {
			t.Errorf("%s is a GET but not a read", r.pattern)
		}
	}
}

func TestActorIsTheLocalOperator(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/version", nil)
	if got := actorFrom(identify(req)); got != LocalOperator {
		t.Fatalf("actor %q", got)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `go test ./internal/airlock -run TestActorKeepsTheChain -v && go test ./internal/api -run 'Routes|Actor' -v`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the log changes**

In `internal/airlock/store.go`, change the struct to:

```go
type Store struct {
	Root string
	// Actor, when set, is recorded on log entries that name none: the
	// signed-in user, or "local-operator" for the console's loopback API.
	Actor string
}
```

In `internal/airlock/log.go`:
- Add `Actor string `json:"actor,omitempty"`` to `Event`, after `Detail`.
- At the top of `Record`, add:

```go
	if e.Actor == "" {
		e.Actor = s.Actor
	}
```

Rename the body of `Store.Verify` into a package function that takes the path:

```go
// Verify checks the store's log; see VerifyFile.
func (s *Store) Verify(opts VerifyOptions) (ChainReport, error) { return VerifyFile(s.LogPath(), opts) }

// VerifyFile walks the hash chain of a log file, such as an exported copy.
func VerifyFile(path string, opts VerifyOptions) (ChainReport, error) {
	var r ChainReport
	f, err := os.Open(path)
	// ... the rest of the former Store.Verify body, unchanged ...
}
```

- [ ] **Step 4: Implement `routes.go` and wire it**

`internal/api/routes.go`:

```go
package api

import (
	"context"
	"net/http"

	"github.com/defilantech/socair/internal/airlock"
)

// access is what a route needs: reading the store, or changing it. Step 1
// grants both to the local operator; a login (Step 1b) or roles (paid)
// decide per route here, without touching handlers.
type access int

const (
	readAccess access = iota
	writeAccess
)

type route struct {
	pattern string
	access  access
	handler http.HandlerFunc
}

// LocalOperator is the actor of every request in Step 1: the console binds
// loopback and has no login.
const LocalOperator = "local-operator"

type actorKey struct{}

// identify attaches the caller's identity to the request. Step 1b replaces
// this with an OIDC session; nothing else reads identity.
func identify(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), actorKey{}, LocalOperator))
}

func actorFrom(r *http.Request) string {
	if a, ok := r.Context().Value(actorKey{}).(string); ok {
		return a
	}
	return ""
}

// authorize is the one place access is decided. In Step 1 every identified
// caller may read and write.
func authorize(_ access, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { next(w, r) }
}

// storeFor opens the configured store with the request's actor, so every log
// entry the request causes names who caused it.
func (o Options) storeFor(r *http.Request) (*airlock.Store, error) {
	s, err := o.store()
	if err != nil {
		return nil, err
	}
	s.Actor = actorFrom(r)
	return s, nil
}

func (o Options) routes(limit func(http.HandlerFunc) http.HandlerFunc) []route {
	return []route{
		{"GET /api/version", readAccess, o.version},
		{"GET /api/health", readAccess, o.health},
		{"POST /api/scan", readAccess, limit(o.scan)},
		{"POST /api/render", readAccess, o.render},
		{"GET /api/airlock/log", readAccess, o.airlockLog},
		{"POST /api/airlock/ingest", writeAccess, limit(o.airlockIngest)},
		{"POST /api/airlock/pull", writeAccess, limit(o.airlockPull)},
		{"POST /api/airlock/promote", writeAccess, limit(o.airlockPromote)},
	}
}
```

`POST /api/scan` and `POST /api/render` are reads: they change no store state.

In `internal/api/server.go`, replace the block of `mux.HandleFunc` calls in `handler` with:

```go
	mux := http.NewServeMux()
	for _, rt := range o.routes(limit) {
		mux.HandleFunc(rt.pattern, authorize(rt.access, rt.handler))
	}
```

Then wrap the returned handler so identity is attached before the guard:

```go
	guarded := o.guard(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { guarded.ServeHTTP(w, identify(r)) })
```

In `airlockIngest`, `airlockPull` and `airlockPromote`, replace `s, err := o.store()` with `s, err := o.storeFor(r)`.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/airlock ./internal/api -count=1`
Expected: PASS, including all existing guard and server tests.

- [ ] **Step 6: Commit**

```bash
gofmt -l cmd internal
git add internal/airlock/log.go internal/airlock/store.go internal/airlock/chain_test.go internal/api/routes.go internal/api/routes_test.go internal/api/server.go
git commit -s -m "api: route table with read/write access and one identity hook; log entries name their actor

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Read endpoints (models, model detail, evidence files)

**Files:**
- Create: `internal/api/console.go`
- Modify: `internal/api/routes.go` (register the routes)
- Test: `internal/api/console_test.go`

**Interfaces:**
- Consumes: `Store.Models`, `Store.Model`, `Store.EvidencePath`, `airlock.ErrNoModel` (Tasks 2 and 3); `storeFor` (Task 4).
- Produces:
  - `GET /api/airlock/models` returns `{"models":[Model...]}`.
  - `GET /api/airlock/models/{id}` returns `{"model":Model,"report":Document|null,"events":[Event...]}`, where `events` are those whose `sha256` equals `id`.
  - `GET /api/airlock/models/{id}/files/{name}` returns the file bytes. `Content-Type` is `application/json`, and `Content-Disposition` is `attachment; filename="<name>"`.

- [ ] **Step 1: Write the failing test**

`internal/api/console_test.go`:

```go
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// consoleStore is an initialized store with one staged safetensors entry.
func consoleStore(t *testing.T) (root, id string) {
	t.Helper()
	root = t.TempDir()
	s, err := airlock.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	data := safetensorstest.Clean()
	sum := sha256.Sum256(data)
	id = hex.EncodeToString(sum[:])
	dir := s.StagingPath(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "fixture.safetensors"), data, 0o644)
	_ = os.WriteFile(filepath.Join(dir, airlock.ProvenanceFile), []byte(`{"artifact_sha256":"`+id+`"}`), 0o644)
	return root, id
}

func TestConsoleListsAndDetails(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})

	code, _, body := get(t, ts, "/api/airlock/models")
	var list struct{ Models []airlock.Model }
	if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Models) != 1 || list.Models[0].Stage != airlock.StageStaged {
		t.Fatalf("%d %s", code, body)
	}

	code, _, body = get(t, ts, "/api/airlock/models/"+id)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if code, _, _ := get(t, ts, "/api/airlock/models/"+id+"/files/"+airlock.ProvenanceFile); code != http.StatusOK {
		t.Fatalf("provenance download: %d", code)
	}
}

// Review: the download serves evidence names only, and never leaves the store.
func TestConsoleFileDownloadIsConfined(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	for _, p := range []string{
		"/api/airlock/models/" + id + "/files/fixture.safetensors",
		"/api/airlock/models/" + id + "/files/..%2Flog.jsonl",
		"/api/airlock/models/..%2F..%2Fetc/files/provenance.json",
		"/api/airlock/models/" + id + "/files/report.json",
	} {
		if code, _, _ := get(t, ts, p); code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, _, _ := get(t, ts, "/api/airlock/models/"+id[:63]+"0"); code != http.StatusNotFound {
		t.Errorf("unknown id: %d", code)
	}
}

func TestConsoleNeedsAStore(t *testing.T) {
	ts := server(t, Options{})
	if code, _, _ := get(t, ts, "/api/airlock/models"); code != http.StatusBadRequest {
		t.Fatalf("%d", code)
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/api -run Console -v`
Expected: FAIL. The routes are not registered, so the SPA fallback or the mux answers `404`/`405`.

- [ ] **Step 3: Implement `console.go`**

```go
package api

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/defilantech/socair/internal/airlock"
)

func (o Options) consoleModels(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ms, err := s.Models(time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ms == nil {
		ms = []airlock.Model{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": ms})
}

func (o Options) consoleModel(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	m, d, err := s.Model(id, time.Now())
	if errors.Is(err, airlock.ErrNoModel) {
		writeError(w, http.StatusNotFound, "no model "+id+" in the store")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all, err := s.Events()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	events := []airlock.Event{}
	for _, e := range all {
		if e.SHA256 == id {
			events = append(events, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": m, "report": d, "events": events})
}

func (o Options) consoleFile(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PathValue("name")
	p, err := s.EvidencePath(r.PathValue("id"), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(b)
}
```

Register in `routes()`, after the existing airlock routes:

```go
		{"GET /api/airlock/models", readAccess, o.consoleModels},
		{"GET /api/airlock/models/{id}", readAccess, o.consoleModel},
		{"GET /api/airlock/models/{id}/files/{name}", readAccess, o.consoleFile},
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/api -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/console.go internal/api/console_test.go internal/api/routes.go
git commit -s -m "api: console read endpoints (models, model detail, evidence files)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Write endpoints: scan a staged model, upload a signed attestation

**Files:**
- Modify: `internal/engine/scan.go` (add `Inputs` and `ScanWith`)
- Modify: `internal/api/console.go`, `internal/api/routes.go`
- Test: `internal/engine/scan_test.go` (add), `internal/api/console_test.go` (add)

**Interfaces:**
- Produces:
  - `type Inputs struct { Provenance string }`
  - `func ScanWith(path string, mode Mode, in Inputs) (*report.Document, error)`. `ScanMode` becomes `ScanWith(path, mode, Inputs{})`.
  - `POST /api/airlock/models/{id}/scan` (write, limited) returns `{"report":Document,"model":Model}`.
  - `POST /api/airlock/models/{id}/attestation` (write) takes a DSSE envelope body, at most 4 MiB. It returns `{"file":name,"model":Model}`, or `422` with the reason.

- [ ] **Step 1: Write the failing tests**

Append to `internal/engine/scan_test.go`:

```go
// The console scans a staged model with its pull's provenance file, without
// setting SOCAIR_PROVENANCE in a shared process. Falsification: ignore
// Inputs.Provenance and the provenance row stays NOT_TESTED.
func TestScanWithProvenanceInput(t *testing.T) {
	t.Setenv("SOCAIR_PROVENANCE", "")
	data := safetensors_clean(t)
	p := writeFixture(t, "fixture.safetensors", data)
	sum := sha256.Sum256(data)
	prov := filepath.Join(t.TempDir(), "provenance.json")
	body := `{"artifact_sha256":"` + hex.EncodeToString(sum[:]) + `","publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`
	if err := os.WriteFile(prov, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := ScanWith(p, ModeFull, Inputs{Provenance: prov})
	if err != nil {
		t.Fatal(err)
	}
	if got := rowStatus(d, "Hash, provenance, lineage"); got != report.StatusPass {
		t.Fatalf("provenance row %s", got)
	}
}

func safetensors_clean(t *testing.T) []byte { t.Helper(); return safetensorstest.Clean() }
```

Append to `internal/api/console_test.go`:

```go
func TestConsoleScanStagedWritesTheReport(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/models/"+id+"/scan", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var out struct{ Model airlock.Model }
	if json.Unmarshal(body, &out) != nil || out.Model.Stage != airlock.StageScanned {
		t.Fatalf("%s", body)
	}
}

func TestConsoleUploadRefusesWhatDoesNotVerify(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/models/"+id+"/attestation", map[string]any{"payloadType": "x", "payload": "e30=", "signatures": []any{}})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", code, body)
	}
	big := map[string]any{"payload": strings.Repeat("A", 5<<20)}
	if code, _ := post(t, ts, "/api/airlock/models/"+id+"/attestation", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: %d", code)
	}
}
```

Add `"strings"` to that file's imports.

- [ ] **Step 2: Run to see them fail**

Run: `go test ./internal/engine -run ScanWith -v; go test ./internal/api -run 'ConsoleScan|ConsoleUpload' -v`
Expected: FAIL (`ScanWith` undefined; the routes are missing).

- [ ] **Step 3: Implement `ScanWith`**

In `internal/engine/scan.go`:

```go
// Inputs are scan inputs a caller passes directly instead of through the
// environment, for a long-running process that scans many artifacts. An empty
// field falls back to its environment variable.
type Inputs struct {
	// Provenance is the provenance manifest path (SOCAIR_PROVENANCE).
	Provenance string
}

// ScanMode reads the artifact at path in the given mode and returns a filled
// report document.
func ScanMode(path string, mode Mode) (*report.Document, error) { return ScanWith(path, mode, Inputs{}) }

// ScanWith is ScanMode with explicit inputs.
func ScanWith(path string, mode Mode, in Inputs) (*report.Document, error) {
	// ... the former body of ScanMode ...
}
```

Thread `in` from `ScanWith` down to where `provenance.Options{... ManifestPath: os.Getenv("SOCAIR_PROVENANCE") ...}` is built (scan.go:234 today), and to the directory path in `scandir.go` if it builds provenance options too. Use:

```go
func (in Inputs) provenancePath() string {
	if in.Provenance != "" {
		return in.Provenance
	}
	return os.Getenv("SOCAIR_PROVENANCE")
}
```

Add an `in Inputs` parameter to each function between `ScanWith` and that line, and pass it through.

- [ ] **Step 4: Implement the write handlers**

Append to `internal/api/console.go` (add `"encoding/json"`, `"io"`, `"path/filepath"` and `"github.com/defilantech/socair/internal/engine"` to its imports):

```go
// maxEnvelope bounds an uploaded attestation: real ones are kilobytes.
const maxEnvelope = 4 << 20

func (o Options) consoleScan(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	m, _, err := s.Model(id, time.Now())
	if errors.Is(err, airlock.ErrNoModel) || (err == nil && m.Location != "staging") {
		writeError(w, http.StatusNotFound, "no staged model "+id)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m.ArtifactPath == "" {
		writeError(w, http.StatusUnprocessableEntity, m.StageReason)
		return
	}
	prov := filepath.Join(filepath.Dir(m.ArtifactPath), airlock.ProvenanceFile)
	d, err := engine.ScanWith(m.ArtifactPath, engine.ModeFull, engine.Inputs{Provenance: prov})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.SaveReport(id, d); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m, _, _ = s.Model(id, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"report": d, "model": m})
}

func (o Options) consoleAttestation(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelope+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(raw) > maxEnvelope {
		writeError(w, http.StatusRequestEntityTooLarge, "an attestation is at most 4 MiB")
		return
	}
	if !json.Valid(raw) {
		writeError(w, http.StatusBadRequest, "the body is not a JSON DSSE envelope")
		return
	}
	id := r.PathValue("id")
	name, err := s.SaveAttestation(id, raw, time.Now())
	if errors.Is(err, airlock.ErrNoModel) {
		writeError(w, http.StatusNotFound, "no staged model "+id)
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m, _, _ := s.Model(id, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"file": name, "model": m})
}
```

`readJSON` is not used here: the envelope must be kept byte for byte, because the signature covers it.

Register in `routes()`:

```go
		{"POST /api/airlock/models/{id}/scan", writeAccess, limit(o.consoleScan)},
		{"POST /api/airlock/models/{id}/attestation", writeAccess, o.consoleAttestation},
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/engine ./internal/api -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -l cmd internal
git add internal/engine internal/api
git commit -s -m "api: scan a staged model with its provenance; upload a signed attestation, verified on save

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: The inventory statement (`internal/inventory`)

**Files:**
- Create: `internal/inventory/inventory.go`
- Test: `internal/inventory/inventory_test.go`

**Interfaces:**
- Consumes: `airlock.Model`, `airlock.VerifyFile`, `attest.Verify`, `attest.Keyring`, `attest.PrivateKey`, `dsse.Sign`, `dsse.Verify`.
- Produces:

```go
const PredicateType = "https://socair.ai/inventory/v1"
type Entry struct { ID, Name, PromotionState, Issuer, SignerKeyID, AttestationSHA256 string; AcceptedSurfaces []string; AcceptanceExpires, PromotedAt string } // snake_case json
type Other struct { ID, Name string; Stage airlock.Stage; Reason string }
type Predicate struct { GeneratedUTC, LogHead, ToolVersion string; Models []Entry; Other []Other }
type Statement struct { Type string `json:"_type"`; Subject []Subject; PredicateType string; Predicate Predicate }
func Build(models []airlock.Model, attestations map[string][]byte, logHead, toolVersion string, at time.Time) Statement
func Sign(st Statement, k *attest.PrivateKey) (payload, envelope []byte, err error)
type VerifyOptions struct { AllowUnsigned bool }
func Verify(dir string, trusted attest.Keyring, opts VerifyOptions) (*Statement, error)
```

`Predicate.Other` holds every listed entry that is not approved: pending entries, and clean entries that are `does-not-verify` or `acceptance-expired`. Each carries its stage and reason, so the snapshot hides nothing. This is the spec's `pending` field, renamed to `other` because it also covers clean entries that fail.

- [ ] **Step 1: Write the failing tests**

`internal/inventory/inventory_test.go`:

```go
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
)

// snapshotDir writes a minimal snapshot by hand: one approved entry whose
// attestation file is env, a one-line chained log, and the signed statement.
func snapshotDir(t *testing.T, k *attest.PrivateKey, env []byte, id string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "models", id), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "models", id, "attestation.dsse.json"), env, 0o644)
	line := []byte(`{"ts":"2026-10-04T00:00:00Z","action":"promote","outcome":"ok","sha256":"` + id + `","prev":"` + airlock.Genesis + "\"}\n")
	_ = os.WriteFile(filepath.Join(dir, "log.jsonl"), line, 0o644)
	head := sha256.Sum256(line[:len(line)-1])
	envSum := sha256.Sum256(env)
	st := Build([]airlock.Model{{ID: id, Name: "m", Location: "clean", Stage: airlock.StageApproved, PromotionState: "authorized"}},
		map[string][]byte{id: env}, hex.EncodeToString(head[:]), "socair test", time.Unix(0, 0))
	if st.Predicate.Models[0].AttestationSHA256 != hex.EncodeToString(envSum[:]) {
		t.Fatal("Build did not hash the attestation")
	}
	payload, signed, err := Sign(st, k)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "inventory.json"), payload, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), signed, 0o644)
	return dir
}
```

The fixture needs a real attestation signed by a trusted key. Generate one in the test with `attest.GenerateKey` and `attest.Sign`, from a document produced by `engine.Scan` on `safetensorstest.Clean()` with the three trust inputs set. Use the same steps as `authorizedArtifact` in `internal/airlock/promote_test.go`, copied into an `authorizedEnvelope(t) (env []byte, id string, k *attest.PrivateKey, ring attest.Keyring)` helper in this test file, since test helpers do not cross packages.

```go
func TestInventoryRoundTrip(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	dir := snapshotDir(t, k, env, id)
	st, err := Verify(dir, ring, VerifyOptions{})
	if err != nil || len(st.Predicate.Models) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
}

// Falsification: drop each check in Verify and its case passes.
func TestInventoryVerifyCatches(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	cases := map[string]func(dir string){
		"changed attestation": func(dir string) {
			p := filepath.Join(dir, "models", id, "attestation.dsse.json")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, append(b, ' '), 0o644)
		},
		"dropped attestation": func(dir string) { _ = os.RemoveAll(filepath.Join(dir, "models", id)) },
		"edited log": func(dir string) {
			p := filepath.Join(dir, "log.jsonl")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, []byte(strings.Replace(string(b), "promote", "promoTe", 1)), 0o644)
		},
		"truncated log": func(dir string) { _ = os.WriteFile(filepath.Join(dir, "log.jsonl"), nil, 0o644) },
		"edited statement": func(dir string) {
			p := filepath.Join(dir, "inventory.dsse.json")
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 1
			_ = os.WriteFile(p, b, 0o644)
		},
		"unsigned": func(dir string) { _ = os.Remove(filepath.Join(dir, "inventory.dsse.json")) },
	}
	for name, tamper := range cases {
		dir := snapshotDir(t, k, env, id)
		tamper(dir)
		if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// An untrusted verifier key refuses too.
	if _, err := Verify(snapshotDir(t, k, env, id), attest.Keyring{}, VerifyOptions{}); err == nil {
		t.Error("verified with no trusted key")
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/inventory -v`
Expected: FAIL (the package does not exist).

- [ ] **Step 3: Implement `inventory.go`**

```go
// Package inventory is a signed snapshot of an airlock store: which models
// are approved, on what attestation, and the activity log's head at the time.
// It is an in-toto Statement v1 (predicate type
// https://socair.ai/inventory/v1) in a DSSE envelope signed with Ed25519, the
// same machinery as attestations. Signing it makes the list itself
// tamper-evident: a model cannot be added or dropped without breaking it.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
)

const (
	PredicateType = "https://socair.ai/inventory/v1"
	statementType = "https://in-toto.io/Statement/v1"
)

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Entry struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	PromotionState    string   `json:"promotion_state"`
	Issuer            string   `json:"issuer,omitempty"`
	SignerKeyID       string   `json:"signer_key_id,omitempty"`
	AttestationSHA256 string   `json:"attestation_sha256"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
	PromotedAt        string   `json:"promoted_at,omitempty"`
}

type Other struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Stage  airlock.Stage `json:"stage"`
	Reason string        `json:"reason,omitempty"`
}

type Predicate struct {
	GeneratedUTC string  `json:"generated_utc"`
	LogHead      string  `json:"log_head"`
	ToolVersion  string  `json:"tool_version"`
	Models       []Entry `json:"models"`
	Other        []Other `json:"other"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Build makes the statement from the store's models. attestations maps an
// approved model's id to its attestation.dsse.json bytes.
func Build(models []airlock.Model, attestations map[string][]byte, logHead, toolVersion string, at time.Time) Statement {
	st := Statement{Type: statementType, PredicateType: PredicateType, Subject: []Subject{},
		Predicate: Predicate{GeneratedUTC: at.UTC().Format(time.RFC3339), LogHead: logHead, ToolVersion: toolVersion,
			Models: []Entry{}, Other: []Other{}}}
	for _, m := range models {
		if m.Stage != airlock.StageApproved {
			st.Predicate.Other = append(st.Predicate.Other, Other{ID: m.ID, Name: m.Name, Stage: m.Stage, Reason: m.StageReason})
			continue
		}
		sum := sha256.Sum256(attestations[m.ID])
		st.Subject = append(st.Subject, Subject{Name: m.Name, Digest: map[string]string{"sha256": m.ID}})
		st.Predicate.Models = append(st.Predicate.Models, Entry{ID: m.ID, Name: m.Name, PromotionState: m.PromotionState,
			Issuer: m.Issuer, SignerKeyID: m.SignerKeyID, AttestationSHA256: hex.EncodeToString(sum[:]),
			AcceptedSurfaces: m.AcceptedSurfaces, AcceptanceExpires: m.AcceptanceExpires, PromotedAt: m.PromotedAt})
	}
	return st
}

// Sign returns the statement's JSON and its DSSE envelope.
func Sign(st Statement, k *attest.PrivateKey) (payload, envelope []byte, err error) {
	payload, err = json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	envelope, err = dsse.Sign(payload, k.ID, k.Sign)
	return payload, envelope, err
}

type VerifyOptions struct {
	// AllowUnsigned checks an unsigned snapshot's contents (steps 2 to 4)
	// against its inventory.json. Without it an unsigned snapshot fails.
	AllowUnsigned bool
}

// Verify checks a snapshot directory:
//  1. the envelope verifies against trusted, and its predicate type is inventory/v1;
//  2. every listed attestation file is present and hashes to its recorded value;
//  3. every attestation verifies against trusted, for the listed id;
//  4. log.jsonl verifies as a hash chain whose head is the recorded log_head.
func Verify(dir string, trusted attest.Keyring, opts VerifyOptions) (*Statement, error) {
	var payload []byte
	env, err := os.ReadFile(filepath.Join(dir, "inventory.dsse.json"))
	switch {
	case err == nil:
		p, _, err := dsse.Verify(env, trusted)
		if err != nil {
			return nil, fmt.Errorf("the inventory signature does not verify: %w", err)
		}
		payload = p
		if plain, err := os.ReadFile(filepath.Join(dir, "inventory.json")); err == nil && !bytes.Equal(plain, payload) {
			return nil, errors.New("inventory.json differs from the signed statement")
		}
	case errors.Is(err, os.ErrNotExist) && opts.AllowUnsigned:
		payload, err = os.ReadFile(filepath.Join(dir, "inventory.json"))
		if err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		return nil, errors.New("the snapshot is unsigned (no inventory.dsse.json); export it with --key, or pass --allow-unsigned to check its contents only")
	default:
		return nil, err
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil || st.Type != statementType || st.PredicateType != PredicateType {
		return nil, errors.New("not a Socair inventory statement")
	}
	for _, e := range st.Predicate.Models {
		b, err := os.ReadFile(filepath.Join(dir, "models", e.ID, "attestation.dsse.json"))
		if err != nil {
			return nil, fmt.Errorf("%s: the listed attestation is missing", e.ID)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != e.AttestationSHA256 {
			return nil, fmt.Errorf("%s: the attestation file is not the one the inventory recorded", e.ID)
		}
		v, err := attest.Verify(b, trusted)
		if err != nil {
			return nil, fmt.Errorf("%s: the attestation does not verify: %w", e.ID, err)
		}
		if v.SHA256 != e.ID {
			return nil, fmt.Errorf("%s: the attestation is for %s", e.ID, v.SHA256)
		}
	}
	r, err := airlock.VerifyFile(filepath.Join(dir, "log.jsonl"), airlock.VerifyOptions{ExpectHead: st.Predicate.LogHead})
	if err != nil {
		return nil, err
	}
	if r.Broken != 0 || r.Head != st.Predicate.LogHead {
		return nil, fmt.Errorf("the activity log does not verify to the recorded head: %s", r.Reason)
	}
	return &st, nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/inventory -count=1 -v`
Expected: PASS. Every tamper case is refused.

- [ ] **Step 5: Commit**

```bash
gofmt -l cmd internal
git add internal/inventory
git commit -s -m "inventory: signed inventory/v1 statement of approved models, verified offline

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Export (`socair airlock export`, `socair inventory verify`, `POST /api/airlock/export`)

**Files:**
- Create: `internal/inventory/export.go`, `internal/inventory/index.html`
- Create: `cmd/socair/inventory.go`; modify `cmd/socair/airlock.go` and `cmd/socair/main.go`
- Modify: `internal/api/console.go`, `internal/api/routes.go`
- Test: `internal/inventory/export_test.go`, `internal/api/console_test.go` (add)

**Interfaces:**
- Produces:
  - `func Export(s *airlock.Store, dir string, key *attest.PrivateKey, at time.Time, toolVersion string) (*Statement, error)`. `key` may be nil, giving an unsigned snapshot.
  - CLI: `socair airlock export --out <dir> [--key <k>] [--store <p>]` and `socair inventory verify <dir> --trusted <keys> [--allow-unsigned]`.
  - `POST /api/airlock/export` (read, limited) returns `application/zip`.

- [ ] **Step 1: Write the failing tests**

`internal/inventory/export_test.go`:

```go
package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
)

func TestExportThenVerify(t *testing.T) {
	s, id, k, ring := promotedStore(t) // helper: Init a store, trust k's public key, Promote the authorized fixture
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err != nil {
		t.Fatalf("a fresh export must verify: %v", err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), id[:12]) || !strings.Contains(string(idx), "model inventory") || strings.Contains(string(idx), "UNSIGNED SNAPSHOT") {
		t.Fatalf("index.html: %s", idx)
	}
	if _, err := os.Stat(filepath.Join(dir, "models", id, "report.html")); err != nil {
		t.Fatal(err)
	}
	// No model bytes leave the store.
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".safetensors") {
			t.Errorf("model bytes exported: %s", p)
		}
		return nil
	})
}

func TestUnsignedExportSaysSo(t *testing.T) {
	s, _, _, ring := promotedStore(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, nil, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), "UNSIGNED SNAPSHOT") {
		t.Fatal("an unsigned snapshot must say so")
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
		t.Fatal("an unsigned snapshot must not verify without --allow-unsigned")
	}
	if _, err := Verify(dir, ring, VerifyOptions{AllowUnsigned: true}); err != nil {
		t.Fatalf("its contents check: %v", err)
	}
}

// Review Focus 5: a store with no approved models exports and verifies.
func TestExportEmptyStore(t *testing.T) {
	_, _, k, ring := promotedStore(t)
	s, err := airlock.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), "No approved models") {
		t.Fatal("an empty snapshot says so")
	}
}
```

`promotedStore(t)` lives in `export_test.go`. It:
1. calls `airlock.Init`;
2. builds `authorizedEnvelope` (Task 7's helper), whose key `k` it trusts via `s.TrustAs(pubPath, "Test Operator")`;
3. writes the fixture to a temp file;
4. writes the envelope to a temp file;
5. calls `airlock.Promote`.

It returns `(s, id, k, ring)`.

Append to `internal/api/console_test.go`:

```go
func TestConsoleExportIsAZip(t *testing.T) {
	root, _ := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	resp, err := http.Post(ts.URL+"/api/airlock/export", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/zip" || !bytes.HasPrefix(b, []byte("PK\x03\x04")) {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
```

Add `"bytes"` and `"io"` to that file's imports.

- [ ] **Step 2: Run to see them fail**

Run: `go test ./internal/inventory ./internal/api -run 'Export' -v`
Expected: FAIL (`Export` undefined; the route is missing).

- [ ] **Step 3: Implement `export.go` and `index.html`**

`internal/inventory/export.go`:

```go
package inventory

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/render"
)

//go:embed index.html
var indexTmpl string

var index = template.Must(template.New("index").Parse(indexTmpl))

// Export writes a snapshot of the store to dir: index.html, each approved
// model's report and attestation files, the log and its head, and the
// inventory statement, signed when key is set. It never copies model bytes or
// keys, and it refuses a store whose log chain is broken: a snapshot of a
// tampered log would not verify.
func Export(s *airlock.Store, dir string, key *attest.PrivateKey, at time.Time, toolVersion string) (*Statement, error) {
	chain, err := s.Verify(airlock.VerifyOptions{})
	if err != nil {
		return nil, err
	}
	if chain.Broken != 0 {
		return nil, fmt.Errorf("the activity log chain is broken at line %d (%s); resolve it before exporting", chain.Broken, chain.Reason)
	}
	models, err := s.Models(at)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "models"), 0o755); err != nil {
		return nil, err
	}
	attestations := map[string][]byte{}
	for _, m := range models {
		if m.Stage != airlock.StageApproved && m.Stage != airlock.StageAcceptanceExpired {
			continue
		}
		out := filepath.Join(dir, "models", m.ID)
		if err := os.MkdirAll(out, 0o755); err != nil {
			return nil, err
		}
		for _, name := range []string{"attestation.dsse.json", "attestation.json"} {
			p, err := s.EvidencePath(m.ID, name)
			if err != nil {
				return nil, err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
				return nil, err
			}
			if name == "attestation.dsse.json" {
				attestations[m.ID] = b
			}
		}
		_, d, err := s.Model(m.ID, at)
		if err != nil || d == nil {
			return nil, errors.New(m.ID + ": no verified report to render")
		}
		var html bytes.Buffer
		if err := render.Render(&html, d); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(out, "report.html"), html.Bytes(), 0o644); err != nil {
			return nil, err
		}
	}
	logBytes, err := os.ReadFile(s.LogPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "log.jsonl"), logBytes, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "log-head.txt"), []byte(chain.Head+"\n"), 0o644); err != nil {
		return nil, err
	}

	st := Build(models, attestations, chain.Head, toolVersion, at)
	var payload, envelope []byte
	if key != nil {
		payload, envelope, err = Sign(st, key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), envelope, 0o644); err != nil {
			return nil, err
		}
	} else if payload, err = jsonIndent(st); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.json"), payload, 0o644); err != nil {
		return nil, err
	}

	var page bytes.Buffer
	if err := index.Execute(&page, struct {
		St     Statement
		Signed bool
	}{st, key != nil}); err != nil {
		return nil, err
	}
	return &st, os.WriteFile(filepath.Join(dir, "index.html"), page.Bytes(), 0o644)
}
```

Add `jsonIndent` to `inventory.go`:

```go
func jsonIndent(st Statement) ([]byte, error) { return json.MarshalIndent(st, "", "  ") }
```

Also make `Sign` call `jsonIndent` for its payload, so signed and unsigned payloads are byte-identical in form.

`internal/inventory/index.html`:

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Socair model inventory, {{.St.Predicate.GeneratedUTC}}</title>
<style>
body{font:15px/1.5 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;max-width:1040px;margin:24px auto;padding:0 16px;color:#111}
.warn{border:1px solid #b91c1c;color:#b91c1c;padding:10px 14px;font-weight:700}
.note{border:1px solid #d7dade;padding:10px 14px;color:#3f4347}
table{border-collapse:collapse;width:100%;margin:12px 0}th,td{text-align:left;border-bottom:1px solid #e5e7eb;padding:6px 8px;vertical-align:top;font-size:14px}
.amber{color:#8a5a00}.red{color:#a32323}.ok{color:#0f7a4a}code{font-size:12px}
</style></head><body>
<h1>Model inventory</h1>
{{if not .Signed}}<p class="warn">UNSIGNED SNAPSHOT. Nothing here proves who made it. Export with <code>socair airlock export --key</code> for a signed snapshot, and check it with <code>socair inventory verify</code>.</p>{{end}}
<p class="note">This snapshot contains this site's model inventory. Share it internally only.</p>
<p>Generated {{.St.Predicate.GeneratedUTC}} by {{.St.Predicate.ToolVersion}}. Activity log head <code>{{.St.Predicate.LogHead}}</code>.</p>
<h2>Approved models</h2>
{{if .St.Predicate.Models}}<table><tr><th>Model</th><th>State</th><th>Issuer</th><th>Accepted gaps</th><th>Promoted</th></tr>
{{range .St.Predicate.Models}}<tr><td><a href="models/{{.ID}}/report.html">{{.Name}}</a><br><code>{{.ID}}</code></td>
<td>{{if eq .PromotionState "authorized_with_conditions"}}<span class="amber">authorized with conditions, until {{.AcceptanceExpires}}</span>{{else}}<span class="ok">authorized</span>{{end}}</td>
<td>{{.Issuer}}</td><td>{{range $i, $s := .AcceptedSurfaces}}{{if $i}}, {{end}}{{$s}}{{end}}</td><td>{{.PromotedAt}}</td></tr>{{end}}</table>
{{else}}<p>No approved models.</p>{{end}}
{{if .St.Predicate.Other}}<h2>Not approved</h2><table><tr><th>Model</th><th>Stage</th><th>Reason</th></tr>
{{range .St.Predicate.Other}}<tr><td>{{.Name}}<br><code>{{.ID}}</code></td><td class="{{if or (eq .Stage "does-not-verify") (eq .Stage "acceptance-expired") (eq .Stage "blocked")}}red{{end}}">{{.Stage}}</td><td>{{.Reason}}</td></tr>{{end}}</table>{{end}}
<p class="note">Each approved model's attestation.dsse.json is in models/&lt;id&gt;/ and verifies offline: <code>socair verify models/&lt;id&gt;/attestation.dsse.json --trusted &lt;operator.pub&gt;</code>. The whole snapshot: <code>socair inventory verify . --trusted &lt;operator.pub&gt;</code>.</p>
</body></html>
```

- [ ] **Step 4: CLI and API**

`cmd/socair/airlock.go`: add `case "export": return airlockExport(rest)` (match how the file dispatches its other subcommands), and:

```go
// airlockExport writes a snapshot of the store: socair airlock export --out <dir> [--key <k>] [--store <p>].
func airlockExport(args []string) error {
	fs := parseFlags(args)
	if fs.val("out") == "" {
		return errors.New("usage: socair airlock export --out <dir> [--key <operator.key>] [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	var k *attest.PrivateKey
	if fs.val("key") != "" {
		if k, err = attest.LoadPrivateKey(fs.val("key")); err != nil {
			return err
		}
	}
	st, err := inventory.Export(s, fs.val("out"), k, time.Now(), "socair "+engine.Version)
	if err != nil {
		return err
	}
	signed := "UNSIGNED (pass --key to sign)"
	if k != nil {
		signed = "signed by key " + attest.ShortID(k.ID)
	}
	fmt.Printf("exported %d approved model(s), %d other, %s, to %s\n", len(st.Predicate.Models), len(st.Predicate.Other), signed, fs.val("out"))
	return nil
}
```

`cmd/socair/inventory.go`:

```go
package main

import (
	"errors"
	"fmt"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/inventory"
)

// inventoryCmd: socair inventory verify <dir> --trusted <key.pub|dir> [--allow-unsigned]
func inventoryCmd(args []string) error {
	const usage = "usage: socair inventory verify <dir> --trusted <key.pub|dir> [--allow-unsigned]"
	if len(args) == 0 || args[0] != "verify" {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	if len(fs.pos) != 1 || fs.val("trusted") == "" {
		return errors.New(usage)
	}
	ring, err := attest.LoadKeyring(fs.val("trusted"))
	if err != nil {
		return err
	}
	st, err := inventory.Verify(fs.pos[0], ring, inventory.VerifyOptions{AllowUnsigned: fs.has("allow-unsigned")})
	if err != nil {
		return err
	}
	fmt.Printf("verified: %d approved model(s) as of %s, log head %s\n", len(st.Predicate.Models), st.Predicate.GeneratedUTC, st.Predicate.LogHead)
	return nil
}
```

In `cmd/socair/main.go`, add `case "inventory": return inventoryCmd(args[1:])` (following the file's existing pattern), and a usage line:
`  socair inventory verify <dir> --trusted <key.pub|dir>   verify an exported inventory snapshot`.
Also add under the airlock lines:
`  socair airlock export --out <dir> [--key <k>]   write a shareable, signed snapshot of the store`.

If `parseFlags` does not support boolean flags (`fs.has`), check `cmd/socair/flags.go` (or wherever `parseFlags` lives) and use the same pattern other commands use for a flag without a value.

API, in `internal/api/console.go` (imports `archive/zip`, `io/fs`, `github.com/defilantech/socair/internal/inventory`):

```go
func (o Options) consoleExport(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tmp, err := os.MkdirTemp("", "socair-export-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(tmp)
	at := time.Now()
	if _, err := inventory.Export(s, tmp, nil, at, "socair "+o.Version); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="socair-inventory-`+at.UTC().Format("20060102T150405Z")+`.zip"`)
	zw := zip.NewWriter(w)
	_ = filepath.WalkDir(tmp, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		f, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		return err
	})
	_ = zw.Close()
}
```

Register: `{"POST /api/airlock/export", readAccess, limit(o.consoleExport)},`. It is a read because it changes nothing in the store.

- [ ] **Step 5: Run the tests and a CLI round trip**

Run: `go test ./internal/inventory ./internal/api ./cmd/... -count=1`
Expected: PASS.

Then a manual end-to-end check in a scratch directory (no network). Use the promoted store left by the export test: there is no `airlock` CLI to create a promoted fixture without signing, so rely on the test.

- [ ] **Step 6: Commit**

```bash
gofmt -l cmd internal
git add internal/inventory cmd/socair internal/api
git commit -s -m "export: signed inventory snapshot (socair airlock export), socair inventory verify, and the console's zip

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Web API client for the console

**Files:**
- Modify: `web/src/lib/api.ts`
- Test: `web/src/lib/console-api.spec.ts`

**Interfaces:**
- Produces, in `api.ts`:
  - `export type Stage = 'staged'|'scanned'|'ready'|'needs-acceptance'|'blocked'|'approved'|'acceptance-expired'|'does-not-verify'`
  - `export interface Model { ...the Go json fields... }`
  - `export async function models(signal?): Promise<Model[]>`
  - `export async function model(id, signal?): Promise<{ model: Model; report: Document | null; events: AirlockEvent[] }>`
  - `export async function scanStaged(id): Promise<Model>`
  - `export async function uploadAttestation(id, envelope: string): Promise<Model>`
  - `export async function exportSnapshot(): Promise<Blob>`
  - `export function evidenceURL(id, name): string`
  - `AirlockEvent` gains `actor?: string`.

- [ ] **Step 1: Write the failing test**

`web/src/lib/console-api.spec.ts`:

```ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { models, model, uploadAttestation, evidenceURL, ApiError } from './api';

afterEach(() => vi.unstubAllGlobals());

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('console client', () => {
	it('lists models', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(200, { models: [{ id: 'a', stage: 'staged' }] })));
		expect((await models())[0].stage).toBe('staged');
	});

	it('never returns a stale list on failure', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'read clean: permission denied' })));
		await expect(models()).rejects.toBeInstanceOf(ApiError);
	});

	it('passes the envelope through byte for byte', async () => {
		const fetchMock = vi.fn(async () => json(200, { file: 'report.dsse.json', model: { id: 'a', stage: 'ready' } }));
		vi.stubGlobal('fetch', fetchMock);
		const env = '{"payloadType":"x", "payload":"e30=","signatures":[]}';
		await uploadAttestation('a', env);
		expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body).toBe(env);
	});

	it('carries the engine reason on a refused upload', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(422, { error: 'signed by key abc, which is not trusted' })));
		await expect(uploadAttestation('a', '{}')).rejects.toThrow('not trusted');
	});

	it('returns the detail with a null report', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => json(200, { model: { id: 'a' }, report: null, events: [] })));
		expect((await model('a')).report).toBeNull();
	});

	it('builds evidence URLs', () => {
		expect(evidenceURL('ab', 'report.dsse.json')).toBe('/api/airlock/models/ab/files/report.dsse.json');
	});
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd web && npx vitest run src/lib/console-api.spec.ts`
Expected: FAIL (the exports do not exist).

- [ ] **Step 3: Implement in `api.ts`** (append; add `actor?: string;` to `AirlockEvent`)

```ts
export type Stage =
	| 'staged'
	| 'scanned'
	| 'ready'
	| 'needs-acceptance'
	| 'blocked'
	| 'approved'
	| 'acceptance-expired'
	| 'does-not-verify';

export interface Model {
	id: string;
	name: string;
	format?: string;
	size_bytes?: number;
	location: 'staging' | 'clean';
	stage: Stage;
	stage_reason?: string;
	promotion_state?: string;
	issuer?: string;
	signer_key_id?: string;
	accepted_surfaces?: string[];
	accepted_by?: string;
	acceptance_expires?: string;
	expires_soon?: boolean;
	promoted_at?: string;
	next: { action: 'scan' | 'sign' | 'accept' | 'promote' | 'none'; command?: string };
}

export async function models(signal?: AbortSignal): Promise<Model[]> {
	const resp = await fetch('/api/airlock/models', { signal });
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { models?: Model[] }).models ?? [];
}

export async function model(
	id: string,
	signal?: AbortSignal
): Promise<{ model: Model; report: Document | null; events: AirlockEvent[] }> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}`, { signal });
	if (!resp.ok) await decodeError(resp);
	return await resp.json();
}

export async function scanStaged(id: string): Promise<Model> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}/scan`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: '{}'
	});
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { model: Model }).model;
}

// uploadAttestation sends a signed envelope unchanged: its signature covers
// the exact bytes.
export async function uploadAttestation(id: string, envelope: string): Promise<Model> {
	const resp = await fetch(`/api/airlock/models/${encodeURIComponent(id)}/attestation`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: envelope
	});
	if (!resp.ok) await decodeError(resp);
	return ((await resp.json()) as { model: Model }).model;
}

export async function exportSnapshot(): Promise<Blob> {
	const resp = await fetch('/api/airlock/export', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: '{}'
	});
	if (!resp.ok) await decodeError(resp);
	return await resp.blob();
}

export function evidenceURL(id: string, name: string): string {
	return `/api/airlock/models/${encodeURIComponent(id)}/files/${encodeURIComponent(name)}`;
}
```

- [ ] **Step 4: Run the web checks**

Run: `cd web && npm run check && npm run test`
Expected: 0 errors; all tests pass.

- [ ] **Step 5: Commit**

```bash
git add web/src/lib/api.ts web/src/lib/console-api.spec.ts
git commit -s -m "web: console API client (models, detail, scan, upload, export)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Display rules (`console.ts`)

**Files:**
- Create: `web/src/lib/console.ts`
- Test: `web/src/lib/console.spec.ts`

**Interfaces:**
- Produces:
  - `export type Tone = 'ok' | 'amber' | 'red' | 'neutral'`
  - `export function stageLabel(m: Model): string`
  - `export function stageTone(m: Model): Tone`
  - `export function isApprovedList(m: Model): boolean`, true for `approved`, `acceptance-expired` and `does-not-verify` in `clean`.

- [ ] **Step 1: Write the failing test**

`web/src/lib/console.spec.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { stageLabel, stageTone, isApprovedList } from './console';
import type { Model } from './api';

const m = (over: Partial<Model>): Model => ({
	id: 'a',
	name: 'n',
	location: 'clean',
	stage: 'approved',
	next: { action: 'none' },
	...over
});

describe('display rules', () => {
	it('conditional approval is amber, never green', () => {
		const c = m({ promotion_state: 'authorized_with_conditions', acceptance_expires: '2027-01-31T00:00:00Z' });
		expect(stageTone(c)).toBe('amber');
		expect(stageLabel(c)).toContain('conditions');
	});
	it('only a clean authorization is green', () => {
		expect(stageTone(m({ promotion_state: 'authorized' }))).toBe('ok');
	});
	it('what does not verify, an expired acceptance, and blocked are red', () => {
		for (const stage of ['does-not-verify', 'acceptance-expired', 'blocked'] as const) {
			expect(stageTone(m({ stage }))).toBe('red');
		}
	});
	it('labels an acceptance that expires soon', () => {
		expect(
			stageLabel(m({ promotion_state: 'authorized_with_conditions', expires_soon: true, acceptance_expires: 'x' }))
		).toContain('expires soon');
	});
	it('needs-acceptance never reads as approved', () => {
		const n = m({ stage: 'needs-acceptance', location: 'staging' });
		expect(stageTone(n)).not.toBe('ok');
		expect(isApprovedList(n)).toBe(false);
	});
	it('the approved list holds clean entries only', () => {
		expect(isApprovedList(m({ stage: 'does-not-verify' }))).toBe(true);
		expect(isApprovedList(m({ stage: 'ready', location: 'staging' }))).toBe(false);
	});
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd web && npx vitest run src/lib/console.spec.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `console.ts`**

```ts
import type { Model } from './api';

export type Tone = 'ok' | 'amber' | 'red' | 'neutral';

// stageTone maps the engine's stage to a colour. Only an unconditional
// authorization is green; conditions are amber; anything that does not
// verify, has lapsed, or is blocked is red.
export function stageTone(m: Model): Tone {
	switch (m.stage) {
		case 'approved':
			return m.promotion_state === 'authorized' ? 'ok' : 'amber';
		case 'does-not-verify':
		case 'acceptance-expired':
		case 'blocked':
			return 'red';
		case 'needs-acceptance':
			return 'amber';
		default:
			return 'neutral';
	}
}

export function stageLabel(m: Model): string {
	switch (m.stage) {
		case 'approved':
			if (m.promotion_state === 'authorized_with_conditions') {
				const until = m.acceptance_expires ? ` until ${m.acceptance_expires}` : '';
				return `approved with conditions${until}${m.expires_soon ? ' (expires soon)' : ''}`;
			}
			return 'approved';
		case 'does-not-verify':
			return 'does not verify';
		case 'acceptance-expired':
			return 'acceptance expired';
		case 'needs-acceptance':
			return 'needs acceptance';
		case 'ready':
			return 'ready to promote';
		default:
			return m.stage;
	}
}

export function isApprovedList(m: Model): boolean {
	return (
		m.location === 'clean' &&
		(m.stage === 'approved' || m.stage === 'acceptance-expired' || m.stage === 'does-not-verify')
	);
}
```

- [ ] **Step 4: Run the web checks**

Run: `cd web && npm run check && npm run test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/lib/console.ts web/src/lib/console.spec.ts
git commit -s -m "web: console display rules (conditions amber, failures red, never a false green)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Console pages

**Files:**
- Create: `web/src/lib/ReportView.svelte`, moved out of the `{:else}` branch of `web/src/routes/+page.svelte`.
- Move: `web/src/routes/+page.svelte` to `web/src/routes/scan/+page.svelte`.
- Create:
  - `web/src/routes/+page.svelte` (redirect)
  - `web/src/routes/approved/+page.svelte`
  - `web/src/routes/pending/+page.svelte`
  - `web/src/routes/models/[id]/+page.svelte`
  - `web/src/routes/activity/+page.svelte`
- Modify: `web/src/routes/+layout.svelte` (nav); `web/src/app.css` (`.tone-*`, `nav.console`, `pre.cmd`).

**Interfaces:**
- Consumes: Task 9's `api.ts` functions; Task 10's `console.ts`; the existing `statusPill`, `promotionPill`, `promotionLabel`, `counts`.

- [ ] **Step 1: Extract `ReportView.svelte`**

Create `web/src/lib/ReportView.svelte` with props `{ report: Document }`. Its body is the markup now in `+page.svelte` from `<p><span class="pill {promotionPill(d)}">` through the `{#if d.promotion_authorization.conditions}` block, with `d` replaced by `report`. Import `statusPill`, `promotionLabel`, `promotionPill` and `counts` from `$lib/report`, and compute `const c = $derived(counts(report))`. In the status line, replace `unsigned (OSS tier)` with `unsigned until signed (socair sign)`: open-source output is signed now.

In the scan page, replace that markup with `<ReportView report={run.report} />`, keeping the "Take the report" download block where it is.

- [ ] **Step 2: Move the scan page and add the redirect**

`git mv web/src/routes/+page.svelte web/src/routes/scan/+page.svelte`. Then create `web/src/routes/+page.svelte`:

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { health } from '$lib/api';

	// With a store, the console's home is the approved list; without one, the
	// scan page, as before.
	onMount(async () => {
		try {
			const h = await health();
			await goto(h.store === 'ready' ? '/approved' : '/scan', { replaceState: true });
		} catch {
			await goto('/scan', { replaceState: true });
		}
	});
</script>
```

- [ ] **Step 3: The nav in `+layout.svelte`**

```svelte
<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { health } from '$lib/api';

	let { children } = $props();
	let hasStore = $state(false);

	onMount(async () => {
		try {
			hasStore = (await health()).store === 'ready';
		} catch {
			hasStore = false;
		}
	});

	const links = [
		['/approved', 'Approved'],
		['/pending', 'Pending'],
		['/activity', 'Activity'],
		['/scan', 'Scan']
	];
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Socair: model assurance</title>
</svelte:head>

{#if hasStore}
	<nav class="console" aria-label="Console">
		{#each links as [href, label] (href)}
			<a {href} aria-current={page.url.pathname.startsWith(href) ? 'page' : undefined}>{label}</a>
		{/each}
	</nav>
{/if}

{@render children()}
```

- [ ] **Step 4: `approved/+page.svelte`**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { models, exportSnapshot, type Model } from '$lib/api';
	import { stageLabel, stageTone, isApprovedList } from '$lib/console';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let exporting = $state(false);

	onMount(async () => {
		try {
			list = (await models()).filter(isApprovedList);
		} catch (e) {
			list = null;
			error = e instanceof Error ? e.message : String(e);
		}
	});

	async function onExport() {
		exporting = true;
		try {
			const blob = await exportSnapshot();
			const a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = 'socair-inventory.zip';
			a.click();
			URL.revokeObjectURL(a.href);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			exporting = false;
		}
	}
</script>

<div class="shell">
	<h2>Approved models</h2>
	{#if error}
		<div class="state failed"><p class="error-title">The store could not be read</p><p>{error}</p></div>
	{:else if list === null}
		<p class="hint">Reading the store.</p>
	{:else if list.length === 0}
		<p>No approved models. Bring one in from <a href="/pending">Pending</a>.</p>
	{:else}
		<table>
			<thead><tr><th>Model</th><th>State</th><th>Issuer</th><th>Accepted gaps</th><th>Promoted</th></tr></thead>
			<tbody>
				{#each list as m (m.id)}
					<tr>
						<td class="check"><a href="/models/{m.id}">{m.name}</a><div class="hint">{m.id.slice(0, 12)} · {m.format ?? ''}</div></td>
						<td><span class="tone-{stageTone(m)}">{stageLabel(m)}</span>{#if m.stage_reason}<div class="hint">{m.stage_reason}</div>{/if}</td>
						<td>{m.issuer ?? ''}</td>
						<td>{(m.accepted_surfaces ?? []).join(', ')}</td>
						<td>{m.promoted_at ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<h2>Share a snapshot</h2>
	<p class="hint">
		An unsigned snapshot for a quick look. For leadership or an auditor, export a signed one:
	</p>
	<pre class="cmd">socair airlock export --out snapshot --key operator.key</pre>
	<div class="actions"><button type="button" onclick={onExport} disabled={exporting}>{exporting ? 'Exporting...' : 'Download unsigned snapshot'}</button></div>
</div>
```

- [ ] **Step 5: `pending/+page.svelte`**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { models, scanStaged, uploadAttestation, type Model } from '$lib/api';
	import { stageLabel, stageTone } from '$lib/console';

	let list = $state<Model[] | null>(null);
	let error = $state('');
	let busy = $state('');

	async function load() {
		try {
			list = (await models()).filter((m) => m.location === 'staging');
			error = '';
		} catch (e) {
			list = null;
			error = e instanceof Error ? e.message : String(e);
		}
	}
	onMount(load);

	async function act(m: Model, f: () => Promise<unknown>) {
		busy = m.id;
		try {
			await f();
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = '';
		}
	}

	async function onUpload(m: Model, ev: Event) {
		const file = (ev.currentTarget as HTMLInputElement).files?.[0];
		if (file) await act(m, async () => uploadAttestation(m.id, await file.text()));
	}

	const order = ['ready', 'needs-acceptance', 'scanned', 'staged', 'blocked', 'acceptance-expired', 'does-not-verify'];
	const groups = $derived(
		list ? order.map((s) => [s, list!.filter((m) => m.stage === s)] as const).filter(([, ms]) => ms.length > 0) : []
	);
</script>

<div class="shell">
	<h2>Pending</h2>
	{#if error}<div class="state failed"><p class="error-title">Something went wrong</p><p>{error}</p></div>{/if}
	{#if list === null && !error}<p class="hint">Reading the store.</p>{/if}
	{#if list && list.length === 0}<p>Nothing in staging. Pull a model with <code>socair airlock pull</code>, then scan it here.</p>{/if}
	{#each groups as [stage, ms] (stage)}
		<h3>{stage}</h3>
		{#each ms as m (m.id)}
			<div class="state">
				<p><a href="/models/{m.id}"><strong>{m.name}</strong></a> <span class="hint">{m.id.slice(0, 12)}</span> · <span class="tone-{stageTone(m)}">{stageLabel(m)}</span></p>
				{#if m.stage_reason}<p class="hint">{m.stage_reason}</p>{/if}
				{#if m.next.action === 'scan'}
					<button type="button" disabled={busy === m.id} onclick={() => act(m, () => scanStaged(m.id))}>{busy === m.id ? 'Scanning...' : 'Scan'}</button>
				{/if}
				{#if m.next.action === 'sign' || m.next.action === 'accept'}
					<p class="hint">This step needs a key, so it runs in the CLI:</p>
					<pre class="cmd">{m.next.command}</pre>
					<label>Or upload the signed result <input type="file" accept=".json" onchange={(ev) => onUpload(m, ev)} /></label>
				{/if}
				{#if m.next.action === 'promote'}
					<pre class="cmd">{m.next.command}</pre>
				{/if}
			</div>
		{/each}
	{/each}
</div>
```

Promotion stays the copyable CLI command, which the existing promote endpoint also serves. A Promote button posting `{artifact, attestation}` would need the artifact path, which the API deliberately does not send. Add it later as `POST /api/airlock/models/{id}/promote` only if operators ask for it.

- [ ] **Step 6: `models/[id]/+page.svelte`**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { model, evidenceURL, type Model, type Document, type AirlockEvent } from '$lib/api';
	import { stageLabel, stageTone } from '$lib/console';
	import ReportView from '$lib/ReportView.svelte';

	let m = $state<Model | null>(null);
	let report = $state<Document | null>(null);
	let events = $state<AirlockEvent[]>([]);
	let error = $state('');

	const files = ['provenance.json', 'report.json', 'report.dsse.json', 'report.conditional.dsse.json', 'attestation.json', 'attestation.dsse.json'];

	onMount(async () => {
		try {
			const out = await model(page.params.id ?? '');
			m = out.model;
			report = out.report;
			events = out.events;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	});
</script>

<div class="shell">
	{#if error}
		<div class="state failed"><p class="error-title">This model could not be read</p><p>{error}</p></div>
	{:else if m}
		<h2>{m.name}</h2>
		<p class="hint" style="overflow-wrap:anywhere">{m.location} · {m.id}</p>
		<p><span class="tone-{stageTone(m)}">{stageLabel(m)}</span>{#if m.stage_reason} · {m.stage_reason}{/if}</p>
		{#if m.issuer}<p>Issued by {m.issuer} · signed by key {m.signer_key_id?.slice(0, 16)}</p>{/if}
		{#if m.accepted_by}<p>Accepted by {m.accepted_by}: {(m.accepted_surfaces ?? []).join(', ')}, until {m.acceptance_expires}</p>{/if}
		{#if m.next.command}<pre class="cmd">{m.next.command}</pre>{/if}

		{#if report}
			<ReportView {report} />
		{:else}
			<p class="hint">No verified report to show.</p>
		{/if}

		<h2>Evidence</h2>
		<ul>{#each files as f (f)}<li><a href={evidenceURL(m.id, f)} download>{f}</a></li>{/each}</ul>
		<p class="hint">A file that is not part of this entry answers 404.</p>

		<h2>Activity</h2>
		<ul class="ledger">{#each events.slice().reverse() as e (e.ts + e.action)}<li>{e.ts} · {e.action} · {e.outcome}{e.actor ? ` · ${e.actor}` : ''}{e.detail ? `: ${e.detail}` : ''}</li>{/each}</ul>
	{:else}
		<p class="hint">Reading the model.</p>
	{/if}
</div>
```

- [ ] **Step 7: `activity/+page.svelte`**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { airlockLog, type AirlockEvent } from '$lib/api';

	let events = $state<AirlockEvent[] | null>(null);
	let error = $state('');
	let action = $state('');

	onMount(async () => {
		try {
			events = await airlockLog();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	});

	const shown = $derived((events ?? []).filter((e) => !action || e.action === action).slice().reverse());
</script>

<div class="shell">
	<h2>Activity</h2>
	{#if error}<div class="state failed"><p class="error-title">The log could not be read</p><p>{error}</p></div>{/if}
	<label>Action <select bind:value={action}><option value="">all</option>{#each ['pull', 'ingest', 'trust', 'promote', 'refuse'] as a (a)}<option value={a}>{a}</option>{/each}</select></label>
	<p class="hint">The log is hash-chained. Check it, and record the head somewhere this host cannot rewrite:</p>
	<pre class="cmd">socair airlock log --verify</pre>
	<ul class="ledger">{#each shown as e (e.ts + e.action + (e.sha256 ?? ''))}<li>{e.ts} · {e.action} · {e.outcome}{e.actor ? ` · ${e.actor}` : ''}{e.sha256 ? ` · ${e.sha256.slice(0, 12)}` : ''}{e.detail ? `: ${e.detail}` : ''}</li>{/each}</ul>
</div>
```

The spec's "Verify chain" button becomes the copyable command here, consistent with the other key or host-local steps. An API route for `log --verify` would be one more read route; add it only if an operator asks.

- [ ] **Step 8: CSS** (append to `web/src/app.css`)

```css
nav.console {
	display: flex;
	gap: 1.25rem;
	max-width: 1080px;
	margin: 0.75rem auto 0;
	padding: 0 1rem;
}
nav.console a[aria-current='page'] {
	font-weight: 700;
	text-decoration: underline;
}
.tone-ok {
	color: #0f7a4a;
	font-weight: 600;
}
.tone-amber {
	color: #8a5a00;
	font-weight: 600;
}
.tone-red {
	color: #a32323;
	font-weight: 700;
}
.tone-neutral {
	color: var(--ink-soft);
}
pre.cmd {
	white-space: pre-wrap;
	overflow-wrap: anywhere;
	background: #f4f5f6;
	border: 1px solid #e3e5e8;
	padding: 0.6rem 0.8rem;
	font-size: 0.85rem;
}
```

- [ ] **Step 9: Build and check**

Run: `cd web && npm run check && npm run test && npm run build`
Expected: 0 errors, all tests pass, and the build writes `web/build` with `200.html`.

Then a manual smoke run against a temp store:

```bash
go run ./cmd/socair airlock init /tmp/socair-console-store
go run ./cmd/socair serve --store /tmp/socair-console-store --web web/build
```

Open `http://127.0.0.1:8080/`. It should redirect to `/approved` and show "No approved models". Pending, Activity and Scan should load without errors.

- [ ] **Step 10: Commit**

```bash
git add web/src
git commit -s -m "web: console pages (approved, pending, model detail, activity) and a shared report view

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Docs and spec refinements

**Files:**
- Modify: `docs/api.md`, `docs/wizard.md`, `docs/airlock.md`, `docs/intake-host.md`, `README.md`, `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-10-04-airlock-console-design.md`

- [ ] **Step 1: `docs/api.md`.** Add a "Console endpoints" section listing the six routes with request and response shapes (the Interfaces of Tasks 5, 6 and 8). Note under the routes table that every route is classified read or write, and that the actor is `local-operator`.

- [ ] **Step 2: `docs/wizard.md`.** Add a "Console" section:
- the pages;
- that `/` goes to `/approved` when a store is configured;
- the display rules: conditions amber, failures red, only an unconditional authorization green, NOT_TESTED never a pass;
- that every key step is a copyable CLI command.

- [ ] **Step 3: `docs/airlock.md`.**
- In the store layout, add the staging evidence files (`report.json`, `report.dsse.json`, `report.acceptance.dsse.json`, `report.conditional.dsse.json`).
- Add an "Export and inventory" section with both commands and the four checks.
- Note that the console reads attestations but does not re-hash model bytes on display; re-running `socair airlock promote` re-verifies the bytes.

- [ ] **Step 4: `docs/intake-host.md`.** In "Bringing a model in", add that the console (`socair serve --store … --web web/build`) shows each step. In "The record", add the signed snapshot for leadership.

- [ ] **Step 5: `README.md` and `CLAUDE.md`.**
- README: one docs-table line for the console (in wizard.md) and the inventory export (in airlock.md).
- CLAUDE.md, Airlock paragraph: `Store.Assess` is the gate's one verification, used by `Promote` and the console; stages are derived from evidence (`Store.Models`); the inventory snapshot is `internal/inventory`.

- [ ] **Step 6: Spec refinements**, recorded in `docs/superpowers/specs/2026-10-04-airlock-console-design.md`:
- The staging evidence is the CLI's own output names (Task 2). Only the console's scan writes `report.json`; `airlock ingest --scan` does not, because it does not stage.
- The inventory's `pending` field is named `other` and also covers clean entries that do not verify or whose acceptance expired (Task 7).
- Promote and Verify chain are copyable commands in Step 1, not buttons (Task 11).

- [ ] **Step 7: Full check and commit**

```bash
gofmt -l cmd internal
go vet ./... && go test ./... -count=1
(cd web && npm run check && npm run test && npm run build)
git add docs README.md CLAUDE.md
git commit -s -m "docs: the airlock console, staging evidence, and the signed inventory export

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Then push the branch and open a PR. The PR body has no Claude Code links.
