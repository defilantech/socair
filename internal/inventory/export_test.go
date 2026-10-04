package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// promotedStore initializes a store, trusts the authorized fixture's signing
// key, and promotes the fixture into clean.
func promotedStore(t *testing.T) (s *airlock.Store, id string, k *attest.PrivateKey, ring attest.Keyring) {
	t.Helper()
	env, id, k, ring, pub := authorizedEnvelopeKey(t)
	s, err := airlock.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(pub); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "attestation.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Promote(s, artifact, envPath); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	return s, id, k, ring
}

func TestExportThenVerify(t *testing.T) {
	s, id, k, ring := promotedStore(t)
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
	// Only the snapshot layout leaves the store: no model bytes, no keys.
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, _ error) error {
		if fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if !allowedLayout.MatchString(filepath.ToSlash(rel)) && rel != "inventory.dsse.json" {
			t.Errorf("file outside the snapshot layout: %s", rel)
		}
		return nil
	})
}

var allowedLayout = regexp.MustCompile(`^(index\.html|log\.jsonl|log-head\.txt|inventory\.json|models/[0-9a-f]{64}/(report\.html|attestation\.json|attestation\.dsse\.json))$`)

func TestExportRefusesNonEmptyDir(t *testing.T) {
	s, _, k, _ := promotedStore(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(s, dir, nil, time.Now(), "socair test"); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("an unsigned export over a signed one must be refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "inventory.dsse.json")); err != nil {
		t.Fatal("the first snapshot must be untouched")
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "op.key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(s, other, k, time.Now(), "socair test"); err == nil {
		t.Fatal("a directory with an unrelated file must be refused")
	}
	if b, err := os.ReadFile(filepath.Join(other, "op.key")); err != nil || string(b) != "secret" {
		t.Fatal("the unrelated file must be untouched")
	}
	if _, err := os.Stat(filepath.Join(other, "index.html")); err == nil {
		t.Fatal("nothing may be written into a refused directory")
	}
	// An existing empty directory is fine.
	empty := t.TempDir()
	if _, err := Export(s, empty, k, time.Now(), "socair test"); err != nil {
		t.Fatalf("empty dir: %v", err)
	}
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

// A store with no approved models exports and verifies.
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

// Falsification: a log whose chain link is wrong refuses the export.
func TestExportRefusesBrokenChain(t *testing.T) {
	s, _, k, _ := promotedStore(t)
	f, err := os.OpenFile(s.LogPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"prev":"deadbeef","action":"promote"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Export(s, filepath.Join(t.TempDir(), "snap"), k, time.Now(), "socair test"); err == nil {
		t.Fatal("export must refuse a broken log chain")
	}
}

// conditionalStore promotes the fixture on a conditional attestation, the way
// the CLI does it: a withheld scan (no provenance manifest, so provenance is
// NOT_TESTED) is signed by the operator, an acceptor trusted by the store
// accepts it, and the re-issued report is signed again by the operator.
func conditionalStore(t *testing.T) (s *airlock.Store, id string, k *attest.PrivateKey, ring attest.Keyring) {
	t.Helper()
	return conditionalStoreWith(t, true)
}

// conditionalStoreWith builds a conditional (authorized with conditions)
// attestation and either promotes it, or only stages it with the envelope
// saved as staging evidence.
func conditionalStoreWith(t *testing.T, promote bool) (s *airlock.Store, id string, k *attest.PrivateKey, ring attest.Keyring) {
	t.Helper()
	_, id, k, ring, pub := authorizedEnvelopeKey(t)
	t.Setenv("SOCAIR_PROVENANCE", "")
	dir := t.TempDir()
	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if d.PromotionAuthorization.State != report.StateWithheld || len(d.Findings.NotTested) == 0 ||
		len(d.Findings.Fails)+len(d.Findings.Leads) != 0 {
		t.Fatalf("want withheld on gaps only: %s %+v", d.PromotionAuthorization.State, d.Findings)
	}
	reviewed, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.Verify(reviewed, ring)
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "acceptor")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	ak, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := attest.Accept(v, ak, "Jane Doe, CISO", time.Now().Add(40*24*time.Hour), "reviewed in change 4411", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	acceptors, err := attest.LoadKeyring(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	final, err := attest.Conditional(v, acc, acceptors, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(final, k)
	if err != nil {
		t.Fatal(err)
	}
	if s, err = airlock.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrustAcceptor(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	if !promote {
		staged := s.StagingPath(id)
		if err := os.MkdirAll(staged, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staged, "fixture.safetensors"), safetensorstest.Clean(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SaveAttestation(id, env, time.Now()); err != nil {
			t.Fatalf("SaveAttestation: %v", err)
		}
		return s, id, k, ring
	}
	envPath := filepath.Join(dir, "attestation.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Promote(s, artifact, envPath); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	return s, id, k, ring
}

// A staged conditional attestation whose acceptance has lapsed is
// acceptance-expired in staging, with no attestation.dsse.json in clean.
// Export must list it under other and still succeed: only clean entries are
// copied. Falsification: drop the location check in Export and it fails
// looking for the clean attestation.
func TestExportSkipsStagingOnlyExpiredEntry(t *testing.T) {
	s, id, _, _ := conditionalStoreWith(t, false)
	at := time.Now().Add(50 * 24 * time.Hour)
	st, err := Export(s, filepath.Join(t.TempDir(), "snap"), nil, at, "test")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(st.Predicate.Models) != 0 {
		t.Fatalf("a staging entry must not be listed as approved: %+v", st.Predicate.Models)
	}
	found := false
	for _, o := range st.Predicate.Other {
		if o.ID == id && o.Stage == airlock.StageAcceptanceExpired {
			found = true
		}
	}
	if !found {
		t.Fatalf("want %s under other as acceptance-expired, got %+v", id, st.Predicate.Other)
	}
}

// resign replaces a snapshot's statement with mutate applied, validly signed.
func resign(t *testing.T, dir string, k *attest.PrivateKey, mutate func(*Statement)) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	mutate(&st)
	payload, signed, err := Sign(st, k)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "inventory.json"), payload, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), signed, 0o644)
}

// The Model to Verify seam for a conditional entry: an unedited export
// verifies, with the acceptance carried in the entry, and re-signed edits to
// accepted_surfaces or acceptance_expires are refused against the
// attestation. Falsification: drop either conditional comparison in Verify
// and its case verifies.
func TestConditionalExportVerifiesAndTamperIsRefused(t *testing.T) {
	s, id, k, ring := conditionalStore(t)
	export := func() string {
		dir := filepath.Join(t.TempDir(), "snap")
		if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	v, err := Verify(export(), ring, VerifyOptions{})
	if err != nil {
		t.Fatalf("an unedited conditional export must verify: %v", err)
	}
	if len(v.Predicate.Models) != 1 || v.Predicate.Models[0].ID != id ||
		v.Predicate.Models[0].PromotionState != string(report.StateAuthorizedWithConditions) ||
		len(v.Predicate.Models[0].AcceptedSurfaces) == 0 || v.Predicate.Models[0].AcceptanceExpires == "" {
		t.Fatalf("%+v", v.Predicate.Models)
	}
	for name, mutate := range map[string]func(*Statement){
		"accepted_surfaces dropped": func(st *Statement) { st.Predicate.Models[0].AcceptedSurfaces = nil },
		"accepted_surfaces changed": func(st *Statement) { st.Predicate.Models[0].AcceptedSurfaces = []string{"Chat template"} },
		"acceptance_expires":        func(st *Statement) { st.Predicate.Models[0].AcceptanceExpires = "2099-01-01T00:00:00Z" },
	} {
		dir := export()
		resign(t, dir, k, mutate)
		if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// The readable attestation.json must say what the envelope signs.
// Falsification: drop sameDocument from Verify and both cases verify.
func TestTamperedAttestationJSONIsRefused(t *testing.T) {
	s, id, k, ring := promotedStore(t)
	for name, edit := range map[string]func([]byte) []byte{
		"edited field": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"state": "authorized"`, `"state": "authorized_with_conditions"`, 1))
		},
		"not a report": func([]byte) []byte { return []byte(`{"hello":"world"}`) },
	} {
		dir := filepath.Join(t.TempDir(), "snap")
		if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "models", id, "attestation.json")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		changed := edit(b)
		if string(changed) == string(b) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		_ = os.WriteFile(p, changed, 0o644)
		_, err = Verify(dir, ring, VerifyOptions{})
		if err == nil || !strings.Contains(err.Error(), id) {
			t.Errorf("%s: want a refusal naming %s, got %v", name, id, err)
		}
	}
}
