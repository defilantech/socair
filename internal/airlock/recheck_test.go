package airlock

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/feed"
	"github.com/defilantech/socair/internal/report"
)

// feedSigner publishes signed feeds with one test key, as a feed issuer does.
type feedSigner struct {
	key *attest.PrivateKey
	pub string
}

func newFeedSigner(t *testing.T) feedSigner {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "feed-signer")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return feedSigner{key: k, pub: prefix + ".pub"}
}

// publish writes a feed whose denylist lists deny (hash to label), signs it,
// and points the engine at it, as an operator importing it would.
func (f feedSigner) publish(t *testing.T, version string, deny map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("# denylist.txt: <sha256> <label>\n")
	for h, label := range deny {
		b.WriteString(h + "  " + label + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "denylist.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// Each feed is issued after the one before, as an issuer's releases
	// are: a store refuses one that is not (CheckFeed).
	published++
	at := time.Now().UTC()
	info := feed.Info{Issuer: "Example Intel", Version: version,
		Issued:  at.Add(-time.Hour + time.Duration(published)*time.Second).Format(time.RFC3339),
		Expires: at.Add(30 * 24 * time.Hour).Format(time.RFC3339)}
	if err := feed.Sign(dir, info, f.key.ID, f.key.Sign); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_FEED", dir)
	t.Setenv("SOCAIR_FEED_KEYS", f.pub)
	return dir
}

// published counts the feeds the tests have issued, to order their issue
// times.
var published int

func noFeed(t *testing.T) {
	t.Setenv("SOCAIR_FEED", "")
	t.Setenv("SOCAIR_FEED_KEYS", "")
}

func lastEvent(t *testing.T, s *Store) Event {
	t.Helper()
	ev, err := s.Events()
	if err != nil || len(ev) == 0 {
		t.Fatalf("no log entry: %v", err)
	}
	return ev[len(ev)-1]
}

func chainIntact(t *testing.T, s *Store) {
	t.Helper()
	r, err := s.Verify(VerifyOptions{})
	if err != nil || r.Broken != 0 {
		t.Fatalf("the log chain must verify after a recheck: %+v %v", r, err)
	}
}

func recheckOnly(t *testing.T, s *Store, opts RecheckOptions) Recheck {
	t.Helper()
	got, err := s.Recheck(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("rechecked %d models, want 1", len(got))
	}
	return got[0]
}

// cleanFiles maps every file under a clean entry to its bytes.
func cleanFiles(t *testing.T, s *Store, id string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	root := s.CleanPath(id)
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(root, p)
		out[rel] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The issue's falsification: a model promoted before its hash appears in a
// feed shows as flagged after a recheck, with a log entry that names the
// feed. Neuter the match (KnownBad.Match, or matchKnownBad) and it stays
// approved, and this fails.
func TestRecheckFlagsAModelANewFeedLists(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved {
		t.Fatalf("before the feed: %+v", m)
	}
	before := cleanFiles(t, s, id)

	signer := newFeedSigner(t)
	signer.publish(t, "2026.10.2", map[string]string{id: "trojaned community upload, reported 2026-10"})
	rc := recheckOnly(t, s, RecheckOptions{})

	if rc.Outcome != OutcomeFlagged || len(rc.Flags) != 1 || rc.Flags[0].Kind != FlagKnownBad ||
		!strings.Contains(rc.Reason, "trojaned community upload") || !strings.Contains(rc.Reason, "feed Example Intel 2026.10.2") {
		t.Fatalf("a hash the feed lists must flag the model: %+v", rc)
	}
	if !rc.KnownBad.Checked || len(rc.KnownBad.Matches) != 1 || rc.KnownBad.Matches[0].SHA256 != id {
		t.Fatalf("known-bad level: %+v", rc.KnownBad)
	}
	if rc.Feed == nil || rc.Feed.Issuer != "Example Intel" || rc.Feed.Version != "2026.10.2" || rc.Feed.KeyID != signer.key.ID {
		t.Fatalf("the evidence must name the feed: %+v", rc.Feed)
	}
	if rc.Rescan.Due || rc.Rescan.Ran {
		t.Errorf("a feed alone needs no rescan: %+v", rc.Rescan)
	}

	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageFlagged || m.Location != "clean" || !strings.Contains(m.StageReason, "trojaned community upload") ||
		m.RecheckOutcome != OutcomeFlagged || m.RecheckedAt == "" {
		t.Fatalf("listing after the recheck: %+v", m)
	}
	// The attestation still says what it said; the flag sits beside it.
	if m.PromotionState != report.StateAuthorized || m.Issuer == "" {
		t.Errorf("the flagged listing must keep the attestation's state and issuer: %+v", m)
	}

	e := lastEvent(t, s)
	for _, want := range []string{"Example Intel", "2026.10.2", attest.ShortID(signer.key.ID), engine.CheckSetVersion} {
		if !strings.Contains(e.Detail, want) {
			t.Errorf("the log entry must name %q: %s", want, e.Detail)
		}
	}
	if e.Action != ActionRecheck || e.Outcome != OutcomeFlagged || e.SHA256 != id {
		t.Errorf("log entry %+v", e)
	}
	chainIntact(t, s)

	// Nothing moved, deleted, or re-signed: the only change is the evidence.
	after := cleanFiles(t, s, id)
	if _, ok := after[RecheckFile]; !ok {
		t.Fatal("the recheck must be recorded in the clean entry")
	}
	delete(after, RecheckFile)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("a recheck must not change the clean entry's artifact or attestation")
	}
	if names, err := s.Evidence(id); err != nil || !strings.Contains(strings.Join(names, ","), RecheckFile) {
		t.Errorf("the recheck evidence must be served: %v %v", names, err)
	}
}

// Falsification of the match itself: the same flow with the match against a
// list that does not name the hash leaves the model approved.
func TestRecheckFlagsOnlyWhatAListNames(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	newFeedSigner(t).publish(t, "2026.10.2", map[string]string{strings.Repeat("1", 64): "something else"})
	rc := recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeUnchanged || len(rc.Flags) != 0 {
		t.Fatalf("a list that does not name the model must not flag it: %+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved || m.RecheckOutcome != OutcomeUnchanged {
		t.Fatalf("%+v", m)
	}
}

// Unchanged models stay as they were: same listing apart from the recorded
// recheck, same files apart from its evidence. One model of two is listed.
func TestRecheckLeavesUnchangedModelsAsTheyWere(t *testing.T) {
	dir, dd := conditionalDirectory(t)
	s := trustedStore(t)
	if _, err := Promote(s, dir, acceptedTicket(t, s, dd, 40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	dirID := dd.Artifact.SHA256
	fileID := promoted(t, s)
	var config string
	for _, f := range dd.Artifact.Files {
		if f.Path == "config.json" {
			config = f.SHA256
		}
	}

	beforeModel := modelByID(t, s, fileID, time.Now())
	beforeFiles := cleanFiles(t, s, fileID)
	if beforeModel.Stage != StageApproved {
		t.Fatalf("%+v", beforeModel)
	}

	newFeedSigner(t).publish(t, "2026.10.2", map[string]string{config: "poisoned config"})
	got, err := s.Recheck(RecheckOptions{})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	outcomes := map[string]string{}
	for _, r := range got {
		outcomes[r.ID] = r.Outcome
	}
	if outcomes[dirID] != OutcomeFlagged || outcomes[fileID] != OutcomeUnchanged {
		t.Fatalf("outcomes %v", outcomes)
	}

	afterModel := modelByID(t, s, fileID, time.Now())
	if afterModel.RecheckOutcome != OutcomeUnchanged || afterModel.RecheckedAt == "" {
		t.Fatalf("%+v", afterModel)
	}
	afterModel.RecheckOutcome, afterModel.RecheckedAt, afterModel.RecheckReason = "", "", ""
	if !reflect.DeepEqual(beforeModel, afterModel) {
		t.Fatalf("an unchanged model's listing changed:\nbefore %+v\nafter  %+v", beforeModel, afterModel)
	}
	afterFiles := cleanFiles(t, s, fileID)
	delete(afterFiles, RecheckFile)
	if !reflect.DeepEqual(beforeFiles, afterFiles) {
		t.Fatal("an unchanged model's files changed")
	}
	if m := modelByID(t, s, dirID, time.Now()); m.Stage != StageFlagged || m.PromotionState != report.StateAuthorizedWithConditions {
		t.Fatalf("%+v", m)
	}
	chainIntact(t, s)
}

// A model directory is matched by every file hash its attestation lists, as
// a scan matches it, without reading the files.
func TestRecheckMatchesEveryFileOfADirectory(t *testing.T) {
	dir, d := conditionalDirectory(t)
	s := trustedStore(t)
	if _, err := Promote(s, dir, acceptedTicket(t, s, d, 40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var config string
	for _, f := range d.Artifact.Files {
		if f.Path == "config.json" {
			config = f.SHA256
		}
	}
	local := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(local, []byte(config+"  poisoned config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noFeed(t)
	t.Setenv("SOCAIR_DENYLIST", local)
	rc := recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeFlagged || len(rc.KnownBad.Matches) != 1 || rc.KnownBad.Matches[0].File != "config.json" ||
		!strings.Contains(rc.Reason, "file config.json") || !strings.Contains(rc.Reason, "denylist "+local) {
		t.Fatalf("a listed file in a directory must flag it: %+v", rc)
	}
	if rc.KnownBad.Hashes != len(d.Artifact.Files)+1 {
		t.Errorf("matched %d hashes, want the digest and %d files", rc.KnownBad.Hashes, len(d.Artifact.Files))
	}
	if e := lastEvent(t, s); !strings.Contains(e.Detail, "no feed") || !strings.Contains(e.Detail, "denylist "+local) {
		t.Errorf("log detail: %s", e.Detail)
	}
}

// A flag clears only when a later recheck re-examines it. A recheck with no
// list, and a promotion, leave it standing; a list that no longer names the
// hash clears it, and the evidence and the log say so.
func TestRecheckFlagClearsOnlyWhenReexamined(t *testing.T) {
	s := trustedStore(t)
	artifact, d := authorizedArtifact(t)
	ticket := writeReport(t, d)
	if _, err := Promote(s, artifact, ticket); err != nil {
		t.Fatal(err)
	}
	id := d.Artifact.SHA256
	localList := os.Getenv("SOCAIR_DENYLIST")
	signer := newFeedSigner(t)
	signer.publish(t, "2026.10.2", map[string]string{id: "known-bad"})
	if rc := recheckOnly(t, s, RecheckOptions{}); rc.Outcome != OutcomeFlagged {
		t.Fatalf("%+v", rc)
	}
	since := recheckOnly(t, s, RecheckOptions{}).Flags[0].Since

	// No list at all: nothing was re-examined, so the flag stands.
	noFeed(t)
	t.Setenv("SOCAIR_DENYLIST", "")
	rc := recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeFlagged || len(rc.Flags) != 1 || !rc.Flags[0].Carried || rc.Flags[0].Since != since ||
		!strings.Contains(rc.Reason, "it stands") {
		t.Fatalf("a recheck that matched nothing must carry the flag: %+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageFlagged {
		t.Fatalf("%+v", m)
	}

	// A promotion does not clear it either, and its log entry says so.
	if _, err := Promote(s, artifact, ticket); err != nil {
		t.Fatal(err)
	}
	if e := lastEvent(t, s); !strings.Contains(e.Detail, "stays flagged") {
		t.Errorf("promote detail: %s", e.Detail)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageFlagged {
		t.Fatalf("a promotion must not clear a flag: %+v", m)
	}

	// A newer feed that no longer lists the hash, read with the local list:
	// re-examined, so the flag clears, and the record says which it was.
	t.Setenv("SOCAIR_DENYLIST", localList)
	signer.publish(t, "2026.10.3", map[string]string{strings.Repeat("1", 64): "something else"})
	rc = recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeUnchanged || len(rc.Flags) != 0 || len(rc.Cleared) != 1 || rc.Cleared[0].Kind != FlagKnownBad ||
		!strings.Contains(rc.Reason, "cleared the known-bad flag") {
		t.Fatalf("a re-examined flag that no longer holds must clear, on the record: %+v", rc)
	}
	if e := lastEvent(t, s); !strings.Contains(e.Detail, "cleared") || !strings.Contains(e.Detail, "2026.10.3") {
		t.Errorf("the log must record the clear and the feed: %s", e.Detail)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved {
		t.Fatalf("%+v", m)
	}
	chainIntact(t, s)
}

// The engine's known-bad lists, with a configured local list unread: not a
// full match, so the outcome is incomplete, never unchanged.
func TestRecheckWithoutAListIsIncomplete(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	noFeed(t)
	t.Setenv("SOCAIR_DENYLIST", "")
	rc := recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeIncomplete || rc.KnownBad.Checked || !strings.Contains(rc.Reason, "no known-bad list is configured") {
		t.Fatalf("a recheck that matched against nothing must say so: %+v", rc)
	}
	t.Setenv("SOCAIR_DENYLIST", filepath.Join(t.TempDir(), "missing.txt"))
	rc = recheckOnly(t, s, RecheckOptions{})
	if rc.Outcome != OutcomeIncomplete || !strings.Contains(rc.Reason, "could not read denylist") {
		t.Fatalf("an unread list must leave the recheck incomplete: %+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved || m.RecheckOutcome != OutcomeIncomplete {
		t.Fatalf("an incomplete recheck neither flags nor clears: %+v", m)
	}
}

// A configured feed that does not verify stops the recheck before anything
// is written, as it stops a scan.
func TestRecheckStopsOnAFeedThatDoesNotVerify(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	newFeedSigner(t).publish(t, "2026.10.2", map[string]string{id: "known-bad"})
	t.Setenv("SOCAIR_FEED_KEYS", newFeedSigner(t).pub)
	logBefore, _ := os.ReadFile(s.LogPath())
	if _, err := s.Recheck(RecheckOptions{}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a feed signed by another key must stop the recheck: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.CleanPath(id), RecheckFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stopped recheck must write no evidence")
	}
	if logAfter, _ := os.ReadFile(s.LogPath()); !bytes.Equal(logBefore, logAfter) {
		t.Fatal("a stopped recheck must log nothing")
	}
}

// A changed check set rescans the clean bytes with the real engine. The same
// inputs give the same rows, so nothing changes.
func TestRecheckRescansWhenTheCheckSetChanged(t *testing.T) {
	s := trustedStore(t)
	artifact, d := authorizedArtifact(t)
	d.Scope.CheckSetVersion = "tier1/0.1"
	if _, err := Promote(s, artifact, writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	noFeed(t)
	rc := recheckOnly(t, s, RecheckOptions{})
	if !rc.Rescan.Due || !rc.Rescan.Ran || rc.Rescan.WouldWithhold || len(rc.Rescan.Changed) != 0 ||
		!strings.Contains(rc.Rescan.Why, "tier1/0.1") || rc.Outcome != OutcomeUnchanged {
		t.Fatalf("a check-set change must rescan, and the same rows change nothing: %+v", rc)
	}
	if rc.AttestedCheckSetVersion != "tier1/0.1" || rc.Rescan.CheckSetVersion != engine.CheckSetVersion {
		t.Errorf("%+v", rc)
	}
	if e := lastEvent(t, s); !strings.Contains(e.Detail, "attested tier1/0.1") || !strings.Contains(e.Detail, "rescanned") {
		t.Errorf("log detail: %s", e.Detail)
	}
}

// A rescan that grades a row LEAD would withhold the model, so it is flagged
// with the row named. The scan is replaced to stand for a newer check set.
// Falsification: drop the row comparison and this stays approved.
func TestRecheckRescanFlagsANewLead(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	noFeed(t)
	calls := 0
	prev := rescanWith
	t.Cleanup(func() { rescanWith = prev })
	rescanWith = func(path string, mode engine.Mode, in engine.Inputs) (*report.Document, error) {
		calls++
		d, err := prev(path, mode, in)
		if err != nil {
			return nil, err
		}
		d.Checks[0].Status = report.StatusLead
		d.Checks[0].Evidence = "instruction-override language: ignore previous instructions"
		return d, nil
	}

	// The check set is current: no rescan without --rescan.
	if rc := recheckOnly(t, s, RecheckOptions{}); rc.Rescan.Due || calls != 0 || rc.Outcome != OutcomeUnchanged {
		t.Fatalf("no rescan is due: %+v (%d calls)", rc, calls)
	}
	rc := recheckOnly(t, s, RecheckOptions{Rescan: true})
	if calls != 1 || rc.Outcome != OutcomeFlagged || len(rc.Flags) != 1 || rc.Flags[0].Kind != FlagRescan {
		t.Fatalf("a new LEAD must flag the model: %+v", rc)
	}
	if len(rc.Rescan.Changed) != 1 {
		t.Fatalf("one row changed: %+v", rc.Rescan.Changed)
	}
	name := rc.Rescan.Changed[0].Name
	if rc.Rescan.Changed[0].Was != "PASS" || rc.Rescan.Changed[0].Now != "LEAD" ||
		!strings.Contains(rc.Reason, name+" is LEAD (was PASS)") || rc.Rescan.Changed[0].Evidence == "" {
		t.Fatalf("the reason must name the row that changed: %+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageFlagged || !strings.Contains(m.StageReason, name) {
		t.Fatalf("%+v", m)
	}

	// A recheck without a rescan carries the rescan flag; one with clears it.
	rescanWith = prev
	if rc := recheckOnly(t, s, RecheckOptions{}); rc.Outcome != OutcomeFlagged || !rc.Flags[0].Carried {
		t.Fatalf("a rescan flag needs a rescan to clear: %+v", rc)
	}
	if rc := recheckOnly(t, s, RecheckOptions{Rescan: true}); rc.Outcome != OutcomeUnchanged || len(rc.Cleared) != 1 {
		t.Fatalf("%+v", rc)
	}
}

// With the real engine: a rescan that cannot test a row the attestation
// PASSed (here, no repository mirror) would withhold it on a gap no signed
// acceptance covers.
func TestRecheckRescanNamesANewGap(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	noFeed(t)
	t.Setenv("SOCAIR_REPO_MIRROR", "")
	rc := recheckOnly(t, s, RecheckOptions{Rescan: true})
	if rc.Outcome != OutcomeFlagged || !strings.Contains(rc.Reason, "is NOT_TESTED (was PASS) and no signed acceptance covers it") {
		t.Fatalf("a new gap must flag the model: %+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageFlagged {
		t.Fatalf("%+v", m)
	}
}

// A conditional model's accepted gaps are not new: a rescan that leaves them
// NOT_TESTED does not flag it. Falsification: ignore the accepted surfaces
// and this flags.
func TestRecheckRescanHonoursTheSignedAcceptance(t *testing.T) {
	dir, d := conditionalDirectory(t)
	s := trustedStore(t)
	if _, err := Promote(s, dir, acceptedTicket(t, s, d, 40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	noFeed(t)
	rc := recheckOnly(t, s, RecheckOptions{Rescan: true})
	if !rc.Rescan.Ran || rc.Rescan.WouldWithhold || rc.Rescan.PromotionState != report.StateWithheld {
		t.Fatalf("accepted gaps must not withhold on a rescan: %+v", rc.Rescan)
	}
	// Still incomplete: no known-bad list was read.
	if rc.Outcome != OutcomeIncomplete || len(rc.Flags) != 0 {
		t.Fatalf("%+v", rc)
	}
}

// Clean bytes changed after promotion no longer hash to their subject: a
// rescan flags that without comparing rows that describe other bytes.
func TestRecheckRescanCatchesChangedCleanBytes(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	noFeed(t)
	art := s.cleanArtifact(s.CleanPath(id))
	if err := os.Chmod(art, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art, []byte("not the attested bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := recheckOnly(t, s, RecheckOptions{Rescan: true})
	if rc.Outcome != OutcomeFlagged || !strings.Contains(rc.Reason, "not its attested subject") || len(rc.Rescan.Changed) != 0 {
		t.Fatalf("%+v", rc)
	}
}

// Evidence that cannot be read is not read as unflagged; the next recheck
// replaces it and says so.
func TestUnreadableRecheckEvidenceShowsFlagged(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	for _, body := range []string{"not json", `{"format":"socair.recheck/v1","id":"` + strings.Repeat("b", 64) + `","outcome":"unchanged"}`,
		`{"format":"socair.recheck/v1","id":"` + id + `","outcome":"unchanged","flags":[{"kind":"known-bad"}]}`} {
		if err := os.WriteFile(filepath.Join(s.CleanPath(id), RecheckFile), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if m := modelByID(t, s, id, time.Now()); m.Stage != StageFlagged || !strings.Contains(m.StageReason, "cannot be read") {
			t.Fatalf("%s: %+v", body, m)
		}
	}
	rc := recheckOnly(t, s, RecheckOptions{})
	if !strings.Contains(rc.Reason, "could not be read and is replaced") {
		t.Fatalf("%+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved {
		t.Fatalf("%+v", m)
	}
}

// A flagged clean entry has crossed: its staged copy is not offered for
// promotion again.
func TestFlaggedModelLeavesStaging(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if _, err := Promote(s, filepath.Join(s.StagingPath(id), "fixture.safetensors"), writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	newFeedSigner(t).publish(t, "2026.10.2", map[string]string{id: "known-bad"})
	if _, err := s.Recheck(RecheckOptions{}); err != nil {
		t.Fatal(err)
	}
	ms, err := s.Models(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Location != "clean" || ms[0].Stage != StageFlagged {
		t.Fatalf("only the flagged clean entry is listed: %+v", ms)
	}
}

// The evidence file is written whole and parses as what Recheck returned.
func TestRecheckEvidenceRoundTrips(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	newFeedSigner(t).publish(t, "2026.10.2", map[string]string{id: "known-bad"})
	rc := recheckOnly(t, s, RecheckOptions{})
	b, err := os.ReadFile(filepath.Join(s.CleanPath(id), RecheckFile))
	if err != nil {
		t.Fatal(err)
	}
	var got Recheck
	if err := json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(got, rc) {
		t.Fatalf("%v\n%+v\n%+v", err, got, rc)
	}
	if entries, _ := os.ReadDir(s.CleanPath(id)); len(entries) != 4 {
		t.Errorf("a temp file was left behind: %v", entries)
	}
}

// A clean entry whose attestation does not verify has no signed file list and
// no attested result: only its digest is matched, and the recheck says it is
// incomplete. A match on the digest still flags it, and the flag keeps the
// does-not-verify reason beside its own.
func TestRecheckOfAnEntryThatDoesNotVerify(t *testing.T) {
	dir, d := conditionalDirectory(t)
	s := trustedStore(t)
	if _, err := Promote(s, dir, acceptedTicket(t, s, d, 40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	id := d.Artifact.SHA256
	if err := os.RemoveAll(s.AcceptorPath()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageDoesNotVerify {
		t.Fatalf("%+v", m)
	}
	noFeed(t)
	list := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(list, []byte(strings.Repeat("1", 64)+"  another model\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", list)
	rc := recheckOnly(t, s, RecheckOptions{Rescan: true})
	if rc.Outcome != OutcomeIncomplete || rc.KnownBad.Checked || rc.KnownBad.Hashes != 1 || rc.Rescan.Ran ||
		!strings.Contains(rc.Reason, "manifest digest") || !strings.Contains(rc.Reason, "the attestation does not verify") {
		t.Fatalf("%+v", rc)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageDoesNotVerify || m.RecheckOutcome != OutcomeIncomplete {
		t.Fatalf("an incomplete recheck leaves the stage: %+v", m)
	}

	if err := os.WriteFile(list, []byte(id+"  known-bad repo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := recheckOnly(t, s, RecheckOptions{}); rc.Outcome != OutcomeFlagged {
		t.Fatalf("%+v", rc)
	}
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageFlagged || !strings.Contains(m.StageReason, "known-bad repo") || !strings.Contains(m.StageReason, "does-not-verify: ") {
		t.Fatalf("a flag outranks does-not-verify and keeps its reason: %+v", m)
	}
	// It was never approved here, so a staged copy of it would stay listed.
	if m.base != StageDoesNotVerify {
		t.Errorf("base %s", m.base)
	}
}
