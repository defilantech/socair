package airlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// A promoted model's attestation reflects the reference data and check set
// of its scan. A hash added to a known-bad list later, or a check that grades
// differently in a newer check set, does not touch it. Recheck re-examines
// the clean store against what a scan would use now and flags the models that
// would now be withheld.
//
// A recheck never acts on bytes: it moves, deletes, and re-signs nothing.
// It writes its result into each clean entry as evidence (RecheckFile) and
// appends one log entry per model. A model's stage is derived from that
// evidence (StageFlagged), so every listing says plainly that a flagged model
// is still in clean/.

// RecheckFile is the evidence a recheck writes into clean/<id>/.
const RecheckFile = "recheck.json"

// RecheckFormat names the recheck evidence format.
const RecheckFormat = "socair.recheck/v1"

// ActionRecheck is the log action of a recheck, one entry per clean model.
const ActionRecheck = "recheck"

// Recheck outcomes, per model, and the log outcome of its entry.
const (
	// OutcomeFlagged: the model would now be withheld, or an earlier flag
	// stands because this recheck did not re-examine it.
	OutcomeFlagged = "flagged"
	// OutcomeUnchanged: every level that was due ran and found nothing that
	// would withhold the model.
	OutcomeUnchanged = "unchanged"
	// OutcomeIncomplete: nothing was flagged, but a level that was due could
	// not run (a known-bad list that could not be read or fully matched, a
	// rescan that failed, an attestation that does not verify). It is not a
	// pass and clears no flag it did not re-examine. No known-bad list at all
	// is not a gap: that level does not run.
	OutcomeIncomplete = "incomplete"
)

// Flag kinds: what a flag rests on, and so what a later recheck must
// re-examine to clear it.
const (
	FlagKnownBad = "known-bad"
	FlagRescan   = "rescan"
)

// RecheckFeed is the signed feed a recheck read.
type RecheckFeed struct {
	Issuer  string `json:"issuer"`
	Version string `json:"version"`
	Issued  string `json:"issued"`
	Expires string `json:"expires"`
	KeyID   string `json:"key_id"`
}

// KnownBadMatch is one hash a known-bad list names.
type KnownBadMatch struct {
	SHA256 string `json:"sha256"`
	// File is the model directory's file with this hash; empty for the
	// entry's own hash (a file's SHA-256, or a directory's manifest digest).
	File string `json:"file,omitempty"`
	// Lists are the entries that name it, each "<label> (<source>)".
	Lists []string `json:"lists"`
}

// KnownBadRecheck is level 1: the entry's hashes matched against the
// known-bad lists, without reading the model's bytes.
type KnownBadRecheck struct {
	// Checked is true only when every hash was matched against every
	// configured list: a list was read, no configured list was unreadable,
	// and a directory's file list came from a verified attestation.
	Checked bool            `json:"checked"`
	Lists   []string        `json:"lists,omitempty"`
	Hashes  int             `json:"hashes"`
	Matches []KnownBadMatch `json:"matches,omitempty"`
	Note    string          `json:"note,omitempty"`
	// noList: no known-bad list is configured, so the level did not run. As
	// at scan time, that is not a gap (docs/feed.md); a configured list that
	// could not be read, or hashes it could not all be matched, are.
	noList bool
}

// RowChange is a check row whose status differs between the attestation and
// a rescan. "absent" stands for a row one of them does not have.
type RowChange struct {
	Name     string `json:"name"`
	Was      string `json:"was"`
	Now      string `json:"now"`
	Evidence string `json:"evidence,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// RescanRecheck is level 2: the engine's scan run again on the clean bytes
// and compared with the attestation.
type RescanRecheck struct {
	// Due is true when the check set changed or a rescan was requested.
	Due bool   `json:"due"`
	Why string `json:"why"`
	Ran bool   `json:"ran"`
	// Error is why a due rescan did not run.
	Error string `json:"error,omitempty"`
	// SHA256 is what the clean bytes hash to now.
	SHA256          string `json:"sha256,omitempty"`
	CheckSetVersion string `json:"check_set_version,omitempty"`
	ReferenceData   string `json:"reference_data,omitempty"`
	// PromotionState is the rescan's own state, before the attestation's
	// signed acceptance is applied; WouldWithhold applies it.
	PromotionState string      `json:"promotion_state,omitempty"`
	WouldWithhold  bool        `json:"would_withhold"`
	Withholding    []string    `json:"withholding,omitempty"`
	Changed        []RowChange `json:"changed,omitempty"`
}

// Flag is one reason a model would now be withheld.
type Flag struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	// Since is when a recheck first raised it.
	Since string `json:"since"`
	// Carried marks a flag an earlier recheck raised that this one did not
	// re-examine, so it stands.
	Carried bool `json:"carried,omitempty"`
}

// Recheck is one clean model's recheck, as written to RecheckFile.
type Recheck struct {
	Format          string `json:"format"`
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	CheckedUTC      string `json:"checked_utc"`
	ToolVersion     string `json:"tool_version"`
	CheckSetVersion string `json:"check_set_version"`
	// AttestedCheckSetVersion is the check set the attestation was scanned
	// under; empty when the attestation does not verify.
	AttestedCheckSetVersion string `json:"attested_check_set_version,omitempty"`
	// AttestationSHA256 is the SHA-256 of the attestation.dsse.json bytes
	// this recheck read.
	AttestationSHA256 string `json:"attestation_sha256,omitempty"`
	// Attestation is how the attestation assessed: "verifies", or why not.
	Attestation string          `json:"attestation"`
	Feed        *RecheckFeed    `json:"feed,omitempty"`
	KnownBad    KnownBadRecheck `json:"known_bad"`
	Rescan      RescanRecheck   `json:"rescan"`
	Flags       []Flag          `json:"flags,omitempty"`
	// Cleared are flags an earlier recheck raised that this one re-examined
	// and found no longer hold.
	Cleared []Flag `json:"cleared,omitempty"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// RecheckOptions configures Recheck.
type RecheckOptions struct {
	// Rescan rescans every clean model, not only those whose attestation
	// names another check set than this socair's.
	Rescan bool
}

// Test seams: the engine's known-bad lists and scan.
var (
	loadKnownBad = engine.LoadKnownBad
	rescanWith   = engine.ScanWith
)

// Recheck re-checks every model in the clean store, writes each result into
// its entry as RecheckFile, and logs one entry per model naming the feed, the
// lists, the check set, and the outcome. It returns the results in id order.
//
// Level 1 always runs: the entry's hash, and for a model directory every
// file hash its verified attestation lists, matched against the known-bad
// lists a scan would read now (the signed feed's denylist and any local
// SOCAIR_DENYLIST). It reads no model bytes. Level 2 runs when the
// attestation names another check set than this socair's, or for every model
// with opts.Rescan: the engine's scan of the clean bytes, compared row by row
// with the attestation. A model is flagged when a known-bad list names one of
// its hashes, or when the rescan would withhold it: a FAIL or LEAD row, a
// NOT_TESTED row the attestation's signed acceptance does not cover, or clean
// bytes that no longer hash to the attested subject.
//
// A configured feed that does not verify, or has expired, stops the recheck
// before anything is written, as it stops a scan. So does a feed older than
// the newest one the store has used (CheckFeed), whose refusal is logged.
func (s *Store) Recheck(opts RecheckOptions) ([]Recheck, error) {
	kb, err := loadKnownBad(now())
	if err != nil {
		return nil, err
	}
	// A feed older than the newest this store has used stops the recheck
	// too, before any evidence is written: it could clear a flag a newer
	// feed raised.
	if kb.Feed != nil {
		if err := s.CheckFeed(kb.Feed); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(s.cleanRoot())
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cleanDir, err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && hexSHA256.MatchString(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	var out []Recheck
	for _, id := range ids {
		prev, prevErr := s.readRecheck(id)
		rc := s.recheckOne(id, kb, opts, now())
		rc.settle(prev, prevErr)
		b, err := json.MarshalIndent(rc, "", "  ")
		if err != nil {
			return out, err
		}
		if err := s.WriteFile(filepath.Join(s.CleanPath(id), RecheckFile), append(b, '\n')); err != nil {
			return out, fmt.Errorf("record the recheck of %s: %w", id, err)
		}
		if err := s.Record(Event{Action: ActionRecheck, Outcome: rc.Outcome, SHA256: id, Detail: rc.logDetail()}); err != nil {
			return out, err
		}
		out = append(out, rc)
	}
	return out, nil
}

// recheckOne runs both levels for one clean entry. settle decides the
// outcome.
func (s *Store) recheckOne(id string, kb *engine.KnownBad, opts RecheckOptions, at time.Time) Recheck {
	dir := s.CleanPath(id)
	rc := Recheck{Format: RecheckFormat, ID: id, CheckedUTC: at.UTC().Format(time.RFC3339),
		ToolVersion: "socair " + engine.Version, CheckSetVersion: engine.CheckSetVersion}
	if f := kb.Feed; f != nil {
		rc.Feed = &RecheckFeed{Issuer: f.Issuer, Version: f.Version, Issued: f.Issued, Expires: f.Expires, KeyID: f.KeyID}
	}

	// The attestation, through the gate's own checks: its document is what
	// the rescan is compared with, and a directory's signed file list is
	// what level 1 matches.
	var doc *report.Document
	env, err := os.ReadFile(filepath.Join(dir, attestationEnvelope))
	if err != nil {
		rc.Attestation = "is missing: " + err.Error()
	} else {
		sum := sha256.Sum256(env)
		rc.AttestationSHA256 = hex.EncodeToString(sum[:])
		a, err := s.Assess(env, at)
		switch {
		case a != nil && a.SHA256 != id:
			rc.Attestation = fmt.Sprintf("does not verify: the attestation is for %s, not this entry", a.SHA256)
		case errors.Is(err, ErrAcceptanceExpired):
			doc = &a.Verified.Document
			rc.Attestation = "verifies, but " + err.Error()
		case err != nil:
			rc.Attestation = "does not verify: " + err.Error()
		case a.Admits() != nil:
			rc.Attestation = "does not admit: " + a.Admits().Error()
		default:
			doc = &a.Verified.Document
			rc.Attestation = "verifies"
		}
	}
	art := s.cleanArtifact(dir)
	if doc != nil {
		rc.Name = doc.Artifact.Name
		rc.AttestedCheckSetVersion = doc.Scope.CheckSetVersion
	} else if art != "" {
		rc.Name = filepath.Base(art)
	}

	rc.KnownBad = matchKnownBad(id, doc, art, kb)
	rc.Rescan = s.rescan(id, art, doc, opts.Rescan)
	return rc
}

// matchKnownBad is level 1.
func matchKnownBad(id string, doc *report.Document, art string, kb *engine.KnownBad) KnownBadRecheck {
	r := KnownBadRecheck{Lists: kb.Sources()}
	type hashed struct{ sha, file string }
	hashes := []hashed{{sha: id}}
	fileList := ""
	if doc != nil {
		for _, f := range doc.Artifact.Files {
			hashes = append(hashes, hashed{sha: normalizeSHA(f.SHA256), file: f.Path})
		}
	} else if fi, err := os.Stat(art); art == "" || err != nil {
		fileList = "only the entry's own hash was matched: the clean entry does not hold exactly one artifact"
	} else if fi.IsDir() {
		// A model directory's file hashes come only from its verified
		// attestation; the recheck reads no model bytes.
		fileList = "only the directory's manifest digest was matched: its file hashes come from a verified attestation, and it has none"
	}
	r.Hashes = len(hashes)
	for _, h := range hashes {
		if lists := kb.Match(h.sha); len(lists) > 0 {
			r.Matches = append(r.Matches, KnownBadMatch{SHA256: h.sha, File: h.file, Lists: lists})
		}
	}
	var notes []string
	if len(kb.Lists) == 0 && kb.Unread == "" {
		r.noList = true
		notes = append(notes, "no known-bad list is configured (SOCAIR_FEED with SOCAIR_FEED_KEYS, or SOCAIR_DENYLIST), so the known-bad match did not run")
	}
	if kb.Unread != "" {
		notes = append(notes, kb.Unread)
	}
	if fileList != "" {
		notes = append(notes, fileList)
	}
	r.Checked = len(kb.Lists) > 0 && kb.Unread == "" && fileList == ""
	r.Note = strings.Join(notes, "; ")
	return r
}

// rescan is level 2: due when the check set changed, or when requested.
func (s *Store) rescan(id, art string, doc *report.Document, force bool) RescanRecheck {
	var r RescanRecheck
	switch {
	case force:
		r.Due, r.Why = true, "requested (--rescan)"
	case doc == nil:
		r.Why = "not due: there is no verified attestation to compare a rescan with"
		return r
	case doc.Scope.CheckSetVersion != engine.CheckSetVersion:
		r.Due, r.Why = true, fmt.Sprintf("the check set changed: the attestation was scanned under %s, this socair runs %s",
			doc.Scope.CheckSetVersion, engine.CheckSetVersion)
	default:
		r.Why = "not due: the attestation was scanned under this check set, " + engine.CheckSetVersion
		return r
	}
	if doc == nil {
		r.Error = "not rescanned: without a verified attestation there is no attested result to compare with"
		return r
	}
	if art == "" {
		r.Error = "not rescanned: the clean entry does not hold exactly one artifact"
		return r
	}
	// The scan's inputs come from the environment, as for any scan, plus the
	// provenance manifest a pull wrote beside the staged copy, when there is
	// one; the engine counts it only if it names these bytes.
	in := engine.Inputs{Feed: s.CheckFeed}
	if p := filepath.Join(s.StagingPath(id), ProvenanceFile); fileExists(p) {
		in.Provenance = p
	}
	d, err := rescanWith(art, engine.ModeFull, in)
	if err != nil {
		r.Error = "the rescan did not run: " + err.Error()
		return r
	}
	r.Ran = true
	r.SHA256 = normalizeSHA(d.Artifact.SHA256)
	r.CheckSetVersion, r.ReferenceData, r.PromotionState = d.Scope.CheckSetVersion, d.Scope.ReferenceData, d.PromotionAuthorization.State
	if r.SHA256 != id {
		// The rows describe other bytes, so they are not compared.
		r.WouldWithhold = true
		r.Withholding = []string{fmt.Sprintf("the clean copy hashes to %s, not its attested subject %s; promote it again from the staged copy to restore it", r.SHA256, id)}
		return r
	}
	r.Changed, r.Withholding = compareRows(doc, d)
	r.WouldWithhold = len(r.Withholding) > 0
	return r
}

// compareRows compares a rescan's rows with the attestation's. A row
// withholds when it is a FAIL or a LEAD, or NOT_TESTED and not among the
// surfaces the attestation's signed acceptance covers.
func compareRows(was, now *report.Document) (changed []RowChange, withholding []string) {
	before := map[string]report.Status{}
	for _, c := range was.Checks {
		before[c.Name] = c.Status
	}
	accepted := map[string]bool{}
	if was.PromotionAuthorization.State == report.StateAuthorizedWithConditions {
		for _, n := range was.PromotionAuthorization.AcceptedSurfaces {
			accepted[n] = true
		}
	}
	seen := map[string]bool{}
	for _, c := range now.Checks {
		seen[c.Name] = true
		w, ok := before[c.Name]
		ws := string(w)
		if !ok {
			ws = "absent"
		}
		if !ok || w != c.Status {
			changed = append(changed, RowChange{Name: c.Name, Was: ws, Now: string(c.Status), Evidence: c.Evidence, Notes: c.Notes})
		}
		switch c.Status {
		case report.StatusFail, report.StatusLead:
			withholding = append(withholding, fmt.Sprintf("%s is %s (was %s)", c.Name, c.Status, ws))
		case report.StatusNotTested:
			if !accepted[c.Name] {
				withholding = append(withholding, fmt.Sprintf("%s is NOT_TESTED (was %s) and no signed acceptance covers it", c.Name, ws))
			}
		}
	}
	for _, c := range was.Checks {
		if !seen[c.Name] {
			changed = append(changed, RowChange{Name: c.Name, Was: string(c.Status), Now: "absent"})
		}
	}
	return changed, withholding
}

// settle raises this recheck's flags, carries or clears the previous
// recheck's, and sets the outcome and reason.
//
// A flag clears only when a later recheck re-examines what it rests on and
// finds it no longer holds: a known-bad flag needs every hash matched against
// every configured list (KnownBad.Checked), a rescan flag a rescan that ran.
// A recheck that covers less carries the flag forward. Evidence that could
// not be read is replaced, and the reason says so; the log keeps the record.
func (rc *Recheck) settle(prev *Recheck, prevErr error) {
	fresh := map[string]*Flag{}
	if len(rc.KnownBad.Matches) > 0 {
		var parts []string
		for _, m := range rc.KnownBad.Matches {
			what := "its hash"
			if m.File != "" {
				what = "file " + m.File
			}
			parts = append(parts, fmt.Sprintf("%s (%s) is on a known-bad list: %s", what, shortSHA(m.SHA256), strings.Join(m.Lists, "; ")))
		}
		fresh[FlagKnownBad] = &Flag{Kind: FlagKnownBad, Reason: strings.Join(parts, "; "), Since: rc.CheckedUTC}
	}
	if rc.Rescan.Ran && rc.Rescan.WouldWithhold {
		fresh[FlagRescan] = &Flag{Kind: FlagRescan, Since: rc.CheckedUTC,
			Reason: "a rescan under check set " + rc.Rescan.CheckSetVersion + " would withhold it: " + strings.Join(rc.Rescan.Withholding, "; ")}
	}
	reexamined := map[string]bool{FlagKnownBad: rc.KnownBad.Checked, FlagRescan: rc.Rescan.Ran}

	var carried []Flag
	if prev != nil {
		for _, f := range prev.Flags {
			switch {
			case fresh[f.Kind] != nil:
				if f.Since < fresh[f.Kind].Since {
					fresh[f.Kind].Since = f.Since
				}
			case reexamined[f.Kind]:
				f.Carried = false
				rc.Cleared = append(rc.Cleared, f)
			default:
				f.Carried = true
				carried = append(carried, f)
			}
		}
	}
	for _, k := range []string{FlagKnownBad, FlagRescan} {
		if f := fresh[k]; f != nil {
			rc.Flags = append(rc.Flags, *f)
		}
	}
	rc.Flags = append(rc.Flags, carried...)

	var reasons []string
	for _, f := range rc.Flags {
		r := f.Reason
		if f.Carried {
			r += fmt.Sprintf(" (raised by the recheck of %s; it stands because this recheck %s)", f.Since, notReexamined(f.Kind))
		}
		reasons = append(reasons, r)
	}
	var gaps []string
	if !rc.KnownBad.Checked && !rc.KnownBad.noList {
		gaps = append(gaps, "the known-bad match is incomplete: "+rc.KnownBad.Note)
	}
	if rc.Rescan.Due && !rc.Rescan.Ran {
		gaps = append(gaps, "the rescan was due ("+rc.Rescan.Why+") but did not run: "+rc.Rescan.Error)
	}
	if rc.Attestation != "verifies" && !strings.HasPrefix(rc.Attestation, "verifies, but") {
		gaps = append(gaps, "the attestation "+rc.Attestation)
	}
	var notes []string
	if prevErr != nil {
		notes = append(notes, "the earlier "+RecheckFile+" could not be read and is replaced: "+prevErr.Error())
	}
	for _, f := range rc.Cleared {
		notes = append(notes, fmt.Sprintf("cleared the %s flag raised at %s: this recheck re-examined it and it no longer holds", f.Kind, f.Since))
	}

	switch {
	case len(rc.Flags) > 0:
		rc.Outcome = OutcomeFlagged
		reasons = append(reasons, gaps...)
	case len(gaps) > 0:
		rc.Outcome = OutcomeIncomplete
		reasons = gaps
	default:
		rc.Outcome = OutcomeUnchanged
		r := "no known-bad match against " + strings.Join(rc.KnownBad.Lists, " + ")
		if rc.KnownBad.noList {
			r = "no known-bad list is configured, so no known-bad match ran"
		}
		if rc.Rescan.Ran {
			r += ", and a rescan under check set " + rc.Rescan.CheckSetVersion + " would not withhold it"
		}
		reasons = []string{r}
	}
	rc.Reason = strings.Join(append(reasons, notes...), "; ")
}

func notReexamined(kind string) string {
	if kind == FlagRescan {
		return "did not rescan"
	}
	return "did not match every hash against every configured known-bad list"
}

// logDetail names what the recheck read and what it found, for the log.
func (rc *Recheck) logDetail() string {
	parts := []string{rc.Reason}
	if f := rc.Feed; f != nil {
		parts = append(parts, fmt.Sprintf("feed %s %s, issued %s, expires %s, signed by key %s", f.Issuer, f.Version, f.Issued, f.Expires, attest.ShortID(f.KeyID)))
	} else {
		parts = append(parts, "no feed")
	}
	if len(rc.KnownBad.Lists) > 0 {
		parts = append(parts, "known-bad lists: "+strings.Join(rc.KnownBad.Lists, ", "))
	} else {
		parts = append(parts, "no known-bad list")
	}
	attested := rc.AttestedCheckSetVersion
	if attested == "" {
		attested = "unknown"
	}
	cs := fmt.Sprintf("check set %s (attested %s)", rc.CheckSetVersion, attested)
	switch {
	case rc.Rescan.Ran:
		cs += ", rescanned: " + rc.Rescan.Why
	case rc.Rescan.Due:
		cs += ", rescan did not run"
	default:
		cs += ", no rescan"
	}
	return strings.Join(append(parts, cs), "; ")
}

// readRecheck returns a clean entry's recheck evidence, or nil when it has
// none. Evidence that does not parse, is for another entry, or contradicts
// itself is an error: the caller must not read it as unflagged.
func (s *Store) readRecheck(id string) (*Recheck, error) {
	b, err := os.ReadFile(filepath.Join(s.CleanPath(id), RecheckFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rc Recheck
	if err := json.Unmarshal(b, &rc); err != nil {
		return nil, fmt.Errorf("%s does not parse: %v", RecheckFile, err)
	}
	switch {
	case rc.Format != RecheckFormat:
		return nil, fmt.Errorf("%s is not %s", RecheckFile, RecheckFormat)
	case rc.ID != id:
		return nil, fmt.Errorf("%s is for %s, not this entry", RecheckFile, rc.ID)
	case rc.Outcome != OutcomeFlagged && rc.Outcome != OutcomeUnchanged && rc.Outcome != OutcomeIncomplete:
		return nil, fmt.Errorf("%s has an unknown outcome %q", RecheckFile, rc.Outcome)
	case (rc.Outcome == OutcomeFlagged) != (len(rc.Flags) > 0):
		return nil, fmt.Errorf("%s contradicts itself: outcome %q with %d flag(s)", RecheckFile, rc.Outcome, len(rc.Flags))
	}
	return &rc, nil
}

// withRecheck applies a clean entry's recheck evidence to its derived stage.
// A flag outranks every other clean stage, whose reason it keeps. Evidence
// that cannot be read shows as flagged too: it may hold a flag, and an
// unreadable flag is not a cleared one.
func (s *Store) withRecheck(m Model, id string) Model {
	m.base = m.Stage
	also := ""
	if m.Stage != StageApproved && m.StageReason != "" {
		also = "; " + string(m.Stage) + ": " + m.StageReason
	}
	rc, err := s.readRecheck(id)
	switch {
	case err != nil:
		m.Stage = StageFlagged
		m.StageReason = "the recheck evidence cannot be read, so a flag it may hold is not cleared (" + err.Error() +
			"); run socair airlock recheck" + also
	case rc == nil:
	default:
		m.RecheckedAt, m.RecheckOutcome, m.RecheckReason = rc.CheckedUTC, rc.Outcome, rc.Reason
		if rc.Outcome != OutcomeFlagged {
			break
		}
		reason := rc.Reason
		if cur, err := hashFile(filepath.Join(s.CleanPath(id), attestationEnvelope)); err == nil && rc.AttestationSHA256 != "" && cur != rc.AttestationSHA256 {
			reason += "; the attestation was replaced after this recheck, which does not clear it: run socair airlock recheck"
		}
		m.Stage, m.StageReason = StageFlagged, reason+also
	}
	return m
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
