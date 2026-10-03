// Package feed is Socair's signed reference data: the known-bad artifact
// hashes, reviewed known-good chat templates, and canonical tokenizers the
// checks compare against, delivered as a bundle an air-gapped site imports.
//
// A feed is a directory of data files and feed.dsse.json, an in-toto
// statement (predicate type https://socair.ai/feed/v1) signed with Ed25519
// that names each data file by its SHA-256 and states who issued the feed,
// its version, and when it was issued and expires. The format is open, so
// anyone can build and sign a feed; a curated, maintained feed is what a
// publisher such as Defilan sells.
//
// A feed is used only if it verifies: its signature against the configured
// feed keys, every data file against the hash the statement names, and its
// time window. Anything else is a configuration error, never a silent
// fallback, because a feed changes verdicts: a reviewed template clears a
// language lead, a known-bad hash fails an artifact.
//
// Data files, all optional, one entry per line, "#" comments:
//
//	denylist.txt    <sha256> <label>     known-bad artifacts (Known-bad hash match)
//	templates.txt   <sha256> [note]      reviewed chat templates (Chat template)
//	tokenizers.txt  <sha256> <name>      canonical tokenizers (Tokenizer config)
package feed

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/dsse"
)

const (
	// PredicateType names a Socair feed statement.
	PredicateType = "https://socair.ai/feed/v1"
	statementType = "https://in-toto.io/Statement/v1"
	// StatementFile is the signed statement inside a feed directory.
	StatementFile = "feed.dsse.json"

	maxFile = 64 << 20
)

// DataFiles are the files a feed may carry.
var DataFiles = []string{"denylist.txt", "templates.txt", "tokenizers.txt"}

// Info is what the feed says about itself.
type Info struct {
	Issuer      string `json:"issuer"`
	Version     string `json:"version"`
	Issued      string `json:"issued"`
	Expires     string `json:"expires"`
	Description string `json:"description,omitempty"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Info      `json:"predicate"`
}

// Feed is a verified feed.
type Feed struct {
	Info
	KeyID string
	// Denylist maps a known-bad artifact hash to its label.
	Denylist map[string]string
	// Templates holds reviewed chat-template hashes.
	Templates map[string]struct{}
	// Tokenizers maps a canonical tokenizer hash to its name.
	Tokenizers map[string]string
}

// Describe names the feed for a report.
func (f *Feed) Describe() string {
	return fmt.Sprintf("feed %s %s, issued %s, expires %s, signed by key %s",
		f.Issuer, f.Version, f.Issued, f.Expires, shortID(f.KeyID))
}

// Sign writes feed.dsse.json for the data files present in dir, signed by
// sign as keyID.
func Sign(dir string, info Info, keyID string, sign func([]byte) []byte) error {
	if strings.TrimSpace(info.Issuer) == "" || strings.TrimSpace(info.Version) == "" {
		return errors.New("a feed needs an issuer and a version")
	}
	issued, err := time.Parse(time.RFC3339, info.Issued)
	if err != nil {
		return fmt.Errorf("issued %q is not RFC 3339", info.Issued)
	}
	expires, err := time.Parse(time.RFC3339, info.Expires)
	if err != nil {
		return fmt.Errorf("expires %q is not RFC 3339", info.Expires)
	}
	if !expires.After(issued) {
		return errors.New("the feed expires before it is issued")
	}
	var subjects []subject
	for _, name := range DataFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := parse(name, b); err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		subjects = append(subjects, subject{Name: name, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}})
	}
	if len(subjects) == 0 {
		return fmt.Errorf("%s holds none of %s", dir, strings.Join(DataFiles, ", "))
	}
	payload, err := json.Marshal(statement{Type: statementType, Subject: subjects, PredicateType: PredicateType, Predicate: info})
	if err != nil {
		return err
	}
	env, err := dsse.Sign(payload, keyID, sign)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, StatementFile), env, 0o644)
}

// Load verifies the feed in dir against keys at now and returns its data.
func Load(dir string, keys map[string]ed25519.PublicKey, now time.Time) (*Feed, error) {
	raw, err := readBounded(filepath.Join(dir, StatementFile))
	if err != nil {
		return nil, fmt.Errorf("feed %s: %w", dir, err)
	}
	payload, keyID, err := dsse.Verify(raw, keys)
	if err != nil {
		return nil, fmt.Errorf("feed %s does not verify: %w", dir, err)
	}
	var st statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil || st.Type != statementType || st.PredicateType != PredicateType {
		return nil, fmt.Errorf("feed %s: not a Socair feed statement", dir)
	}
	issued, err1 := time.Parse(time.RFC3339, st.Predicate.Issued)
	expires, err2 := time.Parse(time.RFC3339, st.Predicate.Expires)
	switch {
	case err1 != nil || err2 != nil:
		return nil, fmt.Errorf("feed %s: issued and expires must be RFC 3339", dir)
	case now.Add(5 * time.Minute).Before(issued):
		return nil, fmt.Errorf("feed %s is issued in the future (%s)", dir, st.Predicate.Issued)
	case !now.Before(expires):
		return nil, fmt.Errorf("feed %s %s expired at %s; import a current feed", st.Predicate.Issuer, st.Predicate.Version, st.Predicate.Expires)
	}

	f := &Feed{Info: st.Predicate, KeyID: keyID, Denylist: map[string]string{}, Templates: map[string]struct{}{}, Tokenizers: map[string]string{}}
	listed := map[string]bool{}
	for _, s := range st.Subject {
		if !known(s.Name) || listed[s.Name] {
			return nil, fmt.Errorf("feed %s names %q, which is not a feed data file or is named twice", dir, s.Name)
		}
		listed[s.Name] = true
		b, err := readBounded(filepath.Join(dir, s.Name))
		if err != nil {
			return nil, fmt.Errorf("feed %s: %w", dir, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != strings.ToLower(s.Digest["sha256"]) {
			return nil, fmt.Errorf("feed %s: %s does not match its signed hash", dir, s.Name)
		}
		entries, err := parse(s.Name, b)
		if err != nil {
			return nil, fmt.Errorf("feed %s: %w", dir, err)
		}
		for h, v := range entries {
			switch s.Name {
			case "denylist.txt":
				f.Denylist[h] = v
			case "templates.txt":
				f.Templates[h] = struct{}{}
			case "tokenizers.txt":
				f.Tokenizers[h] = v
			}
		}
	}
	// A data file the signature does not cover is not part of the feed; its
	// presence means the directory is not what was signed.
	for _, name := range DataFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil && !listed[name] {
			return nil, fmt.Errorf("feed %s holds %s, which its signature does not cover", dir, name)
		}
	}
	return f, nil
}

func known(name string) bool {
	for _, n := range DataFiles {
		if n == name {
			return true
		}
	}
	return false
}

// parse reads one data file: "<sha256> <rest>" per line. Signed data is held
// to its format; a malformed line refuses the feed.
func parse(name string, b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		h := strings.ToLower(fields[0])
		if len(h) != 64 {
			return nil, fmt.Errorf("%s line %d: %q is not a SHA-256", name, n, fields[0])
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("%s line %d: %q is not a SHA-256", name, n, fields[0])
		}
		rest := strings.Join(fields[1:], " ")
		if name != "templates.txt" && rest == "" {
			return nil, fmt.Errorf("%s line %d: a %s entry needs a label", name, n, strings.TrimSuffix(name, ".txt"))
		}
		out[h] = rest
	}
	return out, sc.Err()
}

func readBounded(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(p), maxFile)
	}
	return b, nil
}

func shortID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
