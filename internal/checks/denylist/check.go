// Package denylist matches an artifact hash against a local list of known-bad
// artifacts.
//
// Offline by design: the list is a file on the appliance. No list means
// NOT_TESTED, never a silent pass.
package denylist

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

// Entry is one denylisted artifact.
type Entry struct {
	SHA256 string
	Label  string
}

// Load reads a denylist file. Each line is "<sha256>  <label>"; blank lines and
// lines starting with # are ignored. A line that does not start with a SHA-256
// refuses the whole list, as the feed loader does: a list that is partly
// wrong may be missing the entry that matters, so it is not matched against.
func Load(path string) (map[string]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := map[string]Entry{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		sha := strings.ToLower(fields[0])
		if _, err := hex.DecodeString(sha); err != nil || len(sha) != 64 {
			return nil, fmt.Errorf("%s line %d: %q is not a SHA-256", path, n, fields[0])
		}
		label := strings.Join(fields[1:], " ")
		entries[sha] = Entry{SHA256: sha, Label: label}
	}
	return entries, sc.Err()
}

// Check reports whether sha256hex is on the denylist at listPath.
func Check(sha256hex, listPath string) checks.Result {
	r := checks.Result{
		Name:     "Known-bad hash match",
		LooksFor: "Match against the known-bad artifact denylist",
	}

	sha := strings.ToLower(strings.TrimSpace(sha256hex))
	if sha == "" {
		r.Status = checks.NotTested
		r.Notes = "no artifact hash available to match"
		return r
	}
	if listPath == "" {
		r.Status = checks.NotTested
		r.Notes = "no denylist configured (set SOCAIR_DENYLIST to a local list file)"
		return r
	}

	entries, err := Load(listPath)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not read denylist: " + err.Error()
		return r
	}
	return Match(sha, entries, "denylist "+listPath)
}

// Match reports whether sha256hex is among entries, which came from source
// (named in the notes, so a reader knows what was matched against). No
// entries is NOT_TESTED: nothing was matched.
func Match(sha256hex string, entries map[string]Entry, source string) checks.Result {
	r := checks.Result{
		Name:     "Known-bad hash match",
		LooksFor: "Match against the known-bad artifact denylist",
	}
	sha := strings.ToLower(strings.TrimSpace(sha256hex))
	if sha == "" {
		r.Status = checks.NotTested
		r.Notes = "no artifact hash available to match"
		return r
	}
	if len(entries) == 0 {
		r.Status = checks.NotTested
		r.Notes = "the denylist is empty (" + source + "); nothing was matched against"
		return r
	}
	if e, ok := entries[sha]; ok {
		r.Status = checks.Fail
		label := e.Label
		if label == "" {
			label = "listed artifact"
		}
		r.Findings = append(r.Findings, checks.Finding{
			Pattern: "denylist-match",
			Span:    sha,
			Detail:  label,
		})
		r.Notes = "artifact hash is on the denylist: " + label
		return r
	}
	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("no entry matched among %d known-bad hashes (%s)", len(entries), source)
	return r
}
