package engine

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/denylist"
	"github.com/defilantech/socair/internal/feed"
)

// references is the reference data the checks compare against: a verified
// signed feed (SOCAIR_FEED, checked against SOCAIR_FEED_KEYS) and a local
// denylist file (SOCAIR_DENYLIST). Either, both, or neither.
type references struct {
	feed     *feed.Feed
	deny     map[string]denylist.Entry
	denySrc  []string
	denyErr  string
	describe []string
}

// loadReferences reads and verifies the reference data. A feed that is
// configured but does not verify, or is expired, is an error: the scan does
// not run on unverified reference data, and does not quietly drop it either.
func loadReferences(now time.Time) (*references, error) {
	r := &references{deny: map[string]denylist.Entry{}}
	if dir := strings.TrimSpace(os.Getenv("SOCAIR_FEED")); dir != "" {
		keysPath := strings.TrimSpace(os.Getenv("SOCAIR_FEED_KEYS"))
		if keysPath == "" {
			return nil, errors.New("SOCAIR_FEED needs SOCAIR_FEED_KEYS, the public key(s) the feed must be signed by")
		}
		keys, err := attest.LoadKeyring(keysPath)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_FEED_KEYS: %w", err)
		}
		f, err := feed.Load(dir, keys, now)
		if err != nil {
			return nil, err
		}
		r.feed = f
		r.describe = append(r.describe, f.Describe())
		for h, label := range f.Denylist {
			r.deny[h] = denylist.Entry{SHA256: h, Label: label + " (feed " + f.Issuer + " " + f.Version + ")"}
		}
		if len(f.Denylist) > 0 {
			r.denySrc = append(r.denySrc, "feed "+f.Issuer+" "+f.Version)
		}
	}
	if p := strings.TrimSpace(os.Getenv("SOCAIR_DENYLIST")); p != "" {
		entries, err := denylist.Load(p)
		if err != nil {
			// As before #122: an unreadable local list leaves the row
			// NOT_TESTED with the reason, rather than stopping the scan.
			r.denyErr = "could not read denylist: " + err.Error()
		} else {
			for h, e := range entries {
				if _, ok := r.deny[h]; !ok {
					r.deny[h] = e
				}
			}
			r.denySrc = append(r.denySrc, "denylist "+p)
			r.describe = append(r.describe, "local denylist "+p)
		}
	}
	return r, nil
}

// denylist matches one hash against every configured list.
func (r *references) denylist(sha string) checks.Result {
	if r.denyErr != "" && len(r.denySrc) == 0 {
		return checks.Result{Name: "Known-bad hash match", LooksFor: "Match against the known-bad artifact denylist",
			Status: checks.NotTested, Notes: r.denyErr}
	}
	if len(r.denySrc) == 0 {
		return denylist.Check(sha, "")
	}
	return denylist.Match(sha, r.deny, strings.Join(r.denySrc, " + "))
}

// configured reports whether any denylist is in use.
func (r *references) configured() bool { return len(r.denySrc) > 0 || r.denyErr != "" }

// reviewedTemplates are the feed's reviewed chat-template hashes.
func (r *references) reviewedTemplates() map[string]struct{} {
	if r.feed == nil {
		return nil
	}
	return r.feed.Templates
}

// tokenizerNote is an informational line comparing a tokenizer hash to the
// feed's canonical tokenizers. It never changes a status: a fine-tune may add
// tokens legitimately, and judging a mismatch needs the model's family.
func (r *references) tokenizerNote(hash string) string {
	if r.feed == nil || len(r.feed.Tokenizers) == 0 || hash == "" {
		return ""
	}
	if name, ok := r.feed.Tokenizers[strings.ToLower(hash)]; ok {
		return " Tokenizer matches the canonical " + name + " tokenizer (feed " + r.feed.Issuer + " " + r.feed.Version + ")."
	}
	return " Tokenizer is not among the feed's canonical tokenizers (informational)."
}

// scope is the report's reference_data line.
func (r *references) scope() string { return strings.Join(r.describe, "; ") }
