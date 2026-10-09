package engine

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/checks/denylist"
	"github.com/defilantech/socair/internal/checks/license"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/feed"
)

// references is the reference data the checks compare against: a verified
// signed feed (SOCAIR_FEED, checked against SOCAIR_FEED_KEYS) and a local
// denylist file (SOCAIR_DENYLIST). Either, both, or neither. Canonical
// tokenizer tables come from the feed and from SOCAIR_TOKENIZER_REFERENCE.
//
// The operator's allowed licenses (SOCAIR_LICENSE_POLICY) are read here too:
// the License policy row compares against them, and with no policy (nil) the
// row is not added.
type references struct {
	feed     *feed.Feed
	deny     map[string]denylist.Entry
	denySrc  []string
	denyErr  string
	tables   []tokenizer.Table
	policy   *license.Policy
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
		if n := len(f.TokenizerTables); n > 0 {
			r.describe = append(r.describe, fmt.Sprintf("%d tokenizer table(s) from that feed", n))
		}
		for h, label := range f.Denylist {
			r.deny[h] = denylist.Entry{SHA256: h, Label: label + " (feed " + f.Issuer + " " + f.Version + ")"}
		}
		if len(f.Denylist) > 0 {
			r.denySrc = append(r.denySrc, "feed "+f.Issuer+" "+f.Version)
		}
		names := make([]string, 0, len(f.TokenizerTables))
		for name := range f.TokenizerTables {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			t, err := tokenizer.ParseTable(f.TokenizerTables[name], name)
			if err != nil {
				return nil, fmt.Errorf("feed %s %s: tokenizer table %s: %w", f.Issuer, f.Version, name, err)
			}
			t.Name = name
			r.tables = append(r.tables, t)
		}
	}
	// A configured reference that cannot be read stops the scan, like a feed
	// that does not verify: a tokenizer row must not quietly lose its
	// reference.
	if p := strings.TrimSpace(os.Getenv("SOCAIR_TOKENIZER_REFERENCE")); p != "" {
		tables, err := tokenizer.LoadTables(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_TOKENIZER_REFERENCE: %w", err)
		}
		r.tables = append(r.tables, tables...)
		r.describe = append(r.describe, fmt.Sprintf("%d local tokenizer reference table(s) %s", len(tables), p))
	}
	// A license policy that cannot be read, or names a license the catalogue
	// does not know, stops the scan: a misspelled id would fail every model.
	if p := strings.TrimSpace(os.Getenv("SOCAIR_LICENSE_POLICY")); p != "" {
		pol, err := license.LoadPolicy(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_LICENSE_POLICY: %w", err)
		}
		r.policy = pol
		r.describe = append(r.describe, pol.Describe())
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

// denylist is the known-bad row for one hash.
func (r *references) denylist(sha string) checks.Result { return r.withUnread(r.match(sha)) }

// match matches one hash against every list that loaded.
func (r *references) match(sha string) checks.Result {
	if r.denyErr != "" && len(r.denySrc) == 0 {
		return checks.Result{Name: "Known-bad hash match", LooksFor: "Match against the known-bad artifact denylist",
			Status: checks.NotTested, Notes: r.denyErr}
	}
	if len(r.denySrc) == 0 {
		return denylist.Check(sha, "")
	}
	return denylist.Match(sha, r.deny, strings.Join(r.denySrc, " + "))
}

// withUnread keeps a row from passing over a configured local list that could
// not be read, even when a feed's list was matched: no one read the list the
// operator named. A match on another list still FAILs on its evidence.
func (r *references) withUnread(row checks.Result) checks.Result {
	if r.denyErr == "" || len(r.denySrc) == 0 || row.Status == checks.Fail {
		return row
	}
	row.Status = checks.NotTested
	row.Notes += "; " + r.denyErr
	return row
}

// loaded reports whether any denylist was read.
func (r *references) loaded() bool { return len(r.denySrc) > 0 }

// templateOptions are the chat-template check's inputs: the feed's reviewed
// hashes, which clear language leads, and the artifact's special tokens.
func (r *references) templateOptions(t chattemplate.Tokens) chattemplate.Options {
	o := chattemplate.Options{Tokens: t}
	if r.feed != nil {
		o.Reviewed = map[string]string{}
		for h := range r.feed.Templates {
			o.Reviewed[h] = ""
		}
	}
	return o
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

// compareTokenizer folds the canonical-table comparison into a tokenizer row.
func (r *references) compareTokenizer(row checks.Result, tokens []string, special func(int) bool) checks.Result {
	if len(tokens) == 0 {
		return row
	}
	return tokenizer.ApplyReference(row, tokenizer.Compare(tokens, special, r.tables))
}

// licenseRow grades the identified license against the operator's policy, or
// returns false when no policy is configured: the row is opt-in, so without
// a policy no report carries it and none is withheld for it. why says where a
// license would have been read, for a row that identified none.
func (r *references) licenseRow(id license.Identification, why string) (checks.Result, bool) {
	if r.policy == nil {
		return checks.Result{}, false
	}
	row := r.policy.Check(id)
	if row.Status == checks.NotTested && len(id.Identified()) == 0 && why != "" {
		row.Notes += " " + why
	}
	return row, true
}

// scope is the report's reference_data line.
func (r *references) scope() string { return strings.Join(r.describe, "; ") }
