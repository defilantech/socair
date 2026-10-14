package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/checks/denylist"
	"github.com/defilantech/socair/internal/checks/intake"
	"github.com/defilantech/socair/internal/checks/license"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/feed"
)

// references is the reference data the checks compare against: a verified
// signed feed (SOCAIR_FEED, checked against SOCAIR_FEED_KEYS) and a local
// denylist file (SOCAIR_DENYLIST). Either, both, or neither. Canonical
// tokenizer tables come from the feed and from SOCAIR_TOKENIZER_REFERENCE;
// reviewed template texts from the feed and from SOCAIR_TEMPLATE_REFERENCE.
//
// The operator's allowed licenses (SOCAIR_LICENSE_POLICY) are read here too:
// the License policy row compares against them, and with no policy (nil) the
// row is not added. So is the organization's intake policy
// (SOCAIR_INTAKE_POLICY), beside it and independent of it: the Intake policy
// row is likewise added only with a policy.
type references struct {
	feed      *feed.Feed
	deny      map[string]denylist.Entry
	denySrc   []string
	denyErr   string
	tables    []tokenizer.Table
	templates []chattemplate.Reference
	policy    *license.Policy
	intake    *intake.Policy
	describe  []string

	// local and localPath are the local SOCAIR_DENYLIST as read, kept apart
	// from deny (which merges it with the feed's list) for KnownBad.
	local     map[string]denylist.Entry
	localPath string
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
		if n := len(f.TemplateTexts); n > 0 {
			r.describe = append(r.describe, fmt.Sprintf("%d reviewed template text(s) from that feed", n))
		}
		hashes := make([]string, 0, len(f.TemplateTexts))
		for h := range f.TemplateTexts {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for _, h := range hashes {
			r.templates = append(r.templates, chattemplate.Reference{Label: f.Templates[h], Text: f.TemplateTexts[h]})
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
		tables, files, err := loadTokenizerReferences(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_TOKENIZER_REFERENCE: %w", err)
		}
		r.tables = append(r.tables, tables...)
		r.describe = append(r.describe, fmt.Sprintf("%d local tokenizer reference table(s) %s", len(tables), files))
	}
	// Local reviewed templates, like local tokenizer tables, are compared
	// with but never clear a lead: only a signed feed or the embedded
	// allowlist does that.
	if p := strings.TrimSpace(os.Getenv("SOCAIR_TEMPLATE_REFERENCE")); p != "" {
		refs, files, err := loadTemplateReferences(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_TEMPLATE_REFERENCE: %w", err)
		}
		r.templates = append(r.templates, refs...)
		r.describe = append(r.describe, fmt.Sprintf("%d local reviewed template text(s) %s", len(refs), files))
	}
	// A license policy that cannot be read, or names a license the catalogue
	// does not know, stops the scan: a misspelled id would fail every model.
	if p := strings.TrimSpace(os.Getenv("SOCAIR_LICENSE_POLICY")); p != "" {
		pol, err := loadLicensePolicy(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_LICENSE_POLICY: %w", err)
		}
		r.policy = pol
		r.describe = append(r.describe, pol.Describe())
	}
	// An intake policy that cannot be read, or that names a key, format, or
	// publisher it does not know, stops the scan the same way: a rule that
	// quietly failed to load would let through what it was written to stop.
	// The report names it in scope.intake_policy, not in reference_data.
	if p := strings.TrimSpace(os.Getenv("SOCAIR_INTAKE_POLICY")); p != "" {
		pol, err := intake.Load(p)
		if err != nil {
			return nil, fmt.Errorf("SOCAIR_INTAKE_POLICY: %w", err)
		}
		r.intake = pol
	}
	if p := strings.TrimSpace(os.Getenv("SOCAIR_DENYLIST")); p != "" {
		entries, f, err := loadDenylist(p)
		if err != nil {
			// As before #122: an unreadable local list leaves the row
			// NOT_TESTED with the reason, rather than stopping the scan.
			r.denyErr = "could not read denylist " + err.Error()
		} else {
			r.local, r.localPath = entries, p
			for h, e := range entries {
				if _, ok := r.deny[h]; !ok {
					r.deny[h] = e
				}
			}
			r.denySrc = append(r.denySrc, "denylist "+f.String())
			r.describe = append(r.describe, "local denylist "+f.String())
		}
	}
	return r, nil
}

// localFile is one local reference file as the scan read it. A report names
// it by its base name and the SHA-256 of the bytes the check used, never by
// its path on the scanning host: a filed report travels, a path can carry a
// username and a directory layout, and the hash names the exact contents.
type localFile struct {
	name string
	sha  string
	data []byte
}

func (f localFile) String() string { return f.name + " (sha256 " + f.sha + ")" }

// readLocal reads a local reference input once, so its hash names the bytes
// that were parsed: the file at p, or, when p is a directory and ext is set,
// each file in it whose name ends in ext, sorted. limit bounds each file; 0
// is no bound. An error may name the path as given: it stops the scan, and
// the one input whose error a report carries (the denylist) reduces it to a
// base name first.
func readLocal(p, ext string, limit int64) ([]localFile, bool, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, false, err
	}
	paths := []string{p}
	dir := info.IsDir()
	if dir {
		if ext == "" {
			return nil, true, errors.New("a directory, not a file")
		}
		if paths, err = filepath.Glob(filepath.Join(p, "*"+ext)); err != nil {
			return nil, true, err
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			return nil, true, fmt.Errorf("%s holds no %s file", p, ext)
		}
	}
	var out []localFile
	for _, f := range paths {
		b, err := readBounded(f, limit)
		if err != nil {
			return nil, dir, err
		}
		sum := sha256.Sum256(b)
		out = append(out, localFile{name: filepath.Base(f), sha: hex.EncodeToString(sum[:]), data: b})
	}
	return out, dir, nil
}

func readBounded(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit <= 0 {
		return io.ReadAll(f)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over the %d-byte limit", p, limit)
	}
	return b, nil
}

// named is how the report lists a local input's files: each by base name and
// hash, after the directory's base name when the input was a directory.
func named(p string, dir bool, files []localFile) string {
	parts := make([]string, len(files))
	for i, f := range files {
		parts[i] = f.String()
	}
	s := strings.Join(parts, ", ")
	if dir {
		s = "from " + filepath.Base(filepath.Clean(p)) + "/: " + s
	}
	return s
}

// hostless is an error's text as a report may carry it: a path the error
// names (an *fs.PathError's) reduced to its base name, so the path on the
// scanning host does not travel with the report.
func hostless(err error) string {
	msg := err.Error()
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Path != "" {
		msg = strings.ReplaceAll(msg, pe.Path, filepath.Base(pe.Path))
	}
	return msg
}

// loadDenylist reads a local denylist. Its error names the file by base name,
// because an unreadable list is reported in the row, not refused.
func loadDenylist(p string) (map[string]denylist.Entry, localFile, error) {
	files, _, err := readLocal(p, "", 0)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, localFile{}, fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	entries, err := denylist.Parse(bytes.NewReader(files[0].data))
	if err != nil {
		return nil, localFile{}, fmt.Errorf("%s: %w", files[0], err)
	}
	return entries, files[0], nil
}

// loadLicensePolicy reads the operator's license policy, named in the report
// by base name and hash.
func loadLicensePolicy(p string) (*license.Policy, error) {
	files, _, err := readLocal(p, "", 0)
	if err != nil {
		return nil, err
	}
	pol, err := license.ParsePolicy(files[0].name, bytes.NewReader(files[0].data))
	if err != nil {
		return nil, err
	}
	pol.Source = files[0].String()
	return pol, nil
}

// loadTokenizerReferences reads canonical tokenizer tables: a table file or
// tokenizer.json, or a directory of them (*.json). A table is named by its
// file name, or by its directory when the file is tokenizer.json.
func loadTokenizerReferences(p string) ([]tokenizer.Table, string, error) {
	files, dir, err := readLocal(p, ".json", tokenizer.MaxReferenceBytes)
	if err != nil {
		return nil, "", err
	}
	parent := filepath.Dir(p)
	if dir {
		parent = p
	}
	var out []tokenizer.Table
	for _, f := range files {
		name := strings.TrimSuffix(f.name, ".json")
		if name == "tokenizer" {
			name = filepath.Base(parent)
		}
		t, err := tokenizer.ParseTable(f.data, name)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", f.name, err)
		}
		out = append(out, t)
	}
	return out, named(p, dir, files), nil
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
// hashes (which clear language leads), every reviewed template text (which
// renders are compared with), and the artifact's special tokens.
func (r *references) templateOptions(t chattemplate.Tokens) chattemplate.Options {
	o := chattemplate.Options{References: r.templates, Tokens: t}
	if r.feed != nil {
		o.Reviewed = r.feed.Templates
	}
	return o
}

// maxReferenceTemplate bounds a local reviewed template, like the analyser's
// own limit.
const maxReferenceTemplate = 1 << 20

// loadTemplateReferences reads reviewed template texts: a .jinja file, or a
// directory of them, each labelled by its file name.
func loadTemplateReferences(p string) ([]chattemplate.Reference, string, error) {
	files, dir, err := readLocal(p, ".jinja", maxReferenceTemplate)
	if err != nil {
		return nil, "", err
	}
	var out []chattemplate.Reference
	for _, f := range files {
		out = append(out, chattemplate.Reference{Label: strings.TrimSuffix(f.name, ".jinja"), Text: string(f.data)})
	}
	return out, named(p, dir, files), nil
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
