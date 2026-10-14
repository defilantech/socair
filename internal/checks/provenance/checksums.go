package provenance

// Uploader checksum lists.
//
// A model repository sometimes ships its uploader's own list of SHA-256
// hashes: a SHA256SUMS file, or a <file>.sha256 sidecar. The scan reads each
// list as GNU coreutils' `sha256sum --check` reads it (coreutils 9.12,
// src/cksum.c: split_3, bsd_split_3, filename_unescape, digest_check) and
// compares every entry with the bytes the scan hashed. The list is the
// uploader's claim, so what it can show is consistency, never safety:
//
//   - a listed file whose bytes differ is a LEAD, since a list that no longer
//     matches its file is what a swapped file, or a partial re-upload, leaves
//     behind; a Markdown file is the exception, named and not graded, since
//     no loader reads one and a model card edited on the Hub after the list
//     was written is the commonest disagreement in real repositories;
//   - agreement is noted, never a PASS;
//   - a listed file the scan does not hold is noted, since a selected pull or
//     a partial download legitimately leaves files out;
//   - a listed name the scan does not hold, whose hash is that of a file the
//     scan does hold under another name, is noted as a rename;
//   - names resolve from the list's own directory, as sha256sum run there
//     resolves them; a list none of whose names is a file there is named and
//     not compared, never placed by a guess;
//   - a list, or a line, that does not parse is named, never guessed at.
//
// Every read is bounded, and a list past a bound is named and not read in
// part. docs/provenance-bundle.md describes the rules for a reader.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

const (
	// MaxChecksumListBytes bounds one list. A line is a 64-character hash,
	// two characters, and a path, so 4 MiB holds well over 10,000 entries,
	// the most files a directory scan reads (modeldir.MaxFiles).
	MaxChecksumListBytes = 4 << 20
	// MaxChecksumListLines bounds the lines of one list.
	MaxChecksumListLines = 50000
	// MaxChecksumBytes bounds all the lists one scan reads together.
	MaxChecksumBytes = 16 << 20
	// checksumNamed is how many items of one kind a note names before it
	// counts the rest.
	checksumNamed = 8
	// checksumFindings is how many disagreeing entries are findings; the rest
	// are counted in the notes.
	checksumFindings = 20
)

// isChecksumList reports whether the file at rel, a slash path, is read as
// an uploader's checksum list: SHA256SUMS, SHA256SUMS.txt, or
// checksums.sha256, in any case, or a <file>.sha256 sidecar beside the file
// it is named for (exists reports whether the scan holds a file). Other
// names are not read. Real repositories use them for lists of something
// else: an older release (checksums-v4.5.0.sha256, SHA256SUMS.v3), another
// repository's files (SOURCE_SHA256SUMS), or a staging area; and MD5 lists
// (checklist.chk, MD5SUMS) and JSON files are not SHA-256 lists in this
// format.
func isChecksumList(rel string, exists func(string) bool) bool {
	return listName(rel) || bareFor(rel, exists) != ""
}

// listName reports whether rel is named as a list of many files.
func listName(rel string) bool {
	switch strings.ToLower(path.Base(rel)) {
	case "sha256sums", "sha256sums.txt", "checksums.sha256":
		return true
	}
	return false
}

// bareFor is the name, relative to its own directory, of the file a sidecar
// at rel is named for, which a bare hash in it speaks of; "" when rel is a
// list name or no sidecar.
func bareFor(rel string, exists func(string) bool) string {
	if listName(rel) {
		return ""
	}
	if stem, ok := sidecarFor(rel); ok && exists(stem) {
		return path.Base(stem)
	}
	return ""
}

// sidecarFor returns the file a <file>.sha256 sidecar at rel is named for.
func sidecarFor(rel string) (string, bool) {
	const suffix = ".sha256"
	base := path.Base(rel)
	if len(base) <= len(suffix) || !strings.EqualFold(base[len(base)-len(suffix):], suffix) {
		return "", false
	}
	return rel[:len(rel)-len(suffix)], true
}

// checksumEntry is one checksum line: the name it lists and the hash.
type checksumEntry struct {
	line int
	name string // as listed, unescaped
	sum  string // lowercase hex
}

// parsedList is a list's checksum lines, and the lines that are not one.
type parsedList struct {
	entries   []checksumEntry
	malformed []int // line numbers, from 1
}

// parseChecksumList reads b as `sha256sum --check` reads a list. bareFor is
// the file a <file>.sha256 sidecar names by its own name, or "": a sidecar
// whose whole content is one 64-character hash is that file's hash, a form
// sha256sum does not read but real sidecars use. Anything else is read line
// by line, as coreutils does:
//
//   - a line beginning with '#' is a comment, and an empty line is skipped; a
//     trailing carriage return is dropped;
//   - leading blanks are skipped, and a backslash then marks an escaped name,
//     in which only \\, \n, and \r are escapes;
//   - the tagged form is "SHA256 (name) = hash", or OpenSSL's
//     "SHA256(name)= hash": the name runs to the last ')' on the line;
//   - the untagged form is the hash, one blank, then ' ' (text) or '*'
//     (binary) and the name; a list whose first such line has neither is in
//     the BSD reversed form, "hash name", and the two forms do not mix;
//   - the hash is exactly 64 hex digits, in either case;
//   - every character of the name counts, leading and trailing blanks
//     included.
//
// A line that is none of these is malformed: named by its number, never
// guessed at. So is a line holding a NUL byte, which coreutils cannot name a
// file by.
func parseChecksumList(b []byte, bareFor string) parsedList {
	var p parsedList
	if bareFor != "" {
		if t := strings.Trim(string(b), " \t\r\n"); isHex64(t) {
			p.entries = []checksumEntry{{line: 1, name: bareFor, sum: strings.ToLower(t)}}
			return p
		}
	}
	reversed := -1 // coreutils' bsd_reversed: unknown, 0 standard, 1 reversed
	lines := bytes.Split(b, []byte{'\n'})
	for i, raw := range lines {
		n := i + 1
		if i == len(lines)-1 && len(raw) == 0 {
			break // the newline that ends the last line
		}
		if len(raw) > 0 && raw[0] == '#' {
			continue
		}
		line := bytes.TrimSuffix(raw, []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		if bytes.IndexByte(line, 0) >= 0 {
			p.malformed = append(p.malformed, n)
			continue
		}
		e, ok := splitChecksumLine(string(line), &reversed)
		if !ok {
			p.malformed = append(p.malformed, n)
			continue
		}
		e.line = n
		p.entries = append(p.entries, e)
	}
	return p
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// splitChecksumLine is coreutils' split_3 for SHA-256.
func splitChecksumLine(s string, reversed *int) (checksumEntry, bool) {
	i := 0
	for i < len(s) && isBlank(s[i]) {
		i++
	}
	escaped := false
	if i < len(s) && s[i] == '\\' {
		i++
		escaped = true
	}
	if strings.HasPrefix(s[i:], "SHA256") {
		j := i + len("SHA256")
		if j < len(s) && s[j] == ' ' {
			j++
		}
		if j < len(s) && s[j] == '(' {
			return splitTagged(s[j+1:], escaped)
		}
	}
	rest := s[i:]
	// The hash, a blank, and at least one more character.
	if len(rest) < 64+1+1 {
		return checksumEntry{}, false
	}
	k := 0
	for k < len(rest) && !isBlank(rest[k]) {
		k++
	}
	if k == len(rest) || !isHex64(rest[:k]) {
		return checksumEntry{}, false
	}
	sum := strings.ToLower(rest[:k])
	rest = rest[k+1:]
	if len(rest) == 1 || (rest[0] != ' ' && rest[0] != '*') {
		// BSD reversed: the name follows the one blank.
		if *reversed == 0 {
			return checksumEntry{}, false
		}
		*reversed = 1
	} else if *reversed != 1 {
		*reversed = 0
		rest = rest[1:] // the ' ' or '*' mode flag
	}
	name := rest
	if escaped {
		var ok bool
		if name, ok = unescapeChecksumName(name); !ok {
			return checksumEntry{}, false
		}
	}
	return checksumEntry{name: name, sum: sum}, true
}

// splitTagged is coreutils' bsd_split_3: s follows the '('.
func splitTagged(s string, escaped bool) (checksumEntry, bool) {
	if s == "" {
		return checksumEntry{}, false
	}
	i := len(s) - 1
	for i > 0 && s[i] != ')' {
		i--
	}
	if s[i] != ')' {
		return checksumEntry{}, false
	}
	name := s[:i]
	if escaped {
		var ok bool
		if name, ok = unescapeChecksumName(name); !ok {
			return checksumEntry{}, false
		}
	}
	j := i + 1
	for j < len(s) && isBlank(s[j]) {
		j++
	}
	if j == len(s) || s[j] != '=' {
		return checksumEntry{}, false
	}
	j++
	for j < len(s) && isBlank(s[j]) {
		j++
	}
	if !isHex64(s[j:]) {
		return checksumEntry{}, false
	}
	return checksumEntry{name: name, sum: strings.ToLower(s[j:])}, true
}

// unescapeChecksumName is coreutils' filename_unescape: \\, \n, and \r are
// the only escapes, and a name ending in a lone backslash is invalid.
func unescapeChecksumName(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i == len(s)-1 {
			return "", false
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			return "", false
		}
	}
	return b.String(), true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// listedPath returns the path a list's entry resolves to, relative to the
// list's own directory (dir, "." at the top), as `sha256sum --check` resolves
// it when run there. It is "" with a reason when the name leaves the
// directory: an absolute path, or a ".." anywhere in it.
func listedPath(dir, name string) (string, string) {
	if name == "" {
		return "", "an empty name"
	}
	if strings.HasPrefix(name, "/") {
		return "", "an absolute path"
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", "a path that leaves the directory"
		}
	}
	return path.Join(dir, name), ""
}

// checksumList is one list the scan found, read or not.
type checksumList struct {
	path    string // slash path relative to the root
	sha256  string // of its bytes, for a list beside a single file
	notRead string // why it was not read, or ""
	parsedList
}

// heldFile is a file the scan hashed.
type heldFile struct{ path, sha256 string }

// checksumScan is the comparison of an artifact's checksum lists with the
// bytes the scan hashed.
type checksumScan struct {
	single   bool   // a single file, whose lists sit beside it
	artifact string // a single file's name
	lists    []checksumList
	held     []heldFile
	// leftOut are the files a selected repo pull left out, from a provenance
	// manifest bound to this artifact.
	leftOut []string

	agree      []string // paths whose bytes agree with a list
	findings   []checks.Finding
	disagreed  int
	notHeld    []string // listed paths the scan does not hold
	otherFiles int      // a single file's lists: entries naming other files
	renamed    []string // "listed as X; held as Y"
	outside    []string // "LIST line N: why"
	selfListed []string // lists that list themselves
	skipped    []string // listed paths under a directory the scan skips
	unplaced   []string // lists none of whose names is a file beside them
	notGraded  []string // Markdown files that disagree, named and not graded
	unlisted   []string // held files no list names
}

// readList reads one list, bounded, into l. budget is what the scan may still
// read of all its lists together. bareFor is the file a sidecar is named
// for, or "" for a list (see parseChecksumList).
func readList(l *checksumList, bareFor string, open func() (io.ReadCloser, int64, error), budget *int64) {
	r, size, err := open()
	if err != nil {
		l.notRead = "could not read it: " + reason(err)
		return
	}
	defer r.Close()
	if size > MaxChecksumListBytes {
		l.notRead = fmt.Sprintf("%d bytes, over the %d MiB bound for one list", size, MaxChecksumListBytes>>20)
		return
	}
	if size > *budget {
		l.notRead = fmt.Sprintf("past the %d MiB bound for all the lists one scan reads", MaxChecksumBytes>>20)
		return
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxChecksumListBytes+1))
	if err != nil {
		l.notRead = "could not read it: " + reason(err)
		return
	}
	if len(b) > MaxChecksumListBytes || int64(len(b)) > *budget {
		l.notRead = fmt.Sprintf("grew past its bound while read (%d bytes)", len(b))
		return
	}
	*budget -= int64(len(b))
	if n := bytes.Count(b, []byte{'\n'}); n > MaxChecksumListLines {
		l.notRead = fmt.Sprintf("%d lines, over the %d-line bound for one list", n, MaxChecksumListLines)
		return
	}
	sum := sha256.Sum256(b)
	l.sha256 = hex.EncodeToString(sum[:])
	l.parsedList = parseChecksumList(b, bareFor)
	if len(l.entries) == 0 {
		l.notRead = "no SHA-256 checksum line in it"
		if len(l.malformed) > 0 {
			l.notRead += " (" + lineNumbers(l.malformed) + " not in a checksum format)"
		}
	}
}

// dirChecksums reads the checksum lists among a directory scan's files, from
// its snapshot at root.
func dirChecksums(root string, files []modeldir.File) *checksumScan {
	s := &checksumScan{}
	held := map[string]bool{}
	for _, f := range files {
		held[f.Path] = true
	}
	exists := func(p string) bool { return held[p] }
	budget := int64(MaxChecksumBytes)
	for _, f := range files {
		s.held = append(s.held, heldFile{f.Path, f.SHA256})
		if !isChecksumList(f.Path, exists) {
			continue
		}
		l := checksumList{path: f.Path}
		size := f.Size
		readList(&l, bareFor(f.Path, exists), func() (io.ReadCloser, int64, error) {
			r, err := os.Open(filepath.Join(root, filepath.FromSlash(f.Path)))
			return r, size, err
		}, &budget)
		s.lists = append(s.lists, l)
	}
	return s
}

// fileChecksums reads the checksum lists in a single artifact's directory,
// beside it. They are not part of the attested bytes, so each is named with
// the SHA-256 of what was read.
func fileChecksums(artifact, sha string) *checksumScan {
	name := filepath.Base(artifact)
	s := &checksumScan{single: true, artifact: name}
	if sha != "" {
		s.held = []heldFile{{name, sha}}
	}
	dir := filepath.Dir(artifact)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return s
	}
	// Beside a single file, the only sidecar that speaks of it is its own.
	exists := func(p string) bool { return p == name }
	budget := int64(MaxChecksumBytes)
	for _, e := range ents {
		if e.Name() == name || !isChecksumList(e.Name(), exists) {
			continue
		}
		l := checksumList{path: e.Name()}
		p := filepath.Join(dir, e.Name())
		readList(&l, bareFor(e.Name(), exists), func() (io.ReadCloser, int64, error) {
			fi, err := os.Stat(p) // follows a symlink, as a Hugging Face cache snapshot is built of them
			if err != nil {
				return nil, 0, err
			}
			if !fi.Mode().IsRegular() {
				return nil, 0, errors.New("not a regular file")
			}
			r, err := os.Open(p)
			return r, fi.Size(), err
		}, &budget)
		s.lists = append(s.lists, l)
	}
	return s
}

// compare compares every read list with the held files.
func (s *checksumScan) compare() {
	held := map[string]string{}
	byHash := map[string][]string{}
	for _, f := range s.held {
		held[f.path] = f.sha256
		byHash[f.sha256] = append(byHash[f.sha256], f.path)
	}
	type unheld struct{ list, path, sum string }
	var missing []unheld
	named := map[string]bool{}   // held paths some entry names
	agreed := map[string]bool{}  // held paths some entry agrees with
	differs := map[string]bool{} // held paths some entry disagrees with
	for i := range s.lists {
		l := &s.lists[i]
		if l.notRead != "" {
			continue
		}
		dir := path.Dir(l.path)
		if s.single {
			dir = "."
		}
		if !s.single && !resolvesAt(l.entries, dir, held, l.path) {
			// Its names are not files beside it: a list of another tree
			// (a bundle, a staging area, the source model) or one written
			// from another directory. Which, the list does not say, so it
			// is named and not compared, never resolved by a guess.
			s.unplaced = append(s.unplaced, fmt.Sprintf("%s (%s)", l.path, count(len(l.entries), "entry", "entries")))
			continue
		}
		for _, e := range l.entries {
			p, why := listedPath(dir, e.name)
			switch {
			case why != "":
				s.outside = append(s.outside, fmt.Sprintf("%s line %d (%s)", l.path, e.line, why))
			case p == l.path:
				s.selfListed = append(s.selfListed, l.path)
			default:
				sum, ok := held[p]
				switch {
				case ok && sum == e.sum:
					named[p], agreed[p] = true, true
				case ok && isMarkdown(p):
					named[p], differs[p] = true, true
					s.notGraded = append(s.notGraded, fmt.Sprintf("%s (%s line %d)", display(p), l.path, e.line))
				case ok:
					named[p], differs[p] = true, true
					s.disagreed++
					if len(s.findings) < checksumFindings {
						s.findings = append(s.findings, checks.Finding{
							Pattern: "checksum-mismatch",
							Span:    display(p),
							Detail:  fmt.Sprintf("%s line %d lists %s; the scan hashed %s", s.listLabel(l), e.line, e.sum, sum),
						})
					}
				case !s.single && skippedDir(p) != "":
					s.skipped = append(s.skipped, display(p)+" (under "+skippedDir(p)+", which the scan does not read)")
				default:
					missing = append(missing, unheld{l.path, p, e.sum})
				}
			}
		}
	}
	for _, m := range missing {
		// A rename: the listed name is not held, and its hash is that of a
		// held file no entry agrees with under its own name.
		renamedTo := ""
		for _, q := range byHash[m.sum] {
			if !agreed[q] {
				renamedTo = q
				break
			}
		}
		switch {
		case renamedTo != "" && s.single:
			s.renamed = append(s.renamed, fmt.Sprintf("%s lists %s with this artifact's hash", m.list, display(m.path)))
		case renamedTo != "":
			s.renamed = append(s.renamed, fmt.Sprintf("%s (listed in %s) is held as %s", display(m.path), m.list, display(renamedTo)))
		case s.single:
			s.otherFiles++
		default:
			s.notHeld = append(s.notHeld, m.path)
		}
	}
	for p := range agreed {
		if !differs[p] {
			s.agree = append(s.agree, p)
		}
	}
	sort.Strings(s.agree)
	if !s.single {
		for _, f := range s.held {
			if !named[f.path] {
				s.unlisted = append(s.unlisted, display(f.path))
			}
		}
	}
	s.notHeld = dedupe(s.notHeld)
	s.selfListed = dedupe(s.selfListed)
}

// resolvesAt reports whether any entry names a held file other than the list
// itself, from dir.
func resolvesAt(entries []checksumEntry, dir string, held map[string]string, self string) bool {
	for _, e := range entries {
		if p, why := listedPath(dir, e.name); why == "" && p != self {
			if _, ok := held[p]; ok {
				return true
			}
		}
	}
	return false
}

// isMarkdown reports whether p is a Markdown file: a model card, or other
// documentation, which no loader reads and which an uploader edits in place
// on the Hub after writing a list.
func isMarkdown(p string) bool { return strings.EqualFold(path.Ext(p), ".md") }

// skippedDir returns the directory on p's path that a directory scan does not
// read (modeldir's skipped directories), with a trailing "/", or "".
func skippedDir(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts[:len(parts)-1] {
		if _, ok := modeldir.Skipped(part); ok {
			return strings.Join(parts[:i+1], "/") + "/"
		}
	}
	return ""
}

// listLabel names a list in a finding: by its path in a directory, and beside
// a single file by its name and the hash of what was read, since it is not
// among the attested files.
func (s *checksumScan) listLabel(l *checksumList) string {
	if s.single {
		return l.path + " (sha256 " + l.sha256 + ", beside the artifact)"
	}
	return l.path
}

// apply folds the comparison into the provenance row: a disagreement makes
// it a LEAD unless it is already worse, and everything is noted.
func (s *checksumScan) apply(r checks.Result) checks.Result {
	if s == nil || len(s.lists) == 0 {
		return r
	}
	s.compare()
	if s.disagreed > 0 {
		r.Findings = append(r.Findings, s.findings...)
		if r.Status != checks.Fail {
			r.Status = checks.Lead
		}
	}
	note := s.note()
	if r.Notes != "" {
		r.Notes += ". "
	}
	r.Notes += note
	return r
}

// note says what the comparison found, every kind of item named up to a
// bound and counted past it.
func (s *checksumScan) note() string {
	var labels []string
	for i := range s.lists {
		l := &s.lists[i]
		label := l.path
		if s.single && l.sha256 != "" {
			label += " (sha256 " + l.sha256 + ")"
		}
		if l.notRead == "" {
			label += ", " + count(len(l.entries), "entry", "entries")
		}
		labels = append(labels, label)
	}
	var parts []string
	if s.single {
		parts = append(parts, "Uploader checksum lists beside the artifact, not among the attested bytes: "+strings.Join(firstN(labels, checksumNamed), "; "))
	} else {
		parts = append(parts, "Uploader checksum lists: "+strings.Join(firstN(labels, checksumNamed), "; "))
	}
	if s.single && len(s.held) == 0 {
		parts = append(parts, "Not compared: the artifact was not hashed (a header-only scan)")
		return strings.Join(parts, ". ")
	}
	if s.disagreed > 0 {
		part := count(s.disagreed, "listed entry disagrees", "listed entries disagree") + " with the bytes the scan hashed, a LEAD: a list that no longer matches its file is what a swapped file or a partial re-upload leaves behind"
		if s.disagreed > len(s.findings) {
			part += fmt.Sprintf(" (the first %d are in the evidence)", len(s.findings))
		}
		parts = append(parts, part)
	}
	if len(s.agree) > 0 {
		var agree []string
		for _, p := range s.agree {
			agree = append(agree, display(p))
		}
		parts = append(parts, fmt.Sprintf("Agree with the bytes the scan hashed: %d (%s). A list is the uploader's own claim, so agreement shows the files are the ones it lists, not that they are safe",
			len(agree), strings.Join(firstN(agree, checksumNamed), ", ")))
	} else if s.disagreed == 0 && s.single && len(s.renamed) == 0 && s.anyRead() {
		parts = append(parts, "No list names "+display(s.artifact))
	}
	if len(s.renamed) > 0 {
		parts = append(parts, "Listed under another name with the same hash: "+strings.Join(firstN(s.renamed, checksumNamed), "; "))
	}
	if len(s.notHeld) > 0 {
		left := map[string]bool{}
		for _, p := range s.leftOut {
			left[p] = true
		}
		var names []string
		selected := 0
		for _, p := range s.notHeld {
			names = append(names, display(p))
			if left[p] {
				selected++
			}
		}
		part := fmt.Sprintf("Listed but not in the scan, so not compared (a selected pull or a partial download leaves files out): %d (%s)",
			len(names), strings.Join(firstN(names, checksumNamed), ", "))
		if selected > 0 {
			part += fmt.Sprintf(", %d of them left out by the selection the bound provenance manifest records", selected)
		}
		parts = append(parts, part)
	}
	if s.otherFiles > 0 {
		parts = append(parts, count(s.otherFiles, "entry names another file", "entries name other files")+", which a single-file scan does not hold")
	}
	if len(s.skipped) > 0 {
		parts = append(parts, "Listed, not compared: "+strings.Join(firstN(s.skipped, checksumNamed), ", "))
	}
	if len(s.notGraded) > 0 {
		parts = append(parts, "Disagree, named and not graded, as Markdown no loader reads and a model card is edited in place after a list is written: "+
			strings.Join(firstN(s.notGraded, checksumNamed), "; "))
	}
	if len(s.unplaced) > 0 {
		parts = append(parts, "Not compared, as none of their names is a file beside them (a list of another tree, or written from another directory; not guessed at): "+
			strings.Join(firstN(s.unplaced, checksumNamed), "; "))
	}
	if len(s.selfListed) > 0 {
		parts = append(parts, "Lists itself, an entry not compared, as no list can hold its own hash: "+strings.Join(firstN(s.selfListed, checksumNamed), ", "))
	}
	if len(s.outside) > 0 {
		parts = append(parts, "Names outside the directory, not compared: "+strings.Join(firstN(s.outside, checksumNamed), "; "))
	}
	var malformed, notRead []string
	for i := range s.lists {
		l := &s.lists[i]
		if l.notRead != "" {
			notRead = append(notRead, l.path+" ("+l.notRead+")")
		} else if len(l.malformed) > 0 {
			malformed = append(malformed, l.path+" "+lineNumbers(l.malformed))
		}
	}
	if len(malformed) > 0 {
		parts = append(parts, "Lines that are not SHA-256 checksum lines, not compared: "+strings.Join(firstN(malformed, checksumNamed), "; "))
	}
	if len(notRead) > 0 {
		parts = append(parts, "Not read: "+strings.Join(firstN(notRead, checksumNamed), "; "))
	}
	if len(s.unlisted) > 0 {
		parts = append(parts, fmt.Sprintf("Not covered by any list, the lists themselves included: %d (%s)",
			len(s.unlisted), strings.Join(firstN(s.unlisted, checksumNamed), ", ")))
	}
	return strings.Join(parts, ". ")
}

func (s *checksumScan) anyRead() bool {
	for i := range s.lists {
		if s.lists[i].notRead == "" {
			return true
		}
	}
	return false
}

// lineNumbers names line numbers, at most checksumNamed of them.
func lineNumbers(ns []int) string {
	word := "line "
	if len(ns) > 1 {
		word = "lines "
	}
	var s []string
	for _, n := range ns {
		s = append(s, strconv.Itoa(n))
	}
	return word + strings.Join(firstN(s, checksumNamed), ", ")
}

// display is a name as a note shows it: as it is when it is printable UTF-8
// of a reasonable length, else quoted and cut, so a listed name cannot break
// the report's text.
func display(name string) string {
	const max = 160
	plain := utf8.ValidString(name) && len(name) <= max
	for _, r := range name {
		if unicode.IsControl(r) {
			plain = false
		}
	}
	if plain {
		return name
	}
	if len(name) > max {
		name = name[:max]
	}
	return strconv.Quote(name)
}

// count is n and the noun that agrees with it.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// reason is an error's cause without the path the note already names.
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
