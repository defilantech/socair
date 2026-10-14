package oms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/modeldir"
)

// ErrUnsupported is a signed manifest this verifier cannot check against the
// files, such as one hashed with BLAKE2; the signature is then unverified,
// not invalid.
var ErrUnsupported = errors.New("unsupported OMS serialization")

// DefaultExclusions are the paths OMS v1.0 section 6.2 leaves out of every
// signature by default, matched at the top of the model directory only.
var DefaultExclusions = []string{".git", ".gitattributes", ".github", ".gitignore"}

// Exclusion is a path a verifier leaves out of the comparison, and why.
type Exclusion struct {
	Path string // relative to the directory, "/"-separated; a directory excludes its subtree
	Why  string
}

// Compare says what a verifier leaves out of the comparison besides the
// paths the signer listed in ignore_paths.
type Compare struct {
	// Signature is the signature file's own path in the directory, when it
	// is in it. A signature cannot cover itself (OMS v1.0 section 6.2).
	Signature string
	// Exclude are further paths left out when the manifest does not list
	// them: another signature file, or a verifier's own ignore paths.
	Exclude []Exclusion
	// AllowUnsigned tolerates files the manifest does not list, naming them
	// (OMS v1.0 section 8.5, --ignore-unsigned-files). A scan never sets it:
	// there, a file nobody signed is a difference.
	AllowUnsigned bool
}

// CheckFiles compares a model directory snapshot (root, with its files) to a
// verified manifest. It returns every difference: a file changed, missing,
// or present but not signed. A file the manifest lists is always compared. A
// file it does not list is left out, not a difference, only when the signer
// excluded it (ignore_paths), when it is an OMS default exclusion (.git,
// .gitattributes, .github, .gitignore at the top), or when c excludes it;
// each is returned in ignored as "path (why)", so the report can name what
// the signature does not cover. The signature file itself is never compared.
func CheckFiles(m *Manifest, root string, files []modeldir.File, c Compare) (diffs, ignored []string, err error) {
	if err := supported(m); err != nil {
		return nil, nil, err
	}
	signerSkip := func(p string) bool { return p == c.Signature || under(p, m.IgnorePaths) }
	listed := map[string]bool{}
	for _, r := range m.Resources {
		name := r.Name
		if m.Method == "shards" {
			if p, _, _, ok := shardName(r.Name); ok {
				name = p
			}
		}
		listed[path.Clean(name)] = true
	}
	onDisk := map[string]modeldir.File{}
	for _, f := range files {
		p := f.Path
		switch {
		case p == c.Signature:
		case signerSkip(p):
			ignored = append(ignored, p+" (excluded by the signer)")
		case listed[p]:
			onDisk[p] = f
		case under(p, DefaultExclusions):
			ignored = append(ignored, p+" (an OMS default exclusion)")
		case excludedBy(p, c.Exclude) != "":
			ignored = append(ignored, p+" ("+excludedBy(p, c.Exclude)+")")
		case c.AllowUnsigned:
			ignored = append(ignored, p+" (not signed; unsigned files tolerated)")
		default:
			onDisk[p] = f
		}
	}
	sort.Strings(ignored)

	if m.Method == "shards" {
		diffs, err = checkShards(m, root, onDisk)
		return diffs, ignored, err
	}
	signed := map[string]string{}
	for _, r := range m.Resources {
		signed[path.Clean(r.Name)] = strings.ToLower(r.Digest)
	}
	for p, f := range onDisk {
		want, ok := signed[p]
		switch {
		case !ok:
			diffs = append(diffs, "not signed: "+p)
		case want != f.SHA256:
			diffs = append(diffs, "changed: "+p)
		}
	}
	for p := range signed {
		if _, ok := onDisk[p]; !ok && !signerSkip(p) {
			diffs = append(diffs, "missing: "+p)
		}
	}
	sort.Strings(diffs)
	return diffs, ignored, nil
}

// Without returns a copy of m that no longer signs the files leave names, and
// the paths of the signed files it left out, sorted. A shard manifest's
// resources are left out by their file. A verifier uses it for files it holds
// no bytes for, so they are neither compared nor missing; CheckFiles on the
// copy still compares every other signed file, and a file on disk that the
// copy does not list is still a difference. A resource name that does not
// parse is kept, so CheckFiles refuses it as before.
func (m *Manifest) Without(leave func(path string) bool) (*Manifest, []string) {
	out := *m
	out.Resources = nil
	left := map[string]bool{}
	for _, r := range m.Resources {
		name := r.Name
		if m.Method == "shards" {
			p, _, _, ok := shardName(r.Name)
			if !ok {
				out.Resources = append(out.Resources, r)
				continue
			}
			name = p
		}
		if p := path.Clean(name); leave(p) {
			left[p] = true
			continue
		}
		out.Resources = append(out.Resources, r)
	}
	paths := make([]string, 0, len(left))
	for p := range left {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return &out, paths
}

// under reports whether p is one of paths or inside one, as OMS matches an
// ignore path: an exact path from the directory's top, and its subtree.
func under(p string, paths []string) bool {
	for _, ip := range paths {
		ip = strings.TrimSuffix(path.Clean(filepath.ToSlash(ip)), "/")
		if ip != "." && ip != "" && (p == ip || strings.HasPrefix(p, ip+"/")) {
			return true
		}
	}
	return false
}

func excludedBy(p string, ex []Exclusion) string {
	for _, e := range ex {
		if under(p, []string{e.Path}) {
			return e.Why
		}
	}
	return ""
}

// CheckFile compares a single-file artifact to a verified manifest: it must
// sign exactly one file, with this artifact's hash. A signature over several
// files that lists this one is not checked here, since the others are not in
// hand: it is an error, so the signature is unverified, not invalid.
func CheckFile(m *Manifest, sha string) ([]string, error) {
	if err := supported(m); err != nil {
		return nil, err
	}
	if m.Method != "files" {
		return nil, fmt.Errorf("%w: a %s manifest for a single file", ErrUnsupported, m.Method)
	}
	if len(m.Resources) != 1 {
		for _, r := range m.Resources {
			if strings.ToLower(r.Digest) == sha {
				return nil, fmt.Errorf("the signature covers %d files and this artifact is one of them (%s); scan the directory to check it over all of them", len(m.Resources), r.Name)
			}
		}
		return []string{fmt.Sprintf("the signature covers %d files, and this artifact is none of them", len(m.Resources))}, nil
	}
	if strings.ToLower(m.Resources[0].Digest) != sha {
		return []string{"changed: the artifact is not the file that was signed"}, nil
	}
	return nil, nil
}

func supported(m *Manifest) error {
	if m.Method != "files" && m.Method != "shards" {
		return fmt.Errorf("%w: serialization method %q", ErrUnsupported, m.Method)
	}
	if m.HashType != "sha256" {
		return fmt.Errorf("%w: hash type %q (only sha256 is verified)", ErrUnsupported, m.HashType)
	}
	// Shard digests are named for their shard size, as sha256-sharded-<size>.
	want := "sha256"
	if m.Method == "shards" {
		if m.ShardSize <= 0 {
			return fmt.Errorf("%w: a shard manifest with no shard size", ErrUnsupported)
		}
		want = fmt.Sprintf("sha256-sharded-%d", m.ShardSize)
	}
	for _, r := range m.Resources {
		if r.Algorithm != want {
			return fmt.Errorf("%w: resource %q hashed with %q", ErrUnsupported, r.Name, r.Algorithm)
		}
	}
	return nil
}

// checkShards verifies a shard manifest: each file's shards must tile it from
// zero to its size, and each shard's bytes must hash to the signed digest.
func checkShards(m *Manifest, root string, onDisk map[string]modeldir.File) ([]string, error) {
	type shard struct {
		start, end int64
		digest     string
	}
	byFile := map[string][]shard{}
	for _, r := range m.Resources {
		p, s, e, ok := shardName(r.Name)
		if !ok {
			return nil, fmt.Errorf("%w: shard name %q", ErrUnsupported, r.Name)
		}
		p = path.Clean(p)
		byFile[p] = append(byFile[p], shard{s, e, strings.ToLower(r.Digest)})
	}
	var diffs []string
	for p, f := range onDisk {
		shards, ok := byFile[p]
		if !ok {
			diffs = append(diffs, "not signed: "+p)
			continue
		}
		sort.Slice(shards, func(i, j int) bool { return shards[i].start < shards[j].start })
		var next int64
		for _, s := range shards {
			if s.start != next {
				diffs = append(diffs, fmt.Sprintf("changed: %s (signed shards do not tile the file at offset %d)", p, next))
				break
			}
			next = s.end
		}
		if next != f.Size {
			if len(diffs) == 0 || !strings.HasPrefix(diffs[len(diffs)-1], "changed: "+p) {
				diffs = append(diffs, fmt.Sprintf("changed: %s (signed for %d bytes, holds %d)", p, next, f.Size))
			}
			continue
		}
		fh, err := os.Open(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			return nil, err
		}
		for _, s := range shards {
			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(fh, s.start, s.end-s.start)); err != nil {
				fh.Close()
				return nil, err
			}
			if hex.EncodeToString(h.Sum(nil)) != s.digest {
				diffs = append(diffs, fmt.Sprintf("changed: %s bytes %d-%d", p, s.start, s.end))
				break
			}
		}
		fh.Close()
	}
	for p := range byFile {
		if _, ok := onDisk[p]; !ok {
			diffs = append(diffs, "missing: "+p)
		}
	}
	sort.Strings(diffs)
	return diffs, nil
}
