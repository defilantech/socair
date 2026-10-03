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

// CheckFiles compares a model directory snapshot (root, with its files) to a
// verified manifest. sigRel is the signature file's own path, which a
// signature cannot cover. It returns every difference: a file changed,
// missing, or present but not signed. Paths the signer listed in
// ignore_paths are not compared, and are returned as ignored, so the report
// can name what the signature does not cover.
func CheckFiles(m *Manifest, root string, files []modeldir.File, sigRel string) (diffs, ignored []string, err error) {
	if err := supported(m); err != nil {
		return nil, nil, err
	}
	skip := func(p string) bool {
		if p == sigRel {
			return true
		}
		for _, ip := range m.IgnorePaths {
			ip = strings.TrimSuffix(path.Clean(filepath.ToSlash(ip)), "/")
			if ip != "." && (p == ip || strings.HasPrefix(p, ip+"/")) {
				return true
			}
		}
		return false
	}
	onDisk := map[string]modeldir.File{}
	for _, f := range files {
		if skip(f.Path) {
			if f.Path != sigRel {
				ignored = append(ignored, f.Path)
			}
			continue
		}
		onDisk[f.Path] = f
	}

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
		if _, ok := onDisk[p]; !ok && !skip(p) {
			diffs = append(diffs, "missing: "+p)
		}
	}
	sort.Strings(diffs)
	sort.Strings(ignored)
	return diffs, ignored, nil
}

// CheckFile compares a single-file artifact to a verified manifest: it must
// sign exactly one file, with this artifact's hash.
func CheckFile(m *Manifest, sha string) ([]string, error) {
	if err := supported(m); err != nil {
		return nil, err
	}
	if m.Method != "files" {
		return nil, fmt.Errorf("%w: a %s manifest for a single file", ErrUnsupported, m.Method)
	}
	if len(m.Resources) != 1 {
		return []string{fmt.Sprintf("the signature covers %d files, not this one artifact", len(m.Resources))}, nil
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
