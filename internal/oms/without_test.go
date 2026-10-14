package oms_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
)

// Without leaves out the signed files it is told to, by file for a shard
// manifest too, and nothing else: on the copy, CheckFiles still finds a
// changed, missing, or unsigned file anywhere else, and the original manifest
// is untouched. Falsification: leave out every resource, or none, and the
// differences below change.
func TestWithoutLeavesOutOnlyTheNamedFiles(t *testing.T) {
	underMeta := func(p string) bool { return strings.HasPrefix(p, "meta/") }

	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.bin"), "changed")
	write(t, filepath.Join(dir, "extra.py"), "x")
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := &oms.Manifest{Method: "files", HashType: "sha256", Resources: []oms.Resource{
		{Name: "a.bin", Algorithm: "sha256", Digest: sum("a")},
		{Name: "b.bin", Algorithm: "sha256", Digest: sum("b")},
		{Name: "./meta/x.metadata", Algorithm: "sha256", Digest: sum("x")},
		{Name: "meta/download/y.metadata", Algorithm: "sha256", Digest: sum("y")},
		{Name: "metadata.json", Algorithm: "sha256", Digest: sum("z")},
	}}
	kept, left := m.Without(underMeta)
	if strings.Join(left, "|") != "meta/download/y.metadata|meta/x.metadata" {
		t.Errorf("left out %v", left)
	}
	if len(m.Resources) != 5 || len(kept.Resources) != 3 {
		t.Fatalf("original %d resources, copy %d", len(m.Resources), len(kept.Resources))
	}
	diffs, _, err := oms.CheckFiles(kept, dir, files, oms.Compare{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(diffs, "|"); got != "changed: a.bin|missing: b.bin|missing: metadata.json|not signed: extra.py" {
		t.Errorf("diffs %s", got)
	}

	// A shard manifest: every shard of a left-out file goes, and a shard
	// name that does not parse is kept, for CheckFiles to refuse.
	sh := &oms.Manifest{Method: "shards", HashType: "sha256", ShardSize: 4}
	alg := fmt.Sprintf("sha256-sharded-%d", sh.ShardSize)
	for _, n := range []string{"w.bin:0:4", "w.bin:4:6", "meta/w.bin.metadata:0:3", "meta/w.bin.metadata:3:5", "meta/bad"} {
		sh.Resources = append(sh.Resources, oms.Resource{Name: n, Algorithm: alg, Digest: sum(n)})
	}
	kept, left = sh.Without(underMeta)
	if strings.Join(left, "|") != "meta/w.bin.metadata" {
		t.Errorf("shards: left out %v", left)
	}
	var names []string
	for _, r := range kept.Resources {
		names = append(names, r.Name)
	}
	if strings.Join(names, "|") != "w.bin:0:4|w.bin:4:6|meta/bad" {
		t.Errorf("shards: kept %v", names)
	}
	if _, _, err := oms.CheckFiles(kept, dir, nil, oms.Compare{}); err == nil {
		t.Error("a shard name that does not parse must still be refused")
	}
}

// A shard manifest without its left-out files verifies the rest: the shards
// of a signed weight file are still hashed and compared.
func TestWithoutKeepsShardComparison(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "w.bin"), "abcdef")
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	sh := &oms.Manifest{Method: "shards", HashType: "sha256", ShardSize: 4, Resources: []oms.Resource{
		{Name: "w.bin:0:4", Algorithm: "sha256-sharded-4", Digest: sum("abcd")},
		{Name: "w.bin:4:6", Algorithm: "sha256-sharded-4", Digest: sum("eX")},
		{Name: ".cache/huggingface/download/w.bin.metadata:0:3", Algorithm: "sha256-sharded-4", Digest: sum("abc")},
	}}
	kept, left := sh.Without(func(p string) bool { _, _, ok := modeldir.DownloadMetadata(p); return ok })
	if strings.Join(left, "|") != ".cache/huggingface/download/w.bin.metadata" {
		t.Errorf("left out %v", left)
	}
	diffs, _, err := oms.CheckFiles(kept, dir, files, oms.Compare{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(diffs, "|") != "changed: w.bin bytes 4-6" {
		t.Errorf("diffs %v", diffs)
	}
}
