package ociattest_test

import (
	"archive/tar"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/ociattest"
)

// The fuzzer builds images from a small vocabulary of names, link targets,
// and contents: the ones that reach the model root, cross it, or stay out of
// it, which is where the rules are.
var (
	fuzzNames = []string{
		"models/", "models/w", "models/d/", "models/d/c", "models/x", "./models/w", "a/", "a/b",
		"l", "l/w", "l/d/c", ".wh.models", "models/.wh.w", "a/.wh..wh..opq", ".wh..wh..opq", "models/.wh..wh..opq",
		"/models/w", "x", "x/y", "x/y/w", "models/d/.wh.c", "./", "a/l", "a/l/w",
		"models/l", "bin/sh", "models/d", "a/b/c", "l/models/w", ".wh.a", "models/w/", "p/",
		"p/models/w", "a/../models/w", "models//w", "y", "y/w", "y/d/c", ".wh.l", "a/.wh.l",
	}
	fuzzTargets = []string{
		"/models", "models", "../models", "..", ".", "/", "a", "models/d",
		"/a/b", "l", "x/..", "../..", "y/../models", "/x", "models/w", "w",
		"d", "../models/w", "bin/sh", "a/b", "/p", "p/../models", "/y", "a/l",
	}
	fuzzData  = []string{"W", "C", "Z", ""}
	fuzzFiles = map[string][]byte{"w": []byte("W"), "d/c": []byte("C")}
)

// decodeImage turns fuzz bytes into layers: three bytes an entry (kind and
// flags, name, target or contents), and 0xff starts a new layer.
func decodeImage(prog []byte) (layers [][]ent, gzipped []bool) {
	cur := []ent{}
	flush := func(g bool) {
		layers = append(layers, cur)
		gzipped = append(gzipped, g)
		cur = []ent{}
	}
	for i := 0; i+2 < len(prog) && len(layers) < 5; i += 3 {
		if prog[i] == 0xff {
			flush(prog[i+1]&1 == 0)
			continue
		}
		if len(cur) >= 14 {
			continue
		}
		name := fuzzNames[int(prog[i+1])%len(fuzzNames)]
		arg := int(prog[i+2])
		kind := prog[i] % 5
		if strings.HasSuffix(name, "/") {
			kind = 1 // Go's tar.Writer writes a trailing slash only on a directory
		}
		switch kind {
		case 0:
			cur = append(cur, reg(name, fuzzData[arg%len(fuzzData)]))
		case 1:
			cur = append(cur, dir(name))
		case 2:
			cur = append(cur, sym(name, fuzzTargets[arg%len(fuzzTargets)]))
		case 3:
			cur = append(cur, hard(name, fuzzNames[arg%len(fuzzNames)]))
		case 4:
			cur = append(cur, ent{name: name, kind: tar.TypeChar}) // 0/0: an overlayfs whiteout
		}
	}
	if len(cur) > 0 {
		flush(true)
	}
	return layers, gzipped
}

func encodeImage(layers ...[]ent) []byte {
	var out []byte
	index := func(list []string, s string) byte {
		for i, v := range list {
			if v == s {
				return byte(i)
			}
		}
		panic(s)
	}
	for li, l := range layers {
		if li > 0 {
			out = append(out, 0xff, 0, 0)
		}
		for _, e := range l {
			switch e.kind {
			case tar.TypeReg:
				out = append(out, 0, index(fuzzNames, e.name), index(fuzzData, e.data))
			case tar.TypeDir:
				out = append(out, 1, index(fuzzNames, e.name), 0)
			case tar.TypeSymlink:
				out = append(out, 2, index(fuzzNames, e.name), index(fuzzTargets, e.link))
			case tar.TypeLink:
				out = append(out, 3, index(fuzzNames, e.name), index(fuzzNames, e.link))
			case tar.TypeChar:
				out = append(out, 4, index(fuzzNames, e.name), 0)
			}
		}
	}
	return out
}

// FuzzMapLayers checks the property the mapping exists for: whenever
// MapTarLayers accepts an image, the tree under /models that containerd
// (both apply paths) and KServe's oci+fetch unpack is exactly the attested
// files. A consumer that fails to unpack the image is fail-closed and passes.
// It also may not panic, and must be deterministic.
func FuzzMapLayers(f *testing.F) {
	model := []ent{dir("models/"), reg("models/w", "W"), dir("models/d/"), reg("models/d/c", "C")}
	f.Add(encodeImage(model))
	f.Add(encodeImage([]ent{dir("./"), dir("a/"), reg("a/b", "Z"), sym("l", "a"), hard("bin/sh", "a/b")}, []ent{dir("models/")}, model))
	f.Add(encodeImage([]ent{dir("a/"), sym("l", "/models")}, model))
	f.Add(encodeImage(model, []ent{reg("models/.wh.w", "")}))
	f.Add(encodeImage([]ent{dir("p/"), dir("a/"), sym("y", "/p"), sym("a/l", "y/../models")}, model))
	f.Add(encodeImage(model, []ent{reg("models/w", "Z")}))
	f.Add(encodeImage([]ent{dir("a/"), sym("a/l", "../models")}, model, []ent{reg("a/l/w", "Z")}))
	f.Add(encodeImage(model, []ent{{name: "models/w", kind: tar.TypeChar}}))
	f.Add(encodeImage([]ent{{name: "x", kind: tar.TypeChar}, dir("a/")}, model))
	a := dirIdentity(fuzzFiles)
	want := fmt.Sprint(map[string]string{"w": "W", "d/c": "C"})
	f.Fuzz(func(t *testing.T, prog []byte) {
		layers, gzipped := decodeImage(prog)
		var imgs []imgLayer
		for i, l := range layers {
			raw := tarOf(t, l)
			if gzipped[i] {
				imgs = append(imgs, imgLayer{gz(raw), ociLayerGzip, nil})
			} else {
				imgs = append(imgs, imgLayer{raw, ociLayerTar, nil})
			}
		}
		m, err := mapImage(t, imgs, a, ociattest.MapOptions{})
		m2, err2 := mapImage(t, imgs, a, ociattest.MapOptions{})
		if fmt.Sprint(m, err) != fmt.Sprint(m2, err2) {
			t.Fatalf("not deterministic: %v %v / %v %v", m, err, m2, err2)
		}
		if err != nil {
			if !errors.Is(err, ociattest.ErrNotBound) {
				t.Fatalf("a refusal that is not ErrNotBound: %v", err)
			}
			return
		}
		var hss [][]*tar.Header
		var dss [][][]byte
		for i, l := range imgs {
			hs, ds, err := entries(l.blob, gzipped[i])
			if err != nil {
				t.Fatalf("archive/tar cannot read a layer the mapping accepted: %v", err)
			}
			hss, dss = append(hss, hs), append(dss, ds)
		}
		naive := fsys{}
		naiveOK := true
		uppers := []fsys{}
		for i := range hss {
			if naiveOK && naive.apply(hss[i], dss[i], false) != nil {
				naiveOK = false
			}
			u := fsys{}
			if u.apply(hss[i], dss[i], true) == nil {
				uppers = append(uppers, u)
			}
		}
		check := func(who string, fs fsys, root string) {
			tree, err := modelTree(fs, root)
			if err != nil {
				t.Fatalf("%s: accepted %v, and the unpacked model root has %v", who, layers, err)
			}
			if fmt.Sprint(tree) != want {
				t.Fatalf("%s: accepted %v, and the unpacked model root holds %v", who, layers, tree)
			}
		}
		if naiveOK {
			check("containerd (naive)", naive, "models")
		}
		if len(uppers) == len(hss) {
			check("containerd (overlayfs)", merge(uppers), "models")
		}
		if out, err := fetch(hss, dss); err == nil {
			check("KServe oci+fetch", out, "")
		}
	})
}
