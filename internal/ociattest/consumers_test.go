package ociattest_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"sort"
	"strings"
)

// Emulations of how three consumers unpack an image's layers, from their
// source (docs/oci.md cites each). They are models, written to check one
// property in FuzzMapLayers: when MapTarLayers accepts an image, every
// consumer's tree under the model root is exactly the attested files.
//
//   - naive: containerd's applyNaive over the merged root (the path when the
//     snapshotter is not overlayfs): each entry's parent is resolved through
//     the symbolic links already in the tree, scoped to the root; a whiteout
//     removes its target, an opaque marker every child not unpacked in this
//     layer; an entry replaces what is at its path unless both are
//     directories. CRI-O's containers/storage behaves the same way for these
//     inputs (it runs in a chroot, so the OS follows links the same way).
//   - overlay: containerd's overlayfs fast path: each layer is applied into
//     its own empty upper directory (links in lower layers are not seen),
//     whiteouts become 0/0 character devices and opaque markers the opaque
//     attribute, and overlayfs merges the layers.
//   - fetch: KServe v0.21.0's oci+fetch: every layer's entries named
//     models/<path> are extracted, in order, with no whiteouts applied.

type node struct {
	kind     byte // tar.TypeReg, TypeDir, TypeSymlink; whiteout is 'w'
	data     string
	link     string
	opaque   bool
	unpacked bool
}

type fsys map[string]*node

func (f fsys) removeAll(p string) {
	for k := range f {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f, k)
		}
	}
}

// resolve follows symbolic links in p, scoped to the root, ".." stopping at
// it, as fs.RootPath does.
func (f fsys) resolve(p string) (string, error) {
	var cur []string
	todo := strings.Split(p, "/")
	for hops := 0; len(todo) > 0; {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := strings.Join(append(append([]string(nil), cur...), c), "/")
		if n, ok := f[next]; ok && n.kind == tar.TypeSymlink {
			if hops++; hops > 255 {
				return "", errors.New("too many links")
			}
			if strings.HasPrefix(n.link, "/") {
				cur = nil
			}
			todo = append(strings.Split(n.link, "/"), todo...)
			continue
		}
		cur = append(cur, c)
	}
	return strings.Join(cur, "/"), nil
}

func (f fsys) mkparents(p string) error {
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		d := strings.Join(parts[:i], "/")
		n, ok := f[d]
		if !ok {
			f[d] = &node{kind: tar.TypeDir}
			continue
		}
		if n.kind != tar.TypeDir {
			return fmt.Errorf("%s is not a directory", d)
		}
	}
	return nil
}

// entries reads a layer as Go's archive/tar does.
func entries(blob []byte, gzipped bool) ([]*tar.Header, [][]byte, error) {
	var r io.Reader = bytes.NewReader(blob)
	if gzipped {
		g, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, err
		}
		r = g
	}
	tr := tar.NewReader(r)
	var hs []*tar.Header
	var ds [][]byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return hs, ds, nil
		}
		if err != nil {
			return nil, nil, err
		}
		d, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, err
		}
		hs, ds = append(hs, h), append(ds, d)
	}
}

// apply applies one layer to f the way containerd's applyNaive does. With
// overlay set, whiteouts are recorded as markers, as OverlayConvertWhiteout
// writes them.
func (f fsys) apply(hs []*tar.Header, ds [][]byte, overlay bool) error {
	for _, n := range f {
		n.unpacked = false
	}
	for i, h := range hs {
		name := pathpkg.Clean(h.Name)
		if name == "." || name == "/" {
			continue
		}
		dir, base := pathpkg.Split(strings.TrimPrefix(name, "/"))
		pp, err := f.resolve(dir)
		if err != nil {
			return err
		}
		p := strings.TrimPrefix(pathpkg.Join(pp, base), "/")
		if p == "" || p == "." {
			continue
		}
		if err := f.mkparents(p); err != nil {
			return err
		}
		if base == ".wh..wh..opq" {
			d := parentPath(p)
			if overlay {
				if n, ok := f[d]; ok {
					n.opaque = true
				} else if d != "" {
					f[d] = &node{kind: tar.TypeDir, opaque: true}
				}
				continue
			}
			for k, n := range f {
				if strings.HasPrefix(k, d+"/") || (d == "" && k != "") {
					if !n.unpacked {
						delete(f, k)
					}
				}
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			target := pathpkg.Join(parentPath(p), base[4:])
			if overlay {
				f.removeAll(target)
				f[target] = &node{kind: 'w', unpacked: true}
			} else {
				f.removeAll(target)
			}
			continue
		}
		if n, ok := f[p]; ok && !(n.kind == tar.TypeDir && h.Typeflag == tar.TypeDir) {
			f.removeAll(p)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if n, ok := f[p]; !ok || n.kind != tar.TypeDir {
				f[p] = &node{kind: tar.TypeDir}
			}
		case tar.TypeReg:
			f[p] = &node{kind: tar.TypeReg, data: string(ds[i])}
		case tar.TypeSymlink:
			f[p] = &node{kind: tar.TypeSymlink, link: h.Linkname}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			if overlay && h.Typeflag == tar.TypeChar && h.Devmajor == 0 && h.Devminor == 0 {
				// In an overlayfs upper directory, a 0/0 character
				// device is a whiteout.
				f[p] = &node{kind: 'w'}
			} else {
				f[p] = &node{kind: h.Typeflag}
			}
		case tar.TypeLink:
			ld, lb := pathpkg.Split(pathpkg.Clean(strings.TrimPrefix(h.Linkname, "/")))
			lp, err := f.resolve(ld)
			if err != nil {
				return err
			}
			t, ok := f[strings.TrimPrefix(pathpkg.Join(lp, lb), "/")]
			if !ok || t.kind == tar.TypeDir {
				return fmt.Errorf("hard link target %s", h.Linkname)
			}
			c := *t
			f[p] = &c
		default:
			return fmt.Errorf("type %q", h.Typeflag)
		}
		f[p].unpacked = true
	}
	return nil
}

func parentPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

// merge stacks overlay upper directories, bottom first, as overlayfs shows
// them: a whiteout hides a lower path, an opaque directory hides a lower
// directory's children, a directory over a directory merges, and anything
// else replaces.
func merge(uppers []fsys) fsys {
	out := fsys{}
	for _, u := range uppers {
		keys := make([]string, 0, len(u))
		for k := range u {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			n := u[k]
			// A lower non-directory on the path hides nothing of this
			// layer's: the upper's directories replace it.
			for d := parentPath(k); d != ""; d = parentPath(d) {
				if l, ok := out[d]; ok && l.kind != tar.TypeDir {
					out.removeAll(d)
				}
			}
			switch {
			case n.kind == 'w':
				out.removeAll(k)
			case n.kind == tar.TypeDir:
				if l, ok := out[k]; ok && l.kind != tar.TypeDir {
					out.removeAll(k)
				}
				if n.opaque {
					for k2 := range out {
						if strings.HasPrefix(k2, k+"/") {
							delete(out, k2)
						}
					}
				}
				c := *n
				out[k] = &c
			default:
				out.removeAll(k)
				c := *n
				out[k] = &c
			}
		}
	}
	return out
}

// fetch extracts models/ from each layer as KServe's _download_oci does.
func fetch(layers [][]*tar.Header, data [][][]byte) (fsys, error) {
	out := fsys{}
	for li, hs := range layers {
		for i, h := range hs {
			name := strings.TrimRight(h.Name, "/")
			if name == "models" || !strings.HasPrefix(name, "models/") {
				continue
			}
			rel := strings.TrimPrefix(name[len("models/"):], "/")
			if rel == "" {
				continue
			}
			if strings.Contains("/"+rel+"/", "/../") {
				return nil, errors.New("outside")
			}
			rel = pathpkg.Clean(rel)
			if err := out.mkparents(rel); err != nil {
				return nil, err
			}
			switch h.Typeflag {
			case tar.TypeDir:
				out[rel] = &node{kind: tar.TypeDir}
			case tar.TypeReg:
				if n, ok := out[rel]; ok && n.kind == tar.TypeSymlink {
					return nil, errors.New("writes through a link")
				}
				out[rel] = &node{kind: tar.TypeReg, data: string(data[li][i])}
			case tar.TypeSymlink:
				out[rel] = &node{kind: tar.TypeSymlink, link: h.Linkname}
			default:
				return nil, fmt.Errorf("type %q", h.Typeflag)
			}
		}
	}
	return out, nil
}

// modelTree is what a consumer reading root finds: every file under it,
// following no link (a link anywhere on the way is reported).
func modelTree(f fsys, root string) (map[string]string, error) {
	for d := root; d != ""; d = parentPath(d) {
		if n, ok := f[d]; ok && n.kind != tar.TypeDir {
			return nil, fmt.Errorf("%s is not a directory", d)
		}
	}
	out := map[string]string{}
	for k, n := range f {
		if root != "" && !strings.HasPrefix(k, root+"/") {
			continue
		}
		rel := k
		if root != "" {
			rel = k[len(root)+1:]
		}
		switch n.kind {
		case tar.TypeReg:
			out[rel] = n.data
		case tar.TypeDir:
		default:
			return nil, fmt.Errorf("%s is a %q", k, n.kind)
		}
	}
	return out, nil
}
