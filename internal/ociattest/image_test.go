package ociattest_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

// Image layers built in code: what a container build (FROM busybox, RUN
// mkdir /models, COPY data/ /models/) writes, and variations on it.

const (
	ociLayerGzip    = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociLayerTar     = "application/vnd.oci.image.layer.v1.tar"
	dockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	ociImageConfig  = "application/vnd.oci.image.config.v1+json"
)

// ent is one tar entry: kind is tar.TypeReg, TypeDir, TypeSymlink, TypeLink,
// or TypeChar.
type ent struct {
	name string
	kind byte
	data string
	link string
	pax  map[string]string
}

func reg(name, data string) ent   { return ent{name: name, kind: tar.TypeReg, data: data} }
func dir(name string) ent         { return ent{name: name, kind: tar.TypeDir} }
func sym(name, target string) ent { return ent{name: name, kind: tar.TypeSymlink, link: target} }
func hard(name, target string) ent {
	return ent{name: name, kind: tar.TypeLink, link: target}
}

// tarOf writes entries as Go's tar.Writer does (PAX when a name needs it),
// as BuildKit and containerd write layers.
func tarOf(t testing.TB, ents []ent) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.kind, Linkname: e.link, Mode: 0o644, PAXRecords: e.pax}
		if e.kind == tar.TypeDir {
			h.Mode = 0o755
		}
		if e.kind == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("%s: %v", e.name, err)
		}
		if e.kind == tar.TypeReg {
			io.WriteString(tw, e.data)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// imgLayer is a layer blob and its media type.
type imgLayer struct {
	blob      []byte
	mediaType string
	urls      []string
}

func gzLayer(t testing.TB, ents ...ent) imgLayer {
	return imgLayer{gz(tarOf(t, ents)), ociLayerGzip, nil}
}

// busyboxBase is a base layer like busybox's: a root entry, applets as hard
// links to one binary, and two relative symbolic links.
func busyboxBase(t testing.TB) imgLayer {
	return gzLayer(t, dir("./"), dir("dev/"), ent{name: "dev/null", kind: tar.TypeChar}, dir("bin/"), reg("bin/busybox", "\x7fELF busybox"), hard("bin/sh", "bin/busybox"),
		hard("bin/ln", "bin/busybox"), hard("bin/sleep", "bin/busybox"), dir("lib/"), sym("lib64", "lib"),
		dir("usr/"), dir("usr/bin/"), sym("usr/bin/env", "../../bin/env"), dir("etc/"), reg("etc/passwd", "root:x:0:0::/root:/bin/sh\n"))
}

// runLayer is what RUN mkdir /models && chmod 775 /models leaves in a
// BuildKit build: the model root and the runtime's mount points.
func runLayer(t testing.TB) imgLayer { return gzLayer(t, dir("models/"), dir("proc/"), dir("sys/")) }

// copyLayer is COPY data/ /models/ of a model directory's files.
func copyLayer(t testing.TB, files map[string][]byte, extra ...ent) imgLayer {
	ents := []ent{dir("models/")}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	dirs := map[string]bool{}
	for _, p := range paths {
		for d := parentOf(p); d != ""; d = parentOf(d) {
			if !dirs[d] {
				dirs[d] = true
				ents = append(ents, dir("models/"+d+"/"))
			}
		}
		ents = append(ents, reg("models/"+p, string(files[p])))
	}
	return gzLayer(t, append(ents, extra...)...)
}

func parentOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}

// pushImage pushes an image manifest of the layers, with an image config,
// tagged, and returns its reference and digest.
func pushImage(t testing.TB, srv *registrytest.Registry, repoName, tag string, layers []imgLayer, mediaType string) (registry.Reference, string) {
	t.Helper()
	ref, err := registry.ParseReference(srv.Host + "/" + repoName + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	m := imageManifest(layers, mediaType, srv.PutBlob)
	b, _ := json.Marshal(m)
	return ref, srv.PutManifest(repoName, tag, m.MediaType, b)
}

// imageManifest builds the manifest of an image, storing each blob with put.
func imageManifest(layers []imgLayer, mediaType string, put func([]byte) string) registry.Manifest {
	if mediaType == "" {
		mediaType = registry.MediaTypeImageManifest
	}
	cfgType := ociImageConfig
	if mediaType == registry.MediaTypeDockerManifest {
		cfgType = "application/vnd.docker.container.image.v1+json"
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux","config":{"Cmd":["sh"]},"rootfs":{"type":"layers","diff_ids":[]}}`)
	m := registry.Manifest{SchemaVersion: 2, MediaType: mediaType,
		Config: registry.Descriptor{MediaType: cfgType, Digest: put(cfg), Size: int64(len(cfg))}}
	for _, l := range layers {
		m.Layers = append(m.Layers, registry.Descriptor{MediaType: l.mediaType, Digest: put(l.blob), Size: int64(len(l.blob)), URLs: l.urls})
	}
	return m
}

// memBlobs is an in-memory layer store for MapTarLayers.
type memBlobs map[string][]byte

func (b memBlobs) put(blob []byte) string {
	d := registry.Digest(blob)
	b[d] = blob
	return d
}

func (b memBlobs) open(_ context.Context, l registry.Descriptor) (io.ReadCloser, error) {
	blob, ok := b[l.Digest]
	if !ok {
		return nil, fmt.Errorf("no blob %s", l.Digest)
	}
	return io.NopCloser(bytes.NewReader(blob)), nil
}

// renamed rewrites a header's name in a tar archive to another of the same
// length, and its checksum: for a name Go's tar.Writer will not write.
func renamed(archive []byte, from, to string) []byte {
	b := append([]byte(nil), archive...)
	i := bytes.Index(b, []byte(from+"\x00"))
	if i < 0 || i%512 != 0 || len(from) != len(to) {
		panic("renamed: " + from)
	}
	copy(b[i:], to)
	h := b[i : i+512]
	copy(h[148:156], "        ")
	var sum int
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}
