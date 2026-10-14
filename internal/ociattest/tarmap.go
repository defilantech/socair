package ociattest

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/ociattest/tarwalk"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

// An image (a KServe ModelCar, built FROM a base image with the model copied
// under /models) holds the model as files inside tar layers, which a runtime
// unpacks on top of each other. MapTarLayers maps those files to the attested
// ones. It refuses anything that could make the tree a consumer unpacks under
// the model root differ from what was scanned, as containerd, CRI-O, or
// KServe's oci+fetch would unpack it. docs/oci.md lists the rules and their
// sources.

const (
	// MatchModelRoot is the match kind of an image whose tar layers hold the
	// attested files, and nothing else, under a model root.
	MatchModelRoot = "model-root"
	// DefaultModelRoot is where KServe v0.21.0 reads a model from in an
	// image, in all three of its OCI modes: /models.
	DefaultModelRoot = "models"
	// LayerRules names the rules MapTarLayers maps layers under. A binding
	// records it, and verify refuses a binding made under other rules: a
	// change that can map an image differently changes this name.
	LayerRules = "socair.tar-map/v1"
)

// Layer roles in a model-root match.
const (
	// RoleModel is a layer that holds files under the model root, and
	// nothing outside it but the directories above it.
	RoleModel = "model"
	// RoleBase is a layer that holds nothing under the model root: the base
	// image, and layers such as RUN mkdir /models. Its files are checked
	// only for not reaching into the model root; their content is not
	// examined.
	RoleBase = "base"
)

type compression int

const (
	uncompressed compression = iota
	gzipped
)

// tarLayerTypes are the image layer media types mapped, and the compression
// each declares. They are the types KServe v0.21.0's oci+fetch reads
// (_LAYER_MEDIA_TYPE_MODES); containerd and CRI-O read them too.
var tarLayerTypes = map[string]compression{
	"application/vnd.oci.image.layer.v1.tar":            uncompressed,
	"application/vnd.oci.image.layer.v1.tar+gzip":       gzipped,
	"application/vnd.docker.image.rootfs.diff.tar.gzip": gzipped,
}

// refusedTarTypes are image layer types that are refused, and why.
var refusedTarTypes = map[string]string{
	"application/vnd.oci.image.layer.v1.tar+zstd":                  "is zstd-compressed: Socair has no zstd decoder among its dependencies, and KServe's oci+fetch refuses zstd layers too",
	"application/vnd.docker.image.rootfs.diff.tar":                 "is a Docker layer type KServe's oci+fetch skips, so it would unpack fewer files than containerd does",
	"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":    "is a foreign layer, fetched from URLs outside the registry",
	"application/vnd.oci.image.layer.nondistributable.v1.tar":      "is a non-distributable layer, which may be fetched from outside the registry",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip": "is a non-distributable layer, which may be fetched from outside the registry",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd": "is a non-distributable layer, which may be fetched from outside the registry",
}

// isImageLayer reports whether a media type is an image layer type, mapped
// or refused.
func isImageLayer(mt string) bool {
	_, ok := tarLayerTypes[mt]
	_, refused := refusedTarTypes[mt]
	return ok || refused
}

// MapOptions bound MapTarLayers. Zero values take the defaults.
type MapOptions struct {
	// ModelRoot is the directory, relative to the image's root, that must
	// hold exactly the attested files; DefaultModelRoot when empty.
	ModelRoot string
	// MaxLayers bounds the layers of one image (default 256).
	MaxLayers int
	// MaxEntries bounds the entries of all layers together (default 1<<20).
	MaxEntries int
	// MaxRatio bounds a layer's decompressed bytes per compressed byte
	// (default 128), past MinBudget (default 64 MiB) for a small layer.
	MaxRatio  int64
	MinBudget int64
}

func (o MapOptions) withDefaults() MapOptions {
	if o.ModelRoot == "" {
		o.ModelRoot = DefaultModelRoot
	}
	if o.MaxLayers <= 0 {
		o.MaxLayers = 256
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 1 << 20
	}
	if o.MaxRatio <= 0 {
		o.MaxRatio = 128
	}
	if o.MinBudget <= 0 {
		o.MinBudget = 64 << 20
	}
	return o
}

// BlobOpener streams a layer blob. The reader must check the blob against
// its digest when it reaches the end, and fail the read that does if it does
// not match, as registry.Repo.OpenBlob does.
type BlobOpener func(ctx context.Context, layer registry.Descriptor) (io.ReadCloser, error)

// CleanModelRoot checks and normalizes a model root: a relative,
// "/"-separated directory path (a leading or trailing "/" is dropped), with
// no empty, ".", or ".." part and no part that starts with ".wh.".
func CleanModelRoot(root string) (string, error) {
	r := strings.Trim(root, "/")
	if r == "" {
		return "", fmt.Errorf("model root %q: the image's root directory cannot be a model root, as base files would share it", root)
	}
	if len(r) > tarwalk.MaxName {
		return "", fmt.Errorf("model root %q is too long", root)
	}
	for _, c := range strings.Split(r, "/") {
		if c == "" || c == "." || c == ".." || strings.HasPrefix(c, ".wh.") || len(c) > 255 || strings.ContainsAny(c, "\x00\\") {
			return "", fmt.Errorf("model root %q is not a clean directory path", root)
		}
	}
	return r, nil
}

// MapTarLayers reads every layer of an image, in order, and checks that the
// tree a consumer unpacks holds, under the model root, exactly the attested
// files (for a single-file attestation, exactly one file, directly in the
// model root), each a regular file with the attested bytes; and that nothing
// in any layer can change that tree for any of the consumers Socair models.
// Each layer is streamed through open, decompressed as it is read, and every
// file under the model root is hashed as it is read. The first problem found
// is returned as ErrNotBound with its reason.
func MapTarLayers(ctx context.Context, m registry.Manifest, a report.ArtifactIdentity, open BlobOpener, o MapOptions) (*Match, error) {
	o = o.withDefaults()
	root, err := CleanModelRoot(o.ModelRoot)
	if err != nil {
		return nil, notBound("%v", err)
	}
	if len(m.Layers) == 0 {
		return nil, notBound("the manifest has no layers")
	}
	if len(m.Layers) > o.MaxLayers {
		return nil, notBound("the image has %d layers, over the %d Socair maps", len(m.Layers), o.MaxLayers)
	}
	for i, l := range m.Layers {
		if err := registry.ValidDigest(l.Digest); err != nil {
			return nil, notBound("layer %d: %v; Socair attests SHA-256", i, err)
		}
		if _, ok := tarLayerTypes[l.MediaType]; !ok {
			why, refused := refusedTarTypes[l.MediaType]
			if !refused {
				why = "is not an image layer type; an image's layers must all be tar layers"
				if _, raw := rawLayerTypes[l.MediaType]; raw {
					why = "is a raw model layer, in an image of tar layers; the two are not mixed"
				}
			}
			return nil, notBound("layer %d: media type %q %s", i, l.MediaType, why)
		}
		if len(l.URLs) != 0 {
			return nil, notBound("layer %d names URLs to fetch it from outside the registry", i)
		}
	}
	mp := newMapper(root, a, o.MaxEntries)
	layers := make([]Layer, len(m.Layers))
	for i, l := range m.Layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rc, err := open(ctx, l)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, l.Digest, err)
		}
		lay, err := mp.layer(i, l, rc, o)
		rc.Close()
		if err != nil {
			var te *tarwalk.Error
			var me *mapError
			switch {
			case errors.As(err, &te):
				return nil, notBound("layer %d (%s): %s", i, l.Digest, te.Reason)
			case errors.As(err, &me):
				return nil, notBound("layer %d (%s): %s", i, l.Digest, me.reason)
			}
			return nil, fmt.Errorf("layer %d (%s): %w", i, l.Digest, err)
		}
		layers[i] = *lay
	}
	if err := mp.finish(); err != nil {
		var me *mapError
		if errors.As(err, &me) {
			return nil, notBound("%s", me.reason)
		}
		return nil, err
	}
	return &Match{Kind: MatchModelRoot, ModelRoot: root, Rules: LayerRules, Layers: layers}, nil
}

// mapError is a refusal found while mapping.
type mapError struct{ reason string }

func (e *mapError) Error() string { return e.reason }

func refuseMap(format string, args ...any) error {
	return &mapError{fmt.Sprintf(format, args...)}
}

// mapper is the tree as the layers so far would unpack it, as far as the
// model root needs: every symbolic link (to resolve a later entry's path
// through it), and every path at, in, or above the model root.
type mapper struct {
	root       string
	single     *report.ArtifactIdentity
	files      map[string]report.ArtifactFile // attested files, by path under the root
	dirs       map[string]bool                // directories under the root that hold attested files
	links      map[string]string              // symbolic links: path -> target
	model      map[string]placed              // what is at each path at, in, or above the root
	found      map[string]bool
	entries    int
	maxEntries int
}

type placed struct {
	kind  tarwalk.Kind
	layer int
}

func newMapper(root string, a report.ArtifactIdentity, maxEntries int) *mapper {
	mp := &mapper{root: root, links: map[string]string{}, model: map[string]placed{}, found: map[string]bool{},
		files: map[string]report.ArtifactFile{}, dirs: map[string]bool{}, maxEntries: maxEntries}
	if len(a.Files) == 0 {
		mp.single = &a
	}
	for _, f := range a.Files {
		mp.files[f.Path] = f
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			mp.dirs[d] = true
		}
	}
	return mp
}

// inside reports whether p is under the model root; under, whether it is
// the root or under it; above, whether it is a directory the root is in
// (the image's root directory "" among them); and modelSide, any of those.
func (mp *mapper) inside(p string) bool { return strings.HasPrefix(p, mp.root+"/") }
func (mp *mapper) under(p string) bool  { return p == mp.root || mp.inside(p) }
func (mp *mapper) above(p string) bool  { return p == "" || strings.HasPrefix(mp.root, p+"/") }
func (mp *mapper) modelSide(p string) bool {
	return mp.under(p) || mp.above(p)
}

func (mp *mapper) rel(p string) string { return p[len(mp.root)+1:] }

func join(dir, base string) string {
	if dir == "" {
		return base
	}
	return dir + "/" + base
}

func parent(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

// maxHops bounds the symbolic links followed in one path: Linux's
// MAXSYMLINKS. containerd allows more (255); past this a path is refused.
const maxHops = 40

// resolve returns where p (a clean path relative to the image's root, ""
// the root) is in the tree, following every symbolic link on it as
// containerd's fs.RootPath does when it places an entry: scoped to the
// image's root, with ".." stopping there.
func (mp *mapper) resolve(p string) (string, error) {
	var cur []string
	todo := strings.Split(p, "/")
	hops, steps := 0, 0
	for len(todo) > 0 {
		if steps++; steps > 4*tarwalk.MaxName {
			return "", refuseMap("resolving %s takes too many steps", p)
		}
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
		next := strings.Join(append(cur, c), "/")
		if t, ok := mp.links[next]; ok {
			if hops++; hops > maxHops {
				return "", refuseMap("%s goes through more than %d symbolic links", p, maxHops)
			}
			if strings.HasPrefix(t, "/") {
				cur = nil
			}
			todo = append(strings.Split(t, "/"), todo...)
			continue
		}
		cur = append(cur, c)
	}
	return strings.Join(cur, "/"), nil
}

// canon reads an entry's name as a clean relative path ("" for the image's
// root). An absolute path, an empty, ".", or ".." part, or a trailing "/"
// on anything but a directory is refused: consumers clean such names
// differently (containerd joins them to the root, CRI-O refuses a "..",
// KServe's oci+fetch matches the raw name). A leading "./" is read as tar
// archives made from "." write it, but not in the model root, as KServe's
// oci+fetch reads a model file only when its entry is named models/<path>.
func (mp *mapper) canon(raw string, dir bool) (string, error) {
	s := raw
	if strings.HasPrefix(s, "/") {
		return "", refuseMap("%q is an absolute path", raw)
	}
	if strings.HasSuffix(s, "/") {
		if !dir {
			return "", refuseMap("%q ends in / but is not a directory", raw)
		}
		s = strings.TrimRight(s, "/")
	}
	if s == "." {
		return "", nil
	}
	dotted := strings.HasPrefix(s, "./")
	s = strings.TrimPrefix(s, "./")
	for _, c := range strings.Split(s, "/") {
		switch {
		case c == "..":
			return "", refuseMap("%q climbs out of its directory with ..", raw)
		case c == "" || c == ".":
			return "", refuseMap("%q is not a clean path", raw)
		case len(c) > 255:
			return "", refuseMap("%q has a name over 255 bytes", raw)
		}
	}
	if dotted && mp.under(s) {
		return "", refuseMap("%q is named with a leading ./: KServe's oci+fetch reads a model file only when its entry is named %s/<path>, and would skip it", raw, mp.root)
	}
	return s, nil
}

// layerState counts a layer's entries by where they are.
type layerState struct {
	model, outside, entries int
	files                   []string
}

func (mp *mapper) layer(i int, d registry.Descriptor, rc io.Reader, o MapOptions) (*Layer, error) {
	br := bufio.NewReaderSize(rc, 64<<10)
	head, err := br.Peek(6)
	if err != nil && err != io.EOF {
		return nil, err
	}
	var src io.Reader = br
	var gz *gzip.Reader
	found := sniff(head)
	switch tarLayerTypes[d.MediaType] {
	case uncompressed:
		if found != "" {
			return nil, refuseMap("its media type says uncompressed, and its bytes start with a %s header: containerd and CRI-O decompress by the bytes, KServe's oci+fetch by the media type", found)
		}
	case gzipped:
		if found != "gzip" {
			return nil, refuseMap("its media type says gzip, and its bytes are not a gzip stream")
		}
		if gz, err = gzip.NewReader(br); err != nil {
			return nil, refuseMap("its gzip header does not read: %v", err)
		}
		// One member only: Python's tarfile, reading a layer as a stream
		// ("r|gz", as KServe's oci+fetch does), stops at the end of the
		// first member, so it would unpack fewer files than containerd.
		gz.Multistream(false)
		src = gz
	}
	budget := o.MinBudget
	switch {
	case d.Size > math.MaxInt64/o.MaxRatio:
		budget = math.MaxInt64
	case d.Size*o.MaxRatio > budget:
		budget = d.Size * o.MaxRatio
	}
	lim := &budgetReader{r: src, left: budget, ratio: o.MaxRatio}
	tr := tarwalk.NewReader(lim)
	st := &layerState{}
	for {
		e, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, unwrapRead(err)
		}
		if err := mp.entry(i, e, tr, st); err != nil {
			return nil, unwrapRead(err)
		}
	}
	if err := tr.Finish(); err != nil {
		return nil, unwrapRead(err)
	}
	// The blob's reader checks its digest on the read that reaches its end,
	// and fails that read if the bytes are not the digest's. Finish read an
	// uncompressed layer to that end; for a gzip layer, the end must follow
	// the one member at once. Nothing above counts until then.
	if gz != nil {
		if _, err := br.Peek(1); err == nil {
			return nil, refuseMap("its blob holds more than one gzip member, or bytes after one: Python's tarfile, reading it as KServe's oci+fetch does, stops at the end of the first, so it would unpack fewer files than containerd")
		} else if err != io.EOF {
			return nil, err
		}
	}
	if st.model > 0 && st.outside > 0 {
		return nil, refuseMap("it holds files in the model root %s/ and %d entries outside it: build the model root in layers of its own (COPY data/ /%s/), so the base layers can be told apart", mp.root, st.outside, mp.root)
	}
	l := &Layer{Digest: d.Digest, Size: d.Size, MediaType: d.MediaType, Role: RoleBase, Entries: st.entries}
	if st.model > 0 {
		l.Role = RoleModel
		sort.Strings(st.files)
		l.Files = st.files
	}
	return l, nil
}

// unwrapRead turns a read error that carries a refusal (a tar refusal or a
// decompression bound) into it, and leaves others as they are.
func unwrapRead(err error) error {
	var be *budgetError
	if errors.As(err, &be) {
		return refuseMap("%s", be.Error())
	}
	var corrupt flate.CorruptInputError
	if errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) || errors.As(err, &corrupt) || errors.Is(err, io.ErrUnexpectedEOF) {
		return refuseMap("its gzip stream does not decompress: %v", err)
	}
	return err
}

// sniff names the compression a blob's first bytes declare, as containerd
// (gzip, zstd and its skippable frames) and containers/image (gzip, bzip2,
// xz, zstd) detect it, or "".
func sniff(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b, 0x08}):
		return "gzip"
	case bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd"
	case len(b) >= 4 && binary.LittleEndian.Uint32(b[:4])&0xfffffff0 == 0x184d2a50:
		return "zstd"
	case bytes.HasPrefix(b, []byte("BZh")):
		return "bzip2"
	case bytes.HasPrefix(b, []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}):
		return "xz"
	}
	return ""
}

// budgetReader fails a read past a layer's decompression budget.
type budgetReader struct {
	r     io.Reader
	left  int64
	ratio int64
	read  int64
}

type budgetError struct {
	read  int64
	ratio int64
}

func (e *budgetError) Error() string {
	return fmt.Sprintf("it decompresses to more than %d bytes, past the %d:1 bound", e.read, e.ratio)
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, &budgetError{b.read, b.ratio}
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	b.read += int64(n)
	return n, err
}

func (mp *mapper) entry(li int, e *tarwalk.Entry, data io.Reader, st *layerState) error {
	if mp.entries++; mp.entries > mp.maxEntries {
		return refuseMap("the image has more than %d entries", mp.maxEntries)
	}
	st.entries++
	n, err := mp.canon(e.Name, e.Kind == tarwalk.Directory)
	if err != nil {
		return err
	}
	if n == "" {
		if e.Kind != tarwalk.Directory {
			return refuseMap("a %s names the image's root directory", e.Kind)
		}
		return nil
	}
	dir, base := parent(n), path.Base(n)
	for _, c := range strings.Split(dir, "/") {
		if strings.HasPrefix(c, ".wh.") {
			return refuseMap("%s goes through a directory named %s, a whiteout name", n, c)
		}
	}
	if strings.HasPrefix(base, ".wh.") {
		return mp.whiteout(n, dir, base, e, st)
	}
	pp, err := mp.resolve(dir)
	if err != nil {
		return err
	}
	phys := join(pp, base)
	if phys != n && (mp.modelSide(n) || mp.modelSide(phys)) {
		return refuseMap("%s is placed at %s through a symbolic link: a runtime that follows links in an entry's path places it there, one that unpacks each layer on its own does not", n, phys)
	}
	switch {
	case mp.inside(n):
		st.model++
	case !mp.modelSide(n):
		st.outside++
	}
	switch e.Kind {
	case tarwalk.Directory:
		return mp.directory(li, n, phys)
	case tarwalk.Regular:
		return mp.regular(li, n, phys, e, data, st)
	case tarwalk.Symlink:
		return mp.symlink(n, phys, e.Linkname)
	case tarwalk.Hardlink:
		return mp.hardlink(n, phys, e.Linkname)
	case tarwalk.CharDevice, tarwalk.BlockDevice, tarwalk.FIFO:
		// Base images ship /dev nodes (Amazon Linux 2023, Wolfi), so a
		// special file outside the model root is allowed. At its path or
		// above it, it would replace what the model needs, and a 0/0
		// character device in an overlayfs layer is a whiteout.
		if mp.modelSide(n) {
			return refuseMap("a %s at %s, which is the model root, in it, or above it", e.Kind, n)
		}
		delete(mp.links, phys)
		return nil
	}
	return refuseMap("%s is a %s", n, e.Kind)
}

func (mp *mapper) whiteout(n, dir, base string, e *tarwalk.Entry, st *layerState) error {
	if e.Kind != tarwalk.Regular || e.Size != 0 {
		return refuseMap("%s, a whiteout, is not an empty regular file", n)
	}
	pp, err := mp.resolve(dir)
	if err != nil {
		return err
	}
	if base == ".wh..wh..opq" {
		if mp.modelSide(dir) || mp.modelSide(pp) {
			return refuseMap("an opaque whiteout on %s/, which is the model root, in it, or above it: it would hide what lower layers put there, and KServe's oci+fetch does not apply whiteouts", or(dir, "."))
		}
		st.outside++
		return nil
	}
	if strings.HasPrefix(base, ".wh..wh.") {
		return refuseMap("%s is an AUFS metadata name, which containerd and CRI-O read differently", n)
	}
	target, phys := join(dir, base[4:]), join(pp, base[4:])
	if mp.modelSide(target) || mp.modelSide(phys) {
		return refuseMap("a whiteout of %s, which is the model root, in it, or above it: it would remove what a lower layer put there, and KServe's oci+fetch does not apply whiteouts", target)
	}
	// Symbolic links a whiteout removes stay in the map: a link kept that a
	// runtime removed can only make a later entry look placed through it,
	// which refuses more, never less.
	st.outside++
	return nil
}

func or(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

func (mp *mapper) directory(li int, n, phys string) error {
	if mp.inside(n) && (mp.single != nil || !mp.dirs[mp.rel(n)]) {
		return refuseMap("%s/ is a directory in the model root that holds no attested file", n)
	}
	// Nothing but a directory can be at a model-side path before this one
	// (a file there is refused unless attested, and an attested file's
	// path is no directory's), so a directory never replaces a model file.
	if mp.modelSide(n) {
		mp.model[n] = placed{tarwalk.Directory, li}
	}
	delete(mp.links, phys)
	return nil
}

func (mp *mapper) regular(li int, n, phys string, e *tarwalk.Entry, data io.Reader, st *layerState) error {
	switch {
	case n == mp.root:
		return refuseMap("a file at %s, where the model root's directory is", n)
	case mp.above(n):
		return refuseMap("a file at %s, a directory the model root is in", n)
	case !mp.inside(n):
		delete(mp.links, phys)
		return nil
	}
	if p, dup := mp.model[n]; dup {
		return refuseMap("%s appears twice, in layer %d and layer %d: a consumer keeps one, and which depends on how it applies layers", n, p.layer, li)
	}
	r := mp.rel(n)
	var wantSHA string
	var wantSize int64
	if mp.single != nil {
		if strings.Contains(r, "/") {
			return refuseMap("%s is in a subdirectory of the model root; the attestation covers one file (%s), directly in it", n, mp.single.FileName)
		}
		if len(mp.found) > 0 {
			return refuseMap("%s is a second file in the model root; the attestation covers one file (%s). Scan a model directory holding every file the image carries under %s/, and attach that attestation", n, mp.single.FileName, mp.root)
		}
		wantSHA, wantSize = mp.single.SHA256, mp.single.SizeBytes
	} else {
		f, ok := mp.files[r]
		if !ok {
			return refuseMap("%s is not a file the attestation lists", n)
		}
		wantSHA, wantSize = f.SHA256, f.SizeBytes
	}
	if e.Size != wantSize {
		return refuseMap("%s is %d bytes, but the attested file is %d", n, e.Size, wantSize)
	}
	h := sha256.New()
	if _, err := io.Copy(h, data); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return refuseMap("%s is sha256:%s, but the attested file is sha256:%s", n, got, wantSHA)
	}
	mp.model[n] = placed{tarwalk.Regular, li}
	mp.found[r] = true
	st.files = append(st.files, r)
	return nil
}

// linkTarget returns where a symbolic link at phys pointing to target
// leads: as written, cleaned (lexical), and as resolved in the tree.
func (mp *mapper) linkTarget(phys, target string) (lexical, resolved string, err error) {
	from := parent(phys)
	abs := strings.HasPrefix(target, "/")
	if abs {
		lexical = strings.TrimPrefix(path.Clean(target), "/")
		resolved, err = mp.resolve(strings.TrimPrefix(target, "/"))
	} else {
		lexical = strings.TrimPrefix(path.Clean("/"+join(from, target)), "/")
		resolved, err = mp.resolve(join(from, target))
	}
	return lexical, resolved, err
}

func (mp *mapper) symlink(n, phys, target string) error {
	if mp.modelSide(n) {
		return refuseMap("a symbolic link at %s, which is the model root, in it, or above it", n)
	}
	lex, res, err := mp.linkTarget(phys, target)
	if err != nil {
		return err
	}
	if mp.modelSide(lex) || mp.modelSide(res) {
		return refuseMap("a symbolic link %s -> %s, which leads to the model root, into it, or above it: an entry written through it would land there", n, target)
	}
	mp.links[phys] = target
	return nil
}

func (mp *mapper) hardlink(n, phys, target string) error {
	if mp.modelSide(n) {
		return refuseMap("a hard link at %s, which is the model root, in it, or above it", n)
	}
	lk, err := mp.canon(target, false)
	if err != nil {
		return refuseMap("the hard link %s: its target: %v", n, err)
	}
	pp, err := mp.resolve(parent(lk))
	if err != nil {
		return err
	}
	lphys := join(pp, path.Base(lk))
	if lk == "" || mp.modelSide(lk) || mp.modelSide(lphys) {
		return refuseMap("a hard link %s to %s, which is the model root, in it, or above it", n, target)
	}
	if _, isLink := mp.links[lphys]; isLink {
		return refuseMap("a hard link %s to %s, a symbolic link: it would make %s another symbolic link", n, target, n)
	}
	delete(mp.links, phys)
	return nil
}

// finish checks what only the whole image shows: every attested file is
// there, and no symbolic link in the final tree leads to the model root,
// into it, or above it (a later layer can change where an earlier link
// leads).
func (mp *mapper) finish() error {
	if mp.single != nil {
		if len(mp.found) == 0 {
			return refuseMap("the image has no file in its model root %s/; the attestation covers %s", mp.root, mp.single.FileName)
		}
	} else {
		var missing []string
		for p := range mp.files {
			if !mp.found[p] {
				missing = append(missing, mp.root+"/"+p)
			}
		}
		if len(missing) != 0 {
			sort.Strings(missing)
			return refuseMap("the image has no file for attested %s", strings.Join(missing, ", "))
		}
	}
	links := make([]string, 0, len(mp.links))
	for p := range mp.links {
		links = append(links, p)
	}
	sort.Strings(links)
	for _, p := range links {
		lex, res, err := mp.linkTarget(p, mp.links[p])
		if err != nil {
			return err
		}
		if mp.modelSide(lex) || mp.modelSide(res) {
			return refuseMap("in the unpacked image, the symbolic link %s -> %s leads to the model root, into it, or above it", p, mp.links[p])
		}
	}
	return nil
}
