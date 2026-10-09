package pickle

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

// Each container is checked as its loader reads it: which pickles it
// unpickles, which records back which storages, and which bytes it never
// reads. A storage that claims more bytes than its record holds is a
// contradiction (FAIL: the loader rejects the file or reads outside the
// record); bytes no loader reads are a place to carry a payload (LEAD).

func (s *scan) gopts(pids pidMode) grammarOpts {
	return grammarOpts{pids: pids, reviewed: s.opts.Reviewed}
}

// addGrammar records what validating one pickle found.
func (s *scan) addGrammar(where string, g *validation) {
	for _, v := range g.violations {
		s.finding(v.status, v.pattern, where+": "+v.span, v.detail)
	}
	if g.dropped > 0 {
		s.finding(checks.Lead, "pickle-grammar", where, fmt.Sprintf("%d more departure(s) from the grammar, not listed", g.dropped))
	}
	for _, gap := range g.gaps {
		s.gap(where + ": " + gap)
	}
	if g.broken != "" && !s.unreadableAt(where) {
		s.finding(checks.Lead, "pickle-unreadable", where, "CPython stops with an error here ("+g.broken+"); anything before this point runs")
	}
	if !g.conforms() {
		return
	}
	p := &s.proof
	p.pickles++
	if p.protocols == nil {
		p.protocols = map[int]bool{}
	}
	p.protocols[g.protocol] = true
	p.tensors = append(p.tensors, g.tensors...)
	for c := range g.reviewed {
		if p.reviewed == nil {
			p.reviewed = map[string]bool{}
		}
		p.reviewed[c] = true
	}
}

func (s *scan) unreadableAt(where string) bool {
	for _, u := range s.unreadable {
		if strings.HasPrefix(u, where+":") {
			return true
		}
	}
	return false
}

func (s *scan) unaccounted(span, detail string) {
	s.finding(checks.Lead, "pickle-unaccounted-bytes", span, detail+"; no loader reads them, so they are a place to carry a payload")
}

func (s *scan) contradiction(span, detail string) {
	s.finding(checks.Fail, "pickle-storage-layout", span, detail)
}

// validateStream validates the first pickle in r within the scan budget and
// reports how many bytes r held in all, so bytes after STOP can be counted.
func validateStream(r io.Reader, opts grammarOpts) (*validation, int64, error) {
	cr := &countReader{r: r}
	g := validate(io.LimitReader(cr, maxScanBytes), opts)
	if g.root == nil && cr.n >= maxScanBytes {
		g.broken = ""
		g.gap(fmt.Sprintf("a pickle longer than the %d-byte scan budget", maxScanBytes))
	}
	_, _ = io.Copy(io.Discard, cr)
	return g, cr.n, cr.err
}

func validateAt(ra io.ReaderAt, off, size int64, opts grammarOpts) *validation {
	g, _, _ := validateStream(io.NewSectionReader(ra, off, size-off), opts)
	return g
}

// legacyMagic is the first pickle of a legacy torch.save stream.
var legacyMagic, _ = new(big.Int).SetString("1950A86A20F9469CFC6C", 16)

func isLegacyMagic(root *value) bool {
	return root != nil && root.kind == kInt && root.x != nil && root.x.big != nil && root.x.big.Cmp(legacyMagic) == 0
}

// rawStream checks a file that is pickles end to end: a raw pickle (each in
// turn, as a loop of pickle.load reads them), or a legacy torch.save stream,
// which begins with torch's magic number.
func (s *scan) rawStream(f io.ReaderAt, size int64) {
	first := validateAt(f, 0, size, s.gopts(pidNone))
	if isLegacyMagic(first.root) {
		s.legacyStream(f, size, first)
		return
	}
	s.addGrammar("stream", first)
	if first.root == nil {
		return
	}
	off := first.end
	for i := 2; off < size; i++ {
		var b [1]byte
		if _, err := f.ReadAt(b[:], off); err != nil || b[0] != 0x80 {
			break
		}
		g := validateAt(f, off, size, s.gopts(pidNone))
		if g.root == nil {
			break // trailing data that happens to start with PROTO
		}
		s.addGrammar(fmt.Sprintf("stream (pickle %d)", i), g)
		off += g.end
	}
	if off < size {
		s.unaccounted("stream", fmt.Sprintf("%d byte(s) after the last pickle", size-off))
	}
}

// legacyStream checks torch.save's format before zips: the magic number, the
// protocol version, sys_info, the object (whose storage ids carry element
// counts), the storage keys, then for each key an 8-byte element count and
// the storage's bytes. torch.load reads exactly that and nothing after.
func (s *scan) legacyStream(f io.ReaderAt, size int64, magic *validation) {
	s.addGrammar("stream (magic number)", magic)
	off := magic.end
	steps := []struct {
		name string
		pids pidMode
	}{{"protocol version", pidNone}, {"sys_info", pidNone}, {"object", pidLegacy}, {"storage keys", pidNone}}
	var gs [4]*validation
	for i, st := range steps {
		g := validateAt(f, off, size, s.gopts(st.pids))
		s.addGrammar("stream ("+st.name+")", g)
		if g.root == nil {
			return
		}
		gs[i], off = g, off+g.end
	}
	if v := gs[0].root; v.kind != kInt || v.num != 1001 {
		s.finding(checks.Lead, "pickle-noncanonical", "stream (protocol version)", "a protocol version other than 1001, which torch.load refuses")
	}
	keys := gs[3].root
	if keys.kind != kList {
		s.finding(checks.Lead, "pickle-grammar", "stream (storage keys)", "storage keys that are not a list")
		return
	}
	stored := gs[2].storages
	listed := map[string]bool{}
	for _, k := range keys.items {
		if k.kind != kStr {
			s.finding(checks.Lead, "pickle-grammar", "stream (storage keys)", "a storage key that is not a string")
			return
		}
		st := stored[k.s]
		switch {
		case st == nil:
			s.contradiction("storage "+k.s, "a storage record no tensor references; torch.load rejects the file")
			return
		case listed[k.s]:
			s.contradiction("storage "+k.s, "a storage record listed twice; the second overwrites the first")
			return
		}
		listed[k.s] = true
		var b [8]byte
		if _, err := f.ReadAt(b[:], off); err != nil {
			s.contradiction("storage "+k.s, "a record cut off at the end of the file")
			return
		}
		n := int64(binary.LittleEndian.Uint64(b[:]))
		if n != st.numel {
			s.contradiction("storage "+k.s, fmt.Sprintf("a record of %d element(s) for a storage whose id says %d; torch.load rejects the file", n, st.numel))
			return
		}
		hi, lo := bits.Mul64(uint64(n), uint64(st.itemsize))
		if hi != 0 || lo > uint64(size-off-8) {
			s.contradiction("storage "+k.s, fmt.Sprintf("a record of %d %s element(s) that runs past the end of the file", n, st.dtype))
			return
		}
		off += 8 + int64(lo)
	}
	for _, k := range gs[2].order {
		if !listed[k] {
			s.contradiction("storage "+k, "a storage a tensor references but with no record; torch.load leaves it uninitialized")
		}
	}
	if off < size {
		s.unaccounted("stream", fmt.Sprintf("%d byte(s) after the last storage record", size-off))
	}
	s.proof.layouts = append(s.proof.layouts, fmt.Sprintf("legacy torch stream: %d storage record(s), each exactly its storage's element count, and nothing after", len(listed)))
}

// torchMetadata are the records torch.save writes beside data.pkl and the
// storages, each a few bytes.
var torchMetadata = map[string]bool{
	"version": true, ".data/version": true, "byteorder": true, ".format_version": true,
	".storage_alignment": true, ".data/serialization_id": true,
}

// zipArchive checks a zip as its loader reads it: an .npz (every entry an
// .npy), or a torch.save checkpoint, whose loader reads <dir>/data.pkl and
// the data/<key> records it references, in the directory the first entry
// names.
func (s *scan) zipArchive(zr *zip.Reader) {
	var files []*zip.File
	for _, zf := range zr.File {
		if !zf.FileInfo().IsDir() {
			files = append(files, zf)
		}
	}
	if len(files) == 0 {
		return
	}
	npz := true
	for _, zf := range files {
		npz = npz && strings.HasSuffix(strings.ToLower(zf.Name), ".npy")
	}
	if npz {
		for _, zf := range files {
			s.npyArray(zf.Name, int64(zf.UncompressedSize64), zf.Open)
		}
		return
	}
	dir, _, hasDir := strings.Cut(files[0].Name, "/")
	byName := map[string]*zip.File{}
	for _, zf := range files {
		if byName[zf.Name] != nil {
			s.finding(checks.Lead, "pickle-noncanonical", zf.Name, "a record name repeated in the archive: readers disagree on which copy they read")
		}
		byName[zf.Name] = zf
	}
	data := dir + "/data.pkl"
	if !hasDir || byName[data] == nil {
		s.gap("a zip archive that is neither a torch.save checkpoint (data.pkl in the first entry's directory) nor an .npz")
		return
	}
	for name := range byName {
		if strings.HasPrefix(name, dir+"/code/") || name == dir+"/constants.pkl" {
			s.gap("a TorchScript archive (torch.jit.save), whose code this check does not model")
			return
		}
	}
	rc, err := byName[data].Open()
	if err != nil {
		s.unreadable = append(s.unreadable, data+": "+err.Error())
		return
	}
	g, total, rerr := validateStream(rc, s.gopts(pidZip))
	_ = rc.Close()
	s.addGrammar(data, g)
	if errors.Is(rerr, zip.ErrChecksum) {
		s.finding(checks.Lead, "pickle-noncanonical", data, "a CRC-32 that does not match: PyTorch's loader reads on, and other readers stop")
	}
	if g.root == nil {
		return
	}
	if total > g.end {
		s.unaccounted(data, fmt.Sprintf("%d byte(s) after STOP", total-g.end))
	}
	used := map[string]bool{data: true}
	matched := 0
	for _, key := range g.order {
		st := g.storages[key]
		name := dir + "/data/" + key
		used[name] = true
		zf := byName[name]
		if zf == nil {
			s.contradiction(name, fmt.Sprintf("missing: a storage of %d %s element(s) has no record; torch.load rejects the file", st.numel, st.dtype))
			continue
		}
		hi, want := bits.Mul64(uint64(st.numel), uint64(st.itemsize))
		have := zf.UncompressedSize64
		switch {
		case hi != 0 || want > have:
			s.contradiction(name, fmt.Sprintf("%d byte(s) for a storage of %d %s element(s); the loader reads past the record", have, st.numel, st.dtype))
		case have > want:
			s.unaccounted(name, fmt.Sprintf("%d byte(s), %d more than its storage of %d %s element(s)", have, have-want, st.numel, st.dtype))
		default:
			matched++
		}
	}
	for _, zf := range files {
		rel, inDir := strings.CutPrefix(zf.Name, dir+"/")
		if used[zf.Name] || (inDir && torchMetadata[rel] && zf.UncompressedSize64 <= 64) {
			continue
		}
		s.unaccounted(zf.Name, fmt.Sprintf("a record of %d byte(s) torch.load never reads", zf.UncompressedSize64))
	}
	records := fmt.Sprintf("%d storage record(s), each exactly numel x itemsize bytes", matched)
	if matched == 0 {
		records = "no storage records"
	}
	s.proof.layouts = append(s.proof.layouts, "torch zip: "+records+", and no record torch.load does not read")
}

// npyArray checks one .npy: its header, then its data, raw or pickled.
func (s *scan) npyArray(where string, size int64, open func() (io.ReadCloser, error)) {
	rc, err := open()
	if err != nil {
		s.unreadable = append(s.unreadable, where+": "+err.Error())
		return
	}
	defer rc.Close()
	h, err := readNPYHeader(rc)
	if err != nil {
		s.gap(where + ": " + strings.TrimPrefix(err.Error(), errNPYUnread.Error()+": "))
		return
	}
	shape := fmt.Sprint(h.shape)
	if !h.object {
		cr := &countReader{r: rc}
		_, _ = io.Copy(io.Discard, cr)
		if errors.Is(cr.err, zip.ErrChecksum) {
			s.finding(checks.Lead, "pickle-noncanonical", where, "a CRC-32 that does not match: some readers stop, others read on")
		}
		hi, want := bits.Mul64(uint64(h.count), uint64(h.itemsize))
		switch {
		case hi != 0 || want > math.MaxInt64 || int64(want) > cr.n:
			s.contradiction(where, fmt.Sprintf("%d data byte(s) for shape %s of %s, which needs %d; numpy rejects the file", cr.n, shape, h.descr, want))
		case cr.n > int64(want):
			s.unaccounted(where, fmt.Sprintf("%d data byte(s), %d more than shape %s of %s needs", cr.n, cr.n-int64(want), shape, h.descr))
		default:
			s.proof.arrays = append(s.proof.arrays, fmt.Sprintf("%s %s %s", where, h.descr, shape))
		}
		return
	}
	// An object dtype: the data is a pickle numpy.load(allow_pickle=True)
	// unpickles. Both passes read it.
	w, truncated := walkCapped(rc)
	s.addWalk(where, w)
	switch {
	case truncated:
		s.truncated = append(s.truncated, where)
	case w.err != nil && w.pickles == 0:
		s.unreadable = append(s.unreadable, where+": "+w.err.Error())
	}
	rc2, err := open()
	if err != nil {
		return
	}
	defer rc2.Close()
	if _, err := io.CopyN(io.Discard, rc2, h.dataStart); err != nil {
		return
	}
	g, total, _ := validateStream(rc2, s.gopts(pidNone))
	s.addGrammar(where, g)
	if g.root != nil && total > g.end {
		s.unaccounted(where, fmt.Sprintf("%d byte(s) after the pickled data", total-g.end))
	}
}

// tarArchive applies the grammar to the pickle at the start of each entry of
// a legacy torch tar (sys_info, pickle, and the counts that begin storages
// and tensors). Its storage records are interleaved with pickles in a layout
// this check does not match, so a clean tar is a gap, not a pass.
func (s *scan) tarArchive(f *os.File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	tr := tar.NewReader(f)
	for i := 0; i < maxEntries; i++ {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		br := bufio.NewReader(tr)
		if b, err := br.Peek(1); err != nil || b[0] != 0x80 {
			continue
		}
		g, _, _ := validateStream(br, s.gopts(pidTar))
		s.addGrammar(h.Name, g)
	}
	s.gap("a legacy tar checkpoint: " + Grammar + " checked its pickles, but this check does not match the tar's storage records")
}
