package convert

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"

	"github.com/defilantech/socair/internal/safetensors"
)

// Output is a written conversion.
type Output struct {
	// SHA256 and Size are the output file's, read back from disk.
	SHA256 string
	Size   int64
	// Tensors are every input tensor, written and aliases, by name.
	Tensors []Tensor
	// Metadata is the output's __metadata__.
	Metadata map[string]string
}

// writeHook, when set, wraps the writer each tensor's bytes go through on
// their way into the output. The falsification tests corrupt bytes there to
// show the read-back comparison catches it.
var writeHook func(name string, w io.Writer) io.Writer

// Write converts the planned checkpoint into a new file at dst, which must
// not exist. It reads every storage record twice by two paths: once through
// the zip reader, which checks each record's CRC-32 and hashes each tensor's
// bytes, and once in place, to copy them. It then reads the output back,
// checks it with Socair's safetensors parser, and compares every tensor's
// bytes with its source's. Any difference, or any error, removes dst: a
// partial or unverified output is never left behind.
func (p *Plan) Write(dst string) (out *Output, err error) {
	in, err := os.Open(p.path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(in, fi.Size())
	if err != nil {
		return nil, refuse("the checkpoint is not a readable zip: %v", err)
	}
	records, err := p.records(zr)
	if err != nil {
		return nil, err
	}
	source, err := p.hashSources(records)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	if err := p.copyTensors(f, in, records); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return p.readBack(dst, source)
}

// records finds each storage record the output reads: present once, stored
// uncompressed as torch.save writes it, and exactly the size the stream says.
func (p *Plan) records(zr *zip.Reader) (map[string]*zip.File, error) {
	want := map[string]bool{}
	for _, r := range p.Records {
		want[r] = true
	}
	out := map[string]*zip.File{}
	for _, zf := range zr.File {
		if !want[zf.Name] {
			continue
		}
		if out[zf.Name] != nil {
			return nil, refuse("record %s appears twice in the zip, and readers disagree on which they read", zf.Name)
		}
		out[zf.Name] = zf
	}
	sizes := map[string]int64{}
	for _, s := range p.state.Storages {
		n, _ := mul(s.Numel, s.Itemsize)
		sizes[s.Record] = n
	}
	for _, r := range p.Records {
		zf := out[r]
		switch {
		case zf == nil:
			return nil, refuse("record %s is missing", r)
		case zf.Method != zip.Store:
			return nil, refuse("record %s is compressed (zip method %d); torch.save writes storage records uncompressed, and this converter reads them in place", r, zf.Method)
		case zf.UncompressedSize64 != uint64(sizes[r]) || zf.CompressedSize64 != zf.UncompressedSize64:
			return nil, refuse("record %s holds %d byte(s) (%d stored) for a storage of %d", r, zf.UncompressedSize64, zf.CompressedSize64, sizes[r])
		}
	}
	return out, nil
}

// span is one tensor's bytes in a record or in the output, and its hash.
type span struct {
	name       string
	start, end int64
	h          hash.Hash
}

// spanHasher hashes the spans of a stream it is written, which must be
// sorted and disjoint.
type spanHasher struct {
	pos   int64
	spans []*span
	next  int
}

func (s *spanHasher) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 && s.next < len(s.spans) {
		sp := s.spans[s.next]
		if s.pos >= sp.end {
			s.next++
			continue
		}
		if s.pos < sp.start {
			skip := min(int64(len(b)), sp.start-s.pos)
			b, s.pos = b[skip:], s.pos+skip
			continue
		}
		take := min(int64(len(b)), sp.end-s.pos)
		sp.h.Write(b[:take])
		b, s.pos = b[take:], s.pos+take
	}
	s.pos += int64(len(b))
	return n, nil
}

func sortedSpans(spans []*span) []*span {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	return spans
}

// hashSources reads each record whole through the zip reader, which returns
// an error at its end when the CRC-32 does not hold, and hashes each written
// tensor's bytes on the way.
func (p *Plan) hashSources(records map[string]*zip.File) (map[string]string, error) {
	byRecord := map[string][]*span{}
	for _, t := range p.written {
		if t.Size > 0 {
			byRecord[t.Record] = append(byRecord[t.Record], &span{name: t.Name, start: t.Offset, end: t.Offset + t.Size, h: sha256.New()})
		}
	}
	out := map[string]string{}
	buf := make([]byte, 4<<20)
	for _, r := range p.Records {
		spans := sortedSpans(byRecord[r])
		rc, err := records[r].Open()
		if err != nil {
			return nil, refuse("record %s cannot be read: %v", r, err)
		}
		n, err := io.CopyBuffer(&spanHasher{spans: spans}, rc, buf)
		rc.Close()
		switch {
		case errors.Is(err, zip.ErrChecksum):
			return nil, refuse("record %s fails its CRC-32 check (or torch.save wrote none, with compute_crc32 off); torch.load reads on and other zip readers stop, so the readers disagree", r)
		case err != nil:
			return nil, refuse("record %s cannot be read: %v", r, err)
		case uint64(n) != records[r].UncompressedSize64:
			return nil, refuse("record %s gave %d byte(s), not %d", r, n, records[r].UncompressedSize64)
		}
		for _, sp := range spans {
			out[sp.name] = hex.EncodeToString(sp.h.Sum(nil))
		}
	}
	return out, nil
}

// copyTensors writes the header and each tensor's bytes, read in place from
// its record in the checkpoint.
func (p *Plan) copyTensors(f *os.File, in io.ReaderAt, records map[string]*zip.File) error {
	w := bufio.NewWriterSize(f, 4<<20)
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(p.header)))
	w.Write(n[:])
	w.Write(p.header)
	for _, t := range p.written {
		if t.Size == 0 {
			continue
		}
		at, err := records[t.Record].DataOffset()
		if err != nil {
			return err
		}
		var dst io.Writer = w
		if writeHook != nil {
			dst = writeHook(t.Name, w)
		}
		if _, err := io.Copy(dst, io.NewSectionReader(in, at+t.Offset, t.Size)); err != nil {
			return fmt.Errorf("copy %s: %w", t.Name, err)
		}
	}
	return w.Flush()
}

// stHeader is one header entry as the output holds it.
type stHeader struct {
	Dtype       string   `json:"dtype"`
	Shape       []int64  `json:"shape"`
	DataOffsets [2]int64 `json:"data_offsets"`
}

// readBack checks the output on disk: Socair's safetensors parser finds a
// sound layout, the header names every written tensor with its dtype and
// shape, and each tensor's bytes hash to its source's. It hashes the whole
// file on the way, so the output's hash is of the bytes on disk.
func (p *Plan) readBack(dst string, source map[string]string) (*Output, error) {
	m, err := safetensors.ReadHeader(dst)
	if err != nil {
		return nil, fmt.Errorf("the output does not read as safetensors: %w", err)
	}
	if problems := append(append(append(append([]string(nil), m.Duplicates...), m.Malformed...), m.Layout...), m.Unverified...); len(problems) > 0 {
		return nil, fmt.Errorf("the output's header is not sound: %v", problems)
	}
	if m.TensorCount != len(p.written) {
		return nil, fmt.Errorf("the output holds %d tensors, not %d", m.TensorCount, len(p.written))
	}

	f, err := os.Open(dst)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var n [8]byte
	if _, err := io.ReadFull(f, n[:]); err != nil {
		return nil, err
	}
	hlen := int64(binary.LittleEndian.Uint64(n[:]))
	if hlen != int64(len(p.header)) {
		return nil, fmt.Errorf("the output's header is %d bytes, not %d", hlen, len(p.header))
	}
	raw := make([]byte, hlen)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, err
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("the output's header: %w", err)
	}
	var meta map[string]string
	if err := json.Unmarshal(entries["__metadata__"], &meta); err != nil || len(meta) != len(p.metadata) {
		return nil, fmt.Errorf("the output's __metadata__ is not the planned one")
	}
	for k, v := range p.metadata {
		if meta[k] != v {
			return nil, fmt.Errorf("the output's __metadata__ %q is %q, not %q", k, meta[k], v)
		}
	}
	var spans []*span
	for _, t := range p.written {
		var e stHeader
		if err := json.Unmarshal(entries[t.Name], &e); err != nil {
			return nil, fmt.Errorf("the output's header has no entry for %q", t.Name)
		}
		if e.Dtype != t.Dtype || !sameShape(e.Shape, t.Shape) {
			return nil, fmt.Errorf("the output's header gives %q %s %v, not %s %v", t.Name, e.Dtype, e.Shape, t.Dtype, t.Shape)
		}
		spans = append(spans, &span{name: t.Name, start: e.DataOffsets[0], end: e.DataOffsets[1], h: sha256.New()})
	}
	file := sha256.New()
	file.Write(n[:])
	file.Write(raw)
	data, err := io.Copy(io.MultiWriter(file, &spanHasher{spans: sortedSpans(spans)}), bufio.NewReaderSize(f, 4<<20))
	if err != nil {
		return nil, err
	}
	got := map[string]string{}
	for _, sp := range spans {
		got[sp.name] = hex.EncodeToString(sp.h.Sum(nil))
	}
	empty := hex.EncodeToString(sha256.New().Sum(nil))
	out := &Output{SHA256: hex.EncodeToString(file.Sum(nil)), Size: 8 + hlen + data, Metadata: p.metadata}
	byName := map[string]string{}
	for _, t := range p.written {
		want := source[t.Name]
		if t.Size == 0 {
			want = empty
		}
		if got[t.Name] != want {
			return nil, fmt.Errorf("tensor %q: the output's bytes differ from its source's in %s", t.Name, t.Record)
		}
		t.SHA256 = want
		byName[t.Name] = want
	}
	if out.Size != p.Size {
		return nil, fmt.Errorf("the output is %d bytes, not the planned %d", out.Size, p.Size)
	}
	for _, a := range p.aliases {
		a.SHA256 = byName[a.AliasOf]
	}
	for _, t := range append(append([]*Tensor(nil), p.written...), p.aliases...) {
		out.Tensors = append(out.Tensors, *t)
	}
	sort.Slice(out.Tensors, func(i, j int) bool { return out.Tensors[i].Name < out.Tensors[j].Name })
	return out, nil
}
