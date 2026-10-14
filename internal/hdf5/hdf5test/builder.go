// Package hdf5test builds HDF5 files for tests, in the format h5py writes by
// default: a version 0 superblock, version 1 object headers, groups as
// symbol tables (a version 1 B-tree, a symbol table node, and a local
// heap), attributes in the object header with variable-length strings in
// a global heap, and contiguous datasets. Options write what h5py writes
// with other settings (chunked storage, a filter, links, a user block) and
// what no writer produces (storage past the end, a wrong size), for the
// checks' falsification tests.
//
// Fixtures are generated, not committed. Structures are allocated at the
// sizes the HDF5 library reads them at, so h5py opens what this writes.
package hdf5test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"github.com/defilantech/socair/internal/hdf5"
)

// Sizes of offsets and lengths, and the group B-tree K values h5py uses.
const (
	off       = 8
	leafK     = 4
	internalK = 16
	chunkK    = 32
	undefined = math.MaxUint64
	// freeNull ends a local heap's free list (H5HL_FREE_NULL in the HDF5 library):
	// the specification says the undefined address, the library refuses one.
	freeNull = 1
)

// File is an HDF5 file.
type File struct {
	Root *Group
	// UserBlock is the size of a user block before the superblock (0, or
	// 512, 1024, ...), filled with UserBlockBytes.
	UserBlock      int
	UserBlockBytes []byte
	// Trailing bytes are written after the end of the HDF5 data, which the
	// superblock's end-of-file address does not include.
	Trailing []byte
	// EOFDelta is added to the end-of-file address the superblock records.
	EOFDelta int64
	// Version2 writes what h5py writes with libver="latest": a version 2
	// superblock, version 2 (OHDR) object headers with checksums, and
	// every group as a compact new-style group of link messages.
	Version2 bool
}

// Group is a group: attributes, member groups and datasets, and links.
type Group struct {
	Attrs    []Attr
	Groups   map[string]*Group
	Datasets map[string]*Dataset
	// Soft links name a path; a group with links is written as a "new
	// style" group, with link messages in its object header.
	Soft     map[string]string
	External map[string][2]string // name: file, path
	// Continuation moves the attributes into a continuation block.
	Continuation bool
	// Extra messages are appended to the object header as written.
	Extra []Message
}

// Message is a raw object header message.
type Message struct {
	Type  uint16
	Flags uint8
	Data  []byte
}

// Attr is an attribute. Exactly one value field is set.
type Attr struct {
	Name string
	// Strings are string values: one, as a scalar, unless Array.
	Strings []string
	// Fixed writes the strings as fixed-length (h5py's numpy bytes), not
	// variable-length (h5py's str).
	Fixed bool
	Array bool
	// Float64 is a numeric array, as Keras writes an empty weight_names.
	Float64 []float64
	IsFloat bool
}

// Type is a dataset's element type.
type Type int

const (
	Float32 Type = iota
	Float16
	Int64
)

func (t Type) size() int {
	switch t {
	case Float16:
		return 2
	case Int64:
		return 8
	}
	return 4
}

// Dataset is a dataset.
type Dataset struct {
	Type Type
	Dims []uint64 // nil for a scalar
	// Data is written as the dataset's storage; nil writes zeros of the
	// size the type and dims need.
	Data  []byte
	Attrs []Attr
	// Chunk, when set, stores the dataset chunked with these chunk
	// dimensions, indexed by a version 1 B-tree; Deflate compresses each
	// chunk with zlib and adds the deflate filter.
	Chunk   []uint64
	Deflate bool
	// Compact stores the data in the layout message.
	Compact bool
	// Unallocated writes no storage, as h5py leaves a dataset never
	// written.
	Unallocated bool
	// StoredSize overrides the contiguous size the layout message records;
	// Addr overrides the storage address (relative to the superblock).
	StoredSize *uint64
	Addr       *uint64
	// External names an external data file the data is in.
	External string
}

// Weights is the zero-filled data of a float32 tensor of these dims.
func Weights(dims ...uint64) *Dataset { return &Dataset{Type: Float32, Dims: dims} }

// Bytes writes the file.
func (f *File) Bytes() []byte {
	w := &writer{base: int64(f.UserBlock), v2: f.Version2}
	w.b = append(w.b, f.UserBlockBytes...)
	if len(w.b) < f.UserBlock {
		w.b = append(w.b, make([]byte, f.UserBlock-len(w.b))...)
	}
	size := 96
	if f.Version2 {
		size = 48
	}
	sb := w.alloc(size)
	root := f.Root
	if root == nil {
		root = &Group{}
	}
	hdr, st := w.group(root)
	eof := int64(len(w.b)) + f.EOFDelta
	b := w.b[w.abs(sb):]
	if f.Version2 {
		copy(b, []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n', 2, off, off, 0})
		binary.LittleEndian.PutUint64(b[12:], uint64(f.UserBlock))
		binary.LittleEndian.PutUint64(b[20:], undefined)
		binary.LittleEndian.PutUint64(b[28:], uint64(eof))
		binary.LittleEndian.PutUint64(b[36:], uint64(hdr))
		binary.LittleEndian.PutUint32(b[44:], hdf5.Checksum(b[:44]))
		return append(w.b, f.Trailing...)
	}
	copy(b, []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'})
	b[13], b[14] = off, off
	binary.LittleEndian.PutUint16(b[16:], leafK)
	binary.LittleEndian.PutUint16(b[18:], internalK)
	binary.LittleEndian.PutUint64(b[24:], uint64(f.UserBlock)) // base address: the superblock's offset
	binary.LittleEndian.PutUint64(b[32:], undefined)
	binary.LittleEndian.PutUint64(b[40:], uint64(eof))
	binary.LittleEndian.PutUint64(b[48:], undefined)
	// The root group's symbol table entry, caching its B-tree and heap.
	binary.LittleEndian.PutUint64(b[56:], 0)
	binary.LittleEndian.PutUint64(b[64:], uint64(hdr))
	if st != nil {
		binary.LittleEndian.PutUint32(b[72:], 1)
		binary.LittleEndian.PutUint64(b[80:], uint64(st[0]))
		binary.LittleEndian.PutUint64(b[88:], uint64(st[1]))
	}
	return append(w.b, f.Trailing...)
}

type writer struct {
	b    []byte
	base int64
	v2   bool
}

// alloc appends n zero bytes, 8-aligned, and returns their address
// relative to the superblock.
func (w *writer) alloc(n int) int64 {
	for (int64(len(w.b))-w.base)%8 != 0 {
		w.b = append(w.b, 0)
	}
	at := int64(len(w.b)) - w.base
	w.b = append(w.b, make([]byte, n)...)
	return at
}

func (w *writer) abs(rel int64) int64 { return rel + w.base }

func (w *writer) put(rel int64, data []byte) { copy(w.b[w.abs(rel):], data) }

// group writes a group's members, then the group, and returns its object
// header's address and, for a symbol table group, its B-tree's and heap's.
func (w *writer) group(g *Group) (int64, *[2]int64) {
	type member struct {
		name string
		addr int64
	}
	var members []member
	names := make([]string, 0, len(g.Groups)+len(g.Datasets))
	for n := range g.Groups {
		names = append(names, n)
	}
	for n := range g.Datasets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if sub, ok := g.Groups[n]; ok {
			a, _ := w.group(sub)
			members = append(members, member{n, a})
		} else {
			members = append(members, member{n, w.dataset(g.Datasets[n])})
		}
	}
	msgs := w.attrs(g.Attrs)
	if len(g.Soft) > 0 || len(g.External) > 0 || w.v2 {
		// A new-style compact group: Link Info, Group Info, and a Link
		// message per member.
		var links []Message
		links = append(links, Message{Type: 0x02, Data: cat([]byte{0, 0}, u64(undefined), u64(undefined))})
		links = append(links, Message{Type: 0x0A, Data: []byte{0, 0}})
		for _, m := range members {
			links = append(links, Message{Type: 0x06, Data: cat([]byte{1, 0, byte(len(m.name))}, []byte(m.name), u64(uint64(m.addr)))})
		}
		for _, n := range sortedKeys(g.Soft) {
			v := g.Soft[n]
			links = append(links, Message{Type: 0x06, Data: cat([]byte{1, 0x08, 1, byte(len(n))}, []byte(n), u16(len(v)), []byte(v))})
		}
		for _, n := range sortedKeys(g.External) {
			v := cat([]byte{0}, []byte(g.External[n][0]), []byte{0}, []byte(g.External[n][1]), []byte{0})
			links = append(links, Message{Type: 0x06, Data: cat([]byte{1, 0x08, 64, byte(len(n))}, []byte(n), u16(len(v)), v)})
		}
		return w.header(append(links, append(msgs, g.Extra...)...), g.Continuation), nil
	}
	// The local heap: "" at 0, then each name, NUL-terminated, padded to 8.
	var heap bytes.Buffer
	heap.Write(make([]byte, 8))
	offs := make([]int, len(members))
	for i, m := range members {
		offs[i] = heap.Len()
		heap.WriteString(m.name)
		heap.WriteByte(0)
		for heap.Len()%8 != 0 {
			heap.WriteByte(0)
		}
	}
	if heap.Len() < 88 {
		heap.Write(make([]byte, 88-heap.Len()))
	}
	// Symbol table nodes of 2K entries each, under one B-tree node.
	const entry = 2*off + 24
	var snods []int64
	for i := 0; i < len(members) || i == 0; i += 2 * leafK {
		end := min(i+2*leafK, len(members))
		node := cat([]byte("SNOD"), []byte{1, 0}, u16(end-i))
		for j := i; j < end; j++ {
			node = cat(node, u64(uint64(offs[j])), u64(uint64(members[j].addr)), make([]byte, 24))
		}
		at := w.alloc(8 + 2*leafK*entry)
		w.put(at, node)
		if end > i {
			snods = append(snods, at)
		}
		if len(members) == 0 {
			break
		}
	}
	if len(snods) > 2*internalK {
		panic(fmt.Sprintf("hdf5test: a group of %d members needs a deeper B-tree than this builder writes", len(members)))
	}
	tree := cat([]byte("TREE"), []byte{0, 0}, u16(len(snods)), u64(undefined), u64(undefined))
	tree = cat(tree, u64(0))
	for i, s := range snods {
		last := min((i+1)*2*leafK, len(members)) - 1
		tree = cat(tree, u64(uint64(s)), u64(uint64(offs[last])))
	}
	bt := w.alloc(8 + 2*off + (2*internalK)*off + (2*internalK+1)*off)
	w.put(bt, tree)
	hh := w.alloc(8 + 2*off + off)
	data := w.alloc(heap.Len())
	w.put(data, heap.Bytes())
	w.put(hh, cat([]byte("HEAP"), []byte{0, 0, 0, 0}, u64(uint64(heap.Len())), u64(freeNull), u64(uint64(data))))
	st := Message{Type: 0x11, Data: cat(u64(uint64(bt)), u64(uint64(hh)))}
	return w.header(append([]Message{st}, append(msgs, g.Extra...)...), g.Continuation), &[2]int64{bt, hh}
}

// dataset writes a dataset's storage, then its object header.
func (w *writer) dataset(d *Dataset) int64 {
	n := uint64(1)
	for _, v := range d.Dims {
		n *= v
	}
	need := n * uint64(d.Type.size())
	data := d.Data
	if data == nil {
		data = make([]byte, need)
	}
	msgs := []Message{
		{Type: 0x01, Data: dataspace(d.Dims, d.Dims == nil)},
		{Type: 0x03, Flags: 1, Data: d.Type.message()},
		// A fill value message, version 2: late allocation, written on
		// allocation, no value defined.
		{Type: 0x05, Flags: 1, Data: []byte{2, 2, 2, 0}},
	}
	switch {
	case d.Compact:
		msgs = append(msgs, Message{Type: 0x08, Data: cat([]byte{3, 0}, u16(len(data)), data)})
	case d.External != "":
		hh, hd := w.nameHeap(d.External)
		msgs = append(msgs, Message{Type: 0x07, Data: cat([]byte{1, 0, 0, 0}, u16(1), u16(1), u64(uint64(hh)), u64(uint64(hd)), u64(0), u64(need))})
		msgs = append(msgs, Message{Type: 0x08, Data: cat([]byte{3, 1}, u64(undefined), u64(need))})
	case d.Chunk != nil:
		msgs = append(msgs, w.chunked(d, data)...)
	case d.Unallocated:
		msgs = append(msgs, Message{Type: 0x08, Data: cat([]byte{3, 1}, u64(undefined), u64(need))})
	default:
		at := w.alloc(len(data))
		w.put(at, data)
		if d.Addr != nil {
			at = int64(*d.Addr)
		}
		size := uint64(len(data))
		if d.StoredSize != nil {
			size = *d.StoredSize
		}
		msgs = append(msgs, Message{Type: 0x08, Data: cat([]byte{3, 1}, u64(uint64(at)), u64(size))})
	}
	return w.header(append(msgs, w.attrs(d.Attrs)...), false)
}

// nameHeap writes a local heap holding one name, for an External Data
// Files message, and returns the heap's address and the name's offset.
func (w *writer) nameHeap(name string) (int64, int64) {
	var heap bytes.Buffer
	heap.Write(make([]byte, 8))
	heap.WriteString(name)
	heap.WriteByte(0)
	for heap.Len()%8 != 0 {
		heap.WriteByte(0)
	}
	hh := w.alloc(8 + 2*off + off)
	data := w.alloc(heap.Len())
	w.put(data, heap.Bytes())
	w.put(hh, cat([]byte("HEAP"), []byte{0, 0, 0, 0}, u64(uint64(heap.Len())), u64(freeNull), u64(uint64(data))))
	return hh, 8
}

// chunked writes a dataset's chunks and its chunk B-tree, and returns its
// layout and filter messages.
func (w *writer) chunked(d *Dataset, data []byte) []Message {
	rank := len(d.Dims)
	elem := d.Type.size()
	chunkBytes := elem
	for _, c := range d.Chunk {
		chunkBytes *= int(c)
	}
	// Chunks in row-major order of their offsets. Each holds the elements
	// of the dataset it covers, zero beyond the dataset's edge.
	var offsets [][]uint64
	var walk func(dim int, cur []uint64)
	walk = func(dim int, cur []uint64) {
		if dim == rank {
			offsets = append(offsets, append([]uint64(nil), cur...))
			return
		}
		for v := uint64(0); v < d.Dims[dim]; v += d.Chunk[dim] {
			walk(dim+1, append(cur, v))
		}
	}
	walk(0, nil)
	if len(offsets) > 2*chunkK {
		panic("hdf5test: more chunks than one B-tree node holds")
	}
	key := 8 + 8*(rank+1)
	tree := cat([]byte("TREE"), []byte{1, 0}, u16(len(offsets)), u64(undefined), u64(undefined))
	for _, o := range offsets {
		raw := make([]byte, chunkBytes)
		fillChunk(raw, data, d.Dims, d.Chunk, o, elem)
		stored := raw
		if d.Deflate {
			var z bytes.Buffer
			zw := zlib.NewWriter(&z)
			_, _ = zw.Write(raw)
			_ = zw.Close()
			stored = z.Bytes()
		}
		at := w.alloc(len(stored))
		w.put(at, stored)
		k := cat(u32(uint32(len(stored))), u32(0))
		for _, v := range o {
			k = cat(k, u64(v))
		}
		tree = cat(tree, k, u64(0), u64(uint64(at)))
	}
	// The last key is one chunk past the last chunk, as the library
	// writes it: every coordinate a multiple of the chunk's dimension.
	last := cat(u32(0), u32(0))
	for i := 0; i < rank; i++ {
		last = cat(last, u64(offsets[len(offsets)-1][i]+d.Chunk[i]))
	}
	tree = cat(tree, last, u64(0))
	bt := w.alloc(8 + 2*off + 2*chunkK*off + (2*chunkK+1)*key)
	w.put(bt, tree)
	layout := cat([]byte{3, 2, byte(rank + 1)}, u64(uint64(bt)))
	for _, c := range d.Chunk {
		layout = cat(layout, u32(uint32(c)))
	}
	layout = cat(layout, u32(uint32(elem)))
	msgs := []Message{{Type: 0x08, Data: layout}}
	if d.Deflate {
		// Filter pipeline version 2: deflate (1), mandatory, one client
		// value, the compression level.
		msgs = append(msgs, Message{Type: 0x0B, Flags: 1, Data: cat([]byte{2, 1}, u16(1), u16(0), u16(1), u32(4))})
	}
	return msgs
}

// fillChunk copies the elements of data a chunk at offset covers.
func fillChunk(dst, data []byte, dims, chunk, at []uint64, elem int) {
	rank := len(dims)
	idx := make([]uint64, rank)
	for i := 0; i < len(dst)/elem; i++ {
		rem := uint64(i)
		for j := rank - 1; j >= 0; j-- {
			idx[j] = rem % chunk[j]
			rem /= chunk[j]
		}
		src := uint64(0)
		inside := true
		for j := 0; j < rank; j++ {
			v := at[j] + idx[j]
			if v >= dims[j] {
				inside = false
				break
			}
			src = src*dims[j] + v
		}
		if inside && int(src+1)*elem <= len(data) {
			copy(dst[i*elem:(i+1)*elem], data[int(src)*elem:int(src+1)*elem])
		}
	}
}

// attrs encodes attribute messages, writing variable-length strings to a
// global heap collection first.
func (w *writer) attrs(as []Attr) []Message {
	var msgs []Message
	for _, a := range as {
		var typ, data []byte
		count := len(a.Strings)
		switch {
		case a.IsFloat:
			typ = float64Type()
			count = len(a.Float64)
			for _, v := range a.Float64 {
				data = cat(data, u64(math.Float64bits(v)))
			}
		case a.Fixed:
			size := 1
			for _, s := range a.Strings {
				size = max(size, len(s))
			}
			typ = cat([]byte{0x13, 0x01, 0, 0}, u32(uint32(size))) // null-padded ASCII
			for _, s := range a.Strings {
				v := make([]byte, size)
				copy(v, s)
				data = cat(data, v)
			}
		default:
			typ = vlenStringType()
			coll, idx := w.globalHeap(a.Strings)
			for i, s := range a.Strings {
				data = cat(data, u32(uint32(len(s))), u64(uint64(coll)), u32(idx[i]))
			}
		}
		space := dataspace([]uint64{uint64(count)}, !a.Array && !a.IsFloat && count == 1)
		name := cat([]byte(a.Name), []byte{0})
		body := cat([]byte{1, 0}, u16(len(name)), u16(len(typ)), u16(len(space)), pad8(name), pad8(typ), pad8(space), data)
		msgs = append(msgs, Message{Type: 0x0C, Data: body})
	}
	return msgs
}

// globalHeap writes a global heap collection holding each string as an
// object and returns its address and the objects' indexes.
func (w *writer) globalHeap(ss []string) (int64, []uint32) {
	body := []byte{}
	idx := make([]uint32, len(ss))
	for i, s := range ss {
		idx[i] = uint32(i + 1)
		if len(s) == 0 {
			continue
		}
		body = cat(body, u16(i+1), u16(0), u32(0), u64(uint64(len(s))), pad8([]byte(s)))
	}
	size := 16 + len(body)
	if size+16 > 4096 {
		size += 16
	} else {
		size = 4096
	}
	free := size - 16 - len(body)
	body = cat(body, u16(0), u16(0), u32(0), u64(uint64(free)))
	at := w.alloc(size)
	w.put(at, cat([]byte("GCOL"), []byte{1, 0, 0, 0}, u64(uint64(size)), body))
	return at, idx
}

// header writes a version 1 object header holding msgs, or, with cont,
// the first message in the header and the rest in a continuation block.
func (w *writer) header(msgs []Message, cont bool) int64 {
	if w.v2 {
		return w.header2(msgs, cont)
	}
	enc := func(ms []Message) []byte {
		var b []byte
		for _, m := range ms {
			d := pad8(m.Data)
			b = cat(b, u16(int(m.Type)), u16(len(d)), []byte{m.Flags, 0, 0, 0}, d)
		}
		return b
	}
	count := len(msgs)
	var body []byte
	if cont && len(msgs) > 1 {
		rest := enc(msgs[1:])
		at := w.alloc(len(rest))
		w.put(at, rest)
		body = enc([]Message{msgs[0], {Type: 0x10, Data: cat(u64(uint64(at)), u64(uint64(len(rest))))}})
		count++
	} else {
		body = enc(msgs)
	}
	if len(body) < 24 {
		// The library allocates at least a NIL message's worth.
		body = cat(body, u16(0), u16(24-len(body)-8), []byte{0, 0, 0, 0}, make([]byte, 24-len(body)-8))
		count++
	}
	at := w.alloc(16 + len(body))
	w.put(at, cat([]byte{1, 0}, u16(count), u32(1), u32(uint32(len(body))), u32(0), body))
	return at
}

// header2 writes a version 2 object header: OHDR, flags selecting a 4-byte
// chunk size, packed messages, and a checksum; with cont, the messages after
// the first go to an OCHK continuation block.
func (w *writer) header2(msgs []Message, cont bool) int64 {
	enc := func(ms []Message) []byte {
		var b []byte
		for _, m := range ms {
			b = cat(b, []byte{byte(m.Type)}, u16(len(m.Data)), []byte{m.Flags}, m.Data)
		}
		return b
	}
	if cont && len(msgs) > 1 {
		rest := cat([]byte("OCHK"), enc(msgs[1:]))
		at := w.alloc(len(rest) + 4)
		w.put(at, cat(rest, u32(hdf5.Checksum(rest))))
		msgs = []Message{msgs[0], {Type: 0x10, Data: cat(u64(uint64(at)), u64(uint64(len(rest)+4)))}}
	}
	body := enc(msgs)
	head := cat([]byte("OHDR"), []byte{2, 0x02}, u32(uint32(len(body))), body)
	at := w.alloc(len(head) + 4)
	w.put(at, cat(head, u32(hdf5.Checksum(head))))
	return at
}

func dataspace(dims []uint64, scalar bool) []byte {
	if scalar {
		return []byte{1, 0, 0, 0, 0, 0, 0, 0}
	}
	b := []byte{1, byte(len(dims)), 0, 0, 0, 0, 0, 0}
	for _, d := range dims {
		b = cat(b, u64(d))
	}
	return b
}

func (t Type) message() []byte {
	switch t {
	case Float16:
		return cat([]byte{0x11, 0x20, 0x0f, 0x00}, u32(2), u16(0), u16(16), []byte{10, 5, 0, 10}, u32(15))
	case Int64:
		return cat([]byte{0x10, 0x08, 0, 0}, u32(8), u16(0), u16(64))
	}
	return cat([]byte{0x11, 0x20, 0x1f, 0x00}, u32(4), u16(0), u16(32), []byte{23, 8, 0, 23}, u32(127))
}

func float64Type() []byte {
	return cat([]byte{0x11, 0x20, 0x3f, 0x00}, u32(8), u16(0), u16(64), []byte{52, 11, 0, 52}, u32(1023))
}

// vlenStringType is a variable-length UTF-8 string, null-terminated, of
// unsigned bytes, as h5py writes a str.
func vlenStringType() []byte {
	return cat([]byte{0x19, 0x01, 0x01, 0x00}, u32(16), []byte{0x10, 0, 0, 0}, u32(1), u16(0), u16(8))
}

func pad8(b []byte) []byte {
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u16(v int) []byte { return binary.LittleEndian.AppendUint16(nil, uint16(v)) }

func u32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func u64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
