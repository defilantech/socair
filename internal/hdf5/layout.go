package hdf5

import (
	"bytes"
	"fmt"
	"math/bits"
)

// Layout classes (specification IV.A.3.i).
const (
	LayoutCompact    = 0
	LayoutContiguous = 1
	LayoutChunked    = 2
	LayoutVirtual    = 3
)

// Chunk index types of layout versions 4 and 5.
const (
	IndexBTree1   = 0 // layout versions 1 to 3: a version 1 B-tree
	IndexSingle   = 1
	IndexImplicit = 2
	IndexFixed    = 3
	IndexExtArray = 4
	IndexBTree2   = 5
)

var indexNames = map[int]string{IndexBTree1: "version 1 B-tree", IndexSingle: "single chunk", IndexImplicit: "implicit",
	IndexFixed: "fixed array", IndexExtArray: "extensible array", IndexBTree2: "version 2 B-tree"}

// Dataset is a dataset's type, shape, and storage.
type Dataset struct {
	Type     Datatype
	Space    Dataspace
	Layout   Layout
	Filters  []Filter
	External []ExternalFile
}

// Layout is a data layout message.
type Layout struct {
	Version int
	Class   int
	// Addr is contiguous data's address, or the chunk index's, absolute,
	// or -1 when storage is not allocated.
	Addr int64
	// Size is contiguous storage's size as the message records it, or
	// compact data's size.
	Size uint64
	// ChunkDims are a chunk's dimensions, in elements; ElemSize is the
	// element size the chunked layout records.
	ChunkDims []uint64
	ElemSize  uint64
	Index     int
	// Chunks are the chunks the index lists, when it was read.
	Chunks []Chunk
	// Unread says why the chunks were not read, or "".
	Unread string
}

// Chunk is one stored chunk.
type Chunk struct {
	Addr   int64
	Size   uint64 // as stored: after filters
	Mask   uint32 // filters skipped for this chunk
	Offset []uint64
}

// Filter is one filter of a dataset's filter pipeline.
type Filter struct {
	ID       int
	Name     string
	Optional bool
}

// FilterNames are the filters the HDF5 library defines.
var FilterNames = map[int]string{1: "deflate (gzip)", 2: "shuffle", 3: "fletcher32", 4: "szip", 5: "nbit", 6: "scaleoffset"}

// ExternalFile is one slot of an External Data Files message.
type ExternalFile struct {
	Name         string
	Offset, Size uint64
}

func (d *reader) layout(c *buf) Layout {
	l := Layout{Version: c.u8(), Addr: undefined}
	switch l.Version {
	case 1, 2:
		rank := c.u8()
		l.Class = c.u8()
		c.skip(5)
		if l.Class != LayoutCompact {
			l.Addr = c.addr()
		}
		if rank == 0 || rank > maxRank+1 {
			c.fail("a layout message of dimensionality %d", rank)
			return l
		}
		dims := make([]uint64, rank)
		for i := range dims {
			dims[i] = uint64(c.u32())
		}
		switch l.Class {
		case LayoutCompact:
			l.Size = uint64(c.u32())
			c.skip(int(l.Size))
		case LayoutChunked:
			l.ChunkDims, l.ElemSize = dims[:rank-1], dims[rank-1]
		case LayoutContiguous:
			// Versions 1 and 2 record no storage size: the library
			// computes it from the dataspace and datatype.
			l.Size = 0
		default:
			c.fail("a layout of class %d", l.Class)
		}
		if l.Version == 1 && l.Addr == undefined && l.Class != LayoutCompact {
			c.fail("a version 1 layout with storage not allocated")
		}
	case 3, 4, 5:
		l.Class = c.u8()
		switch l.Class {
		case LayoutCompact:
			l.Size = uint64(c.u16())
			c.skip(int(l.Size))
		case LayoutContiguous:
			l.Addr = c.addr()
			l.Size = c.length()
		case LayoutChunked:
			if l.Version == 3 {
				rank := c.u8()
				if rank < 2 || rank > maxRank+1 {
					c.fail("a chunked layout of dimensionality %d", rank)
					return l
				}
				l.Addr = c.addr()
				dims := make([]uint64, rank)
				for i := range dims {
					dims[i] = uint64(c.u32())
				}
				l.ChunkDims, l.ElemSize = dims[:rank-1], dims[rank-1]
				return l
			}
			d.chunked45(c, &l)
		case LayoutVirtual:
			if l.Version < 4 {
				c.fail("a virtual layout in a version %d layout message", l.Version)
			}
			l.Addr = c.addr()
			c.u32()
		default:
			c.fail("a layout of class %d", l.Class)
		}
	default:
		c.fail("a layout message of version %d", l.Version)
	}
	return l
}

// chunked45 reads the chunked layout of versions 4 and 5.
func (d *reader) chunked45(c *buf, l *Layout) {
	flags := c.u8()
	rank := c.u8()
	width := c.u8()
	if c.err != nil {
		return
	}
	if rank < 2 || rank > maxRank+1 || width < 1 || width > 8 {
		c.fail("a chunked layout of dimensionality %d with %d-byte dimensions", rank, width)
		return
	}
	dims := make([]uint64, rank)
	for i := range dims {
		dims[i] = c.uint(width)
	}
	l.ChunkDims, l.ElemSize = dims[:rank-1], dims[rank-1]
	l.Index = c.u8()
	switch l.Index {
	case IndexSingle:
		if flags&2 != 0 {
			// A filtered single chunk: its size and filter mask.
			size := c.length()
			mask := c.u32()
			l.Chunks = []Chunk{{Size: size, Mask: mask, Offset: make([]uint64, rank-1)}}
		}
	case IndexImplicit:
	case IndexFixed:
		c.skip(1)
	case IndexExtArray:
		c.skip(5)
	case IndexBTree2:
		c.skip(6)
	default:
		c.fail("a chunk index of type %d", l.Index)
		return
	}
	l.Addr = c.addr()
}

func (d *reader) filters(c *buf) []Filter {
	v, n := c.u8(), c.u8()
	if v == 1 {
		c.skip(6)
	} else if v != 2 {
		c.fail("a filter pipeline message of version %d", v)
		return nil
	}
	if n > 32 {
		c.fail("a filter pipeline of %d filters, more than 32", n)
		return nil
	}
	var out []Filter
	for i := 0; i < n; i++ {
		f := Filter{ID: c.u16()}
		nameLen := 0
		if v == 1 || f.ID >= 256 {
			nameLen = c.u16()
		}
		flags := c.u16()
		f.Optional = flags&1 != 0
		values := c.u16()
		if nameLen > 0 {
			name := c.bytes(nameLen)
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			f.Name = string(name)
		}
		c.skip(4 * values)
		if v == 1 && values%2 == 1 {
			c.skip(4)
		}
		if c.err != nil {
			return nil
		}
		out = append(out, f)
	}
	return out
}

func (d *reader) external(c *buf) []ExternalFile {
	if v := c.u8(); v != 1 {
		c.fail("an external data files message of version %d", v)
		return nil
	}
	c.skip(3)
	c.u16() // allocated slots
	used := c.u16()
	heap := c.addr()
	if c.err != nil {
		return nil
	}
	var h *localHeap
	if heap != undefined {
		var err error
		if h, err = d.localHeap(heap); err != nil {
			c.err = err
			return nil
		}
	}
	var out []ExternalFile
	for i := 0; i < used; i++ {
		nameOff := c.length()
		f := ExternalFile{Offset: c.length(), Size: c.length()}
		if c.err != nil {
			return nil
		}
		if h != nil {
			f.Name, _ = h.name(nameOff)
		}
		out = append(out, f)
	}
	return out
}

// readChunks lists a chunked dataset's chunks from its index, when the
// reader models the index: a version 1 B-tree, a single chunk, or the
// implicit index. Other indexes are named in Layout.Unread.
func (d *reader) readChunks(ds *Dataset, where string) error {
	l := &ds.Layout
	if l.Class != LayoutChunked || l.Addr == undefined {
		return nil
	}
	if len(l.ChunkDims) != len(ds.Space.Dims) && ds.Space.Kind == SpaceSimple {
		return d.errf(l.Addr, "dataset %s: chunks of rank %d for a dataspace of rank %d", where, len(l.ChunkDims), len(ds.Space.Dims))
	}
	switch l.Index {
	case IndexBTree1:
		return d.chunkTree(l.Addr, l, len(l.ChunkDims)+1, 0)
	case IndexSingle:
		if len(l.Chunks) == 0 {
			l.Chunks = []Chunk{{Size: chunkBytes(l), Offset: make([]uint64, len(l.ChunkDims))}}
		}
		l.Chunks[0].Addr = l.Addr
		d.chunks++
		return nil
	case IndexImplicit:
		// Every chunk is stored, in order, at Addr.
		n, ok := chunkCount(ds)
		size := chunkBytes(l)
		hi, total := bits.Mul64(n, size)
		if !ok || hi != 0 || total > 1<<62 {
			return d.errf(l.Addr, "dataset %s: an implicit chunk index whose size overflows", where)
		}
		l.Chunks = []Chunk{{Addr: l.Addr, Size: total, Offset: make([]uint64, len(l.ChunkDims))}}
		d.chunks++
		return nil
	}
	l.Unread = "its chunks are indexed by a " + indexNames[l.Index] + ", which this reader does not read"
	return nil
}

// chunkBytes is one unfiltered chunk's size: its dimensions times the
// element size.
func chunkBytes(l *Layout) uint64 {
	n := l.ElemSize
	for _, v := range l.ChunkDims {
		hi, lo := bits.Mul64(n, v)
		if hi != 0 {
			return 0
		}
		n = lo
	}
	return n
}

// chunkCount is how many chunks cover the dataspace.
func chunkCount(ds *Dataset) (uint64, bool) {
	n := uint64(1)
	for i, v := range ds.Space.Dims {
		c := ds.Layout.ChunkDims[i]
		if c == 0 {
			return 0, false
		}
		k := (v + c - 1) / c
		hi, lo := bits.Mul64(n, k)
		if hi != 0 {
			return 0, false
		}
		n = lo
	}
	return n, true
}

// chunkTree walks a chunked dataset's version 1 B-tree (node type 1). Each
// key holds a chunk's size, filter mask, and offset (rank values, then a
// 0 for the datatype).
func (d *reader) chunkTree(addr int64, l *Layout, rank, depth int) error {
	if d.btrees[addr] {
		return d.errf(addr, "a B-tree node reached twice")
	}
	d.btrees[addr] = true
	d.nodes++
	if d.nodes > maxBTreeNodes {
		return d.errf(addr, "more than %d B-tree nodes, this reader's bound", maxBTreeNodes)
	}
	head := int64(8 + 2*d.off)
	p, err := d.read(addr, head, "a B-tree node")
	if err != nil {
		return err
	}
	if !bytes.Equal(p[:4], []byte("TREE")) {
		return d.errf(addr, "a B-tree node without the TREE signature")
	}
	if p[4] != 1 {
		return d.errf(addr+4, "a chunk B-tree node of type %d, not 1", p[4])
	}
	level := int(p[5])
	used := int(p[6]) | int(p[7])<<8
	if used > 2*d.chunkK {
		return d.errf(addr, "a B-tree node with %d entries, more than its 2K of %d", used, 2*d.chunkK)
	}
	if depth >= 64 {
		return d.errf(addr, "a B-tree deeper than 64 levels")
	}
	key := 8 + 8*rank
	n := head + int64(used)*int64(key+d.off) + int64(key)
	b, err := d.read(addr, n, "a B-tree node")
	if err != nil {
		return err
	}
	d.meta(addr, addr+n, "chunk B-tree node")
	c := d.buf(b, addr)
	c.skip(int(head))
	for i := 0; i < used; i++ {
		size := c.u32()
		mask := c.u32()
		off := make([]uint64, rank)
		for j := range off {
			off[j] = c.uint(8)
		}
		ch := c.addr()
		if c.err != nil {
			return c.err
		}
		if ch == undefined {
			return d.errf(addr, "a chunk B-tree child at an undefined address")
		}
		if level > 0 {
			if err := d.chunkTree(ch, l, rank, depth+1); err != nil {
				return err
			}
			continue
		}
		d.chunks++
		if d.chunks > maxChunks {
			return d.errf(addr, "more than %d chunks, this reader's bound", maxChunks)
		}
		if off[rank-1] != 0 {
			return d.errf(addr, "a chunk key whose datatype offset is %d, not 0", off[rank-1])
		}
		l.Chunks = append(l.Chunks, Chunk{Addr: ch, Size: uint64(size), Mask: mask, Offset: off[:rank-1]})
	}
	return nil
}

// FilterList names a dataset's filters for a report.
func FilterList(fs []Filter) string {
	var b bytes.Buffer
	for i, f := range fs {
		if i > 0 {
			b.WriteString(", ")
		}
		name := FilterNames[f.ID]
		if name == "" {
			name = f.Name
		}
		if name == "" {
			name = "unregistered"
		}
		fmt.Fprintf(&b, "%d (%s)", f.ID, name)
	}
	return b.String()
}
