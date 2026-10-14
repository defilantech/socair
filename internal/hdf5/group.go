package hdf5

import (
	"bytes"
)

// localHeap is a local heap's data segment: the link names of an old-style
// group, NUL-terminated.
type localHeap struct {
	data []byte
	at   int64
}

// localHeap reads a local heap (specification III.D).
func (d *reader) localHeap(addr int64) (*localHeap, error) {
	n := int64(8 + 2*d.len + d.off)
	b, err := d.read(addr, n, "a local heap")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b[:4], []byte("HEAP")) {
		return nil, d.errf(addr, "a local heap without the HEAP signature")
	}
	if b[4] != 0 {
		return nil, d.errf(addr+4, "a local heap of version %d", b[4])
	}
	c := d.buf(b, addr)
	c.skip(8)
	size := c.length()
	c.length() // the free list's head
	seg := c.addr()
	if c.err != nil {
		return nil, c.err
	}
	if seg == undefined || size > maxHeapBytes {
		return nil, d.errf(addr, "a local heap data segment at an undefined address or of %d bytes", size)
	}
	d.meta(addr, addr+n, "local heap")
	data, err := d.read(seg, int64(size), "a local heap's data segment")
	if err != nil {
		return nil, err
	}
	d.meta(seg, seg+int64(size), "local heap data")
	return &localHeap{data: data, at: seg}, nil
}

// name reads the NUL-terminated string at an offset in the heap.
func (h *localHeap) name(off uint64) (string, bool) {
	if off >= uint64(len(h.data)) {
		return "", false
	}
	rest := h.data[off:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", false
	}
	return string(rest[:i]), true
}

// groupTree walks a group's version 1 B-tree (node type 0), whose leaves
// point at symbol table nodes.
func (d *reader) groupTree(addr int64, h *localHeap, out *[]child, depth int) error {
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
	if p[4] != 0 {
		return d.errf(addr+4, "a group's B-tree node of type %d, not 0", p[4])
	}
	level := int(p[5])
	used := int(p[6]) | int(p[7])<<8
	if used > 2*d.internalK {
		return d.errf(addr, "a B-tree node with %d entries, more than its 2K of %d", used, 2*d.internalK)
	}
	if level > 0 && depth >= 64 {
		return d.errf(addr, "a B-tree deeper than 64 levels")
	}
	// Keys and children interleave: key 0, child 0, ..., key N.
	n := head + int64(used)*int64(d.len+d.off) + int64(d.len)
	b, err := d.read(addr, n, "a B-tree node")
	if err != nil {
		return err
	}
	d.meta(addr, addr+n, "B-tree node")
	c := d.buf(b, addr)
	c.skip(int(head))
	for i := 0; i < used; i++ {
		c.length() // key: a heap offset
		ch := c.addr()
		if c.err != nil {
			return c.err
		}
		if ch == undefined {
			return d.errf(addr, "a B-tree child at an undefined address")
		}
		if level > 0 {
			err = d.groupTree(ch, h, out, depth+1)
		} else {
			err = d.symbolNode(ch, h, out)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// symbolNode reads a symbol table node (specification III.B): up to 2K
// symbol table entries, each a name in the heap and an object header
// address.
func (d *reader) symbolNode(addr int64, h *localHeap, out *[]child) error {
	if d.btrees[addr] {
		return d.errf(addr, "a symbol table node reached twice")
	}
	d.btrees[addr] = true
	p, err := d.read(addr, 8, "a symbol table node")
	if err != nil {
		return err
	}
	if !bytes.Equal(p[:4], []byte("SNOD")) {
		return d.errf(addr, "a symbol table node without the SNOD signature")
	}
	if p[4] != 1 {
		return d.errf(addr+4, "a symbol table node of version %d", p[4])
	}
	count := int(p[6]) | int(p[7])<<8
	if count > 2*d.leafK {
		return d.errf(addr, "a symbol table node with %d entries, more than its 2K of %d", count, 2*d.leafK)
	}
	entry := 2*d.off + 24
	n := int64(8 + count*entry)
	b, err := d.read(addr, n, "a symbol table node")
	if err != nil {
		return err
	}
	d.meta(addr, addr+n, "symbol table node")
	c := d.buf(b, addr)
	c.skip(8)
	for i := 0; i < count; i++ {
		nameOff := c.length()
		obj := c.addr()
		cache := c.u32()
		c.skip(4)
		scratch := c.bytes(16)
		if c.err != nil {
			return c.err
		}
		name, ok := h.name(nameOff)
		if !ok || name == "" {
			return d.errf(addr, "a symbol table entry whose name is not a string in the group's heap")
		}
		if len(*out) >= maxObjects {
			return d.errf(addr, "a group with more than %d members", maxObjects)
		}
		switch cache {
		case 0, 1:
			if obj == undefined {
				return d.errf(addr, "a symbol table entry %q at an undefined address", name)
			}
			*out = append(*out, child{name: name, addr: obj})
		case 2:
			// A soft link: its value is in the heap.
			sc := d.buf(scratch, 0)
			target, ok := h.name(uint64(sc.u32()))
			if !ok {
				return d.errf(addr, "a soft link %q whose value is not in the group's heap", name)
			}
			*out = append(*out, child{name: name, kind: "soft", target: target})
		default:
			return d.errf(addr, "a symbol table entry with cache type %d", cache)
		}
	}
	return nil
}
