package hdf5

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Object header message types (specification IV.A.3).
const (
	msgNil          = 0x0000
	msgDataspace    = 0x0001
	msgLinkInfo     = 0x0002
	msgDatatype     = 0x0003
	msgFillOld      = 0x0004
	msgFill         = 0x0005
	msgLink         = 0x0006
	msgExternal     = 0x0007
	msgLayout       = 0x0008
	msgBogus        = 0x0009
	msgGroupInfo    = 0x000A
	msgFilter       = 0x000B
	msgAttribute    = 0x000C
	msgComment      = 0x000D
	msgModTimeOld   = 0x000E
	msgSharedTable  = 0x000F
	msgContinuation = 0x0010
	msgSymbolTable  = 0x0011
	msgModTime      = 0x0012
	msgBTreeK       = 0x0013
	msgDriverInfo   = 0x0014
	msgAttrInfo     = 0x0015
	msgRefCount     = 0x0016
	msgFileSpace    = 0x0017
)

var msgNames = map[int]string{
	msgNil: "NIL", msgDataspace: "Dataspace", msgLinkInfo: "Link Info", msgDatatype: "Datatype",
	msgFillOld: "Fill Value (old)", msgFill: "Fill Value", msgLink: "Link", msgExternal: "External Data Files",
	msgLayout: "Data Layout", msgBogus: "Bogus", msgGroupInfo: "Group Info", msgFilter: "Filter Pipeline",
	msgAttribute: "Attribute", msgComment: "Object Comment", msgModTimeOld: "Object Modification Time (old)",
	msgSharedTable: "Shared Message Table", msgContinuation: "Object Header Continuation",
	msgSymbolTable: "Symbol Table", msgModTime: "Object Modification Time", msgBTreeK: "B-tree 'K' Values",
	msgDriverInfo: "Driver Info", msgAttrInfo: "Attribute Info", msgRefCount: "Object Reference Count",
	msgFileSpace: "File Space Info",
}

// Message flags (specification IV.A.1.a).
const (
	flagShared       = 0x02
	flagFailIfWrite  = 0x08
	flagFailAlways   = 0x80
	flagMustUnderstd = flagFailIfWrite | flagFailAlways
)

// message is one object header message.
type message struct {
	typ   int
	flags int
	data  []byte
	at    int64 // the file offset of data
}

// header reads an object header, following continuation blocks, and returns
// its messages in file order.
func (d *reader) header(addr int64) ([]message, error) {
	pfx, err := d.read(addr, 4, "an object header")
	if err != nil {
		return nil, err
	}
	if bytes.Equal(pfx, []byte("OHDR")) {
		return d.header2(addr)
	}
	if pfx[0] != 1 {
		return nil, d.errf(addr, "an object header of version %d, which the specification does not define", pfx[0])
	}
	return d.header1(addr)
}

// header1 reads a version 1 object header: a 16-byte prefix, then messages
// aligned on 8 bytes, each an 8-byte header and its data.
func (d *reader) header1(addr int64) ([]message, error) {
	p, err := d.read(addr, 16, "an object header")
	if err != nil {
		return nil, err
	}
	count := int(binary.LittleEndian.Uint16(p[2:]))
	size := int64(binary.LittleEndian.Uint32(p[8:]))
	var msgs []message
	type block struct{ at, n int64 }
	queue := []block{{addr + 16, size}}
	d.meta(addr, addr+16+size, "object header")
	total := size
	for i := 0; i < len(queue); i++ {
		if i >= maxHeaderChunks {
			return nil, d.errf(addr, "an object header with more than %d continuation blocks", maxHeaderChunks)
		}
		bl := queue[i]
		b, err := d.read(bl.at, bl.n, "an object header block")
		if err != nil {
			return nil, err
		}
		if i > 0 {
			d.meta(bl.at, bl.at+bl.n, "object header continuation")
		}
		c := d.buf(b, bl.at)
		for c.left() > 0 {
			if c.left() < 8 {
				return nil, d.errf(bl.at+int64(c.pos), "%d stray bytes at the end of an object header block", c.left())
			}
			typ, n, flags := c.u16(), c.u16(), c.u8()
			c.skip(3)
			data := c.bytes(n)
			if c.err != nil {
				return nil, c.err
			}
			m := message{typ: typ, flags: flags, data: data, at: bl.at + int64(c.pos-n)}
			if len(msgs) >= maxMessages {
				return nil, d.errf(addr, "an object header with more than %d messages", maxMessages)
			}
			msgs = append(msgs, m)
			if typ == msgContinuation {
				next, err := d.continuation(m)
				if err != nil {
					return nil, err
				}
				total += next.n
				if total > maxHeaderBytes {
					return nil, d.errf(addr, "an object header of more than %d bytes", maxHeaderBytes)
				}
				queue = append(queue, block{next.at, next.n})
			}
		}
	}
	if len(msgs) != count {
		return nil, d.errf(addr, "an object header that counts %d messages and holds %d; the HDF5 library refuses it", count, len(msgs))
	}
	return msgs, nil
}

type span struct{ at, n int64 }

func (d *reader) continuation(m message) (span, error) {
	c := d.buf(m.data, m.at)
	at := c.addr()
	n := c.length()
	if c.err != nil {
		return span{}, c.err
	}
	if at == undefined || n == 0 || n > maxHeaderBytes {
		return span{}, d.errf(m.at, "a continuation block at an undefined address or of %d bytes", n)
	}
	return span{at, int64(n)}, nil
}

// header2 reads a version 2 object header: "OHDR", a prefix whose fields
// its flags select, packed messages, a gap, and a checksum, then "OCHK"
// continuation blocks laid out the same way.
func (d *reader) header2(addr int64) ([]message, error) {
	p, err := d.read(addr, 6, "an object header")
	if err != nil {
		return nil, err
	}
	if p[4] != 2 {
		return nil, d.errf(addr, "an OHDR object header of version %d, which the specification does not define", p[4])
	}
	flags := int(p[5])
	if flags&0xc0 != 0 {
		return nil, d.errf(addr, "object header flags with reserved bits set")
	}
	pre := int64(6)
	if flags&0x20 != 0 {
		pre += 16
	}
	if flags&0x10 != 0 {
		pre += 4
	}
	width := int64(1) << uint(flags&3)
	sz, err := d.read(addr+pre, width, "an object header")
	if err != nil {
		return nil, err
	}
	var size uint64
	for i := width - 1; i >= 0; i-- {
		size = size<<8 | uint64(sz[i])
	}
	if size > maxHeaderBytes {
		return nil, d.errf(addr, "an object header chunk of %d bytes", size)
	}
	start := addr + pre + width
	hdr := 4
	if flags&0x04 != 0 {
		hdr = 6
	}
	var msgs []message
	queue := []span{{addr, pre + width + int64(size) + 4}}
	total := int64(size)
	for i := 0; i < len(queue); i++ {
		if i >= maxHeaderChunks {
			return nil, d.errf(addr, "an object header with more than %d continuation blocks", maxHeaderChunks)
		}
		bl := queue[i]
		b, err := d.read(bl.at, bl.n, "an object header block")
		if err != nil {
			return nil, err
		}
		if sum := lookup3(b[:len(b)-4]); sum != binary.LittleEndian.Uint32(b[len(b)-4:]) {
			return nil, d.errf(bl.at, "an object header block whose checksum does not match its bytes; the HDF5 library refuses it")
		}
		what, skip := "object header", int(start-addr)
		if i > 0 {
			what, skip = "object header continuation", 4
			if !bytes.Equal(b[:4], []byte("OCHK")) {
				return nil, d.errf(bl.at, "a continuation block without the OCHK signature")
			}
		}
		d.meta(bl.at, bl.at+bl.n, what)
		c := d.buf(b[:len(b)-4], bl.at)
		c.skip(skip)
		for c.left() >= hdr {
			typ, n, mflags := c.u8(), c.u16(), c.u8()
			if hdr == 6 {
				c.skip(2)
			}
			data := c.bytes(n)
			if c.err != nil {
				return nil, c.err
			}
			m := message{typ: typ, flags: mflags, data: data, at: bl.at + int64(c.pos-n)}
			if len(msgs) >= maxMessages {
				return nil, d.errf(addr, "an object header with more than %d messages", maxMessages)
			}
			msgs = append(msgs, m)
			if typ == msgContinuation {
				next, err := d.continuation(m)
				if err != nil {
					return nil, err
				}
				if next.n < 8 {
					return nil, d.errf(m.at, "a continuation block of %d bytes", next.n)
				}
				total += next.n
				if total > maxHeaderBytes {
					return nil, d.errf(addr, "an object header of more than %d bytes", maxHeaderBytes)
				}
				queue = append(queue, next)
			}
		}
		// What is left is a gap, smaller than a message header.
	}
	return msgs, nil
}

// group is what a group's messages say about where its links are.
type group struct {
	// An old-style group: a symbol table.
	btree, heap int64
	symbol      bool
	// A new-style group: link messages, and whether links are stored
	// densely (a fractal heap this reader does not read).
	links []child
	dense bool
	isNew bool
}

// messages interprets an object's messages: its kind, attributes, comment,
// and dataset fields. It returns the object's links when it is a group.
func (d *reader) messages(o *Object, msgs []message) (*group, error) {
	var g group
	var ds Dataset
	var hasSpace, hasType, hasLayout bool
	count := map[int]int{}
	for _, m := range msgs {
		count[m.typ]++
		if m.flags&flagShared != 0 && m.typ != msgAttribute {
			// A shared message's data points at another object header, or
			// at the shared message heap.
			d.note(fmt.Sprintf("a shared %s message, whose value is stored elsewhere", msgName(m.typ)))
			switch m.typ {
			case msgDatatype:
				hasType = true
				ds.Type.Unread = "a shared datatype"
			case msgDataspace:
				hasSpace = true
				ds.Space.Kind = SpaceUnread
			}
			continue
		}
		c := d.buf(m.data, m.at)
		switch m.typ {
		case msgNil, msgContinuation, msgModTime, msgModTimeOld, msgRefCount, msgGroupInfo, msgFillOld, msgFill:
			// Nothing a check reads. A fill value is the value an
			// unwritten element reads as; it is not the dataset's data.
		case msgDataspace:
			hasSpace = true
			ds.Space = d.dataspace(c)
		case msgDatatype:
			hasType = true
			ds.Type = d.datatype(c, 0)
		case msgLayout:
			hasLayout = true
			ds.Layout = d.layout(c)
		case msgFilter:
			ds.Filters = d.filters(c)
		case msgExternal:
			ds.External = d.external(c)
		case msgAttribute:
			if m.flags&flagShared != 0 {
				d.note("a shared Attribute message, stored in the shared message heap")
				continue
			}
			a, err := d.attribute(c)
			if err != nil {
				return nil, err
			}
			o.Attrs = append(o.Attrs, a)
		case msgAttrInfo:
			if d.attrInfo(c) {
				d.note("attributes stored densely, in a fractal heap this reader does not read")
			}
		case msgComment:
			if i := bytes.IndexByte(m.data, 0); i >= 0 {
				o.Comment = string(m.data[:i])
			} else {
				o.Comment = string(m.data)
			}
		case msgSymbolTable:
			g.symbol = true
			g.btree = c.addr()
			g.heap = c.addr()
		case msgLinkInfo:
			g.isNew = true
			g.dense = d.linkInfo(c)
		case msgLink:
			g.isNew = true
			l, err := d.link(c)
			if err != nil {
				return nil, err
			}
			g.links = append(g.links, l)
		case msgSharedTable, msgBTreeK, msgDriverInfo, msgFileSpace:
			d.note(fmt.Sprintf("a %s message, which belongs in a superblock extension, in an object header", msgName(m.typ)))
		default:
			why := ""
			if m.flags&flagMustUnderstd != 0 {
				why = ", flagged so a reader that does not understand it must refuse the object"
			}
			d.note(fmt.Sprintf("object header message type %d, which this reader does not model%s", m.typ, why))
		}
		if c.err != nil {
			return nil, c.err
		}
	}
	for _, t := range []int{msgDataspace, msgDatatype, msgLayout, msgFilter, msgExternal, msgSymbolTable, msgLinkInfo, msgComment, msgAttrInfo} {
		if count[t] > 1 {
			return nil, d.errf(o.Addr, "an object header with %d %s messages, which may appear once", count[t], msgName(t))
		}
	}
	switch {
	case hasLayout || hasSpace && hasType:
		if !hasLayout || !hasSpace || !hasType {
			return nil, d.errf(o.Addr, "a dataset without a dataspace, datatype, or layout message")
		}
		if g.symbol || g.isNew {
			return nil, d.errf(o.Addr, "an object that is both a dataset and a group")
		}
		o.Kind = KindDataset
		o.Dataset = &ds
		return nil, nil
	case g.symbol || g.isNew:
		if g.symbol && g.isNew {
			return nil, d.errf(o.Addr, "a group with both a symbol table and link messages")
		}
		o.Kind = KindGroup
		return &g, nil
	case hasType:
		o.Kind = KindDatatype
		d.note("a committed (named) datatype")
		return nil, nil
	}
	o.Kind = KindOther
	d.note("an object header that is neither a group nor a dataset")
	return nil, nil
}

func msgName(t int) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

// attrInfo reads an Attribute Info message and reports whether attributes
// are stored densely.
func (d *reader) attrInfo(c *buf) bool {
	if v := c.u8(); v != 0 {
		c.fail("an Attribute Info message of version %d", v)
		return false
	}
	flags := c.u8()
	if flags&1 != 0 {
		c.skip(2)
	}
	heap := c.addr()
	return c.err == nil && heap != undefined
}

// linkInfo reads a Link Info message and reports whether links are stored
// densely.
func (d *reader) linkInfo(c *buf) bool {
	if v := c.u8(); v != 0 {
		c.fail("a Link Info message of version %d", v)
		return false
	}
	flags := c.u8()
	if flags&1 != 0 {
		c.skip(8)
	}
	heap := c.addr()
	return c.err == nil && heap != undefined
}

// link reads a Link message.
func (d *reader) link(c *buf) (child, error) {
	if v := c.u8(); v != 1 {
		return child{}, d.errf(c.at, "a Link message of version %d", v)
	}
	flags := c.u8()
	if flags&0xe0 != 0 {
		return child{}, d.errf(c.at, "a Link message with reserved flag bits set")
	}
	typ := 0
	if flags&0x08 != 0 {
		typ = c.u8()
	}
	if flags&0x04 != 0 {
		c.skip(8)
	}
	if flags&0x10 != 0 {
		c.skip(1)
	}
	n := c.uint(1 << uint(flags&3))
	if c.err != nil {
		return child{}, c.err
	}
	if n == 0 || n > uint64(c.left()) {
		return child{}, d.errf(c.at, "a link name of %d bytes", n)
	}
	name := string(c.bytes(int(n)))
	ch := child{name: name}
	switch typ {
	case 0:
		ch.addr = c.addr()
		if c.err == nil && ch.addr == undefined {
			return child{}, d.errf(c.at, "a hard link %q to an undefined address", name)
		}
	case 1:
		ch.kind = "soft"
		ch.target = string(c.bytes(c.u16()))
	case 64:
		ch.kind = "external"
		v := c.bytes(c.u16())
		if len(v) > 0 {
			parts := bytes.SplitN(v[1:], []byte{0}, 3)
			if len(parts) >= 2 {
				ch.target = string(parts[0]) + ":" + string(parts[1])
			}
		}
	default:
		ch.kind = fmt.Sprintf("user-defined (type %d)", typ)
		c.skip(c.u16())
	}
	return ch, c.err
}

// children lists a group's links.
func (d *reader) children(o *Object, g *group) ([]child, error) {
	if g.isNew {
		if g.dense {
			d.note("links stored densely, in a fractal heap this reader does not read, so the group's members were not read")
		}
		return g.links, nil
	}
	if g.btree == undefined || g.heap == undefined {
		return nil, d.errf(o.Addr, "a symbol table message with an undefined address")
	}
	h, err := d.localHeap(g.heap)
	if err != nil {
		return nil, err
	}
	var out []child
	if err := d.groupTree(g.btree, h, &out, 0); err != nil {
		return nil, err
	}
	return out, nil
}
