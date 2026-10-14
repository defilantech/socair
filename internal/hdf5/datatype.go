package hdf5

import (
	"bytes"
	"fmt"
	"math"
	"math/bits"
)

// Datatype classes (specification IV.A.3.d).
const (
	ClassFixed    = 0
	ClassFloat    = 1
	ClassTime     = 2
	ClassString   = 3
	ClassBitfield = 4
	ClassOpaque   = 5
	ClassCompound = 6
	ClassRef      = 7
	ClassEnum     = 8
	ClassVLen     = 9
	ClassArray    = 10
	ClassComplex  = 11
)

var classNames = []string{"integer", "float", "time", "string", "bitfield", "opaque", "compound", "reference",
	"enum", "variable-length", "array", "complex"}

// Datatype is a datatype message's class and size, and what the reader
// needs of its properties.
type Datatype struct {
	Class   int
	Version int
	// Size is one element's size in the file, in bytes.
	Size uint32
	// Bits is the class bit field.
	Bits uint32
	// VLenString is a variable-length string (class 9, type 1); Base is a
	// variable-length type's base type.
	VLenString bool
	Base       *Datatype
	// Unread says why the type was not read (a shared datatype), or "".
	Unread string
}

// Name names the type for a report: "float32", "string", "int64", ...
func (t Datatype) Name() string {
	switch {
	case t.Unread != "":
		return "unread type"
	case t.Class == ClassFloat:
		return fmt.Sprintf("float%d", 8*t.Size)
	case t.Class == ClassFixed:
		if t.Bits&0x08 != 0 {
			return fmt.Sprintf("int%d", 8*t.Size)
		}
		return fmt.Sprintf("uint%d", 8*t.Size)
	case t.Class == ClassString:
		return fmt.Sprintf("string(%d)", t.Size)
	case t.VLenString:
		return "variable-length string"
	case t.Class >= 0 && t.Class < len(classNames):
		return classNames[t.Class]
	}
	return fmt.Sprintf("class %d", t.Class)
}

// datatype reads a datatype message's header (class, version, bit field,
// size) and, for a variable-length type, its base type.
func (d *reader) datatype(c *buf, depth int) Datatype {
	if depth > maxTypeDepth {
		c.fail("datatypes nested deeper than %d levels", maxTypeDepth)
		return Datatype{}
	}
	cv := c.u8()
	t := Datatype{Class: cv & 0x0f, Version: cv >> 4}
	t.Bits = uint32(c.u8()) | uint32(c.u8())<<8 | uint32(c.u8())<<16
	t.Size = c.u32()
	if c.err != nil {
		return t
	}
	if t.Version < 1 || t.Version > 5 {
		c.fail("a datatype of version %d", t.Version)
		return t
	}
	if t.Class > ClassComplex {
		c.fail("a datatype of class %d, which the specification does not define", t.Class)
		return t
	}
	if t.Class == ClassVLen {
		t.VLenString = t.Bits&0x0f == 1
		base := d.datatype(c, depth+1)
		t.Base = &base
	}
	return t
}

// Dataspace kinds.
const (
	SpaceScalar = iota
	SpaceSimple
	SpaceNull
	// SpaceUnread is a shared dataspace the reader did not resolve.
	SpaceUnread
)

// Dataspace is a dataset's or an attribute's shape.
type Dataspace struct {
	Kind int
	Dims []uint64
}

// Elements is the number of elements, or false when it overflows or the
// dataspace was not read.
func (s Dataspace) Elements() (uint64, bool) {
	switch s.Kind {
	case SpaceScalar:
		return 1, true
	case SpaceNull:
		return 0, true
	case SpaceUnread:
		return 0, false
	}
	n := uint64(1)
	for _, v := range s.Dims {
		hi, lo := bits.Mul64(n, v)
		if hi != 0 {
			return 0, false
		}
		n = lo
	}
	return n, true
}

// String gives the shape as h5py does: () for a scalar, (3, 4).
func (s Dataspace) String() string {
	switch s.Kind {
	case SpaceScalar:
		return "()"
	case SpaceNull:
		return "null"
	case SpaceUnread:
		return "unread"
	}
	var b bytes.Buffer
	b.WriteByte('(')
	for i, v := range s.Dims {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprint(&b, v)
	}
	if len(s.Dims) == 1 {
		b.WriteByte(',')
	}
	b.WriteByte(')')
	return b.String()
}

// dataspace reads a dataspace message (versions 1 and 2).
func (d *reader) dataspace(c *buf) Dataspace {
	v, rank, flags := c.u8(), c.u8(), c.u8()
	var s Dataspace
	switch v {
	case 1:
		c.skip(5)
		s.Kind = SpaceSimple
		if rank == 0 {
			s.Kind = SpaceScalar
		}
	case 2:
		switch c.u8() {
		case 0:
			s.Kind = SpaceScalar
		case 1:
			s.Kind = SpaceSimple
		case 2:
			s.Kind = SpaceNull
		default:
			c.fail("a dataspace of an undefined type")
		}
	default:
		c.fail("a dataspace message of version %d", v)
		return s
	}
	if rank > maxRank {
		c.fail("a dataspace of rank %d, more than HDF5's %d", rank, maxRank)
		return s
	}
	if s.Kind != SpaceSimple && rank != 0 {
		c.fail("a scalar or null dataspace with dimensions")
		return s
	}
	for i := 0; i < rank; i++ {
		s.Dims = append(s.Dims, c.length())
	}
	if flags&1 != 0 {
		c.skip(rank * d.len)
	}
	if v == 1 && flags&2 != 0 {
		c.skip(rank * d.len)
	}
	return s
}

// Attribute is one attribute: its name, type, shape, and, for a string
// type, its values.
type Attribute struct {
	Name  string
	Type  Datatype
	Space Dataspace
	// Strings are the values of a string attribute, fixed-length or
	// variable-length, in element order, when they were read.
	Strings []string
	// Unread says why a string attribute's values were not read, or "".
	Unread string
	// Truncated reports that values past the reader's text caps were not
	// kept.
	Truncated bool
}

// IsString reports a fixed-length or variable-length string attribute.
func (a *Attribute) IsString() bool {
	return a.Type.Class == ClassString || a.Type.VLenString
}

// attribute reads an attribute message (versions 1 to 3).
func (d *reader) attribute(c *buf) (Attribute, error) {
	var a Attribute
	v := c.u8()
	flags := c.u8()
	nameSize, typeSize, spaceSize := c.u16(), c.u16(), c.u16()
	if v == 3 {
		c.u8() // the name's character set
	}
	if c.err != nil {
		return a, c.err
	}
	if v < 1 || v > 3 {
		return a, d.errf(c.at, "an attribute message of version %d", v)
	}
	if v == 1 && flags != 0 || flags&^3 != 0 {
		return a, d.errf(c.at, "an attribute message with flags %d", flags)
	}
	pad := func(n int) int {
		if v == 1 {
			return (n + 7) &^ 7
		}
		return n
	}
	name := c.bytes(pad(nameSize))
	if c.err != nil {
		return a, c.err
	}
	if nameSize == 0 || nameSize > len(name) || name[nameSize-1] != 0 {
		return a, d.errf(c.at, "an attribute name that is not NUL-terminated within its size")
	}
	a.Name = string(name[:nameSize-1])
	tb := c.bytes(pad(typeSize))
	sb := c.bytes(pad(spaceSize))
	if c.err != nil {
		return a, c.err
	}
	if flags&1 != 0 {
		a.Type.Unread = "a shared datatype"
		a.Unread = "its datatype is shared, stored in another object"
	} else {
		tc := d.buf(tb[:typeSize], c.at)
		a.Type = d.datatype(tc, 0)
		if tc.err != nil {
			return a, tc.err
		}
	}
	if flags&2 != 0 {
		a.Space.Kind = SpaceUnread
		a.Unread = "its dataspace is shared, stored in another object"
		return a, nil
	}
	sc := d.buf(sb[:spaceSize], c.at)
	a.Space = d.dataspace(sc)
	if sc.err != nil {
		return a, sc.err
	}
	if a.Unread != "" {
		return a, nil
	}
	n, ok := a.Space.Elements()
	if !ok {
		return a, d.errf(c.at, "attribute %q has a dataspace whose size overflows", a.Name)
	}
	hi, need := bits.Mul64(n, uint64(a.Type.Size))
	if hi != 0 || need > uint64(c.left()) {
		return a, d.errf(c.at, "attribute %q holds %d bytes of data; its type and dataspace need %d", a.Name, c.left(), need)
	}
	data := c.bytes(int(need))
	if c.err != nil {
		return a, c.err
	}
	if a.IsString() {
		if err := d.attrStrings(&a, data, n, c.at); err != nil {
			return a, err
		}
	}
	return a, nil
}

// attrStrings decodes a string attribute's values.
func (d *reader) attrStrings(a *Attribute, data []byte, n uint64, at int64) error {
	size := uint64(a.Type.Size)
	if a.Type.Class == ClassString {
		if size == 0 {
			return d.errf(at, "attribute %q is a string type of size 0", a.Name)
		}
		for i := uint64(0); i < n; i++ {
			v := data[i*size : (i+1)*size]
			switch a.Type.Bits & 0x0f {
			case 0: // null-terminated
				if j := bytes.IndexByte(v, 0); j >= 0 {
					v = v[:j]
				}
			case 1: // null-padded
				v = bytes.TrimRight(v, "\x00")
			case 2: // space-padded
				v = bytes.TrimRight(v, " ")
			}
			if !d.keep(a, string(v)) {
				return nil
			}
		}
		return nil
	}
	// A variable-length string: each element is a sequence length and a
	// global heap ID (a collection's address and an object's index).
	elem := uint64(4 + d.off + 4)
	if size != elem {
		return d.errf(at, "attribute %q is a variable-length string of element size %d, not %d", a.Name, size, elem)
	}
	for i := uint64(0); i < n; i++ {
		c := d.buf(data[i*elem:(i+1)*elem], at)
		length := c.u32()
		coll := c.addr()
		index := c.u32()
		if c.err != nil {
			return c.err
		}
		if length == 0 {
			if !d.keep(a, "") {
				return nil
			}
			continue
		}
		if coll == undefined {
			return d.errf(at, "attribute %q holds a string in a global heap at an undefined address", a.Name)
		}
		if length > MaxText {
			a.Truncated = true
			continue
		}
		v, err := d.heapObject(coll, index, int64(length))
		if err != nil {
			return err
		}
		if !d.keep(a, string(v)) {
			return nil
		}
	}
	return nil
}

// keep adds a string value to an attribute, or marks it truncated once a
// cap is reached; it reports whether more may be kept.
func (d *reader) keep(a *Attribute, v string) bool {
	if d.textBytes+int64(len(v)) > maxTextTotal || d.textCount >= maxTextValues {
		a.Truncated = true
		return false
	}
	d.textBytes += int64(len(v))
	d.textCount++
	a.Strings = append(a.Strings, v)
	return true
}

// collection is a global heap collection's object table.
type collection struct {
	objects map[uint32]span
}

// heapObject reads the first n bytes of object index in the global heap
// collection at addr (specification III.E).
func (d *reader) heapObject(addr int64, index uint32, n int64) ([]byte, error) {
	col, ok := d.heaps[addr]
	if !ok {
		var err error
		if col, err = d.globalHeap(addr); err != nil {
			return nil, err
		}
		d.heaps[addr] = col
	}
	obj, ok := col.objects[index]
	if !ok || index == 0 {
		return nil, d.errf(addr, "a global heap ID names object %d, which the collection does not hold", index)
	}
	if n > obj.n {
		return nil, d.errf(obj.at, "a variable-length value of %d bytes in a global heap object of %d", n, obj.n)
	}
	return d.read(obj.at, n, "a global heap object")
}

func (d *reader) globalHeap(addr int64) (*collection, error) {
	if len(d.heaps) >= maxObjects {
		return nil, d.errf(addr, "more than %d global heap collections", maxObjects)
	}
	p, err := d.read(addr, int64(8+d.len), "a global heap collection")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p[:4], []byte("GCOL")) {
		return nil, d.errf(addr, "a global heap collection without the GCOL signature")
	}
	if p[4] != 1 {
		return nil, d.errf(addr+4, "a global heap collection of version %d", p[4])
	}
	c := d.buf(p, addr)
	c.skip(8)
	size := c.length()
	if c.err != nil {
		return nil, c.err
	}
	if size < uint64(8+d.len) || size > maxCollection || int64(size) > d.f.Size-addr {
		return nil, d.errf(addr, "a global heap collection of %d bytes", size)
	}
	end := addr + int64(size)
	if d.f.EOF > 0 && end > d.f.EOF {
		return nil, d.errf(addr, "a global heap collection past the end of the HDF5 data")
	}
	d.meta(addr, end, "global heap collection")
	col := &collection{objects: map[uint32]span{}}
	hdr := int64(8 + d.len)
	for at := addr + hdr; end-at >= hdr; {
		h, err := d.read(at, hdr, "a global heap object")
		if err != nil {
			return nil, err
		}
		hc := d.buf(h, at)
		index := uint32(hc.u16())
		hc.skip(6)
		osize := hc.length()
		if hc.err != nil {
			return nil, hc.err
		}
		if index == 0 {
			break // free space, to the end of the collection
		}
		padded := (osize + 7) &^ 7
		if osize > uint64(math.MaxInt64) || padded > uint64(end-at-hdr) {
			return nil, d.errf(at, "a global heap object of %d bytes past the end of its collection", osize)
		}
		if _, dup := col.objects[index]; dup {
			return nil, d.errf(at, "a global heap collection with two objects of index %d", index)
		}
		col.objects[index] = span{at + hdr, int64(osize)}
		at += hdr + int64(padded)
	}
	return col, nil
}
