// Package hdf5 reads the parts of an HDF5 file that a model checkpoint uses:
// the group hierarchy, attributes and their string values, and each
// dataset's datatype, dataspace, and storage layout. It exists for the
// Keras checks: a Keras model saved as .h5 (Keras 2, tf.keras, or Keras 3's
// legacy format), the weights file inside a .keras archive, and the
// tf_model.h5 that Hugging Face transformers writes are all HDF5 files.
//
// It is not a general HDF5 library. It is written against the HDF5 File
// Format Specification Version 4.0 (docs/doxygen/dox/H5.format.4.0.dox at
// HDF5 2.2.0) with the Go standard library only, and it reads what h5py
// writes by default and with libver="latest": superblock versions 0 to 3,
// version 1 and 2 object headers, "old style" groups (a symbol table: a
// version 1 B-tree, symbol table nodes, and a local heap) and compact "new
// style" groups (link messages), attributes stored in the object header,
// fixed-length strings and variable-length strings (in the global heap), and
// compact, contiguous, and chunked storage indexed by a version 1 B-tree or
// a single chunk. It never reads dataset data.
//
// Soft and external links are listed with their targets (File.Links), and
// so are datasets whose data is in other files (LayoutCheck.Outside); the
// checks judge them. What it does not model is recorded in File.Unread,
// never guessed: dense link or attribute storage (a fractal heap), shared
// object header messages, a superblock extension, a driver information
// block, user-defined links, an object header message type it does not
// know, and the chunk indexes of layout versions 4 and 5 other than a single
// chunk and the implicit index. Malformed bytes (a bad signature, a
// structure past the end of the file, a length past its message, a checksum
// that does not match) are an error: the file is unparseable. Where the
// specification and the HDF5 library differ, it reads as the library does,
// and says so where it does.
//
// Bounds: objects, nesting, messages, B-tree nodes, chunks, and the bytes
// read for any one structure are capped (see the constants), and past a cap
// the file is unparseable, except text, which is cut off and marked.
package hdf5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

// Signature is the HDF5 format signature, the first eight bytes of the
// superblock.
var Signature = []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}

// Bounds.
const (
	maxObjects      = 1 << 18
	maxDepth        = 64       // group nesting
	maxMessages     = 1 << 16  // messages in one object header
	maxHeaderChunks = 1 << 12  // continuation blocks of one object header
	maxHeaderBytes  = 64 << 20 // one object header, all its blocks
	maxRead         = 64 << 20 // one structure read into memory
	maxBTreeNodes   = 1 << 20
	maxChunks       = 1 << 22
	maxHeapBytes    = 64 << 20 // one local heap's data segment
	maxCollection   = 1 << 30  // one global heap collection's size
	maxRank         = 32       // HDF5's H5S_MAX_RANK
	maxTypeDepth    = 16       // nested datatypes (a variable-length type's base)
	maxUnread       = 64
	maxLinks        = 1 << 16

	// MaxText is the largest single string value kept, and maxTextTotal
	// the most kept in all.
	MaxText       = 16 << 20
	maxTextTotal  = 64 << 20
	maxTextValues = 1 << 20

	// maxSigOffset bounds the search for a superblock after a user block.
	maxSigOffset = 1 << 40
)

// undefined is HDF5's undefined address: all bits set.
const undefined = -1

// File is what the reader found in an HDF5 file.
type File struct {
	// SuperblockOffset is where the superblock begins: 0, or the size of a
	// user block before it (512, 1024, 2048, ...), which HDF5 skips.
	SuperblockOffset  int64
	SuperblockVersion int
	OffsetSize        int
	LengthSize        int
	// EOF is the end-of-file address the superblock records: where the HDF5
	// data ends, as an offset in the file. Size is the file's size.
	EOF  int64
	Size int64
	// Flags is superblock version 3's file consistency flags: bit 0 set
	// means the file was left open for writing.
	Flags int

	// Objects are every group and dataset reached, root first, then in the
	// order their names sort within each group.
	Objects []*Object
	// Links are the soft, external, and user-defined links, which name a
	// path and not an object.
	Links []Link
	// Aliases are names that reach an object already reached by another
	// name (a hard link), with the path that name reached first.
	Aliases []Alias

	// Unread names what the reader read past without modelling, with
	// counts. Sorted.
	Unread []string

	// meta are the byte ranges of the metadata structures read, absolute.
	meta []Extent
}

// Kind is what an object is.
type Kind int

const (
	KindGroup Kind = iota
	KindDataset
	// KindDatatype is a committed (named) datatype.
	KindDatatype
	// KindOther is an object header with neither a group's nor a dataset's
	// messages.
	KindOther
)

func (k Kind) String() string {
	switch k {
	case KindGroup:
		return "group"
	case KindDataset:
		return "dataset"
	case KindDatatype:
		return "committed datatype"
	}
	return "object"
}

// Object is a group or dataset.
type Object struct {
	Path    string // "/" for the root group
	Addr    int64  // the object header's address, absolute
	Kind    Kind
	Attrs   []Attribute
	Comment string
	Dataset *Dataset
}

// Attr returns the attribute with this name, or nil.
func (o *Object) Attr(name string) *Attribute {
	for i := range o.Attrs {
		if o.Attrs[i].Name == name {
			return &o.Attrs[i]
		}
	}
	return nil
}

// Link is a link that names a path rather than an object.
type Link struct {
	Path string // where the link is
	Type string // "soft", "external", or "user-defined (type N)"
	// Target is a soft link's path, or an external link's file and path.
	Target string
}

// Alias is a second name for an object.
type Alias struct {
	Path, Of string
}

// Extent is a byte range in the file, absolute, [Start, End).
type Extent struct {
	Start, End int64
	What       string
}

// ParseError is malformed HDF5 at a byte offset.
type ParseError struct {
	Off int64
	Msg string
}

func (e *ParseError) Error() string { return fmt.Sprintf("at byte %d: %s", e.Off, e.Msg) }

// Sniff reports whether the file at path is HDF5 by its bytes: the format
// signature at offset 0 or, after a user block, at 512, 1024, 2048, and so
// on, where the specification says the library looks. It returns where the
// signature is, or -1.
func Sniff(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return -1
	}
	return Find(f, st.Size())
}

// Find is Sniff over size bytes read through r.
func Find(r io.ReaderAt, size int64) int64 {
	var b [8]byte
	for off := int64(0); off+8 <= size && off <= maxSigOffset; {
		if _, err := r.ReadAt(b[:], off); err != nil {
			return -1
		}
		if bytes.Equal(b[:], Signature) {
			return off
		}
		if off == 0 {
			off = 512
		} else {
			off *= 2
		}
	}
	return -1
}

// Read parses the HDF5 file at path.
func Read(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return ReadFrom(f, st.Size())
}

// ReadFrom parses an HDF5 file of size bytes read through r.
func ReadFrom(r io.ReaderAt, size int64) (*File, error) {
	sb := Find(r, size)
	if sb < 0 {
		return nil, &ParseError{0, "no HDF5 signature at offset 0 or at any offset the specification allows for a user block"}
	}
	d := &reader{src: r, f: &File{SuperblockOffset: sb, Size: size}, unread: map[string]int{},
		seen: map[int64]string{}, btrees: map[int64]bool{}, heaps: map[int64]*collection{}}
	if err := d.superblock(sb); err != nil {
		return nil, err
	}
	if err := d.walk(); err != nil {
		return nil, err
	}
	for u, n := range d.unread {
		if n > 1 {
			u += fmt.Sprintf(" (%d times)", n)
		}
		d.f.Unread = append(d.f.Unread, u)
	}
	sort.Strings(d.f.Unread)
	return d.f, nil
}

type reader struct {
	src io.ReaderAt
	f   *File

	base             int64 // the base address: addresses are relative to it
	off, len         int   // size of offsets and lengths
	leafK, internalK int   // group B-tree K values
	chunkK           int   // chunked-storage B-tree K value

	unread    map[string]int
	seen      map[int64]string // object header address: the first path that reached it
	btrees    map[int64]bool   // B-tree nodes visited
	nodes     int
	chunks    int
	links     int
	heaps     map[int64]*collection
	textBytes int64
	textCount int
}

func (d *reader) errf(off int64, format string, args ...any) error {
	return &ParseError{Off: off, Msg: fmt.Sprintf(format, args...)}
}

// note records something read past and not modelled.
func (d *reader) note(s string) {
	if _, ok := d.unread[s]; !ok && len(d.unread) >= maxUnread {
		s = "further unmodelled structures"
	}
	d.unread[s]++
}

// abs turns a relative address into a file offset.
func (d *reader) abs(rel uint64) (int64, bool) {
	if rel > uint64(1<<62) {
		return 0, false
	}
	return d.base + int64(rel), true
}

// read reads n bytes at an absolute offset. A structure must lie within
// both the file and the HDF5 data the superblock records: the HDF5 library
// refuses to read metadata past its end-of-file address.
func (d *reader) read(at, n int64, what string) ([]byte, error) {
	if n < 0 || n > maxRead {
		return nil, d.errf(at, "%s of %d bytes is past this reader's bounds", what, n)
	}
	if at < d.f.SuperblockOffset || at > d.f.Size || n > d.f.Size-at {
		return nil, d.errf(at, "%s of %d bytes runs past the end of the file (%d bytes)", what, n, d.f.Size)
	}
	if d.f.EOF > 0 && n > d.f.EOF-at {
		return nil, d.errf(at, "%s of %d bytes runs past the end of the HDF5 data the superblock records (%d)", what, n, d.f.EOF)
	}
	b := make([]byte, n)
	if _, err := d.src.ReadAt(b, at); err != nil {
		return nil, err
	}
	return b, nil
}

// meta records a metadata structure's byte range.
func (d *reader) meta(start, end int64, what string) {
	d.f.meta = append(d.f.meta, Extent{start, end, what})
}

// buf is a cursor over bytes read at a file offset, for decoding.
type buf struct {
	b   []byte
	pos int
	at  int64 // the file offset of b[0]
	d   *reader
	err error
}

func (d *reader) buf(b []byte, at int64) *buf { return &buf{b: b, at: at, d: d} }

func (c *buf) fail(format string, args ...any) {
	if c.err == nil {
		c.err = c.d.errf(c.at+int64(c.pos), format, args...)
	}
}

func (c *buf) need(n int) bool {
	if c.err != nil {
		return false
	}
	if n < 0 || n > len(c.b)-c.pos {
		c.fail("a field runs past the end of its structure")
		return false
	}
	return true
}

func (c *buf) left() int { return len(c.b) - c.pos }

func (c *buf) skip(n int) {
	if c.need(n) {
		c.pos += n
	}
}

func (c *buf) bytes(n int) []byte {
	if !c.need(n) {
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}

func (c *buf) u8() int {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return int(v)
}

func (c *buf) u16() int {
	if !c.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(c.b[c.pos:])
	c.pos += 2
	return int(v)
}

func (c *buf) u32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.b[c.pos:])
	c.pos += 4
	return v
}

// uint reads an n-byte little-endian unsigned value.
func (c *buf) uint(n int) uint64 {
	if !c.need(n) {
		return 0
	}
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(c.b[c.pos+i])
	}
	c.pos += n
	return v
}

// addr reads an address: absolute, or undefined (-1).
func (c *buf) addr() int64 {
	v := c.uint(c.d.off)
	if c.err != nil {
		return 0
	}
	if isUndefined(v, c.d.off) {
		return undefined
	}
	a, ok := c.d.abs(v)
	if !ok {
		c.fail("an address %d past any file", v)
		return 0
	}
	return a
}

// length reads a "Size of Lengths" value.
func (c *buf) length() uint64 { return c.uint(c.d.len) }

func isUndefined(v uint64, n int) bool {
	if n >= 8 {
		return v == ^uint64(0)
	}
	return v == 1<<(8*uint(n))-1
}

// --- superblock ---------------------------------------------------------------

func (d *reader) superblock(at int64) error {
	head, err := d.readRaw(at, 9, "the superblock")
	if err != nil {
		return err
	}
	v := int(head[8])
	d.f.SuperblockVersion = v
	switch v {
	case 0, 1:
		return d.superblock01(at, v)
	case 2, 3:
		return d.superblock23(at, v)
	}
	return d.errf(at+8, "superblock version %d, which the specification does not define", v)
}

// readRaw reads before the superblock is known: within the file only.
func (d *reader) readRaw(at, n int64, what string) ([]byte, error) {
	if at < 0 || n > d.f.Size-at {
		return nil, d.errf(at, "%s runs past the end of the file", what)
	}
	b := make([]byte, n)
	if _, err := d.src.ReadAt(b, at); err != nil {
		return nil, err
	}
	return b, nil
}

func (d *reader) sizes(at int64, off, length int) error {
	if !validSize(off) || !validSize(length) {
		return d.errf(at, "size of offsets %d or of lengths %d is not 2, 4, 8, 16, or 32", off, length)
	}
	if off > 8 || length > 8 {
		return d.errf(at, "size of offsets %d or of lengths %d is wider than this reader's 8 bytes", off, length)
	}
	d.off, d.len = off, length
	d.f.OffsetSize, d.f.LengthSize = off, length
	return nil
}

func validSize(n int) bool { return n == 2 || n == 4 || n == 8 || n == 16 || n == 32 }

func (d *reader) superblock01(at int64, v int) error {
	// The fixed part, then four addresses and the root group's symbol
	// table entry; offsets are not known until byte 13.
	fixed, err := d.readRaw(at, 24, "the superblock")
	if err != nil {
		return err
	}
	if err := d.sizes(at, int(fixed[13]), int(fixed[14])); err != nil {
		return err
	}
	if fixed[9] != 0 || fixed[10] != 0 || fixed[12] != 0 {
		return d.errf(at+9, "a free-space, root symbol table entry, or shared header message version other than 0")
	}
	d.leafK = int(binary.LittleEndian.Uint16(fixed[16:]))
	d.internalK = int(binary.LittleEndian.Uint16(fixed[18:]))
	d.chunkK = 32 // the library default when version 0 does not store it
	n := 24
	if v == 1 {
		n += 4
	}
	entry := symbolEntrySize(d)
	total := n + 4*d.off + entry
	b, err := d.readRaw(at, int64(total), "the superblock")
	if err != nil {
		return err
	}
	c := d.buf(b, at)
	c.skip(24)
	if v == 1 {
		d.chunkK = c.u16()
		c.skip(2)
	}
	if d.leafK == 0 || d.internalK == 0 || d.chunkK == 0 {
		return d.errf(at+16, "a B-tree K value of 0, which the specification forbids")
	}
	base := c.uint(d.off)
	freeSpace := c.uint(d.off)
	eof := c.uint(d.off)
	driver := c.uint(d.off)
	if c.err != nil {
		return c.err
	}
	if err := d.setBase(at, base, eof); err != nil {
		return err
	}
	if !isUndefined(freeSpace, d.off) {
		d.note("a global free-space index address in a version 0 or 1 superblock, which the specification says is always undefined")
	}
	if !isUndefined(driver, d.off) {
		d.note("a driver information block (the family or multi file driver: data in other files)")
	}
	// The root group's symbol table entry: its object header address.
	c.length() // link name offset
	root := c.addr()
	if c.err != nil {
		return c.err
	}
	d.meta(at, at+int64(total), "superblock")
	if root == undefined {
		return d.errf(at, "the root group's object header address is undefined")
	}
	return d.root(root)
}

func (d *reader) superblock23(at int64, v int) error {
	fixed, err := d.readRaw(at, 12, "the superblock")
	if err != nil {
		return err
	}
	if err := d.sizes(at, int(fixed[9]), int(fixed[10])); err != nil {
		return err
	}
	d.f.Flags = int(fixed[11])
	d.leafK, d.internalK, d.chunkK = 4, 16, 32 // version 2 stores none: the library defaults, or a B-tree 'K' Values message in the extension
	total := 12 + 4*d.off + 4
	b, err := d.readRaw(at, int64(total), "the superblock")
	if err != nil {
		return err
	}
	if sum := lookup3(b[:total-4]); sum != binary.LittleEndian.Uint32(b[total-4:]) {
		return d.errf(at, "the superblock's checksum does not match its bytes; the HDF5 library refuses the file")
	}
	c := d.buf(b, at)
	c.skip(12)
	base := c.uint(d.off)
	ext := c.uint(d.off)
	eof := c.uint(d.off)
	if c.err != nil {
		return c.err
	}
	if err := d.setBase(at, base, eof); err != nil {
		return err
	}
	if v == 3 && d.f.Flags&0x05 != 0 {
		d.note("superblock version 3 file consistency flags that say the file is still open for writing")
	}
	if !isUndefined(ext, d.off) {
		d.note("a superblock extension (shared message table, file space settings, or driver information)")
	}
	root := c.addr()
	if c.err != nil {
		return c.err
	}
	d.meta(at, at+int64(total), "superblock")
	if root == undefined {
		return d.errf(at, "the root group's object header address is undefined")
	}
	return d.root(root)
}

// setBase records the base address and the end-of-file address as the HDF5
// library does (H5F__super_read in src/H5Fsuper.c, HDF5 2.2.0): the stored
// end-of-file address is absolute, and when the stored base address is not
// the superblock's own offset (the HDF5 data was moved within the file, as
// a user block added afterwards moves it), the library takes the
// superblock's offset as the base and moves the end-of-file address by the
// same distance. A base address at or past the end-of-file address is
// refused, as the library refuses it.
func (d *reader) setBase(at int64, base, eof uint64) error {
	if isUndefined(eof, d.off) || eof > 1<<62 || eof == 0 {
		return d.errf(at, "the end-of-file address is undefined or 0")
	}
	if isUndefined(base, d.off) || base >= eof {
		return d.errf(at, "a base address (%d) at or past the end-of-file address (%d); the HDF5 library refuses the file", base, eof)
	}
	d.base = at
	d.f.EOF = int64(eof) - int64(base) + at
	if d.f.EOF <= at {
		return d.errf(at, "the end-of-file address %d is not after the superblock", d.f.EOF)
	}
	return nil
}

// symbolEntrySize is a symbol table entry's size: a link name offset, which
// the HDF5 library reads as a length (H5G_ent_decode in src/H5Gent.c,
// H5G_SIZEOF_ENTRY in src/H5Gprivate.h; the specification's table marks it
// as an offset, and the two sizes are the same in every file h5py writes),
// an object header address, a cache type, 4 reserved bytes, and a 16-byte
// scratch pad.
func symbolEntrySize(d *reader) int { return d.len + d.off + 24 }

// root keeps the root group's address for walk.
func (d *reader) root(addr int64) error {
	d.f.Objects = append(d.f.Objects, &Object{Path: "/", Addr: addr})
	return nil
}

// --- the object graph ---------------------------------------------------------

// walk reads every object from the root, depth first, children in the
// order their names sort.
func (d *reader) walk() error {
	root := d.f.Objects[0]
	d.f.Objects = d.f.Objects[:0]
	return d.object(root.Path, root.Addr, 0)
}

func (d *reader) object(p string, addr int64, depth int) error {
	if first, ok := d.seen[addr]; ok {
		d.f.Aliases = append(d.f.Aliases, Alias{Path: p, Of: first})
		return nil
	}
	if len(d.f.Objects) >= maxObjects {
		return d.errf(addr, "more than %d objects, this reader's bound", maxObjects)
	}
	d.seen[addr] = p
	o := &Object{Path: p, Addr: addr}
	d.f.Objects = append(d.f.Objects, o)
	h, err := d.header(addr)
	if err != nil {
		return err
	}
	g, err := d.messages(o, h)
	if err != nil {
		return err
	}
	if o.Dataset != nil {
		return d.readChunks(o.Dataset, p)
	}
	if g == nil {
		return nil
	}
	if depth >= maxDepth {
		return d.errf(addr, "groups nest deeper than %d levels, this reader's bound", maxDepth)
	}
	children, err := d.children(o, g)
	if err != nil {
		return err
	}
	sort.Slice(children, func(i, j int) bool { return children[i].name < children[j].name })
	for i, ch := range children {
		if i > 0 && ch.name == children[i-1].name {
			return d.errf(addr, "group %s holds two links named %q", p, ch.name)
		}
	}
	for _, ch := range children {
		cp := join(p, ch.name)
		switch {
		case ch.kind != "":
			d.links++
			if d.links > maxLinks {
				return d.errf(addr, "more than %d soft, external, or user-defined links", maxLinks)
			}
			d.f.Links = append(d.f.Links, Link{Path: cp, Type: ch.kind, Target: ch.target})
			if ch.kind != "soft" && ch.kind != "external" {
				d.note(ch.kind + " links, a link type the specification leaves to the application that registers it")
			}
		default:
			if err := d.object(cp, ch.addr, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// child is a link in a group: a hard link to an object, or another kind.
type child struct {
	name   string
	addr   int64
	kind   string // "" for a hard link
	target string
}
