// Package tarwalk reads a tar stream strictly. It accepts only archives that
// the readers a model image meets on its way to a server read the same way,
// and refuses anything else with a named reason.
//
// Those readers are Go's archive/tar, which containerd and CRI-O's
// containers/storage unpack image layers with, and Python's tarfile, which
// KServe's oci+fetch storage initializer extracts models/ with. Where the two
// read one input differently (a GNU long name and a PAX path on one entry,
// two PAX headers in a row, a PAX global header, a numeric field one trims and
// the other cuts at a NUL, bytes in a GNU header where POSIX keeps a name
// prefix), a crafted layer could unpack into one tree for one consumer and
// another tree for the next, so the input is refused here. docs/oci.md lists
// each rule and the source lines it rests on.
//
// It reads regular files, directories, symbolic links, hard links, devices,
// and FIFOs, with POSIX (ustar and PAX) and GNU headers. Everything else
// (sparse files, global or Solaris extended headers, unknown type flags) is
// refused.
package tarwalk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

const blockSize = 512

// Bounds.
const (
	// MaxName is the longest path or link target accepted, in bytes: Linux's
	// PATH_MAX.
	MaxName = 4096
	// MaxPAX is the most record bytes one PAX header may hold, Go's
	// archive/tar limit for a special header's data.
	MaxPAX = 1 << 20
	// maxUSTARSize is the largest size an 11-digit octal size field holds;
	// a PAX size record may differ from the header's own size field only
	// when the size does not fit it.
	maxUSTARSize = 1<<33 - 1
)

// Kind is an entry's type.
type Kind int

// Entry kinds.
const (
	Regular Kind = iota + 1
	Directory
	Symlink
	Hardlink
	// CharDevice, BlockDevice, and FIFO are special files: base images
	// ship /dev nodes (Amazon Linux 2023, Wolfi), so they are read, and the
	// caller decides where they may be.
	CharDevice
	BlockDevice
	FIFO
)

func (k Kind) String() string {
	switch k {
	case Regular:
		return "regular file"
	case Directory:
		return "directory"
	case Symlink:
		return "symbolic link"
	case Hardlink:
		return "hard link"
	case CharDevice:
		return "character device"
	case BlockDevice:
		return "block device"
	case FIFO:
		return "FIFO"
	}
	return "entry"
}

// Entry is one entry of the archive, with any PAX or GNU long-name header
// before it applied.
type Entry struct {
	// Name is the path the archive records (a ustar prefix, a GNU long name,
	// or a PAX path applied), as written: not cleaned.
	Name string
	// Linkname is a link's target, as written.
	Linkname string
	Kind     Kind
	// Size is the number of data bytes; zero for anything but a regular
	// file.
	Size int64
	// Offset is where the entry's first header block starts in the stream.
	Offset int64
}

// Error is a refusal: the stream is not one this package reads, at Offset.
type Error struct {
	Offset int64
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("at byte %d: %s", e.Offset, e.Reason) }

func refuse(off int64, format string, args ...any) error {
	return &Error{Offset: off, Reason: fmt.Sprintf(format, args...)}
}

// Reader reads a tar stream entry by entry. Next returns io.EOF at the
// end-of-archive marker (two zero blocks), after which Finish checks that
// nothing but zero bytes follows.
type Reader struct {
	r      io.Reader
	off    int64 // bytes consumed from r
	remain int64 // data bytes of the current entry not yet read
	pad    int64 // padding after the current entry's data
	cur    *Entry
	ended  bool
	err    error
	blk    [blockSize]byte
}

// NewReader reads r.
func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Offset is the number of bytes read from the stream so far.
func (tr *Reader) Offset() int64 { return tr.off }

// Next skips what is left of the current entry and returns the next one. It
// returns io.EOF at the end-of-archive marker, and an *Error for anything it
// refuses. An error is sticky.
func (tr *Reader) Next() (*Entry, error) {
	if tr.err != nil {
		return nil, tr.err
	}
	if tr.ended {
		return nil, io.EOF
	}
	e, err := tr.next()
	switch {
	case err == io.EOF:
		tr.ended = true
	case err != nil:
		tr.err = err
	}
	tr.cur = e
	return e, err
}

// Read reads the current regular file's data.
func (tr *Reader) Read(p []byte) (int, error) {
	if tr.err != nil {
		return 0, tr.err
	}
	if tr.remain == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > tr.remain {
		p = p[:tr.remain]
	}
	n, err := tr.r.Read(p)
	tr.off += int64(n)
	tr.remain -= int64(n)
	if err == io.EOF && tr.remain > 0 {
		err = refuse(tr.off, "the stream ends inside %s, %d bytes short", tr.cur.Name, tr.remain)
	}
	if err != nil && err != io.EOF {
		tr.err = err
	}
	if err == io.EOF {
		err = nil
	}
	return n, err
}

// Finish reads the rest of the stream after the end-of-archive marker and
// refuses anything but zero bytes there: a reader that keeps going past the
// marker (GNU tar's --ignore-zeros, Python's ignore_zeros) would find more
// entries.
func (tr *Reader) Finish() error {
	if tr.err != nil {
		return tr.err
	}
	if !tr.ended {
		return errors.New("tarwalk: Finish before the end-of-archive marker")
	}
	buf := make([]byte, 32<<10)
	for {
		n, err := tr.r.Read(buf)
		if i := bytes.IndexFunc(buf[:n], func(r rune) bool { return r != 0 }); i >= 0 {
			tr.err = refuse(tr.off+int64(i), "data follows the end-of-archive marker; a reader that reads past it would find more")
			return tr.err
		}
		tr.off += int64(n)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			tr.err = err
			return err
		}
	}
}

func (tr *Reader) readBlock() error {
	n, err := io.ReadFull(tr.r, tr.blk[:])
	tr.off += int64(n)
	return err
}

// skip discards n bytes, which the stream must hold.
func (tr *Reader) skip(n int64) error {
	if n == 0 {
		return nil
	}
	got, err := io.CopyN(io.Discard, tr.r, n)
	tr.off += got
	if err == io.EOF {
		return refuse(tr.off, "the stream ends inside an entry, %d bytes short", n-got)
	}
	return err
}

// readData reads a meta header's data and its padding, which must be zero
// bytes: Python's tarfile reads a PAX header's records, and a GNU long name,
// from the data rounded up to the block, padding included, where Go's
// archive/tar reads exactly the data. Bytes in the padding would make
// tarfile read a longer name, or fail on a record and end the archive there,
// silently.
func (tr *Reader) readData(n int64) ([]byte, error) {
	b := make([]byte, n+padding(n))
	got, err := io.ReadFull(tr.r, b)
	tr.off += int64(got)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, refuse(tr.off, "the stream ends inside a PAX or long-name header")
	}
	if err != nil {
		return nil, err
	}
	if !isZero(b[n:]) {
		return nil, refuse(tr.off-int64(len(b)-int(n)), "bytes in the padding after a PAX or long-name header's data: Python's tarfile reads them as part of it, Go's archive/tar does not")
	}
	return b[:n], nil
}

func padding(n int64) int64 { return -n & (blockSize - 1) }

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (tr *Reader) next() (*Entry, error) {
	if err := tr.skip(tr.remain + tr.pad); err != nil {
		return nil, err
	}
	tr.remain, tr.pad = 0, 0
	start := tr.off
	var (
		pax                map[string]string
		longName, longLink *string
		meta               bool
	)
	for {
		hoff := tr.off
		if err := tr.readBlock(); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				if meta {
					return nil, refuse(hoff, "the stream ends after a PAX or long-name header, with no entry for it")
				}
				return nil, refuse(hoff, "the stream ends without tar's end-of-archive marker (two zero blocks)")
			}
			return nil, err
		}
		if isZero(tr.blk[:]) {
			if meta {
				return nil, refuse(hoff, "a PAX or long-name header is followed by the end-of-archive marker, not by an entry")
			}
			if err := tr.readBlock(); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return nil, refuse(tr.off, "the archive ends with one zero block, not the two of an end-of-archive marker")
				}
				return nil, err
			}
			if !isZero(tr.blk[:]) {
				return nil, refuse(hoff+blockSize, "a zero block is followed by a header: Python's tarfile stops at the zero block, Go's archive/tar refuses the archive")
			}
			return nil, io.EOF
		}
		h, err := parseHeader(&tr.blk, hoff)
		if err != nil {
			return nil, err
		}
		switch h.typeflag {
		case 'x':
			if pax != nil {
				return nil, refuse(hoff, "two PAX headers in a row: Go's archive/tar applies the second, Python's tarfile applies both")
			}
			if longName != nil || longLink != nil {
				return nil, refuse(hoff, "a PAX header and a GNU long name or link on one entry: Go's archive/tar and Python's tarfile apply them in opposite orders")
			}
			if h.size > MaxPAX {
				return nil, refuse(hoff, "a PAX header of %d bytes, over the %d Socair reads", h.size, MaxPAX)
			}
			data, err := tr.readData(h.size)
			if err != nil {
				return nil, err
			}
			if pax, err = parsePAX(data, hoff); err != nil {
				return nil, err
			}
		case 'L', 'K':
			if pax != nil {
				return nil, refuse(hoff, "a PAX header and a GNU long name or link on one entry: Go's archive/tar and Python's tarfile apply them in opposite orders")
			}
			slot := &longName
			if h.typeflag == 'K' {
				slot = &longLink
			}
			if *slot != nil {
				return nil, refuse(hoff, "two GNU long %s headers in a row", longWhat(h.typeflag))
			}
			if h.size == 0 || h.size > MaxName+1 {
				return nil, refuse(hoff, "a GNU long %s header of %d bytes", longWhat(h.typeflag), h.size)
			}
			data, err := tr.readData(h.size)
			if err != nil {
				return nil, err
			}
			s := data
			if i := bytes.IndexByte(data, 0); i >= 0 {
				if !isZero(data[i:]) {
					return nil, refuse(hoff, "a GNU long %s header with bytes after its name's terminating NUL", longWhat(h.typeflag))
				}
				s = data[:i]
			}
			if len(s) == 0 {
				return nil, refuse(hoff, "an empty GNU long %s", longWhat(h.typeflag))
			}
			v := string(s)
			*slot = &v
		case '0', '1', '2', '5', '3', '4', '6':
			return tr.entry(h, start, pax, longName, longLink)
		default:
			return nil, refuse(hoff, "%s", unread(h.typeflag))
		}
		meta = true
	}
}

func longWhat(t byte) string {
	if t == 'K' {
		return "link"
	}
	return "name"
}

// unread names a type flag Socair does not read, and why.
func unread(t byte) string {
	switch t {
	case 'g':
		return "a PAX global header: containerd ignores it, and Python's tarfile applies it to every entry after it"
	case 'X':
		return "a Solaris extended header: Python's tarfile applies it as a PAX header, Go's archive/tar reads it as an entry"
	case 'S':
		return "a GNU sparse file, which tar readers do not support alike (the OCI image spec: sparse files SHOULD NOT be used)"
	case '7':
		return "a contiguous file (type 7): Python's tarfile extracts it as a file, containerd refuses it"
	case 0:
		return "the old regular-file type flag (NUL): Go's archive/tar and Python's tarfile decide differently whether it names a directory"
	}
	return fmt.Sprintf("type flag %q, which Socair does not read", t)
}

func (tr *Reader) entry(h *header, start int64, pax map[string]string, longName, longLink *string) (*Entry, error) {
	e := &Entry{Name: h.name, Linkname: h.linkname, Size: h.size, Offset: start}
	switch h.typeflag {
	case '0':
		e.Kind = Regular
	case '1':
		e.Kind = Hardlink
	case '2':
		e.Kind = Symlink
	case '5':
		e.Kind = Directory
	case '3':
		e.Kind = CharDevice
	case '4':
		e.Kind = BlockDevice
	case '6':
		e.Kind = FIFO
	}
	if longName != nil {
		e.Name = *longName
	}
	if longLink != nil {
		e.Linkname = *longLink
	}
	if v, ok := pax["path"]; ok {
		e.Name = v
	}
	if v, ok := pax["linkpath"]; ok {
		e.Linkname = v
	}
	if v, ok := pax["size"]; ok {
		n, _ := strconv.ParseInt(v, 10, 64) // checked in parsePAX
		// A reader that ignored the PAX size would read the data as headers
		// (CVE-2025-62518). The writers Socair knows set the header's own
		// field to the size, or to zero when it does not fit.
		if h.size != n && !(h.size == 0 && n > maxUSTARSize) {
			return nil, refuse(start, "a PAX size of %d over a header size field of %d: a reader that ignores PAX records would read the data as headers", n, h.size)
		}
		e.Size = n
	}
	if e.Kind != Regular && e.Size != 0 {
		return nil, refuse(start, "a %s whose header claims %d bytes of data", e.Kind, e.Size)
	}
	// Names and targets are bounded where they are read: a ustar name and
	// prefix hold 256 bytes, a GNU long name and a PAX path MaxName.
	if e.Name == "" {
		return nil, refuse(start, "an entry with no name")
	}
	if (e.Kind == Symlink || e.Kind == Hardlink) && e.Linkname == "" {
		return nil, refuse(start, "a %s with no target (%s)", e.Kind, e.Name)
	}
	if e.Kind == Regular {
		tr.remain, tr.pad = e.Size, padding(e.Size)
	}
	return e, nil
}

type header struct {
	typeflag byte
	name     string
	linkname string
	size     int64
}

// Field offsets of a tar header block.
var numericFields = []struct {
	name     string
	from, to int
}{
	{"mode", 100, 108}, {"uid", 108, 116}, {"gid", 116, 124}, {"size", 124, 136},
	{"mtime", 136, 148}, {"devmajor", 329, 337}, {"devminor", 337, 345},
}

func parseHeader(b *[blockSize]byte, off int64) (*header, error) {
	chk, ok := parseOctal(b[148:156])
	if !ok {
		return nil, refuse(off, "a header whose checksum field is not an octal number")
	}
	var unsigned, signed int64
	for i, c := range b {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	if chk != unsigned && chk != signed {
		return nil, refuse(off, "a header whose checksum does not match: not a tar header")
	}
	var prefix string
	magic, version := string(b[257:263]), string(b[263:265])
	switch {
	case magic == "ustar\x00" && version == "00":
		if string(b[508:512]) == "tar\x00" {
			return nil, refuse(off, "a star header: Go's archive/tar reads a 131-byte name prefix, Python's tarfile a 155-byte one")
		}
		prefix = cstring(b[345:500])
	case magic == "ustar " && version == " \x00":
		if !isZero(b[345:500]) {
			return nil, refuse(off, "a GNU header with bytes where a POSIX header keeps its name prefix: Python's tarfile prepends them to the name, Go's archive/tar does not")
		}
	default:
		return nil, refuse(off, "neither a POSIX (ustar) nor a GNU tar header (magic %q)", magic)
	}
	h := &header{typeflag: b[156], name: cstring(b[0:100]), linkname: cstring(b[157:257])}
	for _, f := range numericFields {
		n, ok := parseNumber(b[f.from:f.to])
		if !ok {
			return nil, refuse(off, "a header whose %s field is not a number Go's archive/tar and Python's tarfile read alike", f.name)
		}
		if f.name == "size" {
			h.size = n
		}
	}
	if prefix != "" {
		h.name = prefix + "/" + h.name
	}
	return h, nil
}

// cstring is b up to its first NUL, as both readers take a string field.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// parseOctal reads an octal field the way Go's archive/tar and Python's
// tarfile read it alike: optional leading spaces, octal digits, then only
// spaces and NULs. Go trims NULs from both ends and Python cuts at the first
// NUL, so a NUL before a digit (or a digit after a terminator) is read
// differently, and refused.
func parseOctal(b []byte) (int64, bool) {
	i := 0
	for i < len(b) && b[i] == ' ' {
		i++
	}
	j := i
	for j < len(b) && b[j] >= '0' && b[j] <= '7' {
		j++
	}
	for _, c := range b[j:] {
		if c != ' ' && c != 0 {
			return 0, false
		}
	}
	if j == i {
		return 0, true
	}
	n, err := strconv.ParseInt(string(b[i:j]), 8, 64)
	return n, err == nil
}

// parseNumber reads a numeric field: octal, or base-256 marked by a first
// byte of exactly 0x80, which both readers read as a non-negative number.
// Negative base-256 numbers, and other first bytes with the high bit set
// (Go reads base-256, Python refuses), are not octal either, so they are
// refused.
func parseNumber(b []byte) (int64, bool) {
	if b[0] == 0x80 {
		var x uint64
		for _, c := range b[1:] {
			if x>>55 != 0 {
				return 0, false
			}
			x = x<<8 | uint64(c)
		}
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	}
	return parseOctal(b)
}

// parsePAX reads a PAX header's records strictly: each "<length> <key>=<value>\n"
// to the end of the data, no key twice, and only values every reader reads
// alike. A NUL may appear only inside a value other than a name's (an
// extended attribute such as security.capability is binary), as Go's
// archive/tar allows; where a record should start, Python's tarfile stops
// reading at a NUL and Go's archive/tar refuses the archive, so the framing
// check refuses it.
func parsePAX(data []byte, off int64) (map[string]string, error) {
	recs := map[string]string{}
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp <= 0 || sp > 20 || data[0] == '0' || !allDigits(data[:sp]) {
			return nil, refuse(off, "a PAX record that does not start with its length")
		}
		n, err := strconv.Atoi(string(data[:sp]))
		if err != nil || n < sp+4 || n > len(data) || data[n-1] != '\n' {
			return nil, refuse(off, "a PAX record whose length does not frame it")
		}
		k, v, ok := strings.Cut(string(data[sp+1:n-1]), "=")
		if !ok || k == "" {
			return nil, refuse(off, "a PAX record with no key")
		}
		if strings.IndexByte(k, 0) >= 0 {
			return nil, refuse(off, "a PAX key holding a NUL byte")
		}
		if _, dup := recs[k]; dup {
			return nil, refuse(off, "a PAX header that sets %s twice", k)
		}
		if why := checkPAX(k, v); why != "" {
			return nil, refuse(off, "a PAX record %s: %s", k, why)
		}
		recs[k] = v
		data = data[n:]
	}
	return recs, nil
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(b) > 0
}

// checkPAX returns why a record is refused, or "".
func checkPAX(k, v string) string {
	switch k {
	case "path", "linkpath", "uname", "gname":
		if strings.IndexByte(v, 0) >= 0 {
			return "holds a NUL byte: Go's archive/tar refuses it, Python's tarfile keeps it in the name"
		}
	}
	switch {
	case k == "path" || k == "linkpath":
		if v == "" {
			return "is empty: Go's archive/tar keeps the header's own name, Python's tarfile uses the empty one"
		}
		if len(v) > MaxName {
			return fmt.Sprintf("is %d bytes, over %d", len(v), MaxName)
		}
	case k == "size" || k == "uid" || k == "gid":
		if len(v) > 19 || !allDigits([]byte(v)) {
			return "is not a decimal number: Python's tarfile reads an unreadable one as 0, Go's archive/tar refuses it"
		}
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return "is out of range"
		}
	case k == "mtime" || k == "atime" || k == "ctime":
		if !isPAXTime(v) {
			return "is not a decimal time"
		}
	case k == "hdrcharset":
		return "Python's tarfile decodes names by it, Go's archive/tar does not"
	case strings.HasPrefix(k, "GNU."):
		return "a GNU extension (sparse files among them), which tar readers do not support alike"
	case strings.HasPrefix(k, "SCHILY.xattr.trusted.overlay.") || strings.HasPrefix(k, "SCHILY.xattr.user.overlay."):
		return "an overlayfs attribute: containerd sets extended attributes from the archive, and overlayfs reads this one as a whiteout, an opaque directory, or a redirect"
	}
	return ""
}

// isPAXTime reports whether v is "[-]seconds[.fraction]" in decimal digits,
// a time Go's archive/tar and Python's tarfile both read.
func isPAXTime(v string) bool {
	secs, frac, dot := strings.Cut(v, ".")
	if !allDigits([]byte(strings.TrimPrefix(secs, "-"))) {
		return false
	}
	if _, err := strconv.ParseInt(secs, 10, 64); err != nil {
		return false
	}
	return !dot || len(frac) <= 19 && allDigits([]byte(frac))
}
