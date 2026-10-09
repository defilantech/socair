package pickle

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks"
)

// Grammar names the pickle grammar a PASS attests to.
//
// socair-wo/1 ("weights only") is the subset of the pickle language that
// torch.save writes for tensors and plain containers, at protocol 2 (as
// torch.save writes it) or 3, in the encoding CPython's pickler emits. The
// validator models the stream with typed values instead of an import list:
//
//   - only the opcodes torch's weights-only unpickler accepts, plus protocol
//     3's bytes opcodes, each in its canonical (shortest) form, with memo slots
//     written once and in order. A stream that claims protocol 2 or 3 and
//     departs from that is a parse-differential shape: a LEAD. A stream in
//     another protocol is outside the grammar: NOT_TESTED.
//   - every call (REDUCE, NEWOBJ) goes to a callable with a signature, and its
//     arguments must match it: a tensor rebuild needs a storage reference, a
//     view that fits inside that storage, and empty backward hooks; an
//     OrderedDict takes nothing or pairs, never a string; _codecs.encode takes
//     latin1 only. A call or BUILD the grammar does not model fails closed.
//   - a persistent id must be a storage reference, which the container check
//     then matches to a record of exactly numel x itemsize bytes.
//
// Conformance means the stream builds only tensors and plain containers under
// CPython's reading of it. It does not cover a bug in a loader, a reader that
// parses the same bytes differently from CPython, code carried as data in a
// string for some later stage to run, or a tampered Python environment.
const Grammar = "socair-wo/1"

// strictGrammar turns the grammar on. Off, the check is the import allowlist
// it replaced, which accepted a safe-listed callable with any arguments; the
// falsification tests switch it off to show each abuse they cover is caught
// by the grammar and missed without it.
var strictGrammar = true

// Budgets that bound the model, so a hostile stream cannot drive memory.
const (
	maxValues    = 1 << 21  // abstract values per pickle
	maxHeldBytes = 64 << 20 // string and bytes content held per pickle
	maxViolation = 20       // violations reported per pickle
)

type kind uint8

const (
	kNone kind = iota
	kBool
	kInt
	kFloat
	kStr
	kBytes
	kTuple
	kList
	kDict
	kGlobal  // a resolved global the grammar knows
	kStorage // a persistent storage reference
	kTensor
	kObj     // a constructed object: set, bytearray, numpy array, a reviewed class...
	kUnknown // the result of something already reported
)

// value is one abstract value on the modelled stack. Containers are pointers,
// so a list reached through the memo is the same list, as in CPython.
type value struct {
	kind  kind
	class string   // kDict, kObj: what was built; kGlobal: module.name
	num   int64    // kInt (when big is nil), kBool; kStr and kBytes: length in bytes
	f     float64  // kFloat; kObj complex: the real part
	s     string   // kStr, kBytes: the content, or its first maxStr bytes
	items []*value // kTuple, kList, set and frozenset; kDict: keys and values alternating
	x     *extra
}

type extra struct {
	big     *big.Int
	long    bool // s holds only the start
	digest  [32]byte
	runes   int64 // kStr: code points
	maxRune rune
	keys    map[string]bool // kDict and sets: the keys already present
	attrs   *value          // kDict OrderedDict: a BUILD state
	frozen  bool            // a call consumed it; it may not change after
	built   bool            // kObj: BUILD ran
	imag    float64         // kObj complex
	st      *storageRef
	t       *tensorInfo
	np      *npInfo
	sym     *symCall
}

// symCall is how a value was made, for the differential reading: the callable,
// its arguments, and the state BUILD gave it.
type symCall struct {
	fn    string
	isNew bool
	args  *value
	state *value
	ctor  int // items the call itself made; SETITEMS adds the rest
}

type storageRef struct {
	key      string
	stype    string // the storage class, e.g. torch.FloatStorage
	dtype    string
	itemsize int64
	numel    int64 // in elements of dtype
	opaque   bool  // a legacy tar key: no size known
	view     *storageView
}

type storageView struct {
	key          string
	offset, size int64
}

type tensorInfo struct {
	dtype  string
	shape  []int64
	key    string // the storage record, "" for a tensor without storage
	param  bool
	offset int64
}

type npInfo struct {
	itemsize int64
	object   bool
	code     string
	dtype    *value // an array or scalar's dtype
	shape    []int64
}

func (v *value) ext() *extra {
	if v.x == nil {
		v.x = &extra{}
	}
	return v.x
}

func (v *value) frozen() bool { return v.x != nil && v.x.frozen }

// pidMode is which persistent ids a stream may carry.
type pidMode int

const (
	pidNone   pidMode = iota // a plain pickle: CPython has no persistent_load
	pidZip                   // a torch zip: ("storage", type, key, location, numel)
	pidLegacy                // a legacy torch stream: the same, plus view metadata
	pidTar                   // a legacy torch tar: an opaque key
)

type grammarOpts struct {
	pids     pidMode
	reviewed map[string]bool
}

// violation is one departure from the grammar, with the status it earns.
type violation struct {
	status  checks.Status
	pattern string
	span    string
	detail  string
}

// validation is what validating one pickle found.
type validation struct {
	protocol   int
	gaps       []string // why the stream is outside the grammar: NOT_TESTED
	broken     string   // where CPython stops with an error
	violations []violation
	dropped    int
	root       *value
	end        int64 // bytes read through STOP
	storages   map[string]*storageRef
	order      []string // storage keys in first-reference order
	tensors    []*tensorInfo
	reviewed   map[string]bool // reviewed classes the stream built
}

func (g *validation) conforms() bool {
	return len(g.gaps) == 0 && g.broken == "" && len(g.violations) == 0
}

func (g *validation) worst() checks.Status {
	s := checks.Pass
	for _, v := range g.violations {
		if v.status == checks.Fail {
			return checks.Fail
		}
		s = checks.Lead
	}
	return s
}

func (g *validation) gap(reason string) {
	for _, r := range g.gaps {
		if r == reason {
			return
		}
	}
	g.gaps = append(g.gaps, reason)
}

// errStop ends a validation: the stream broke, or it left the grammar at a
// point the model cannot follow past.
var errStop = errors.New("validation stopped")

type validator struct {
	r      *bufio.Reader
	off    int64
	at     int64 // offset of the opcode being modelled
	proto  int
	stack  []*value
	marks  []int
	memo   map[uint64]*value
	puts   uint64
	values int
	held   int64
	buf    []byte
	opts   grammarOpts
	out    *validation
}

// validate models one pickle, from its first byte to STOP, against the
// grammar. It reads nothing past STOP.
func validate(r io.Reader, opts grammarOpts) *validation {
	v := &validator{r: bufio.NewReaderSize(r, 1<<16), memo: map[uint64]*value{}, opts: opts,
		out: &validation{storages: map[string]*storageRef{}}}
	v.run()
	return v.out
}

func (v *validator) run() {
	code, err := v.r.ReadByte()
	if err != nil {
		v.out.broken = "empty stream"
		return
	}
	v.off++
	if code != 0x80 {
		v.out.gap("protocol 0 or 1 (the stream does not start with PROTO); " + Grammar + " covers protocols 2 and 3, which torch.save writes")
		return
	}
	p, err := v.r.ReadByte()
	if err != nil {
		v.out.broken = "truncated in PROTO"
		return
	}
	v.off++
	v.proto, v.out.protocol = int(p), int(p)
	switch {
	case p > 5:
		v.out.broken = fmt.Sprintf("protocol %d, which CPython does not read", p)
		return
	case p != 2 && p != 3:
		v.out.gap(fmt.Sprintf("protocol %d; %s covers protocols 2 and 3, which torch.save writes", p, Grammar))
		return
	}
	for {
		stop, err := v.step()
		if err != nil || stop {
			return
		}
	}
}

// broke records where CPython would raise and stops.
func (v *validator) broke(format string, a ...any) error {
	v.out.broken = fmt.Sprintf("offset %d: ", v.at) + fmt.Sprintf(format, a...)
	return errStop
}

func (v *validator) violate(status checks.Status, pattern, span, detail string) {
	if len(v.out.violations) >= maxViolation {
		v.out.dropped++
		return
	}
	v.out.violations = append(v.out.violations, violation{status: status, pattern: pattern,
		span: fmt.Sprintf("%s at offset %d", span, v.at), detail: detail})
}

// noncanonical records a form CPython's pickler never writes. In a stream
// that claims protocol 2 or 3 it is a parse-differential shape.
func (v *validator) noncanonical(span, detail string) {
	v.violate(checks.Lead, "pickle-noncanonical", span, detail+"; CPython's pickler never writes this, and readers can disagree on it")
}

func (v *validator) alloc(k kind) (*value, error) {
	v.values++
	if v.values > maxValues {
		v.out.gap(fmt.Sprintf("more than %d values; the model's budget ends here", maxValues))
		return nil, errStop
	}
	return &value{kind: k}, nil
}

func (v *validator) push(x *value) error {
	if len(v.stack) >= maxStack {
		v.out.gap(fmt.Sprintf("stack deeper than %d", maxStack))
		return errStop
	}
	v.stack = append(v.stack, x)
	return nil
}

func (v *validator) newPush(k kind) (*value, error) {
	x, err := v.alloc(k)
	if err != nil {
		return nil, err
	}
	return x, v.push(x)
}

func (v *validator) fence() int {
	if len(v.marks) == 0 {
		return 0
	}
	return v.marks[len(v.marks)-1]
}

func (v *validator) pop() (*value, error) {
	if len(v.stack) <= v.fence() {
		return nil, v.broke("stack underflow")
	}
	x := v.stack[len(v.stack)-1]
	v.stack = v.stack[:len(v.stack)-1]
	return x, nil
}

func (v *validator) top() (*value, error) {
	if len(v.stack) <= v.fence() {
		return nil, v.broke("stack underflow")
	}
	return v.stack[len(v.stack)-1], nil
}

func (v *validator) popMark() ([]*value, error) {
	if len(v.marks) == 0 {
		return nil, v.broke("no MARK on the stack")
	}
	m := v.marks[len(v.marks)-1]
	v.marks = v.marks[:len(v.marks)-1]
	items := append([]*value(nil), v.stack[m:]...)
	v.stack = v.stack[:m]
	return items, nil
}

// scratch is a reusable buffer for reading long payloads in chunks.
func (v *validator) scratch() []byte {
	if v.buf == nil {
		v.buf = make([]byte, 1<<16)
	}
	return v.buf
}

func (v *validator) read(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(v.r, b); err != nil {
		return nil, v.broke("truncated")
	}
	v.off += int64(n)
	return b, nil
}

func (v *validator) readLine() (string, error) {
	var out []byte
	for {
		b, err := v.r.ReadByte()
		if err != nil {
			return "", v.broke("truncated in a line")
		}
		v.off++
		if b == '\n' {
			return string(out), nil
		}
		if len(out) >= maxLine {
			v.out.gap(fmt.Sprintf("line longer than %d bytes", maxLine))
			return "", errStop
		}
		out = append(out, b)
	}
}

// step models one opcode. It reports whether the pickle ended.
func (v *validator) step() (bool, error) {
	v.at = v.off
	code, err := v.r.ReadByte()
	if err != nil {
		return true, v.broke("truncated before STOP")
	}
	v.off++
	switch code {
	case '.': // STOP
		return true, v.stop()
	case '(': // MARK
		v.marks = append(v.marks, len(v.stack))
	case ')': // EMPTY_TUPLE
		_, err = v.newPush(kTuple)
	case 't': // TUPLE
		var items []*value
		if items, err = v.popMark(); err == nil {
			if len(items) >= 1 && len(items) <= 3 {
				v.noncanonical("TUPLE", fmt.Sprintf("a %d-tuple built with MARK and TUPLE instead of TUPLE%d", len(items), len(items)))
			}
			if len(items) == 0 {
				v.noncanonical("TUPLE", "an empty tuple built with MARK and TUPLE instead of EMPTY_TUPLE")
			}
			err = v.pushTuple(items)
		}
	case 0x85, 0x86, 0x87: // TUPLE1, TUPLE2, TUPLE3
		n := int(code-0x85) + 1
		if len(v.stack)-v.fence() < n {
			return true, v.broke("stack underflow")
		}
		items := append([]*value(nil), v.stack[len(v.stack)-n:]...)
		v.stack = v.stack[:len(v.stack)-n]
		err = v.pushTuple(items)
	case ']': // EMPTY_LIST
		_, err = v.newPush(kList)
	case 'a': // APPEND
		var x *value
		if x, err = v.pop(); err == nil {
			err = v.appendTo([]*value{x})
		}
	case 'e': // APPENDS
		var items []*value
		if items, err = v.popMark(); err == nil {
			err = v.appendTo(items)
		}
	case '}': // EMPTY_DICT
		var d *value
		if d, err = v.newPush(kDict); err == nil {
			d.class = "dict"
		}
	case 's': // SETITEM
		var val, key *value
		if val, err = v.pop(); err == nil {
			if key, err = v.pop(); err == nil {
				err = v.setItems([]*value{key, val})
			}
		}
	case 'u': // SETITEMS
		var items []*value
		if items, err = v.popMark(); err == nil {
			if len(items)%2 != 0 {
				return true, v.broke("odd number of items for SETITEMS")
			}
			err = v.setItems(items)
		}
	case 'N': // NONE
		_, err = v.newPush(kNone)
	case 0x88, 0x89: // NEWTRUE, NEWFALSE
		var b *value
		if b, err = v.newPush(kBool); err == nil && code == 0x88 {
			b.num = 1
		}
	case 'K', 'M', 'J': // BININT1, BININT2, BININT
		err = v.binint(code)
	case 0x8a, 0x8b: // LONG1, LONG4
		err = v.long(code)
	case 'G': // BINFLOAT
		var b []byte
		if b, err = v.read(8); err == nil {
			var x *value
			if x, err = v.newPush(kFloat); err == nil {
				x.f = math.Float64frombits(binary.BigEndian.Uint64(b))
			}
		}
	case 'X': // BINUNICODE
		var b []byte
		if b, err = v.read(4); err == nil {
			err = v.text(uint64(binary.LittleEndian.Uint32(b)))
		}
	case 'U', 'T': // SHORT_BINSTRING, BINSTRING: a Python 2 str
		err = v.py2string(code)
	case 'C', 'B': // SHORT_BINBYTES, BINBYTES
		err = v.binbytes(code)
	case 'c': // GLOBAL
		err = v.global()
	case 'R': // REDUCE
		err = v.reduce()
	case 0x81: // NEWOBJ
		err = v.newobj()
	case 'b': // BUILD
		err = v.build()
	case 'Q': // BINPERSID
		err = v.persid()
	case 'q', 'r': // BINPUT, LONG_BINPUT
		err = v.put(code)
	case 'h', 'j': // BINGET, LONG_BINGET
		err = v.get(code)
	case 0x80: // PROTO after the first opcode
		var b []byte
		if b, err = v.read(1); err == nil {
			v.noncanonical("PROTO", fmt.Sprintf("a second PROTO (%d) inside the stream", b[0]))
			return true, errStop
		}
	default:
		op, known := opcodes[code]
		if !known {
			return true, v.broke("invalid opcode 0x%02x", code)
		}
		// Every other opcode is outside the grammar. In a stream that claims
		// protocol 2 or 3 a writer never emits them (text opcodes, protocol 4
		// framing, OBJ, INST, EXT, NEWOBJ_EX, POP, DUP), and the model stops
		// rather than guess at what follows.
		v.noncanonical(op.name, op.name+" is outside "+Grammar)
		return true, errStop
	}
	return false, err
}

func (v *validator) stop() error {
	if len(v.marks) > 0 || len(v.stack) != 1 {
		v.noncanonical("STOP", fmt.Sprintf("%d value(s) and %d MARK(s) on the stack at STOP, where a writer leaves exactly one value", len(v.stack), len(v.marks)))
	}
	root, err := v.pop()
	if err != nil {
		return err
	}
	v.out.root = root
	v.out.end = v.off
	return nil
}

func (v *validator) pushTuple(items []*value) error {
	t, err := v.alloc(kTuple)
	if err != nil {
		return err
	}
	t.items = items
	return v.push(t)
}

func (v *validator) binint(code byte) error {
	var n int64
	switch code {
	case 'K':
		b, err := v.read(1)
		if err != nil {
			return err
		}
		n = int64(b[0])
	case 'M':
		b, err := v.read(2)
		if err != nil {
			return err
		}
		n = int64(binary.LittleEndian.Uint16(b))
		if n <= 0xff {
			v.noncanonical("BININT2", fmt.Sprintf("%d written as BININT2, where BININT1 holds it", n))
		}
	case 'J':
		b, err := v.read(4)
		if err != nil {
			return err
		}
		n = int64(int32(binary.LittleEndian.Uint32(b)))
		if n >= 0 && n <= 0xffff {
			v.noncanonical("BININT", fmt.Sprintf("%d written as BININT, where a shorter form holds it", n))
		}
	}
	x, err := v.newPush(kInt)
	if err == nil {
		x.num = n
	}
	return err
}

// long reads LONG1 or LONG4: a little-endian two's-complement integer.
func (v *validator) long(code byte) error {
	var n int64
	if code == 0x8a {
		b, err := v.read(1)
		if err != nil {
			return err
		}
		n = int64(b[0])
	} else {
		b, err := v.read(4)
		if err != nil {
			return err
		}
		n = int64(int32(binary.LittleEndian.Uint32(b)))
		if n < 0 {
			return v.broke("LONG4 with a negative byte count")
		}
		if n < 256 {
			v.noncanonical("LONG4", fmt.Sprintf("a %d-byte integer written as LONG4, where LONG1 holds it", n))
		}
		if n > 1<<16 {
			v.out.gap("an integer longer than 65536 bytes")
			return errStop
		}
	}
	b, err := v.read(int(n))
	if err != nil {
		return err
	}
	// A minimal encoding has no redundant sign byte, and zero is not a LONG.
	switch {
	case len(b) == 0:
		v.noncanonical("LONG1", "zero written as an empty LONG1")
	case len(b) > 1 && ((b[len(b)-1] == 0 && b[len(b)-2]&0x80 == 0) || (b[len(b)-1] == 0xff && b[len(b)-2]&0x80 != 0)):
		v.noncanonical("LONG1", "an integer with a redundant sign byte")
	}
	x, err := v.newPush(kInt)
	if err != nil {
		return err
	}
	z := new(big.Int)
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	z.SetBytes(be)
	if len(b) > 0 && b[len(b)-1]&0x80 != 0 {
		z.Sub(z, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	if z.IsInt64() {
		x.num = z.Int64()
	} else {
		x.ext().big = z
	}
	return nil
}

// text reads a BINUNICODE payload: UTF-8, with surrogates allowed, as
// CPython decodes it ("surrogatepass").
func (v *validator) text(n uint64) error {
	x, err := v.alloc(kStr)
	if err != nil {
		return err
	}
	x.num = int64(n)
	var runes int64
	var maxRune rune
	var carry []byte
	h := sha256.New()
	held := make([]byte, 0, min(n, maxStr))
	buf := v.scratch()
	for left := n; left > 0 || len(carry) > 0; {
		k := 0
		if left > 0 {
			want := min(left, uint64(len(buf)))
			if _, err := io.ReadFull(v.r, buf[:want]); err != nil {
				return v.broke("truncated in BINUNICODE")
			}
			v.off += int64(want)
			left -= want
			k = int(want)
			if n > maxStr {
				h.Write(buf[:k])
			}
			if room := maxStr - len(held); room > 0 {
				held = append(held, buf[:min(k, room)]...)
			}
		}
		chunk := append(carry, buf[:k]...)
		carry = nil
		for i := 0; i < len(chunk); {
			if left > 0 && !fullRunePass(chunk[i:]) {
				carry = append([]byte(nil), chunk[i:]...)
				break
			}
			r, size := decodeRunePass(chunk[i:])
			if size == 0 {
				return v.broke("BINUNICODE is not valid UTF-8")
			}
			runes++
			maxRune = max(maxRune, r)
			i += size
		}
	}
	v.held += int64(len(held))
	if v.held > maxHeldBytes {
		v.out.gap(fmt.Sprintf("more than %d bytes of strings", maxHeldBytes))
		return errStop
	}
	x.s = string(held)
	e := x.ext()
	e.runes, e.maxRune = runes, maxRune
	if n > maxStr {
		e.long = true
		copy(e.digest[:], h.Sum(nil))
	}
	return v.push(x)
}

// decodeRunePass decodes one UTF-8 sequence, accepting the three-byte
// encodings of surrogates as CPython's "surrogatepass" does. A size of 0 is
// an invalid sequence.
func decodeRunePass(b []byte) (rune, int) {
	if len(b) >= 3 && b[0] == 0xed && b[1] >= 0xa0 && b[1] <= 0xbf && b[2] >= 0x80 && b[2] <= 0xbf {
		return rune(0xd000 | rune(b[1]&0x3f)<<6 | rune(b[2]&0x3f)), 3
	}
	r, size := utf8.DecodeRune(b)
	if r == utf8.RuneError && size <= 1 {
		return 0, 0
	}
	return r, size
}

func fullRunePass(b []byte) bool {
	if len(b) > 0 && b[0] == 0xed && len(b) < 3 {
		return false
	}
	return utf8.FullRune(b)
}

// py2string reads SHORT_BINSTRING or BINSTRING, a Python 2 str. Python 2
// wrote them at protocol 2; how Python 3 decodes one depends on the loader's
// encoding argument, so only ASCII reads the same everywhere.
func (v *validator) py2string(code byte) error {
	var n int64
	if code == 'U' {
		b, err := v.read(1)
		if err != nil {
			return err
		}
		n = int64(b[0])
	} else {
		b, err := v.read(4)
		if err != nil {
			return err
		}
		n = int64(int32(binary.LittleEndian.Uint32(b)))
		if n < 0 {
			return v.broke("BINSTRING with a negative byte count")
		}
		if n < 256 {
			v.noncanonical("BINSTRING", "a short string written as BINSTRING")
		}
	}
	if v.proto != 2 {
		v.noncanonical(opcodes[code].name, "a Python 2 string in a protocol 3 stream")
	}
	if n > maxStr {
		v.out.gap("a Python 2 string longer than " + fmt.Sprint(maxStr) + " bytes")
		return errStop
	}
	b, err := v.read(int(n))
	if err != nil {
		return err
	}
	for _, c := range b {
		if c >= 0x80 {
			v.noncanonical(opcodes[code].name, "a non-ASCII Python 2 string, which loaders decode differently")
			break
		}
	}
	x, err := v.alloc(kStr)
	if err != nil {
		return err
	}
	x.s, x.num = string(b), n
	x.ext().runes = n
	return v.push(x)
}

func (v *validator) binbytes(code byte) error {
	var n uint64
	if code == 'C' {
		b, err := v.read(1)
		if err != nil {
			return err
		}
		n = uint64(b[0])
	} else {
		b, err := v.read(4)
		if err != nil {
			return err
		}
		n = uint64(binary.LittleEndian.Uint32(b))
		if n < 256 {
			v.noncanonical("BINBYTES", "short bytes written as BINBYTES")
		}
	}
	if v.proto < 3 {
		v.noncanonical(opcodes[code].name, "a protocol 3 bytes opcode in a protocol 2 stream")
	}
	x, err := v.alloc(kBytes)
	if err != nil {
		return err
	}
	x.num = int64(n)
	h := sha256.New()
	held := make([]byte, 0, min(n, maxStr))
	buf := v.scratch()
	for left := n; left > 0; {
		want := min(left, uint64(len(buf)))
		if _, err := io.ReadFull(v.r, buf[:want]); err != nil {
			return v.broke("truncated in BINBYTES")
		}
		v.off += int64(want)
		left -= want
		h.Write(buf[:want])
		if room := maxStr - len(held); room > 0 {
			held = append(held, buf[:min(int(want), room)]...)
		}
	}
	v.held += int64(len(held))
	if v.held > maxHeldBytes {
		v.out.gap(fmt.Sprintf("more than %d bytes of strings", maxHeldBytes))
		return errStop
	}
	x.s = string(held)
	if n > maxStr {
		x.ext().long = true
		copy(x.ext().digest[:], h.Sum(nil))
	}
	return v.push(x)
}

// dottedName and plainName are what a canonical GLOBAL line holds. Below
// protocol 4 CPython looks the name up as one attribute, so it has no dot.
var (
	dottedName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	plainName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func (v *validator) global() error {
	mod, err := v.readLine()
	if err != nil {
		return err
	}
	name, err := v.readLine()
	if err != nil {
		return err
	}
	if !utf8.ValidString(mod) || !utf8.ValidString(name) {
		return v.broke("GLOBAL is not valid UTF-8")
	}
	x, err := v.alloc(kUnknown)
	if err != nil {
		return err
	}
	if !dottedName.MatchString(mod) || !plainName.MatchString(name) {
		v.noncanonical("GLOBAL", fmt.Sprintf("%q is not a module and attribute a writer emits", excerpt(mod+"."+name)))
		return v.push(x)
	}
	rmod, rname := mod, name
	if v.proto < 3 {
		rmod, rname = pyResolve(mod, name)
	} else if pm, pn := pyResolve(mod, name); pm != mod || pn != name {
		// CPython renames Python 2 names only below protocol 3, and PyTorch's
		// weights-only unpickler at every protocol: the two import different
		// things.
		v.noncanonical("GLOBAL", fmt.Sprintf("the Python 2 name %s.%s in a protocol %d stream, which CPython does not rename and weights-only loading does", mod, name, v.proto))
	}
	full := rmod + "." + rname
	known := isModeled(full) || v.opts.reviewed[full]
	if known && spelling(rmod, rname, v.proto) != mod+"."+name {
		v.noncanonical("GLOBAL", fmt.Sprintf("%s spelled %s.%s, where a protocol %d writer spells it %s", full, mod, name, v.proto, spelling(rmod, rname, v.proto)))
	}
	if known {
		x.kind, x.class = kGlobal, full
	}
	// Any other global is judged by the import scan (dangerous, unmodeled,
	// or unreviewed); here it stays unknown, so what it builds is unknown
	// too and is not reported twice.
	if !known && isHarmless(full) {
		x.class = full
	}
	return v.push(x)
}

func (v *validator) put(code byte) error {
	var idx uint64
	if code == 'q' {
		b, err := v.read(1)
		if err != nil {
			return err
		}
		idx = uint64(b[0])
	} else {
		b, err := v.read(4)
		if err != nil {
			return err
		}
		idx = uint64(binary.LittleEndian.Uint32(b))
		if idx < 256 {
			v.noncanonical("LONG_BINPUT", fmt.Sprintf("memo slot %d written with LONG_BINPUT, where BINPUT holds it", idx))
		}
	}
	x, err := v.top()
	if err != nil {
		return err
	}
	if _, seen := v.memo[idx]; seen {
		v.noncanonical("BINPUT", fmt.Sprintf("memo slot %d written twice: a reader that keeps the first value and CPython, which keeps the last, see different objects", idx))
	} else if idx != v.puts {
		v.noncanonical("BINPUT", fmt.Sprintf("memo slot %d written where a writer writes slot %d", idx, v.puts))
	}
	if len(v.memo) >= maxMemo {
		v.out.gap(fmt.Sprintf("memo larger than %d", maxMemo))
		return errStop
	}
	v.memo[idx] = x
	v.puts++
	return nil
}

func (v *validator) get(code byte) error {
	var idx uint64
	if code == 'h' {
		b, err := v.read(1)
		if err != nil {
			return err
		}
		idx = uint64(b[0])
	} else {
		b, err := v.read(4)
		if err != nil {
			return err
		}
		idx = uint64(binary.LittleEndian.Uint32(b))
		if idx < 256 {
			v.noncanonical("LONG_BINGET", fmt.Sprintf("memo slot %d read with LONG_BINGET, where BINGET holds it", idx))
		}
	}
	x, ok := v.memo[idx]
	if !ok {
		return v.broke("memo slot %d was never written", idx)
	}
	return v.push(x)
}

// appendTo models APPEND and APPENDS: the target must be a list. CPython
// calls extend or append on anything else, which runs that object's code.
func (v *validator) appendTo(items []*value) error {
	l, err := v.top()
	if err != nil {
		return err
	}
	switch {
	case l.kind == kUnknown:
	case l.kind != kList:
		v.violate(checks.Lead, "pickle-grammar", "APPENDS", "items appended to "+describe(l)+", which is not a list; CPython calls that object's extend or append")
	case l.frozen():
		v.violate(checks.Lead, "pickle-grammar", "APPENDS", "a list changed after a call consumed it")
	default:
		l.items = append(l.items, items...)
	}
	return nil
}

// setItems models SETITEM and SETITEMS: the target must be a dict, and every
// key must be one CPython can hash.
func (v *validator) setItems(items []*value) error {
	d, err := v.top()
	if err != nil {
		return err
	}
	switch {
	case d.kind == kUnknown:
		return nil
	case d.kind != kDict:
		v.violate(checks.Lead, "pickle-grammar", "SETITEMS", "items set on "+describe(d)+", which is not a dict; CPython calls that object's __setitem__")
		return nil
	case d.frozen():
		v.violate(checks.Lead, "pickle-grammar", "SETITEMS", "a dict changed after a call consumed it")
		return nil
	}
	for i := 0; i < len(items); i += 2 {
		if err := v.addKey(d, items[i], "SETITEMS"); err != nil {
			return err
		}
		d.items = append(d.items, items[i], items[i+1])
	}
	return nil
}

// addKey records a dict key or set element, as CPython hashes it. A key
// CPython cannot hash stops the stream; two keys CPython holds equal (1,
// 1.0, and True are one key) are a form no writer emits.
func (v *validator) addKey(d *value, key *value, span string) error {
	id, how := keyID(key, newBudget())
	switch how {
	case keyUnhashable:
		return v.broke("unhashable %s used as a key", describe(key))
	case keyUnusual:
		v.violate(checks.Lead, "pickle-grammar", span, describe(key)+" used as a key")
		return nil
	}
	e := d.ext()
	if e.keys == nil {
		e.keys = map[string]bool{}
	}
	if e.keys[id] {
		v.noncanonical(span, "a key repeated in one container, where a writer writes each once")
	}
	e.keys[id] = true
	return nil
}

const (
	keyOK = iota
	keyUnhashable
	keyUnusual
)

// budget bounds one walk over a value. Shared structure built through the
// memo makes a small stream a large tree (60 levels of t = (t, t) is a few
// hundred bytes), so a walk counts what it visits and gives up past maxWalk.
type budget int

const maxWalk = 1 << 16

func newBudget() *budget {
	b := budget(maxWalk)
	return &b
}

func (b *budget) spend() bool {
	*b--
	return *b >= 0
}

// keyID is a string equal for two keys exactly when CPython holds them equal.
func keyID(k *value, b *budget) (string, int) {
	if !b.spend() {
		return "", keyUnusual
	}
	switch k.kind {
	case kNone:
		return "N", keyOK
	case kBool, kInt:
		if k.x != nil && k.x.big != nil {
			return "i" + k.x.big.String(), keyOK
		}
		return fmt.Sprint("i", k.num), keyOK
	case kFloat:
		return floatID(k.f)
	case kStr:
		return strID("s", k), keyOK
	case kBytes:
		return strID("b", k), keyOK
	case kTuple:
		id := "("
		for _, it := range k.items {
			s, how := keyID(it, b)
			if how != keyOK {
				return "", how
			}
			id += s + ","
		}
		return id + ")", keyOK
	case kGlobal:
		return "g" + k.class, keyOK
	case kUnknown:
		// Something already reported built it; it is no new finding.
		return fmt.Sprintf("?%p", k), keyOK
	case kList, kDict:
		return "", keyUnhashable
	case kObj:
		switch k.class {
		case "builtins.set", "builtins.bytearray":
			return "", keyUnhashable
		case "builtins.complex":
			if k.ext().imag == 0 {
				return floatID(k.f)
			}
			return fmt.Sprintf("c%x,%x", math.Float64bits(k.f), math.Float64bits(k.ext().imag)), keyOK
		}
	}
	return "", keyUnusual
}

func floatID(f float64) (string, int) {
	switch {
	case math.IsNaN(f):
		return "", keyUnusual // NaN keys compare by identity
	case math.IsInf(f, 0):
		return fmt.Sprint("f", f), keyOK
	case f == math.Trunc(f):
		z, _ := big.NewFloat(f).Int(nil)
		return "i" + z.String(), keyOK
	}
	return fmt.Sprintf("f%x", math.Float64bits(f)), keyOK
}

func strID(prefix string, k *value) string {
	if k.x != nil && k.x.long {
		return fmt.Sprintf("%s%d:%x", prefix, k.num, k.x.digest)
	}
	return fmt.Sprintf("%s%d:%s", prefix, len(k.s), k.s)
}

func (v *validator) reduce() error {
	args, err := v.pop()
	if err != nil {
		return err
	}
	fn, err := v.top()
	if err != nil {
		return err
	}
	if args.kind != kTuple && args.kind != kUnknown {
		return v.broke("REDUCE arguments are %s, not a tuple", describe(args))
	}
	res := v.call(fn, args, false)
	if res == nil {
		return errStop
	}
	v.stack[len(v.stack)-1] = res
	return nil
}

func (v *validator) newobj() error {
	args, err := v.pop()
	if err != nil {
		return err
	}
	cls, err := v.pop()
	if err != nil {
		return err
	}
	if args.kind != kTuple && args.kind != kUnknown {
		return v.broke("NEWOBJ arguments are %s, not a tuple", describe(args))
	}
	res := v.call(cls, args, true)
	if res == nil {
		return errStop
	}
	return v.push(res)
}

// call models a REDUCE (fn(*args)) or a NEWOBJ (cls.__new__(cls, *args)).
// It returns nil only when the model's budget ran out.
func (v *validator) call(fn, args *value, isNew bool) *value {
	unknown := func() *value {
		x, err := v.alloc(kUnknown)
		if err != nil {
			return nil
		}
		return x
	}
	switch {
	case fn.kind == kUnknown || args.kind == kUnknown:
		// The callable or its arguments came from something already reported
		// (an unmodeled global, a violation). A harmless callable outside the
		// grammar leaves a gap.
		if fn.kind == kUnknown && fn.class != "" {
			v.out.gap("calls " + fn.class + ", which " + Grammar + " does not model")
		}
		return unknown()
	case fn.kind != kGlobal:
		v.violate(checks.Lead, "pickle-grammar", "REDUCE", "a call of "+describe(fn)+", which is not an importable callable")
		return unknown()
	}
	if v.opts.reviewed[fn.class] {
		return v.reviewedNew(fn.class, args, isNew)
	}
	r, ok := reducers[fn.class]
	if !ok {
		v.argViolation(fn.class, args.items, "a call of "+fn.class+", which "+Grammar+" admits only as a value")
		return unknown()
	}
	if isNew && fn.class != "torch.nn.parameter.Parameter" {
		v.noncanonical("NEWOBJ", fn.class+".__new__ called directly, where a writer calls "+fn.class)
		return unknown()
	}
	for _, a := range args.items {
		freeze(a)
	}
	res := r(v, fn.class, args.items)
	if res == nil {
		return nil
	}
	if res.kind != kUnknown {
		res.ext().sym = &symCall{fn: fn.class, isNew: isNew, args: args, ctor: len(res.items)}
	}
	return res
}

// freeze marks the containers a call consumed. CPython's pickler writes an
// argument in full before the call, so a later change to one is a form no
// writer emits: hooks filled after the tensor was built, say.
// Each container is marked once, so shared structure costs its size.
func freeze(x *value) {
	todo := []*value{x}
	for len(todo) > 0 {
		y := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if y.frozen() {
			continue
		}
		switch y.kind {
		case kList, kDict, kTuple, kObj:
			y.ext().frozen = true
			todo = append(todo, y.items...)
		}
	}
}

func (v *validator) build() error {
	state, err := v.pop()
	if err != nil {
		return err
	}
	inst, err := v.top()
	if err != nil {
		return err
	}
	if inst.kind == kUnknown || state.kind == kUnknown {
		return nil
	}
	if inst.frozen() || (inst.x != nil && inst.x.built) {
		v.violate(checks.Lead, "pickle-grammar", "BUILD", "state given to "+describe(inst)+" after it was built or consumed")
		return nil
	}
	freeze(state)
	switch {
	case inst.kind == kDict && inst.class == "collections.OrderedDict":
		// weights-only and CPython both update the instance's __dict__: a
		// state dict's _metadata attribute rides here.
		if state.kind != kDict || state.class != "dict" || !strKeys(state) {
			v.violate(checks.Lead, "pickle-grammar", "BUILD", "an OrderedDict given "+describe(state)+" as attributes, where a writer gives a dict of names")
			return nil
		}
		inst.ext().attrs = state
	case inst.kind == kObj && inst.class == "numpy.ndarray":
		if err := v.buildNDArray(inst, state); err != nil {
			return err
		}
	case inst.kind == kObj && inst.class == "numpy.dtype":
		if err := v.buildNPDtype(inst, state); err != nil {
			return err
		}
	case inst.kind == kObj && v.opts.reviewed[inst.class]:
		if !reviewedState(state, v.opts.reviewed, newBudget()) {
			v.violate(checks.Lead, "pickle-reviewed-class-state", inst.class,
				"a reviewed class given "+describe(state)+" as state, where its review covers a dict of names to plain values")
			return nil
		}
	default:
		v.violate(checks.Lead, "pickle-grammar", "BUILD", "state given to "+describe(inst)+", which "+Grammar+" does not build; CPython calls its __setstate__")
		return nil
	}
	inst.ext().built = true
	if inst.x.sym != nil {
		inst.x.sym.state = state
	}
	return nil
}

// persid models BINPERSID: the loader's persistent_load turns the id into a
// storage. What a valid id is depends on the container.
func (v *validator) persid() error {
	pid, err := v.pop()
	if err != nil {
		return err
	}
	if v.opts.pids == pidNone {
		return v.broke("a persistent id, which CPython's pickle.load cannot resolve")
	}
	x, err := v.alloc(kStorage)
	if err != nil {
		return err
	}
	st := v.storageRef(pid)
	if st == nil {
		x.kind = kUnknown
		return v.push(x)
	}
	x.ext().st = st
	x.x.sym = &symCall{fn: "pid", args: pid}
	return v.push(x)
}

// describe names a value's type for a finding.
func describe(x *value) string {
	switch x.kind {
	case kNone:
		return "None"
	case kBool:
		return "a bool"
	case kInt:
		return "an int"
	case kFloat:
		return "a float"
	case kStr:
		return fmt.Sprintf("the string %q", excerpt(x.s))
	case kBytes:
		return fmt.Sprintf("%d bytes", x.num)
	case kTuple:
		return fmt.Sprintf("a %d-tuple", len(x.items))
	case kList:
		return "a list"
	case kDict:
		if x.class == "dict" {
			return "a dict"
		}
		return "a " + x.class
	case kGlobal:
		return x.class
	case kStorage:
		return "a storage"
	case kTensor:
		return "a tensor"
	case kObj:
		return "a " + x.class
	}
	return "an unknown value"
}

func strKeys(d *value) bool {
	for i := 0; i < len(d.items); i += 2 {
		if d.items[i].kind != kStr {
			return false
		}
	}
	return true
}
