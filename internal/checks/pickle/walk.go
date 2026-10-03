package pickle

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// argKind is how an opcode's inline argument is encoded, per CPython's
// pickletools.
type argKind int

const (
	argNone  argKind = iota
	argU1            // 1 byte
	argU2            // 2 bytes
	argI4            // 4 bytes
	argU4            // 4 bytes
	argU8            // 8 bytes
	argLine          // up to and including "\n"
	argLine2         // two "\n"-terminated lines (GLOBAL, INST)
	argLen1          // uint8 length, then bytes
	argLen4          // uint32 length, then bytes
	argLen8          // uint64 length, then bytes
)

// effect is an opcode's effect on the modelled stack.
type effect int

const (
	effNone        effect = iota
	effPushUnk            // push one non-string value
	effPushStr            // push the decoded argument as a string
	effMark               // push a mark
	effPop                // pop one
	effPopMark            // pop to and including the mark
	effDup                // duplicate the top
	effPop1Push           // pop 1, push 1
	effPop2Push           // pop 2, push 1
	effPop3Push           // pop 3, push 1
	effPop2               // pop 2
	effMarkPush           // pop to mark, push 1
	effPut                // memo[arg] = top
	effMemoize            // memo[len] = top
	effGet                // push memo[arg]
	effGlobal             // push a global named by the inline argument
	effStackGlobal        // pop name and module, push a global
	effInst               // inline global, pop to mark, push
	effExt                // extension-registry global
	effStop               // end of this pickle
)

type opcode struct {
	name string
	arg  argKind
	eff  effect
}

// opcodes covers protocols 0 to 5, from CPython Lib/pickletools.py.
var opcodes = map[byte]opcode{
	'(': {"MARK", argNone, effMark},
	'.': {"STOP", argNone, effStop},
	'0': {"POP", argNone, effPop},
	'1': {"POP_MARK", argNone, effPopMark},
	'2': {"DUP", argNone, effDup},
	'F': {"FLOAT", argLine, effPushUnk},
	'I': {"INT", argLine, effPushUnk},
	'J': {"BININT", argI4, effPushUnk},
	'K': {"BININT1", argU1, effPushUnk},
	'L': {"LONG", argLine, effPushUnk},
	'M': {"BININT2", argU2, effPushUnk},
	'N': {"NONE", argNone, effPushUnk},
	'P': {"PERSID", argLine, effPushUnk},
	'Q': {"BINPERSID", argNone, effPop1Push},
	'R': {"REDUCE", argNone, effPop2Push},
	'S': {"STRING", argLine, effPushStr},
	'T': {"BINSTRING", argLen4, effPushStr},
	'U': {"SHORT_BINSTRING", argLen1, effPushStr},
	'V': {"UNICODE", argLine, effPushStr},
	'X': {"BINUNICODE", argLen4, effPushStr},
	'a': {"APPEND", argNone, effPop},
	'b': {"BUILD", argNone, effPop},
	'c': {"GLOBAL", argLine2, effGlobal},
	'd': {"DICT", argNone, effMarkPush},
	'}': {"EMPTY_DICT", argNone, effPushUnk},
	'e': {"APPENDS", argNone, effPopMark},
	'g': {"GET", argLine, effGet},
	'h': {"BINGET", argU1, effGet},
	'i': {"INST", argLine2, effInst},
	'j': {"LONG_BINGET", argU4, effGet},
	'l': {"LIST", argNone, effMarkPush},
	']': {"EMPTY_LIST", argNone, effPushUnk},
	'o': {"OBJ", argNone, effMarkPush},
	'p': {"PUT", argLine, effPut},
	'q': {"BINPUT", argU1, effPut},
	'r': {"LONG_BINPUT", argU4, effPut},
	's': {"SETITEM", argNone, effPop2},
	't': {"TUPLE", argNone, effMarkPush},
	')': {"EMPTY_TUPLE", argNone, effPushUnk},
	'u': {"SETITEMS", argNone, effPopMark},
	'G': {"BINFLOAT", argU8, effPushUnk},
	// Protocol 2.
	0x80: {"PROTO", argU1, effNone},
	0x81: {"NEWOBJ", argNone, effPop2Push},
	0x82: {"EXT1", argU1, effExt},
	0x83: {"EXT2", argU2, effExt},
	0x84: {"EXT4", argI4, effExt},
	0x85: {"TUPLE1", argNone, effPop1Push},
	0x86: {"TUPLE2", argNone, effPop2Push},
	0x87: {"TUPLE3", argNone, effPop3Push},
	0x88: {"NEWTRUE", argNone, effPushUnk},
	0x89: {"NEWFALSE", argNone, effPushUnk},
	0x8a: {"LONG1", argLen1, effPushUnk},
	0x8b: {"LONG4", argLen4, effPushUnk},
	// Protocol 3.
	'B': {"BINBYTES", argLen4, effPushUnk},
	'C': {"SHORT_BINBYTES", argLen1, effPushUnk},
	// Protocol 4.
	0x8c: {"SHORT_BINUNICODE", argLen1, effPushStr},
	0x8d: {"BINUNICODE8", argLen8, effPushStr},
	0x8e: {"BINBYTES8", argLen8, effPushUnk},
	0x8f: {"EMPTY_SET", argNone, effPushUnk},
	0x90: {"ADDITEMS", argNone, effPopMark},
	0x91: {"FROZENSET", argNone, effMarkPush},
	0x92: {"NEWOBJ_EX", argNone, effPop3Push},
	0x93: {"STACK_GLOBAL", argNone, effStackGlobal},
	0x94: {"MEMOIZE", argNone, effMemoize},
	0x95: {"FRAME", argU8, effNone},
	// Protocol 5.
	0x96: {"BYTEARRAY8", argLen8, effPushUnk},
	0x97: {"NEXT_BUFFER", argNone, effPushUnk},
	0x98: {"READONLY_BUFFER", argNone, effNone},
}

// Global is one import a pickle makes: the callable an unpickler resolves.
type Global struct {
	Module string
	Name   string
	Offset int64
	Op     string
}

func (g Global) String() string { return g.Module + "." + g.Name }

// walkResult is what walking one opcode stream found.
type walkResult struct {
	globals []Global
	// dynamic are globals whose module or name is not a constant string, so
	// what they import cannot be known statically.
	dynamic []string
	pickles int   // complete pickles (reached STOP)
	ops     int64 // opcodes read
	err     error // why the walk stopped early, nil at a clean end
}

// limits bound the model, so a hostile stream cannot drive memory.
const (
	maxStack = 1 << 20
	maxMemo  = 1 << 20
	maxLine  = 1 << 16
	maxStr   = 1 << 16 // longest string kept for STACK_GLOBAL resolution
)

var errNotPickle = errors.New("not a pickle opcode stream")

type item struct {
	mark bool
	str  *string
}

// walk models the opcode stream in r: every pickle in sequence (a legacy
// torch.save file is several), stopping at the first byte after a STOP that
// does not begin another pickle. It never executes anything.
func walk(r io.Reader) walkResult {
	br := bufio.NewReaderSize(r, 1<<16)
	var res walkResult
	var off int64
	for {
		b, err := br.Peek(1)
		if err != nil {
			return res
		}
		// A pickle starts with PROTO (protocol 2+) or, for protocols 0 and 1,
		// any opcode. After the first pickle only PROTO continues the
		// sequence, so trailing tensor bytes are not misread as opcodes.
		if res.pickles > 0 && b[0] != 0x80 {
			return res
		}
		// Each pickle is walked into its own result. After the first, a pickle
		// that does not reach STOP is taken as trailing data that happened to
		// start with PROTO, and its "globals" are discarded rather than
		// reported. The first pickle's findings always count: CPython runs
		// every import before the point where a stream breaks.
		var one walkResult
		n, err := walkOne(br, &off, &one)
		res.ops += n
		if err != nil {
			if res.pickles == 0 {
				res.globals = append(res.globals, one.globals...)
				res.dynamic = append(res.dynamic, one.dynamic...)
				if n <= 1 {
					res.err = errNotPickle
				} else {
					res.err = err
				}
			}
			return res
		}
		res.globals = append(res.globals, one.globals...)
		res.dynamic = append(res.dynamic, one.dynamic...)
		res.pickles++
	}
}

func walkOne(br *bufio.Reader, off *int64, res *walkResult) (int64, error) {
	var stack []item
	memo := map[uint64]item{}
	var nops int64

	pop := func() (item, error) {
		if len(stack) == 0 {
			return item{}, fmt.Errorf("stack underflow at offset %d", *off)
		}
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return it, nil
	}
	popMark := func() error {
		for len(stack) > 0 {
			it := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if it.mark {
				return nil
			}
		}
		return fmt.Errorf("no mark on the stack at offset %d", *off)
	}
	push := func(it item) error {
		if len(stack) >= maxStack {
			return fmt.Errorf("stack deeper than %d at offset %d", maxStack, *off)
		}
		stack = append(stack, it)
		return nil
	}

	for {
		start := *off
		code, err := br.ReadByte()
		if err != nil {
			return nops, fmt.Errorf("truncated before STOP at offset %d", start)
		}
		*off++
		op, ok := opcodes[code]
		if !ok {
			return nops, fmt.Errorf("unknown opcode 0x%02x at offset %d", code, start)
		}
		nops++
		arg, num, err := readArg(br, off, op.arg)
		if err != nil {
			return nops, fmt.Errorf("%s at offset %d: %w", op.name, start, err)
		}

		switch op.eff {
		case effNone:
		case effStop:
			return nops, nil
		case effPushUnk:
			err = push(item{})
		case effPushStr:
			s := decodeStr(code, arg)
			if len(s) > maxStr {
				err = push(item{})
			} else {
				err = push(item{str: &s})
			}
		case effMark:
			err = push(item{mark: true})
		case effPop:
			_, err = pop()
		case effPopMark:
			err = popMark()
		case effDup:
			if len(stack) == 0 {
				err = fmt.Errorf("DUP on an empty stack at offset %d", start)
			} else {
				err = push(stack[len(stack)-1])
			}
		case effPop1Push, effPop2Push, effPop3Push:
			k := map[effect]int{effPop1Push: 1, effPop2Push: 2, effPop3Push: 3}[op.eff]
			for i := 0; i < k && err == nil; i++ {
				_, err = pop()
			}
			if err == nil {
				err = push(item{})
			}
		case effPop2:
			if _, err = pop(); err == nil {
				_, err = pop()
			}
		case effMarkPush:
			if err = popMark(); err == nil {
				err = push(item{})
			}
		case effPut, effMemoize:
			if len(stack) == 0 {
				err = fmt.Errorf("%s on an empty stack at offset %d", op.name, start)
				break
			}
			idx := num
			if op.eff == effMemoize {
				idx = uint64(len(memo))
			} else if op.arg == argLine {
				idx, err = strconv.ParseUint(strings.TrimSpace(string(arg)), 10, 64)
				if err != nil {
					err = fmt.Errorf("PUT index at offset %d: %w", start, err)
					break
				}
			}
			if len(memo) >= maxMemo {
				err = fmt.Errorf("memo larger than %d at offset %d", maxMemo, start)
				break
			}
			memo[idx] = stack[len(stack)-1]
		case effGet:
			idx := num
			if op.arg == argLine {
				idx, err = strconv.ParseUint(strings.TrimSpace(string(arg)), 10, 64)
				if err != nil {
					err = fmt.Errorf("GET index at offset %d: %w", start, err)
					break
				}
			}
			it, ok := memo[idx]
			if !ok {
				err = fmt.Errorf("memo key %d missing at offset %d", idx, start)
				break
			}
			err = push(it)
		case effGlobal, effInst:
			mod, name, _ := strings.Cut(string(arg), "\n")
			res.globals = append(res.globals, Global{Module: mod, Name: strings.TrimSuffix(name, "\n"), Offset: start, Op: op.name})
			if op.eff == effInst {
				err = popMark()
			}
			if err == nil {
				err = push(item{})
			}
		case effStackGlobal:
			name, e1 := pop()
			mod, e2 := pop()
			if e1 != nil || e2 != nil {
				err = fmt.Errorf("STACK_GLOBAL needs two values at offset %d", start)
				break
			}
			if mod.str != nil && name.str != nil {
				res.globals = append(res.globals, Global{Module: *mod.str, Name: *name.str, Offset: start, Op: op.name})
			} else {
				res.dynamic = append(res.dynamic, fmt.Sprintf("STACK_GLOBAL at offset %d with a non-constant module or name", start))
			}
			err = push(item{})
		case effExt:
			res.dynamic = append(res.dynamic, fmt.Sprintf("%s code %d at offset %d imports through the extension registry", op.name, num, start))
			err = push(item{})
		}
		if err != nil {
			return nops, err
		}
	}
}

// readArg reads an opcode's inline argument. Lengths are checked against what
// is actually present by reading it, never by allocating the declared size.
func readArg(br *bufio.Reader, off *int64, k argKind) ([]byte, uint64, error) {
	fixed := map[argKind]int{argU1: 1, argU2: 2, argI4: 4, argU4: 4, argU8: 8}
	if n, ok := fixed[k]; ok {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, 0, io.ErrUnexpectedEOF
		}
		*off += int64(n)
		var v uint64
		for i := n - 1; i >= 0; i-- {
			v = v<<8 | uint64(buf[i])
		}
		return buf, v, nil
	}
	switch k {
	case argNone:
		return nil, 0, nil
	case argLine:
		line, err := readLine(br, off)
		return line, 0, err
	case argLine2:
		a, err := readLine(br, off)
		if err != nil {
			return nil, 0, err
		}
		b, err := readLine(br, off)
		if err != nil {
			return nil, 0, err
		}
		return append(append(a[:len(a):len(a)], '\n'), b...), 0, nil
	case argLen1, argLen4, argLen8:
		w := map[argKind]int{argLen1: 1, argLen4: 4, argLen8: 8}[k]
		buf := make([]byte, w)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, 0, io.ErrUnexpectedEOF
		}
		*off += int64(w)
		var n uint64
		switch w {
		case 1:
			n = uint64(buf[0])
		case 4:
			n = uint64(binary.LittleEndian.Uint32(buf))
		case 8:
			n = binary.LittleEndian.Uint64(buf)
		}
		// Keep short values (they may name a module); skip long ones without
		// holding them.
		if n <= maxStr {
			v := make([]byte, n)
			if _, err := io.ReadFull(br, v); err != nil {
				return nil, 0, io.ErrUnexpectedEOF
			}
			*off += int64(n)
			return v, n, nil
		}
		if n > 1<<62 {
			return nil, 0, fmt.Errorf("length %d is impossible", n)
		}
		got, err := io.CopyN(io.Discard, br, int64(n))
		*off += got
		if err != nil {
			return nil, 0, io.ErrUnexpectedEOF
		}
		return nil, n, nil
	}
	return nil, 0, fmt.Errorf("unhandled argument kind %d", k)
}

func readLine(br *bufio.Reader, off *int64) ([]byte, error) {
	var out []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		*off++
		if b == '\n' {
			return out, nil
		}
		if len(out) >= maxLine {
			return nil, fmt.Errorf("line longer than %d bytes", maxLine)
		}
		out = append(out, b)
	}
}

// decodeStr turns a string opcode's argument into the text an unpickler would
// see, close enough to resolve module and attribute names.
func decodeStr(code byte, arg []byte) string {
	s := string(arg)
	switch code {
	case 'S': // repr-quoted, protocol 0
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
			return s[1 : len(s)-1]
		}
	case 'V': // raw-unicode-escape
		if u, err := strconv.Unquote(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`); err == nil {
			return u
		}
	}
	return s
}
