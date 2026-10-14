package tarwalk_test

import (
	"bytes"
	"fmt"
	"strconv"
)

// A raw tar builder for tests: each block is written as given, so a test can
// craft exactly the header a refusal is about.

type block [512]byte

// hdrOpt changes a header block before its checksum is computed.
type hdrOpt func(*block)

const (
	posixMagic = "ustar\x0000"
	gnuMagic   = "ustar  \x00"
)

// header builds a POSIX (ustar) header block for name, of type t, with size.
func header(name string, t byte, size int64, opts ...hdrOpt) []byte {
	var b block
	copy(b[0:100], name)
	octal(b[100:108], 0o644)
	octal(b[108:116], 0)
	octal(b[116:124], 0)
	octal(b[124:136], size)
	octal(b[136:148], 1700000000)
	b[156] = t
	copy(b[257:265], posixMagic)
	octal(b[329:337], 0)
	octal(b[337:345], 0)
	for _, o := range opts {
		o(&b)
	}
	sum(&b)
	return b[:]
}

// octal writes n as zero-padded octal digits and a NUL, as Go's and GNU's
// writers do.
func octal(f []byte, n int64) {
	s := strconv.FormatInt(n, 8)
	for len(s) < len(f)-1 {
		s = "0" + s
	}
	copy(f, s)
	f[len(f)-1] = 0
}

// sum fills the checksum field (unsigned sum, field as spaces).
func sum(b *block) {
	copy(b[148:156], "        ")
	var s int64
	for _, c := range b {
		s += int64(c)
	}
	f := fmt.Sprintf("%06o", s)
	copy(b[148:], f)
	b[154], b[155] = 0, ' '
}

func linkTo(target string) hdrOpt   { return func(b *block) { copy(b[157:257], target) } }
func gnu() hdrOpt                   { return func(b *block) { copy(b[257:265], gnuMagic) } }
func prefix(p string) hdrOpt        { return func(b *block) { copy(b[345:500], p) } }
func raw(from int, v []byte) hdrOpt { return func(b *block) { copy(b[from:], v) } }

// field overwrites a field with v, padded with NULs.
func field(from, to int, v string) hdrOpt {
	return func(b *block) {
		for i := from; i < to; i++ {
			b[i] = 0
		}
		copy(b[from:to], v)
	}
}

// data is a file's bytes padded to a block.
func data(b []byte) []byte {
	out := append([]byte(nil), b...)
	for len(out)%512 != 0 {
		out = append(out, 0)
	}
	return out
}

// paxRecord formats one "<length> <key>=<value>\n" record.
func paxRecord(k, v string) string {
	r := " " + k + "=" + v + "\n"
	n := len(r) + 1
	for len(strconv.Itoa(n))+len(r) != n {
		n++
	}
	return strconv.Itoa(n) + r
}

// pax is a PAX extended header ('x') and its records.
func pax(records ...string) []byte {
	var body string
	for i := 0; i+1 < len(records); i += 2 {
		body += paxRecord(records[i], records[i+1])
	}
	return paxRaw(body)
}

func paxRaw(body string) []byte {
	return append(header("PaxHeaders/x", 'x', int64(len(body))), data([]byte(body))...)
}

// long is a GNU long name ('L') or link ('K') header and its data.
func long(t byte, s string) []byte {
	body := append([]byte(s), 0)
	return append(header("././@LongLink", t, int64(len(body)), gnu()), data(body)...)
}

func file(name string, body []byte, opts ...hdrOpt) []byte {
	return append(header(name, '0', int64(len(body)), opts...), data(body)...)
}

func end() []byte { return make([]byte, 1024) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
