package pickle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// cpythonVector is one stream with CPython's reading of it, recorded by
// testdata/gen-cpython-vectors.py.
type cpythonVector struct {
	Name    string `json:"name"`
	Pids    string `json:"pids"`
	Hex     string `json:"hex"`
	CPython string `json:"cpython"`
	Conform bool   `json:"conform"`
}

func loadVectors(t *testing.T) map[string]cpythonVector {
	t.Helper()
	b, err := os.ReadFile("testdata/cpython-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []cpythonVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]cpythonVector{}
	for _, v := range doc.Vectors {
		out[v.Name] = v
	}
	if len(out) < 30 {
		t.Fatalf("only %d vectors; the fixture is incomplete", len(out))
	}
	return out
}

func (c cpythonVector) bytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(c.Hex)
	if err != nil {
		t.Fatalf("%s: %v", c.Name, err)
	}
	return b
}

// render writes a value as the generator's symbolic reading does, so the two
// can be compared.
func render(x *value) string {
	if x.x != nil && x.x.sym != nil {
		s := x.x.sym
		if s.fn == "pid" {
			return "pid" + render(s.args)
		}
		kind := "call:"
		if s.isNew {
			kind = "new:"
		}
		out := kind + s.fn + render(s.args)
		if x.kind == kDict && len(x.items) > s.ctor {
			out += ".items{" + renderPairs(x.items[s.ctor:]) + "}"
		}
		if s.state != nil {
			out += ".state(" + render(s.state) + ")"
		}
		return out
	}
	switch x.kind {
	case kNone:
		return "None"
	case kBool:
		if x.num != 0 {
			return "True"
		}
		return "False"
	case kInt:
		if x.x != nil && x.x.big != nil {
			return x.x.big.String()
		}
		return fmt.Sprint(x.num)
	case kFloat:
		return fmt.Sprintf("f%016x", math.Float64bits(x.f))
	case kStr:
		return "s" + hex.EncodeToString([]byte(x.s))
	case kBytes:
		return "b" + hex.EncodeToString([]byte(x.s))
	case kTuple:
		return "(" + renderList(x.items) + ")"
	case kList:
		return "[" + renderList(x.items) + "]"
	case kDict:
		return "{" + renderPairs(x.items) + "}"
	case kGlobal:
		return "g:" + x.class
	}
	return "?"
}

func renderList(items []*value) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = render(it)
	}
	return strings.Join(parts, ",")
}

func renderPairs(items []*value) string {
	parts := make([]string, 0, len(items)/2)
	for i := 0; i+1 < len(items); i += 2 {
		parts = append(parts, render(items[i])+":"+render(items[i+1]))
	}
	return strings.Join(parts, ",")
}

var pidModes = map[string]pidMode{"none": pidNone, "zip": pidZip, "legacy": pidLegacy}

// validateVector validates a vector's stream. A legacy stream is several
// pickles; the object is the fourth, after the magic number, the protocol
// version, and sys_info.
func validateVector(t *testing.T, c cpythonVector) *validation {
	t.Helper()
	data := c.bytes(t)
	if c.Pids != "legacy" {
		return validate(bytes.NewReader(data), grammarOpts{pids: pidModes[c.Pids]})
	}
	var g *validation
	for i := 0; i < 4; i++ {
		mode := pidNone
		if i == 3 {
			mode = pidLegacy
		}
		g = validate(bytes.NewReader(data), grammarOpts{pids: mode})
		if i < 3 {
			data = data[g.end:]
		}
	}
	return g
}

// sharedTuples leaves one value on the stack: 60 levels of t = (t, t), built
// through the memo. A few hundred bytes whose tree, walked naively, has 2^60
// nodes.
func sharedTuples(p *pk) *pk {
	p.int(1).raw("\x85").put()
	for i := 0; i < 60; i++ {
		p.raw("h" + string([]byte{byte(p.memo - 1)}) + "\x86").put()
	}
	return p
}

// TestSharedStructureIsLinear: every walk over a value (freezing a call's
// arguments, hashing a key or a set element, checking a reviewed class's
// state) must cost the stream's size, not its tree's. Falsification: lift
// the walk budget (maxWalk) and the key, set, and state cases do not finish.
func TestSharedStructureIsLinear(t *testing.T) {
	streams := map[string][]byte{
		"dict key":    sharedTuples(newPK().raw("}").put()).int(0).raw("s").stop(),
		"set element": sharedTuples(newPK().global("__builtin__", "set").raw("]").put()).raw("a\x85").put().raw("R").stop(),
		"reviewed state": sharedTuples(newPK().global("x", "Y").raw(")\x81").put().raw("}").put().str("a")).
			raw("sb").stop(),
	}
	for name, s := range streams {
		done := make(chan *validation, 1)
		go func() { done <- validate(bytes.NewReader(s), grammarOpts{reviewed: map[string]bool{"x.Y": true}}) }()
		select {
		case g := <-done:
			// The walk gave up within its budget, so the value is not shown
			// hashable or plain: a departure, not a pass.
			if len(g.violations) == 0 {
				t.Errorf("%s: no violation; the fixture did not reach the walk (gaps %q broken %q)", name, g.gaps, g.broken)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: validation did not finish", name)
		}
	}
}

// TestParseEquivalenceWithCPython is the grammar's obligation: every stream
// it accepts, CPython reads the same way (the same calls, with the same
// arguments, in the same structure). The readings were recorded once from
// CPython by testdata/gen-cpython-vectors.py; streams torch.save and the
// pickler write must conform, and the hostile shapes (a memo slot written
// twice, NUL in a GLOBAL, a text INT, a list given SETITEMS, REDUCE with list
// arguments...) must not. Falsification: model a memo re-put as "keep the
// first" without flagging it and re-put-memo-key conforms; decode BINFLOAT
// little-endian and floats, the optimizer state, and complex read
// differently from CPython.
func TestParseEquivalenceWithCPython(t *testing.T) {
	compared, rejected := 0, 0
	t.Cleanup(func() {
		if !t.Failed() && (compared < 20 || rejected < 15) {
			t.Errorf("compared %d accepted and %d rejected streams; the fixture or the loop is broken", compared, rejected)
		}
	})
	for name, c := range loadVectors(t) {
		if c.Conform {
			compared++
		} else {
			rejected++
		}
		g := validateVector(t, c)
		if g.conforms() != c.Conform {
			t.Errorf("%s: conforms = %v, want %v (gaps %q, broken %q, violations %+v)", name, g.conforms(), c.Conform, g.gaps, g.broken, g.violations)
			continue
		}
		if !g.conforms() {
			continue
		}
		if strings.HasPrefix(c.CPython, "error:") {
			t.Errorf("%s: the grammar accepts a stream CPython rejects (%s)", name, c.CPython)
			continue
		}
		if got := render(g.root); got != c.CPython {
			t.Errorf("%s: reads differently from CPython\n grammar: %s\n cpython: %s", name, got, c.CPython)
		}
	}
}
