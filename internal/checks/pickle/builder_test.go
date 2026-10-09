package pickle

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"sort"
	"testing"
)

// pk writes protocol 2 pickles as CPython's pickler does: the shortest
// integer opcode, BINUNICODE strings, every memoizable object put into the
// next memo slot. Falsification fixtures start from a canonical stream and
// change one thing, so what a test catches is that one thing.
type pk struct {
	b    bytes.Buffer
	memo int
}

func newPK() *pk {
	p := &pk{}
	p.b.WriteString("\x80\x02")
	return p
}

func (p *pk) raw(s string) *pk { p.b.WriteString(s); return p }

func (p *pk) put() *pk {
	if p.memo < 256 {
		p.b.WriteByte('q')
		p.b.WriteByte(byte(p.memo))
	} else {
		p.b.WriteByte('r')
		_ = binary.Write(&p.b, binary.LittleEndian, uint32(p.memo))
	}
	p.memo++
	return p
}

func (p *pk) global(mod, name string) *pk { return p.raw("c" + mod + "\n" + name + "\n").put() }

func (p *pk) str(s string) *pk {
	p.b.WriteByte('X')
	_ = binary.Write(&p.b, binary.LittleEndian, uint32(len(s)))
	p.b.WriteString(s)
	return p.put()
}

func (p *pk) int(n int) *pk {
	switch {
	case n >= 0 && n <= 0xff:
		p.b.WriteByte('K')
		p.b.WriteByte(byte(n))
	case n >= 0 && n <= 0xffff:
		p.b.WriteByte('M')
		_ = binary.Write(&p.b, binary.LittleEndian, uint16(n))
	default:
		p.b.WriteByte('J')
		_ = binary.Write(&p.b, binary.LittleEndian, int32(n))
	}
	return p
}

// tuple writes a tuple of ints as the pickler does.
func (p *pk) ints(ns ...int) *pk {
	if len(ns) == 0 {
		return p.raw(")")
	}
	if len(ns) > 3 {
		p.raw("(")
	}
	for _, n := range ns {
		p.int(n)
	}
	if len(ns) > 3 {
		return p.raw("t").put()
	}
	p.b.WriteByte(byte(0x84 + len(ns))) // TUPLE1, TUPLE2, TUPLE3
	return p.put()
}

// orderedDict writes collections.OrderedDict(), the empty hooks argument.
func (p *pk) orderedDict() *pk {
	return p.global("collections", "OrderedDict").raw(")R").put()
}

// tensor writes torch._utils._rebuild_tensor_v2 of a float32 storage with
// key, numel elements, and the view given. hooks writes the hooks argument.
func (p *pk) tensor(key string, numel, offset int, size, stride []int, hooks func(*pk)) *pk {
	p.global("torch._utils", "_rebuild_tensor_v2").raw("((")
	p.str("storage").global("torch", "FloatStorage").str(key).str("cpu").int(numel).raw("t").put().raw("Q")
	p.int(offset).ints(size...).ints(stride...).raw("\x89")
	if hooks == nil {
		p.orderedDict()
	} else {
		hooks(p)
	}
	return p.raw("t").put().raw("R").put()
}

// dict wraps what entry writes as the value of one key of a dict.
func (p *pk) dict(key string, entry func(*pk)) *pk {
	p.raw("}").put().str(key)
	entry(p)
	return p.raw("s")
}

func (p *pk) stop() []byte { return append(p.b.Bytes(), '.') }

// stateDict is {"w": <one float32 tensor of 4 elements>}.
func stateDict() []byte {
	return newPK().dict("w", func(p *pk) { p.tensor("0", 4, 0, []int{4}, []int{1}, nil) }).stop()
}

// torchZip is a torch.save zip: data.pkl, its storage records, and the
// metadata records torch writes.
func torchZip(t *testing.T, pkl []byte, records map[string][]byte, extra ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	add := func(name string, data []byte) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add("archive/data.pkl", pkl)
	add("archive/.format_version", []byte("1"))
	add("archive/byteorder", []byte("little"))
	for _, k := range sortedKeys(records) {
		add("archive/data/"+k, records[k])
	}
	add("archive/version", []byte("3\n"))
	for i := 0; i+1 < len(extra); i += 2 {
		add(extra[i], []byte(extra[i+1]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestBuilderWritesWhatCPythonWrites holds the builder to CPython: its
// one-tensor state dict is byte for byte what CPython's pickler wrote for the
// same object (vector torch-one-tensor-dict), so fixtures built from it are
// canonical and each differs from torch.save output only where a test says.
func TestBuilderWritesWhatCPythonWrites(t *testing.T) {
	want := loadVectors(t)["torch-one-tensor-dict"].bytes(t)
	if got := stateDict(); !bytes.Equal(got, want) {
		t.Fatalf("builder wrote\n %x\nCPython wrote\n %x", got, want)
	}
	g := validate(bytes.NewReader(stateDict()), grammarOpts{pids: pidZip})
	if !g.conforms() {
		t.Fatalf("the builder's state dict does not conform: gaps %q broken %q violations %+v", g.gaps, g.broken, g.violations)
	}
	if len(g.tensors) != 1 || g.storages["0"] == nil || g.storages["0"].numel != 4 {
		t.Fatalf("tensors %+v storages %+v, want one tensor over storage 0 of 4 elements", g.tensors, g.storages)
	}
}
