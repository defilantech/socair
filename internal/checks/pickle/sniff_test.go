package pickle

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/safetensors"
)

// TestSniffFindsAPickleByItsBytes: a model directory sent a file to this
// check only when its extension said pickle, so a pickle named notes.txt was
// never opened (#186). Sniff recognises one by content. Falsification: have
// Sniff return "" and every case that wants a pickle fails; drop the walk that
// confirms a stream and the binary that only starts like one is claimed.
func TestSniffFindsAPickleByItsBytes(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"protocol 2 gadget", real["system_p2"], true},
		{"protocol 3 benign", real["benign_p3"], true},
		{"protocol 4 gadget (STACK_GLOBAL)", real["system_p4"], true},
		{"protocol 5 benign", real["benign_p5"], true},
		{"gadget in a stream broken after the import", append(append([]byte{}, real["system_p2"][:18]...), 0xff, 0xff), true},
		{"torch zip", zipOf(t, map[string][]byte{"archive/data.pkl": real["benign_p2"], "archive/version": []byte("3\n")}), true},
		{"zip, gadget under a tensor name", zipOf(t, map[string][]byte{"archive/data/0": real["system_p4"]}), true},
		{"json", []byte(`{"model_type": "llama"}`), false},
		{"text", []byte("hello\n"), false},
		{"empty", nil, false},
		{"zip without a pickle", zipOf(t, map[string][]byte{"README": []byte("hello")}), false},
		{"binary that only starts like a pickle", append([]byte{0x80, 0x03}, bytes.Repeat([]byte{0xff}, 64)...), false},
		// Protocols 0 and 1 have no PROTO header and begin with ordinary
		// text, so they cannot be told from text by their bytes. A stated
		// limit: such a file is found by its extension or not at all.
		{"protocol 0 (a stated limit)", real["system_p0"], false},
	}
	for _, c := range cases {
		got := Sniff(writeFixture(t, "notes.txt", c.data))
		if (got != "") != c.want {
			t.Errorf("%s: Sniff = %q, want pickle %v", c.name, got, c.want)
		}
	}
}

// TestSniffLeavesSafetensorsAlone: a safetensors header of 0x280 bytes begins
// 0x80 0x02, the two bytes a protocol 2 pickle begins with. Safetensors has
// its own reader, so Sniff must not claim it. Two guards hold: Sniff leaves
// safetensors to that reader, and the length's high bytes are 0x00, which is
// not an opcode, so the walk rejects it too. Falsification: drop both and
// this file reads as a pickle.
func TestSniffLeavesSafetensorsAlone(t *testing.T) {
	header := []byte(`{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`)
	header = append(header, bytes.Repeat([]byte(" "), 0x280-len(header))...)
	data := binary.LittleEndian.AppendUint64(nil, uint64(len(header)))
	data = append(append(data, header...), 0x00, 0x00, 0x80, 0x3f)
	p := writeFixture(t, "notes.txt", data)
	if !safetensors.IsSafetensors(p) || !bytes.HasPrefix(data, []byte{0x80, 0x02}) {
		t.Fatal("fixture is not a safetensors file that begins like a protocol 2 pickle")
	}
	if got := Sniff(p); got != "" {
		t.Fatalf("Sniff = %q on a safetensors file, want none", got)
	}
}

// TestSniffNamesTheKind: the kind goes into the report, so a reader sees why
// a file with an unrelated name was scanned as a pickle.
func TestSniffNamesTheKind(t *testing.T) {
	if got := Sniff(writeFixture(t, "notes.txt", real["system_p4"])); !strings.Contains(got, "protocol 4") {
		t.Errorf("stream kind = %q, want the protocol named", got)
	}
	z := zipOf(t, map[string][]byte{"archive/data.pkl": real["benign_p2"]})
	if got := Sniff(writeFixture(t, "weights.dat", z)); !strings.Contains(got, "zip") {
		t.Errorf("zip kind = %q, want it named a zip", got)
	}
}

// torchScriptPickle is data.pkl as a TorchScript archive writes it: the
// module object is a __torch__ class defined by the archive's own code/.
var torchScriptPickle = []byte("\x80\x02c__torch__\nModule\nq\x00)\x81q\x01.")

// TestSniffLeavesTorchScriptAlone: a TorchScript archive (rust_model.ot in
// sentence-transformers/all-MiniLM-L6-v2 and distilbert-base-uncased) is a
// zip that holds pickles, but torch.jit.load runs it as TorchScript, a format
// this check does not model, and its __torch__ classes read as unreviewed
// globals: claimed, it turned two of the Hub's most used repositories into a
// LEAD no acceptance clears. It stays a named, unscanned archive in the
// inventory. Falsification: drop the TorchScript exclusion and it is claimed.
func TestSniffLeavesTorchScriptAlone(t *testing.T) {
	z := zipOf(t, map[string][]byte{
		"rust_model/data.pkl":          torchScriptPickle,
		"rust_model/code/__torch__.py": []byte("class Module(Module):\n  __parameters__ = []\n"),
		"rust_model/constants.pkl":     []byte("\x80\x02)."),
		"rust_model/version":           []byte("1\n"),
	})
	if got := Sniff(writeFixture(t, "rust_model.ot", z)); got != "" {
		t.Fatalf("Sniff = %q on a TorchScript archive, want none", got)
	}
	// The same pickle in a torch.save layout is a checkpoint, and is claimed.
	z = zipOf(t, map[string][]byte{"archive/data.pkl": torchScriptPickle, "archive/version": []byte("3\n")})
	if got := Sniff(writeFixture(t, "weights.dat", z)); got == "" {
		t.Fatal("Sniff claimed nothing for a torch.save zip")
	}
}
