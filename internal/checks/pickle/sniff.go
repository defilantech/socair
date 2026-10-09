package pickle

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// sniffBytes caps how much of a stream Sniff walks to decide it is a pickle.
// A pickle finishes or imports its first global well inside it; bytes that
// only begin like a pickle stop parsing within a few opcodes.
const sniffBytes = 1 << 20

// Sniff reports whether the file at path is a pickle by its bytes, whatever
// it is named, and names the kind; it returns "" for anything else. A model
// directory sends a file to this check by its extension, so a pickle under a
// name like notes.txt would otherwise never be opened.
//
// It recognises a protocol 2 to 5 stream (PROTO first) and a zip archive
// holding a pickle, the torch.save checkpoint format. A stream must also walk:
// it completes a pickle or imports a global within sniffBytes, so a binary
// file that happens to begin 0x80 0x02 is not claimed. Protocols 0 and 1 have
// no header and begin with ordinary text, so they are not recognised here.
// Safetensors and GGUF are left to their own readers: a safetensors header
// length of 0x280 bytes begins with the same two bytes as a protocol 2 pickle.
// A TorchScript archive (code/ and constants.pkl beside its pickles) is left
// alone too: torch.jit.load runs it as TorchScript, which this check does not
// model, and the inventory already names it as an unscanned archive. A
// torch.save zip given a code/ entry to pass as TorchScript is therefore
// named as unscanned, not passed.
func Sniff(path string) string {
	if safetensors.IsSafetensors(path) {
		return ""
	}
	if m, err := gguf.ReadHeader(path); err == nil && m.Format == "GGUF" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case startsProto(head):
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return ""
		}
		if walksAsPickle(f) {
			return fmt.Sprintf("protocol %d pickle stream", head[1])
		}
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		fi, err := f.Stat()
		if err == nil && zipHoldsPickle(f, fi.Size()) {
			return "zip archive holding a pickle"
		}
	}
	return ""
}

// startsProto reports a PROTO opcode for protocol 2 to 5.
func startsProto(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x80 && b[1] >= 2 && b[1] <= 5
}

// walksAsPickle walks the start of a stream that begins with PROTO.
func walksAsPickle(r io.Reader) bool {
	w := walk(io.LimitReader(r, sniffBytes))
	return w.pickles > 0 || len(plausible(w.globals)) > 0 || len(w.dynamic) > 0
}

// zipHoldsPickle reports an entry named .pkl or one whose bytes walk as a
// pickle, the same recognition scanZip applies, in a zip that is not a
// TorchScript archive. A zip it cannot open is not claimed here; the
// inventory already names every archive it finds.
func zipHoldsPickle(f *os.File, size int64) bool {
	zr, err := zip.NewReader(f, size)
	if err != nil || len(zr.File) > maxEntries || isTorchScript(zr) {
		return false
	}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(zf.Name), ".pkl") {
			return true
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		br := bufio.NewReader(rc)
		b, err := br.Peek(2)
		ok := err == nil && startsProto(b) && walksAsPickle(br)
		_ = rc.Close()
		if ok {
			return true
		}
	}
	return false
}

// isTorchScript reports a TorchScript archive: torch.jit.save writes the
// module's code under <name>/code/ and its constants to <name>/constants.pkl.
func isTorchScript(zr *zip.Reader) bool {
	for _, zf := range zr.File {
		parts := strings.SplitN(zf.Name, "/", 3)
		if len(parts) >= 2 && (parts[1] == "code" || parts[1] == "constants.pkl") {
			return true
		}
	}
	return false
}
