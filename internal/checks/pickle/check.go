// Package pickle scans pickle-based model files for dangerous globals in the
// opcode stream.
//
// It never unpickles and never executes: it reads the bytes, checks they start
// with a pickle PROTO opcode, and searches the opcode stream for qualified
// gadget names. Safetensors and GGUF are not pickle formats, so this check
// returns NOT_TESTED for them rather than a false pass.
package pickle

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// maxScanBytes caps how much of a large checkpoint is read.
const maxScanBytes = 256 << 20

// protoOpcode is the pickle PROTO opcode. A real pickle stream starts with it.
const protoOpcode = 0x80

// gadgets are module/name pairs that lead to code execution when unpickled.
// Pickle stores a global as "c<module>\n<name>\n".
var gadgets = []struct {
	module string
	name   string
}{
	{"os", "system"},
	{"posix", "system"},
	{"subprocess", "Popen"},
	{"subprocess", "call"},
	{"subprocess", "run"},
	{"builtins", "eval"},
	{"builtins", "exec"},
	{"__builtin__", "eval"},
	{"runpy", "_run_module_as_main"},
}

var pickleExtensions = map[string]bool{
	".pt": true, ".bin": true, ".pkl": true, ".pickle": true, ".ckpt": true,
}

// Inspect scans one artifact for pickle gadget globals.
func Inspect(path string) checks.Result {
	r := checks.Result{
		Name:     "Pickle opcode scan",
		LooksFor: "Serialized code gadgets in pickle-based model files",
	}

	if safetensors.IsSafetensors(path) {
		r.Status = checks.NotTested
		r.Notes = "artifact is safetensors, not a pickle format; no opcode stream to scan"
		return r
	}
	if m, err := gguf.ReadHeader(path); err == nil && m.Format == "GGUF" {
		r.Status = checks.NotTested
		r.Notes = "artifact is GGUF, not a pickle format; no opcode stream to scan"
		return r
	}

	f, err := os.Open(path)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not open artifact: " + err.Error()
		return r
	}
	defer f.Close()

	head := make([]byte, 1)
	if _, err := io.ReadFull(f, head); err != nil {
		r.Status = checks.NotTested
		r.Notes = "artifact is empty"
		return r
	}
	if head[0] != protoOpcode {
		ext := strings.ToLower(filepath.Ext(path))
		hint := ""
		if pickleExtensions[ext] {
			hint = " (extension suggests pickle, but the bytes do not start with a pickle PROTO opcode)"
		}
		r.Status = checks.NotTested
		r.Notes = "artifact does not start with a pickle PROTO opcode; no opcode stream to scan" + hint
		return r
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not seek artifact: " + err.Error()
		return r
	}
	body, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not read artifact: " + err.Error()
		return r
	}

	var found []string
	for _, g := range gadgets {
		needle := []byte("c" + g.module + "\n" + g.name + "\n")
		if bytes.Contains(body, needle) {
			found = append(found, g.module+"."+g.name)
		}
	}

	if len(found) > 0 {
		sort.Strings(found)
		for _, g := range found {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "pickle-gadget-global",
				Span:    g,
				Detail:  "pickle opcode stream references a code-execution global",
			})
		}
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d dangerous global(s) in the opcode stream: %s",
			len(found), strings.Join(found, ", "))
		return r
	}

	r.Status = checks.Pass
	r.Notes = "pickle stream scanned for known gadget globals; none matched. Heuristic over a known-gadget list, not a proof of safety."
	return r
}
