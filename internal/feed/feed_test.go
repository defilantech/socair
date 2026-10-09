package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/dsse"
)

var (
	h1  = strings.Repeat("aa", 32)
	h2  = strings.Repeat("bb", 32)
	h3  = strings.Repeat("cc", 32)
	now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
)

func signer(t *testing.T) (string, func([]byte) []byte, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := dsse.KeyID(pub)
	return id, func(m []byte) []byte { return ed25519.Sign(priv, m) }, map[string]ed25519.PublicKey{id: pub}
}

func info() Info {
	return Info{Issuer: "Example Intel", Version: "2026.10.1", Issued: "2026-10-01T00:00:00Z", Expires: "2026-11-01T00:00:00Z"}
}

// built writes and signs a feed with all three data files.
func built(t *testing.T) (string, map[string]ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "denylist.txt", "# known bad\n"+h1+"  trojaned Llama quant\n")
	write(t, dir, "templates.txt", h2+"  Qwen3 reviewed 2026-09\n")
	write(t, dir, "tokenizers.txt", h3+"  qwen2.5\n")
	id, sign, keys := signer(t)
	if err := Sign(dir, info(), id, sign); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignLoadRoundTrip(t *testing.T) {
	dir, keys := built(t)
	f, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Denylist[h1] != "trojaned Llama quant" || len(f.Templates) != 1 || f.Tokenizers[h3] != "qwen2.5" || f.Version != "2026.10.1" {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Describe(), "Example Intel 2026.10.1") {
		t.Errorf("describe: %s", f.Describe())
	}
}

// Every way a feed can be other than what was signed is refused.
// Falsification: drop the matching check in Load and its case loads.
func TestLoadRefuses(t *testing.T) {
	cases := map[string]struct {
		mutate func(t *testing.T, dir string)
		keys   func(map[string]ed25519.PublicKey) map[string]ed25519.PublicKey
		at     time.Time
		want   string
	}{
		"data file changed": {mutate: func(t *testing.T, d string) {
			write(t, d, "denylist.txt", h1+"  something else\n")
		}, want: "does not match its signed hash"},
		"signed data file removed": {mutate: func(t *testing.T, d string) {
			_ = os.Remove(filepath.Join(d, "tokenizers.txt"))
		}, want: "tokenizers.txt"},
		"another key": {keys: func(map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
			_, _, other := signer(t)
			return other
		}, want: "not trusted"},
		"expired":           {at: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), want: "expired"},
		"issued in future":  {at: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), want: "future"},
		"statement missing": {mutate: func(t *testing.T, d string) { _ = os.Remove(filepath.Join(d, StatementFile)) }, want: StatementFile},
	}
	for name, c := range cases {
		dir, keys := built(t)
		if c.mutate != nil {
			c.mutate(t, dir)
		}
		if c.keys != nil {
			keys = c.keys(keys)
		}
		at := now
		if !c.at.IsZero() {
			at = c.at
		}
		if _, err := Load(dir, keys, at); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}
}

// A data file the signature does not list is refused, even if the listed
// files all verify: the directory is not what was signed.
func TestUnlistedDataFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "denylist.txt", h1+"  bad\n")
	id, sign, keys := signer(t)
	if err := Sign(dir, info(), id, sign); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "templates.txt", h2+"\n")
	if _, err := Load(dir, keys, now); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedDataIsRefusedAtSigning(t *testing.T) {
	id, sign, _ := signer(t)
	for name, c := range map[string][2]string{
		"short hash":        {"denylist.txt", "abc  bad\n"},
		"non-hex":           {"templates.txt", strings.Repeat("zz", 32) + "\n"},
		"unlabelled bad":    {"denylist.txt", h1 + "\n"},
		"unnamed tokenizer": {"tokenizers.txt", h3 + "\n"},
	} {
		dir := t.TempDir()
		write(t, dir, c[0], c[1])
		if err := Sign(dir, info(), id, sign); err == nil {
			t.Errorf("%s: a malformed feed must not sign", name)
		}
	}
	empty := t.TempDir()
	if err := Sign(empty, info(), id, sign); err == nil {
		t.Error("a feed with no data files must not sign")
	}
	bad := info()
	bad.Expires = "2026-09-01T00:00:00Z"
	dir := t.TempDir()
	write(t, dir, "denylist.txt", h1+"  bad\n")
	if err := Sign(dir, bad, id, sign); err == nil {
		t.Error("a feed that expires before it is issued must not sign")
	}
}

// The signed statement itself, altered after signing, is refused: a forged
// signature, or a payload edited to extend the expiry or swap a file's hash.
// Falsification: skip the signature check and these load.
func TestTamperedStatementIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*dsse.Envelope){
		"signature byte": func(e *dsse.Envelope) {
			sig, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
			sig[0] ^= 1
			e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
		},
		"expiry extended": func(e *dsse.Envelope) {
			p, _ := base64.StdEncoding.DecodeString(e.Payload)
			e.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), "2026-11-01", "2036-11-01", 1)))
		},
	} {
		dir, keys := built(t)
		p := filepath.Join(dir, StatementFile)
		raw, _ := os.ReadFile(p)
		var e dsse.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		edit(&e)
		out, _ := json.Marshal(e)
		if err := os.WriteFile(p, out, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, keys, now); err == nil {
			t.Errorf("%s: a tampered feed statement must be refused", name)
		}
	}
}

// TestTokenizerTablesAreSignedAndCovered: a feed carries canonical tokenizer
// tables under tokenizers/, each covered by the signature like any data file.
// Falsification: skip the uncovered-table check and the second case loads.
func TestTokenizerTablesAreSignedAndCovered(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, TableDir), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, dir, TableDir+"/qwen3.json", `{"format":"socair.tokenizer-table/v1","name":"qwen3","tokens":["a","b"]}`)
	id, sign, keys := signer(t)
	if err := Sign(dir, info(), id, sign); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.TokenizerTables["qwen3"]) == 0 {
		t.Fatalf("table not loaded: %v", f.TokenizerTables)
	}

	// A table added after signing is not part of the feed.
	write(t, dir, TableDir+"/llama3.json", `{"format":"socair.tokenizer-table/v1","name":"llama3","tokens":["x"]}`)
	if _, err := Load(dir, keys, now); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("an unsigned table must refuse the feed, got %v", err)
	}
	_ = os.Remove(filepath.Join(dir, TableDir, "llama3.json"))

	// A changed table no longer matches its signed hash.
	write(t, dir, TableDir+"/qwen3.json", `{"format":"socair.tokenizer-table/v1","name":"qwen3","tokens":["a","EVIL"]}`)
	if _, err := Load(dir, keys, now); err == nil || !strings.Contains(err.Error(), "signed hash") {
		t.Fatalf("a changed table must refuse the feed, got %v", err)
	}

	// A table name outside the pattern is refused at signing.
	bad := t.TempDir()
	_ = os.Mkdir(filepath.Join(bad, TableDir), 0o755)
	write(t, bad, TableDir+"/Qwen 3.json", "{}")
	if err := Sign(bad, info(), id, sign); err == nil {
		t.Error("a table named outside the pattern must not be signed")
	}
}

// TestReviewedTemplateTexts: a reviewed template can carry its text, as
// templates/<sha256>.jinja, so a scan can render it beside an artifact's.
// The text must hash to its name and be listed in templates.txt, whose
// label names it; anything else refuses the feed. Falsification: drop the
// hash or listing check and its case loads.
func TestReviewedTemplateTexts(t *testing.T) {
	text := "{% for m in messages %}{{ m.content }}{% endfor %}"
	hash := sha256Hex(text)
	setup := func(t *testing.T, listed, name, body string) string {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, TemplateDir), 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, dir, "templates.txt", listed+"  org/model@abc1234\n")
		write(t, dir, TemplateDir+"/"+name+".jinja", body)
		return dir
	}
	id, sign, keys := signer(t)

	dir := setup(t, hash, hash, text)
	if err := Sign(dir, info(), id, sign); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Templates[hash] != "org/model@abc1234" || f.TemplateTexts[hash] != text {
		t.Fatalf("templates %v, texts %v", f.Templates, f.TemplateTexts)
	}

	for name, c := range map[string]struct{ listed, file, body string }{
		"text that does not hash to its name": {hash, hash, text + "x"},
		"text not listed in templates.txt":    {h2, hash, text},
	} {
		d := setup(t, c.listed, c.file, c.body)
		if err := Sign(d, info(), id, sign); err == nil {
			if _, err := Load(d, keys, now); err == nil {
				t.Errorf("%s: the feed loaded", name)
			}
		}
	}

	// A text added after signing is not part of the feed.
	write(t, dir, TemplateDir+"/"+h3+".jinja", "x")
	if _, err := Load(dir, keys, now); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("an unsigned template text must refuse the feed, got %v", err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
