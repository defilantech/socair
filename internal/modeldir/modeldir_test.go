package modeldir

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestDigestIsTheDocumentedCanonicalForm pins the manifest format, so a third
// party can recompute the subject from the documentation alone.
func TestDigestIsTheDocumentedCanonicalForm(t *testing.T) {
	files := []File{{Path: "a.json", SHA256: sum("{}"), Size: 2}, {Path: "w/m.safetensors", SHA256: sum("x"), Size: 1}}
	want := sum("socair.modeldir/v1\n" + sum("{}") + " 2 a.json\n" + sum("x") + " 1 w/m.safetensors\n")
	if got := Digest(files); got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
}

func TestSnapshotHashesEveryFileAndBindsTheirNames(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "config.json", `{"model_type":"llama"}`)
	write(t, dir, "model.safetensors", "weights")
	write(t, dir, "sub/extra.py", "print(1)")
	write(t, dir, ".git/HEAD", "ref: refs/heads/main")

	snap, files, excluded, cleanup, err := Snapshot(dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(files) != 3 || files[0].Path != "config.json" || files[2].Path != "sub/extra.py" {
		t.Fatalf("files %+v", files)
	}
	if files[2].Role != RoleCode || files[1].Role != RoleWeights || files[0].Role != RoleConfig {
		t.Errorf("roles %+v", files)
	}
	if len(excluded) != 1 || excluded[0].Path != ".git/" {
		t.Errorf("tool metadata must be excluded and named, got %+v", excluded)
	}
	b, err := os.ReadFile(filepath.Join(snap, "sub", "extra.py"))
	if err != nil || string(b) != "print(1)" || files[2].SHA256 != sum("print(1)") {
		t.Fatalf("snapshot copy %q, hash %s", b, files[2].SHA256)
	}
	if fi, _ := os.Stat(filepath.Join(snap, "model.safetensors")); fi.Mode().Perm()&0o222 != 0 {
		t.Error("snapshot files must be read-only")
	}
	digest, hashed, err := Hash(dir)
	if err != nil || digest != Digest(files) || len(hashed) != 3 {
		t.Fatalf("Hash in place must equal the snapshot digest: %s vs %s (%v)", digest, Digest(files), err)
	}

	// Renaming a file, or changing one byte, changes the subject.
	before := digest
	if err := os.Rename(filepath.Join(dir, "sub", "extra.py"), filepath.Join(dir, "sub", "other.py")); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := Hash(dir); after == before {
		t.Error("a renamed file must change the digest")
	}
	write(t, dir, "sub/other.py", "print(2)")
	if after, _, _ := Hash(dir); after == before {
		t.Error("changed bytes must change the digest")
	}
}

// A Hugging Face cache snapshot is a tree of symlinks into blobs/.
func TestSymlinkedFilesAreFollowedAndDirectoriesAreNot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "blobs/abc", "weights")
	write(t, root, "elsewhere/secret.txt", "x")
	snapDir := filepath.Join(root, "snapshots", "rev")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "blobs", "abc"), filepath.Join(snapDir, "model.safetensors")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(snapDir, "linked")); err != nil {
		t.Fatal(err)
	}
	_, files, excluded, cleanup, err := Snapshot(snapDir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(files) != 1 || files[0].SHA256 != sum("weights") {
		t.Fatalf("files %+v", files)
	}
	if len(excluded) != 1 || !strings.Contains(excluded[0].Reason, "symlinked directory") {
		t.Errorf("a symlinked directory must be excluded and named, got %+v", excluded)
	}
}

func TestEmptyAndUnnameableDirectoriesAreRefused(t *testing.T) {
	if _, _, _, _, err := Snapshot(t.TempDir(), t.TempDir()); err == nil {
		t.Error("an empty directory is not a model")
	}
	dir := t.TempDir()
	write(t, dir, "a\nb", "x")
	if _, _, err := Hash(dir); err == nil {
		t.Error("a file name with a newline cannot be named in the manifest")
	}
}

func TestClassify(t *testing.T) {
	for path, want := range map[string]string{
		"model-00001-of-00002.safetensors": RoleWeights, "pytorch_model.bin": RoleWeights,
		"config.json": RoleConfig, "video_preprocessor_config.json": RoleConfig, "model.safetensors.index.json": RoleConfig,
		"tokenizer.json": RoleTokenizer, "tokenizer_config.json": RoleTokenizer, "tokenizer.model": RoleTokenizer,
		"chat_template.jinja": RoleTemplate, "additional_chat_templates/tool.jinja": RoleTemplate,
		"modeling_custom.py": RoleCode, "README.md": RoleOther, "adapter_config.json": RoleAdapter,
	} {
		if got := Classify(path, false); got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	if Classify("adapter_model.safetensors", true) != RoleAdapter {
		t.Error("weights in an adapter directory are the adapter")
	}
}

func TestChatTemplates(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "tokenizer_config.json", `{"chat_template":[{"name":"default","template":"{{ a }}"},{"name":"tool_use","template":"{{ b }}"}]}`)
	write(t, dir, "chat_template.jinja", "{{ c }}")
	write(t, dir, "additional_chat_templates/rag.jinja", "{{ d }}")
	write(t, dir, "sub/chat_template.json", `{"chat_template": 42}`)
	write(t, dir, "broken/tokenizer_config.json", `{not json`)
	snap, files, _, cleanup, err := Snapshot(dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	tm, nonString, unread := ChatTemplates(snap, files)
	want := map[string]string{
		"tokenizer_config.json#default": "{{ a }}", "tokenizer_config.json#tool_use": "{{ b }}",
		"chat_template.jinja": "{{ c }}", "additional_chat_templates/rag.jinja": "{{ d }}",
	}
	for k, v := range want {
		if tm[k] != v {
			t.Errorf("template %s = %q, want %q", k, tm[k], v)
		}
	}
	if len(tm) != len(want) || len(nonString) != 1 || len(unread) != 1 {
		t.Errorf("templates %v nonString %v unread %v", tm, nonString, unread)
	}
}
