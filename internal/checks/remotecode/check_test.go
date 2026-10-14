package remotecode

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

func repo(t *testing.T, files map[string]string) (string, []modeldir.File) {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	snap, fs, _, cleanup, err := modeldir.Snapshot(dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return snap, fs
}

func inspect(t *testing.T, files map[string]string) checks.Result {
	t.Helper()
	root, fs := repo(t, files)
	return Inspect(root, fs)
}

func TestCleanRepoPasses(t *testing.T) {
	r := inspect(t, map[string]string{"config.json": `{"model_type":"llama"}`, "tokenizer.json": `{"model":{}}`, "vocab.json": `["a"]`})
	if r.Status != checks.Pass || len(r.Findings) != 0 {
		t.Fatalf("status %s (%s)", r.Status, r.Notes)
	}
}

// #254: a training script, an evaluation script, and reference inference
// code that no loader config names are listed, not judged, and the note does
// not say a loader runs them.
func TestScriptsNoLoaderNamesAreListedNotJudged(t *testing.T) {
	files := map[string]string{
		"config.json":           `{"model_type":"bert"}`,
		"modules.json":          `[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"},{"idx":1,"name":"1","path":"1_Pooling","type":"sentence_transformers.models.Pooling"}]`,
		"1_Pooling/config.json": `{"word_embedding_dimension":384,"pooling_mode_mean_tokens":true}`,
		"train_script.py":       "import os\nfrom sentence_transformers import SentenceTransformer\n",
		"eval.py":               "import torch\n",
		"inference/model.py":    "from .kernel import act\n",
		"inference/kernel.py":   "import os\n",
		"encoding/encoding.py":  "import json\n",
		"notebooks/demo.ipynb":  `{"cells":[]}`,
		"scripts/download.sh":   "#!/bin/sh\n",
	}
	r := inspect(t, files)
	if r.Status != checks.Pass || len(r.Findings) != 0 {
		t.Fatalf("status %s, findings %v (%s)", r.Status, r.Findings, r.Notes)
	}
	for _, f := range []string{"train_script.py", "eval.py", "inference/model.py", "inference/kernel.py", "encoding/encoding.py", "notebooks/demo.ipynb", "scripts/download.sh"} {
		if !strings.Contains(r.Notes, f) {
			t.Errorf("the note must list %s: %s", f, r.Notes)
		}
	}
	if !strings.Contains(r.Notes, "imported by none of these (listed, not judged)") || strings.Contains(r.Notes, "runs") {
		t.Errorf("the note must say what Socair established, not that a loader runs the file: %s", r.Notes)
	}
}

// Falsification: each way a loader is told to import repository code is a
// LEAD naming the file. Drop any one reader and its case passes.
func TestLoaderReferencesAreLeadsNamingTheFiles(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  []string // files and words the evidence must name
	}{
		"auto_map in config.json": {map[string]string{
			"config.json": `{"auto_map":{"AutoModelForCausalLM":"modeling_x.XForCausalLM"}}`, "modeling_x.py": "import torch\n"},
			[]string{"modeling_x.py", "AutoModelForCausalLM"}},
		"auto_map in tokenizer_config.json, slow and fast": {map[string]string{
			"config.json": `{}`, "tokenizer_config.json": `{"auto_map":{"AutoTokenizer":["tok.XTokenizer", null]}}`, "tok.py": ""},
			[]string{"tok.py", "AutoTokenizer[0]"}},
		"legacy tokenizer auto_map list": {map[string]string{
			"tokenizer_config.json": `{"auto_map":["tok_slow.T", "tok_fast.TFast"]}`, "tok_slow.py": "", "tok_fast.py": ""},
			[]string{"tok_slow.py", "tok_fast.py"}},
		"auto_map in preprocessor_config.json": {map[string]string{
			"preprocessor_config.json": `{"auto_map":{"AutoProcessor":"processing_x.P","AutoImageProcessor":"image_processing_x.I"}}`,
			"processing_x.py":          "", "image_processing_x.py": ""},
			[]string{"processing_x.py", "image_processing_x.py"}},
		"auto_map in processor_config.json": {map[string]string{
			"processor_config.json": `{"auto_map":{"AutoProcessor":"proc.P"}}`, "proc.py": ""},
			[]string{"proc.py"}},
		"image processor auto_map by backend": {map[string]string{
			"preprocessor_config.json": `{"auto_map":{"AutoImageProcessor":{"torchvision":"ip_fast.F","pil":"ip_slow.S"}}}`, "ip_fast.py": "", "ip_slow.py": ""},
			[]string{"ip_fast.py", "ip_slow.py"}},
		"auto_map in video_preprocessor_config.json": {map[string]string{
			"video_preprocessor_config.json": `{"auto_map":{"AutoVideoProcessor":"video_x.V"}}`, "video_x.py": ""},
			[]string{"video_x.py"}},
		"auto_map in feature extractor config": {map[string]string{
			"preprocessor_config.json": `{"auto_map":{"AutoFeatureExtractor":"fe.F"}}`, "fe.py": ""},
			[]string{"fe.py"}},
		"auto_map in a sub-config": {map[string]string{
			"config.json": `{"model_type":"llava","text_config":{"auto_map":{"AutoModel":"text_model.T"}}}`, "text_model.py": ""},
			[]string{"text_model.py", "text_config.auto_map AutoModel"}},
		"auto_map in a diffusers component config": {map[string]string{
			"model_index.json": `{"_class_name":"StableDiffusionPipeline","unet":["diffusers","UNet2DConditionModel"]}`,
			"unet/config.json": `{"auto_map":{"AutoModel":"my_unet.MyUNet"}}`, "unet/my_unet.py": ""},
			[]string{"unet/my_unet.py"}},
		"auto_map in modular_config.json": {map[string]string{
			"modular_config.json": `{"auto_map":{"ModularPipelineBlocks":"block.MyBlocks"}}`, "block.py": ""},
			[]string{"block.py"}},
		"auto_map naming a subdirectory module": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"code/modeling.M"}}`, "code/modeling.py": ""},
			[]string{"code/modeling.py"}},
		"custom_pipelines": {map[string]string{
			"config.json":            `{"custom_pipelines":{"pair-classification":{"impl":"pair_classification.PairClassificationPipeline","pt":["AutoModelForSequenceClassification"]}}}`,
			"pair_classification.py": ""},
			[]string{"pair_classification.py", "custom_pipelines pair-classification impl"}},
		"sentence-transformers custom module": {map[string]string{
			"modules.json": `[{"idx":0,"name":"0","path":"","type":"custom_st.Transformer"},{"idx":1,"name":"1","path":"1_Pooling","type":"sentence_transformers.models.Pooling"}]`,
			"custom_st.py": "import torch\n"},
			[]string{"custom_st.py", "modules.json: [0] type"}},
		"sentence-transformers custom module as a package": {map[string]string{
			"modules.json":       `[{"idx":0,"name":"0","path":"","type":"my_pkg.layers.Pool"}]`,
			"my_pkg/__init__.py": "", "my_pkg/layers.py": ""},
			[]string{"my_pkg/__init__.py", "my_pkg/layers.py"}},
		"sentence-transformers Router types": {map[string]string{
			"modules.json":                `[{"idx":0,"name":"0","path":"0_Router","type":"sentence_transformers.models.Router"}]`,
			"0_Router/router_config.json": `{"types":{"query":"query_mod.Q","document":"sentence_transformers.models.Transformer"},"structure":{"query":["query"],"document":["document"]}}`,
			"query_mod.py":                ""},
			[]string{"query_mod.py", "types query"}},
		"sentence-transformers legacy Asym config": {map[string]string{
			"2_Asym/config.json": `{"types":{"q":"asym_mod.Q"},"structure":{"query":["q"]},"parameters":{}}`, "asym_mod.py": ""},
			[]string{"asym_mod.py"}},
		"sentence-transformers WordEmbeddings tokenizer_class": {map[string]string{
			"0_WordEmbeddings/wordembedding_config.json": `{"tokenizer_class":"wtok.Tok","update_embeddings":false}`, "wtok.py": ""},
			[]string{"wtok.py"}},
		"sentence-transformers Dense activation_function": {map[string]string{
			"2_Dense/config.json": `{"in_features":768,"out_features":768,"bias":true,"activation_function":"act.Fn"}`, "act.py": ""},
			[]string{"act.py"}},
		"CrossEncoder activation_fn": {map[string]string{
			"config.json": `{"model_type":"bert","sentence_transformers":{"activation_fn":"ce_act.Fn"}}`, "ce_act.py": ""},
			[]string{"ce_act.py"}},
		"CrossEncoder legacy activation": {map[string]string{
			"config.json": `{"model_type":"bert","sbert_ce_default_activation_function":"ce_old.Fn"}`, "ce_old.py": ""},
			[]string{"ce_old.py"}},
		"diffusers custom pipeline": {map[string]string{
			"model_index.json": `{"_class_name":["pipeline_t2v","TextToVideoPipeline"],"unet":["diffusers","UNet3DConditionModel"]}`, "pipeline_t2v.py": ""},
			[]string{"pipeline_t2v.py"}},
		"diffusers custom component": {map[string]string{
			"model_index.json": `{"_class_name":"MyPipeline","unet":["showone_unet","ShowOneUNet"]}`, "unet/showone_unet.py": ""},
			[]string{"unet/showone_unet.py"}},
		"custom_generate/generate.py": {map[string]string{
			"config.json": `{"model_type":"qwen2"}`, "custom_generate/generate.py": "def generate(model, **kw): pass\n"},
			[]string{"custom_generate/generate.py"}},
		"inference toolkit handler.py": {map[string]string{"handler.py": "class EndpointHandler: pass\n"},
			[]string{"handler.py", "without trust_remote_code"}},
		"inference toolkit legacy pipeline.py": {map[string]string{"pipeline.py": "class PreTrainedPipeline: pass\n"},
			[]string{"pipeline.py"}},
		"SageMaker code/inference.py": {map[string]string{"code/inference.py": "def model_fn(d): pass\n"},
			[]string{"code/inference.py"}},
	}
	for name, c := range cases {
		r := inspect(t, c.files)
		if r.Status != checks.Lead {
			t.Errorf("%s: status %s, want LEAD (%s)", name, r.Status, r.Notes)
			continue
		}
		ev := evidence(r)
		for _, w := range c.want {
			if !strings.Contains(ev, w) {
				t.Errorf("%s: the evidence must name %q: %s", name, w, ev)
			}
		}
	}
}

// Falsification: a file reached only through an import of a named module is
// named, transitively, by relative and absolute imports, multi-line
// from-imports, packages, and importlib with a literal name. Neuter follow
// and these files are listed as not imported.
func TestImportedFilesAreNamedTransitively(t *testing.T) {
	r := inspect(t, map[string]string{
		"config.json":     `{"auto_map":{"AutoModel":"modeling_x.M"}}`,
		"modeling_x.py":   "from .layers import L\nimport helpers\nfrom . import (\n    rope,  # comment\n    cache,\n)\nfrom .pkg.mod import thing\nimportlib.import_module('.plugin', __package__)\n",
		"layers.py":       "from .deep import D\n",
		"deep.py":         "import os\n",
		"helpers.py":      "",
		"rope.py":         "",
		"cache.py":        "",
		"pkg/__init__.py": "",
		"pkg/mod.py":      "",
		"plugin.py":       "",
		"train.py":        "import modeling_x\n",
	})
	if r.Status != checks.Lead {
		t.Fatalf("status %s", r.Status)
	}
	ev := evidence(r)
	for _, f := range []string{"layers.py (from modeling_x.py)", "deep.py (from layers.py)", "helpers.py", "rope.py", "cache.py", "pkg/__init__.py", "pkg/mod.py", "plugin.py"} {
		if !strings.Contains(ev, f) {
			t.Errorf("the evidence must name %s: %s", f, ev)
		}
	}
	// train.py imports the model; nothing imports train.py.
	if strings.Contains(ev, "train.py") || !strings.Contains(r.Notes, "imported by none of these (listed, not judged): train.py") {
		t.Errorf("train.py is imported by nothing a loader names: %s / %s", ev, r.Notes)
	}
}

// transformers' get_relative_import_files joins a relative import at any
// depth to the first module's directory, so a nested module's ".x" can name a
// file beside the entry; Python's package rules name the one beside the
// importer. Both are named.
func TestRelativeImportsResolveBothWays(t *testing.T) {
	r := inspect(t, map[string]string{
		"config.json":       `{"auto_map":{"AutoModel":"modeling.M"}}`,
		"modeling.py":       "from .pkg import inner\n",
		"pkg/__init__.py":   "",
		"pkg/inner.py":      "from .beside import Y\n",
		"pkg/beside.py":     "",
		"beside.py":         "",
		"pkg/nested/one.py": "",
	})
	ev := evidence(r)
	imported := map[string]bool{}
	for _, f := range r.Findings {
		if f.Pattern == "imported-code" {
			for _, e := range strings.Split(f.Span, ", ") {
				imported[e] = true
			}
		}
	}
	for _, f := range []string{"pkg/__init__.py (from modeling.py)", "pkg/inner.py (from modeling.py)", "pkg/beside.py (from pkg/inner.py)", "beside.py (from pkg/inner.py)"} {
		if !imported[f] {
			t.Errorf("the evidence must name %s: %s", f, ev)
		}
	}
	if strings.Contains(ev, "nested/one.py") || !strings.Contains(r.Notes, "pkg/nested/one.py") {
		t.Errorf("nothing imports pkg/nested/one.py: %s / %s", ev, r.Notes)
	}
}

// Code in another repository, a path outside the directory, and a module the
// directory does not contain are LEADs: a loader would import code this
// artifact does not carry. Falsification: treat any of them as no reference
// and the case passes.
func TestReferencesOutsideTheArtifactAreLeads(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"auto_map in another repository": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"nomic-ai/nomic-bert-2048--modeling_hf_nomic_bert.NomicBertModel"}}`},
			"another repository, nomic-ai/nomic-bert-2048"},
		"sentence-transformers module in another repository": {map[string]string{
			"modules.json": `[{"idx":0,"name":"0","path":"","type":"evil/repo--mod.Cls"}]`}, "another repository, evil/repo"},
		"custom_pipelines in another repository": {map[string]string{
			"config.json": `{"custom_pipelines":{"t":{"impl":"evil/repo--pipe.P"}}}`}, "another repository, evil/repo"},
		"auto_map to an absolute path": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"/tmp/evil.M"}}`}, "outside this directory"},
		"auto_map climbing out": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"sub/../../evil.M"}}`}, "outside this directory"},
		"auto_map with a backslash": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"..\\evil.M"}}`}, "outside this directory"},
		"auto_map with a drive": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"C:/evil.M"}}`}, "outside this directory"},
		"auto_map to a local repository path": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"/srv/other--modeling.M"}}`}, "another repository, /srv/other"},
		"sentence-transformers module at an absolute path": {map[string]string{
			"modules.json": `[{"idx":0,"name":"0","path":"","type":"/tmp/evil.Cls"}]`}, "outside this directory"},
		"diffusers component outside": {map[string]string{
			"model_index.json": `{"../../tmp":["evil","E"]}`}, "outside this directory"},
		"auto_map module missing": {map[string]string{
			"config.json": `{"auto_map":{"AutoModel":"modeling_gone.M"}}`}, "does not contain"},
		"custom_pipelines module missing": {map[string]string{
			"config.json": `{"custom_pipelines":{"t":{"impl":"pipe_gone.P"}}}`}, "does not contain"},
		"diffusers custom pipeline missing": {map[string]string{
			"model_index.json": `{"_class_name":["pipeline_gone","P"]}`}, "does not contain"},
	}
	for name, c := range cases {
		r := inspect(t, c.files)
		if r.Status != checks.Lead || !strings.Contains(evidence(r), c.want) {
			t.Errorf("%s: %s, evidence %q, want LEAD naming %q", name, r.Status, evidence(r), c.want)
		}
	}
}

// A dotted reference cannot climb out of the directory: its leading dots
// are dropped, and the file it then names is named.
func TestDottedReferenceTricksStayInside(t *testing.T) {
	r := inspect(t, map[string]string{"config.json": `{"auto_map":{"AutoModel":"..evil.M"}}`, "evil.py": ""})
	if r.Status != checks.Lead || !strings.Contains(evidence(r), "names evil.py") {
		t.Fatalf("%s: %s", r.Status, evidence(r))
	}
}

// A case-insensitive file system opens Modeling_X.py for modeling_x.
func TestCaseInsensitiveMatchIsNamed(t *testing.T) {
	r := inspect(t, map[string]string{"config.json": `{"auto_map":{"AutoModel":"modeling_x.M"}}`, "Modeling_X.py": ""})
	if !strings.Contains(evidence(r), "Modeling_X.py") || strings.Contains(r.Notes, "imported by none") {
		t.Fatalf("%s / %s", evidence(r), r.Notes)
	}
}

// A diffusers component whose library name is a file in its folder is loaded
// from that file, not from the library (pipeline_loading_utils.py
// get_class_obj_and_candidates): a standard-looking model_index.json entry
// with unet/diffusers.py beside it runs that file.
func TestDiffusersComponentShadowingTheLibrary(t *testing.T) {
	r := inspect(t, map[string]string{
		"model_index.json":  `{"_class_name":"StableDiffusionPipeline","unet":["diffusers","UNet2DConditionModel"],"vae":["diffusers","AutoencoderKL"]}`,
		"unet/diffusers.py": "import os\n",
	})
	if r.Status != checks.Lead || !strings.Contains(evidence(r), "unet/diffusers.py") {
		t.Fatalf("%s: %s", r.Status, evidence(r))
	}
	clean := inspect(t, map[string]string{"model_index.json": `{"_class_name":"StableDiffusionPipeline","unet":["diffusers","UNet2DConditionModel"]}`})
	if clean.Status != checks.Pass {
		t.Fatalf("a standard pipeline: %s (%s)", clean.Status, clean.Notes)
	}
}

// A sentence-transformers class the directory holds no file for comes from
// an installed package (PyLate's modules), or the load fails: it is named in
// the notes and not judged. The library's own classes are not named.
func TestInstalledPackageClassIsNotedNotJudged(t *testing.T) {
	r := inspect(t, map[string]string{
		"modules.json":        `[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"},{"idx":1,"name":"1","path":"1_Dense","type":"pylate.models.Dense.Dense"}]`,
		"1_Dense/config.json": `{"in_features":768,"out_features":128,"activation_function":"torch.nn.modules.linear.Identity"}`,
	})
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "pylate.models.Dense.Dense, which this directory holds no file for") ||
		strings.Contains(r.Notes, "sentence_transformers.models.Transformer") || strings.Contains(r.Notes, "torch.nn") {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
}

// A repository file that shadows the library's name is imported from
// Python's path when a process runs from the directory.
func TestLibraryNameShadowedByARepositoryFile(t *testing.T) {
	r := inspect(t, map[string]string{
		"modules.json":                      `[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"}]`,
		"sentence_transformers/__init__.py": "import os\n",
	})
	if r.Status != checks.Lead || !strings.Contains(evidence(r), "sentence_transformers/__init__.py") {
		t.Fatalf("%s: %s", r.Status, evidence(r))
	}
}

func TestEmptyAutoMapNamesNothing(t *testing.T) {
	if r := inspect(t, map[string]string{"config.json": `{"auto_map":{}}`}); r.Status != checks.Pass {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
}

// Python's json module reads NaN and Infinity, and Nemotron-H's config.json
// holds Infinity; the auto_map beside it must be read. Falsification: decode
// with encoding/json alone and this is NOT_TESTED.
func TestPythonJSONConstantsAreRead(t *testing.T) {
	r := inspect(t, map[string]string{
		"config.json":   `{"time_step_limit":[0.0, Infinity],"x":-Infinity,"y":NaN,"s":"Infinity \"NaN\"","auto_map":{"AutoModel":"modeling_h.M"}}`,
		"modeling_h.py": "",
	})
	if r.Status != checks.Lead || !strings.Contains(evidence(r), "modeling_h.py") {
		t.Fatalf("%s: %s / %s", r.Status, evidence(r), r.Notes)
	}
}

func TestUnparseableConfigIsNotTested(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"config.json":  {"config.json": `{"auto_map": `},
		"modules.json": {"modules.json": `[{"type": "custom.X"`, "custom.py": ""},
	} {
		if r := inspect(t, files); r.Status != checks.NotTested {
			t.Errorf("%s: status %s: an unreadable config may hide a reference", name, r.Status)
		}
	}
}

func TestImportScanner(t *testing.T) {
	src := "import a, b.c as d\nfrom .e import (f,\n  g as h)  # x\nfrom .. import i\nfrom j.k import *\nx = 1; import l\nimport .m\n" +
		"y = importlib.import_module(\"n.o\")\n__import__('p')\nfrom q import r, \\\n  s\n# import commented\n"
	got := scanImports([]byte(src))
	want := []pyImport{
		{0, "a", nil}, {0, "b.c", nil},
		{1, "e", []string{"f", "g"}},
		{2, "", []string{"i"}},
		{0, "j.k", nil},
		{0, "l", nil},
		{1, "m", nil},
		{0, "n.o", nil},
		{0, "p", nil},
		{0, "q", []string{"r", "s"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// A config with more references than are read says so, in a LEAD's notes.
func TestTooManyReferencesAreNamedAsUnread(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"auto_map":{`)
	for i := 0; i <= maxRefsPerFile; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"Auto%d":"m.X"`, i)
	}
	b.WriteString(`}}`)
	r := inspect(t, map[string]string{"config.json": b.String(), "m.py": ""})
	if r.Status != checks.Lead || !strings.Contains(r.Notes, "the rest not read") || len(r.Findings) > maxFindings+2 {
		t.Fatalf("%s, %d findings: %s", r.Status, len(r.Findings), r.Notes)
	}
}

func evidence(r checks.Result) string {
	var parts []string
	for _, f := range r.Findings {
		parts = append(parts, f.Pattern+": "+f.Span+" ("+f.Detail+")")
	}
	return strings.Join(parts, "; ")
}
