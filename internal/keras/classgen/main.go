// Command classgen writes the class names Keras registers itself, for
// internal/keras/keras-classes.txt:
//
//	go run ./internal/keras/classgen keras-3.15.1-py3-none-any.whl \
//	  tf_keras-2.21.0-py3-none-any.whl > internal/keras/keras-classes.txt
//
// It reads the wheels as zip files (nothing is installed or imported) and
// collects, from each:
//
//   - every name exported with keras_export under the namespaces whose
//     classes appear in a config (keras.layers, keras.initializers,
//     keras.regularizers, keras.constraints, keras.optimizers, keras.losses,
//     keras.metrics, keras.models, keras.mixed_precision,
//     keras.dtype_policies, and the top-level classes), and the class the
//     export decorates;
//   - every public class defined in the layer and engine modules, which
//     tf_keras's layer deserializer registers whether exported or not
//     (Functional, TFOpLambda, SlicingOpLambda, TensorFlowOpLayer).
//
// The output is a superset of what Keras resolves by name: a helper class
// listed here and not registered still fails to load, and runs nothing.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var namespaces = []string{
	"keras.layers.", "keras.initializers.", "keras.regularizers.", "keras.constraints.",
	"keras.optimizers.", "keras.losses.", "keras.metrics.", "keras.models.",
	"keras.mixed_precision.", "keras.dtype_policies.", "keras.quantizers.",
	"keras.Model", "keras.Sequential", "keras.Input", "keras.Layer", "keras.Variable",
	"keras.DTypePolicy", "keras.FloatDTypePolicy", "keras.Initializer", "keras.Loss",
	"keras.Metric", "keras.Optimizer", "keras.Quantizer", "keras.Regularizer", "keras.InputSpec",
}

var definedDirs = []string{"tf_keras/src/layers/", "tf_keras/src/engine/", "tf_keras/src/premade_models/",
	"keras/src/layers/", "keras/src/models/"}

var (
	export   = regexp.MustCompile(`keras_export\(\s*((?:"[^"]*"\s*,?\s*|\[[^\]]*\]\s*,?\s*)+)`)
	quoted   = regexp.MustCompile(`"([^"]+)"`)
	classDef = regexp.MustCompile(`(?m)^class\s+([A-Z]\w*)\s*\(`)
	after    = regexp.MustCompile(`\)\s*\n\s*class\s+(\w+)`)
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: classgen <keras wheel> [<tf_keras wheel> ...]")
		os.Exit(2)
	}
	names := map[string]bool{}
	var sources []string
	for _, whl := range os.Args[1:] {
		sum, err := collect(whl, names)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sources = append(sources, fmt.Sprintf("# %s sha256:%s", filepath.Base(whl), sum))
	}
	out := make([]string, 0, len(names))
	for n := range names {
		if !strings.HasSuffix(n, "Test") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	fmt.Println("# Class names Keras registers itself, written by internal/keras/classgen from:")
	for _, s := range sources {
		fmt.Println(s)
	}
	for _, n := range out {
		fmt.Println(n)
	}
}

func collect(whl string, names map[string]bool) (string, error) {
	raw, err := os.ReadFile(whl)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	zr, err := zip.OpenReader(whl)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".py") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return "", err
		}
		src := string(b)
		for _, m := range export.FindAllStringSubmatchIndex(src, -1) {
			args := src[m[2]:m[3]]
			rest := src[m[1]:min(len(src), m[1]+400)]
			cls := after.FindStringSubmatchIndex(rest)
			isClass := cls != nil && strings.Count(rest[:cls[0]], "@") <= 2
			for _, q := range quoted.FindAllStringSubmatch(args, -1) {
				e := strings.Replace(q[1], "tf_keras.", "keras.", 1)
				if !exported(e) {
					continue
				}
				leaf := e[strings.LastIndex(e, ".")+1:]
				if leaf != "" && leaf[0] >= 'A' && leaf[0] <= 'Z' {
					names[leaf] = true
				}
				if isClass {
					names[rest[cls[2]:cls[3]]] = true
				}
			}
		}
		if defined(f.Name) {
			for _, m := range classDef.FindAllStringSubmatch(src, -1) {
				names[m[1]] = true
			}
		}
	}
	return hex.EncodeToString(sum[:]), nil
}

func exported(e string) bool {
	for _, ns := range namespaces {
		if strings.HasPrefix(e, ns) || e == ns {
			return true
		}
	}
	return false
}

func defined(name string) bool {
	if strings.Contains(name, "/test") || strings.HasSuffix(name, "_test.py") {
		return false
	}
	for _, d := range definedDirs {
		if strings.HasPrefix(name, d) {
			return true
		}
	}
	return false
}
