//go:build js && wasm

// Command socair-preview is Socair's engine built for a browser, for
// socair.ai's preview of a Hugging Face model. The page mounts the repo as a
// filesystem whose reads are HTTP range requests (tools/socair-preview) and
// calls socairPreview(dir, hashesJSON), which reads it with engine.PreviewDir
// and resolves to the report as JSON and as HTML.
package main

import (
	"bytes"
	"encoding/json"
	"syscall/js"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render"
	rpt "github.com/defilantech/socair/internal/report"
)

func main() {
	js.Global().Set("socairPreview", js.FuncOf(preview))
	js.Global().Set("socairPreviewFile", js.FuncOf(previewFile))
	js.Global().Set("socairVersion", engine.Version)
	select {}
}

// preview returns a Promise for the report of the directory args[0], with
// each file's SHA-256 as its source states it in the JSON object args[1].
func preview(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return js.Global().Get("Promise").Call("reject", "socairPreview(dir, hashesJSON)")
	}
	dir, hashesJSON := args[0].String(), args[1].String()
	var run js.Func
	run = js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve, reject := p[0], p[1]
		go func() {
			defer run.Release()
			out, err := report(dir, hashesJSON)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(js.ValueOf(out))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(run)
}

// previewFile returns a Promise for the header-only report of the single file
// args[0], for a file whose own metadata carries checks a directory scan
// does not run on it (a GGUF's chat template, tokenizer, and quant).
func previewFile(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return js.Global().Get("Promise").Call("reject", "socairPreviewFile(path)")
	}
	path := args[0].String()
	var run js.Func
	run = js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve, reject := p[0], p[1]
		go func() {
			defer run.Release()
			d, err := engine.ScanMode(path, engine.ModeHeaders)
			if err == nil {
				var out map[string]any
				if out, err = documents(d); err == nil {
					resolve.Invoke(js.ValueOf(out))
					return
				}
			}
			reject.Invoke(err.Error())
		}()
		return nil
	})
	return js.Global().Get("Promise").New(run)
}

func report(dir, hashesJSON string) (map[string]any, error) {
	var hashes map[string]string
	if err := json.Unmarshal([]byte(hashesJSON), &hashes); err != nil {
		return nil, err
	}
	d, err := engine.PreviewDir(dir, hashes)
	if err != nil {
		return nil, err
	}
	return documents(d)
}

// documents is the report as JSON and as the HTML a scan renders.
func documents(d *rpt.Document) (map[string]any, error) {
	doc, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var html bytes.Buffer
	if err := render.Render(&html, d); err != nil {
		return nil, err
	}
	return map[string]any{"json": string(doc), "html": html.String()}, nil
}
