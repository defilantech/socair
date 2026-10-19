//go:build js && wasm

// Command socair-preview is Socair's engine built for a browser, for the
// preview at socair.ai/try (docs/preview.md). The page mounts a Hugging Face
// repo as a read-only filesystem whose reads are HTTP range requests
// (tools/socair-preview/hffs.js) and calls:
//
//	socairPreview(dir, sourceJSON, hashesJSON)      // the repo as a model directory
//	socairPreviewGGUF(path, sourceJSON, sha256)     // one GGUF's own metadata
//
// Each returns a Promise for an engine.Preview as JSON. A preview is never a
// report: this command has no signing, no promotion, and no renderer.
package main

import (
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/defilantech/socair/internal/engine"
)

func main() {
	js.Global().Set("socairPreview", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return promise(func() (*engine.Preview, error) {
			if len(args) != 3 {
				return nil, errors.New("socairPreview(dir, sourceJSON, hashesJSON)")
			}
			src, err := source(args[1].String())
			if err != nil {
				return nil, err
			}
			var hashes map[string]string
			if err := json.Unmarshal([]byte(args[2].String()), &hashes); err != nil {
				return nil, err
			}
			return engine.PreviewDir(args[0].String(), src, hashes)
		})
	}))
	js.Global().Set("socairPreviewGGUF", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return promise(func() (*engine.Preview, error) {
			if len(args) != 3 {
				return nil, errors.New("socairPreviewGGUF(path, sourceJSON, sha256)")
			}
			src, err := source(args[1].String())
			if err != nil {
				return nil, err
			}
			return engine.PreviewGGUF(args[0].String(), src, args[2].String())
		})
	}))
	js.Global().Set("socairVersion", engine.Version)
	select {}
}

func source(s string) (engine.PreviewSource, error) {
	var src engine.PreviewSource
	err := json.Unmarshal([]byte(s), &src)
	return src, err
}

// promise runs f off the event loop, since it reads through the page's
// filesystem, and resolves to its preview as JSON.
func promise(f func() (*engine.Preview, error)) js.Value {
	var run js.Func
	run = js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve, reject := p[0], p[1]
		go func() {
			defer run.Release()
			pv, err := f()
			if err == nil {
				var b []byte
				if b, err = json.Marshal(pv); err == nil {
					resolve.Invoke(string(b))
					return
				}
			}
			reject.Invoke(err.Error())
		}()
		return nil
	})
	return js.Global().Get("Promise").New(run)
}
