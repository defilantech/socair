#!/usr/bin/env bash
# Builds the browser preview into dist/: the engine as WebAssembly, Go's
# wasm_exec.js loader for it, and the page.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$here/dist"
mkdir -p "$out"
(cd "$repo" && GOOS=js GOARCH=wasm GOFLAGS=-mod=vendor CGO_ENABLED=0 \
	go build -trimpath -ldflags "-s -w -buildid= -X github.com/defilantech/socair/internal/engine.Version=${SOCAIR_VERSION:-preview}" \
	-o "$out/socair.wasm" ./cmd/socair-preview)
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/"
cp "$here/hffs.js" "$here/app.js" "$here/index.html" "$out/"
gzip -9 -k -f "$out/socair.wasm"
ls -l "$out"
