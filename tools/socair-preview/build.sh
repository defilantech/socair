#!/usr/bin/env bash
# Builds the preview into tools/socair-preview/dist/ for try.mjs and local
# work: the engine for js/wasm, and Go's wasm_exec.js loader for it. A release
# carries the same three files (scripts/build-release.sh).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$here/dist"
mkdir -p "$out"
(cd "$repo" && GOOS=js GOARCH=wasm GOFLAGS=-mod=vendor CGO_ENABLED=0 \
	go build -trimpath -ldflags "-s -w -buildid= -X github.com/defilantech/socair/internal/engine.Version=${SOCAIR_VERSION:-dev}" \
	-o "$out/socair-preview.wasm" ./cmd/socair-preview)
cp "$(cd "$repo" && go env GOROOT)/lib/wasm/wasm_exec.js" "$out/"
ls -l "$out"
