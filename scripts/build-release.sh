#!/usr/bin/env bash
# Build Socair's release binaries reproducibly.
#
#   scripts/build-release.sh [--check] <version> <outdir>
#
# Builds socair and socair-sigstore for linux and darwin, amd64 and arm64,
# from vendored modules with no network, no cgo, -trimpath, and an empty
# build id, stamping <version> into both. Writes <outdir>/SHA256SUMS.
#
# With --check it builds everything a second time from an empty build cache
# and requires byte-identical output, so a release is only cut from a build
# that reproduces. Anyone can rebuild a release the same way: check out the
# tag, use the Go version `go version -m <binary>` reports, and run this
# script; the SHA256SUMS must match.
set -euo pipefail

check=0
if [[ "${1:-}" == "--check" ]]; then
	check=1
	shift
fi
version="${1:?usage: build-release.sh [--check] <version> <outdir>}"
out="${2:?usage: build-release.sh [--check] <version> <outdir>}"
if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]]; then
	echo "version $version: use a plain version string, e.g. 0.2.0" >&2
	exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# build <outdir> <gocache>
build() {
	local dir="$1" cache="$2"
	mkdir -p "$dir"
	for t in "${targets[@]}"; do
		local os="${t%/*}" arch="${t#*/}"
		(cd "$root" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOFLAGS=-mod=vendor GOCACHE="$cache" GOPROXY=off \
			go build -trimpath -ldflags "-s -w -buildid= -X github.com/defilantech/socair/internal/engine.Version=$version" \
			-o "$dir/socair_${version}_${os}_${arch}" ./cmd/socair)
		(cd "$root/tools/socair-sigstore" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOFLAGS=-mod=vendor GOCACHE="$cache" GOPROXY=off \
			go build -trimpath -ldflags "-s -w -buildid= -X main.version=$version" \
			-o "$dir/socair-sigstore_${version}_${os}_${arch}" .)
	done
	(cd "$dir" && sha256 socair* > SHA256SUMS)
}

# Every build writes outside the checkout. Go stamps whether the checkout
# has changes (vcs.modified), and build output left in the tree would count
# as one, so the tree stays exactly as checked out while building.
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT

build "$tmp/first" "$tmp/cache1"
if [[ "$check" == 1 ]]; then
	build "$tmp/second" "$tmp/cache2"
	if ! diff "$tmp/first/SHA256SUMS" "$tmp/second/SHA256SUMS"; then
		echo "the build does not reproduce: a second build from an empty cache differs (above)" >&2
		exit 1
	fi
	echo "reproducible: a second build from an empty cache is byte-identical"
fi

mkdir -p "$out"
cp "$tmp/first/"* "$out/"
echo "built $(grep -c . "$out/SHA256SUMS") binaries with $(go version | cut -d' ' -f3) into $out"
if (cd "$root" && [[ -n "$(git status --porcelain 2>/dev/null)" ]]); then
	echo "note: the checkout has changes, so these binaries record vcs.modified=true and will not match a release build" >&2
fi
