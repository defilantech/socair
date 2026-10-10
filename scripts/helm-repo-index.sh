#!/usr/bin/env bash
# Add a packaged chart to a Helm repository index, the index.yaml served from
# the gh-pages branch at https://defilantech.github.io/socair (where Defilan's
# other charts are: https://defilantech.github.io/LLMKube).
#
#   scripts/helm-repo-index.sh <chart.tgz> <download-url-dir> <index.yaml>
#
# The chart itself stays a release asset: the entry points at
# <download-url-dir>/<chart.tgz>, and the index records its SHA-256, which
# helm checks on download. Entries already in <index.yaml> are kept; one with
# the same name and version is replaced. <index.yaml> need not exist yet.
set -euo pipefail

chart="${1:?usage: helm-repo-index.sh <chart.tgz> <download-url-dir> <index.yaml>}"
url="${2:?usage: helm-repo-index.sh <chart.tgz> <download-url-dir> <index.yaml>}"
index="${3:?usage: helm-repo-index.sh <chart.tgz> <download-url-dir> <index.yaml>}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$chart" "$work/"
if [[ -s "$index" ]]; then
	helm repo index "$work" --url "$url" --merge "$index"
else
	helm repo index "$work" --url "$url"
fi
cp "$work/index.yaml" "$index"
