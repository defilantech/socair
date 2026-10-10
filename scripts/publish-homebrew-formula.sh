#!/usr/bin/env bash
# Render Formula/socair.rb from a release's SHA256SUMS and publish it to the
# Defilan Homebrew tap, so `brew install defilantech/tap/socair` installs it
# the way `brew install defilantech/tap/llmkube` installs LLMKube.
#
#   scripts/publish-homebrew-formula.sh <version> [SHA256SUMS]
#
# The formula downloads the release's own binary for the platform and checks
# it against the SHA-256 in SHA256SUMS, so a Homebrew install runs the same
# bytes as the release and its provenance attestation still verifies. It
# installs `socair` only; the optional `socair-sigstore` helper stays a
# release download.
#
# DRY_RUN=1 prints the formula and exits (no clone, no push).
# SOCAIR_RELEASE_URL overrides where the binaries are downloaded from (CI
# points it at a local build to install the formula for real).
# Publishing needs HOMEBREW_TAP_TOKEN, a token that can push to the tap.
set -euo pipefail

version="${1:?usage: publish-homebrew-formula.sh <version> [SHA256SUMS]}"
sums="${2:-dist/SHA256SUMS}"
tap=defilantech/homebrew-tap
base="${SOCAIR_RELEASE_URL:-https://github.com/defilantech/socair/releases/download/v${version}}"

# sha_for prints the SHA-256 of socair_<version>_<os>_<arch> from SHA256SUMS
# ("<sha256>  <file>" lines).
sha_for() {
	local f="socair_${version}_$1" sum
	sum=$(awk -v f="$f" '$2 == f { print $1 }' "$sums")
	[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "no checksum for $f in $sums" >&2; exit 1; }
	echo "$sum"
}

darwin_arm64=$(sha_for darwin_arm64)
darwin_amd64=$(sha_for darwin_amd64)
linux_arm64=$(sha_for linux_arm64)
linux_amd64=$(sha_for linux_amd64)

render() {
	cat <<EOF
class Socair < Formula
  desc "Signed assurance attestations for open-weight AI models"
  homepage "https://socair.ai"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "${base}/socair_${version}_darwin_arm64"
      sha256 "${darwin_arm64}"
    end
    on_intel do
      url "${base}/socair_${version}_darwin_amd64"
      sha256 "${darwin_amd64}"
    end
  end

  on_linux do
    on_arm do
      url "${base}/socair_${version}_linux_arm64"
      sha256 "${linux_arm64}"
    end
    on_intel do
      url "${base}/socair_${version}_linux_amd64"
      sha256 "${linux_amd64}"
    end
  end

  def install
    bin.install Dir["socair_*"].first => "socair"
  end

  test do
    assert_equal "socair #{version}", shell_output("#{bin}/socair version").strip
  end
end
EOF
}

if [[ "${DRY_RUN:-}" == 1 ]]; then
	render
	exit 0
fi

: "${HOMEBREW_TAP_TOKEN:?HOMEBREW_TAP_TOKEN is required to push the tap}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone -q --depth 1 "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${tap}.git" "$work/tap"
mkdir -p "$work/tap/Formula"
render >"$work/tap/Formula/socair.rb"
git -C "$work/tap" add Formula/socair.rb
if git -C "$work/tap" diff --cached --quiet; then
	echo "the socair formula is already at v${version}"
	exit 0
fi
git -C "$work/tap" \
	-c user.name="github-actions[bot]" \
	-c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
	commit -q -m "Update socair to v${version}"
git -C "$work/tap" push -q
echo "published the socair formula v${version} to ${tap}"
