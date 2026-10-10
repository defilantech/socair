# Verifying a Socair release

A tool that vouches for model files should be checkable itself. Each release
gives you three ways to check a binary, so you can decide how much to trust
before you run it. They are not equally strong: the checksums come from the
same release page as the binary, while the attestation and a rebuild check it
against something the release page does not control.

The commands below use a version variable and the linux amd64 binary. Release
assets are named `socair_<version>_<os>_<arch>` and
`socair-sigstore_<version>_<os>_<arch>`, for linux and darwin on amd64 and
arm64; the version has no leading `v`, and the tag has one.

```
V=0.1.0-rc.3
curl -LO https://github.com/defilantech/socair/releases/download/v$V/socair_${V}_linux_amd64
curl -LO https://github.com/defilantech/socair/releases/download/v$V/SHA256SUMS
```

## 1. Checksums

```
sha256sum --check --ignore-missing SHA256SUMS
```

(`shasum -a 256 --check --ignore-missing SHA256SUMS` where `sha256sum` is
missing.) This catches a damaged or incomplete download. It does not catch a
tampered release, since whoever could replace the binary could replace
`SHA256SUMS` beside it.

## 2. Build provenance

Every binary carries a GitHub build-provenance attestation (SLSA). It records
the repository, workflow, commit, and run that built the binary, and it is
signed through Sigstore. With the GitHub CLI, pin the workflow that must have
built it:

```
gh attestation verify socair_${V}_linux_amd64 --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```

This fetches the attestation and the Sigstore trust root over the network.
To verify on a machine without network access, fetch both on a connected
machine first and carry them in:

```
gh attestation download socair_${V}_linux_amd64 --repo defilantech/socair   # writes sha256:<digest>.jsonl
gh attestation trusted-root > trusted_root.jsonl

# then, offline:
gh attestation verify socair_${V}_linux_amd64 --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml \
  --bundle sha256:<digest>.jsonl --custom-trusted-root trusted_root.jsonl
```

## 3. Rebuild it yourself

Releases are reproducible: the same commit, built with the same Go version,
gives byte-identical binaries. The Go version must be the exact one the
release used, which `go version -m` reports. Set it with `GOTOOLCHAIN`.
`scripts/build-release.sh` sets `GOPROXY=off`, so it cannot download a
toolchain: fetch that toolchain once while online.

```
git clone https://github.com/defilantech/socair socair-src && cd socair-src
git checkout v$V
go version -m ../socair_${V}_linux_amd64 | head -1    # e.g. go1.27.2: the Go version to use
GOTOOLCHAIN=go1.27.2 go version                       # online, once: downloads that toolchain
GOTOOLCHAIN=go1.27.2 scripts/build-release.sh $V dist # needs no network: modules are vendored
sha256sum dist/socair_${V}_linux_amd64 ../socair_${V}_linux_amd64   # the two must match
```

Build from a clean checkout of the tag: the script warns when the checkout has
changes, because Go records that in the binary (`vcs.modified`) and the bytes
then differ. `go version -m` also shows the exact commit a binary was built
from (`vcs.revision`).

## The container image and the Helm chart

A release also pushes the container image, `ghcr.io/defilantech/socair:$V`
(linux/amd64 and linux/arm64), and the Helm chart,
`oci://ghcr.io/defilantech/charts/socair` at version `$V`. The same chart
archive, `socair-$V.tgz`, is a release asset, and the Helm repository at
`https://defilantech.github.io/socair` points at it. Each carries a
build-provenance attestation from the same release workflow:

```
gh attestation verify oci://ghcr.io/defilantech/socair:$V --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/defilantech/charts/socair:$V --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml

# or the archive, from the release page or `helm pull socair/socair --version $V`:
gh attestation verify socair-$V.tgz --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```

The image's binaries are the release's: the [Dockerfile](../Dockerfile)
copies what `scripts/build-release.sh` built and compiles nothing, so
`/usr/local/bin/socair` in the image has the SHA-256 listed in `SHA256SUMS`
for its platform. The chart's `image.digest` value pins the image you
verified ([kubernetes.md](kubernetes.md)).

## Installed with Homebrew

`brew install defilantech/tap/socair` downloads the release's binary for
your platform, checks it against the SHA-256 the formula records (taken from
`SHA256SUMS` after the attestations verified), and installs it unchanged. The
attestation therefore verifies the installed copy:

```
gh attestation verify "$(brew --prefix socair)/bin/socair" --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```

## Running it

In the directory you downloaded to:

```
chmod +x socair_${V}_linux_amd64
mv socair_${V}_linux_amd64 socair
```

The macOS builds are not notarized. A binary downloaded with a browser is
quarantined, and Gatekeeper refuses to run it; after verifying it, clear the
quarantine with `xattr -d com.apple.quarantine socair`. A download with
`curl` is not quarantined.

The optional keyless verifier, `socair-sigstore`, is released and checked the
same way. See `tools/socair-sigstore/README.md` for what it does.
