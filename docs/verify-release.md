# Verifying a Socair release

A tool that vouches for model files should be checkable itself. Each release
gives you three independent ways to check a binary, so you can decide how much
to trust before you run it.

## 1. Checksums

Download the binary and `SHA256SUMS` from the release:

```
sha256sum --check --ignore-missing SHA256SUMS
```

## 2. Build provenance

Every binary carries a GitHub build-provenance attestation (SLSA). It records
the repository, workflow, commit, and run that built the binary, and it is
signed through Sigstore. With the GitHub CLI:

```
gh attestation verify socair_0.2.0_linux_amd64 --repo defilantech/socair
```

This needs network access. Verify on a connected machine before carrying the
binary into an air-gapped site.

## 3. Rebuild it yourself

Releases are reproducible: the same commit, built with the same Go version,
gives byte-identical binaries.

```
git clone https://github.com/defilantech/socair && cd socair
git checkout v0.2.0
go version -m socair_0.2.0_linux_amd64 | head -1   # the Go version to use
scripts/build-release.sh 0.2.0 dist                # needs no network: modules are vendored
sha256sum dist/socair_0.2.0_linux_amd64            # matches SHA256SUMS
```

`go version -m` also shows the exact commit a binary was built from
(`vcs.revision`).

The optional keyless verifier, `socair-sigstore`, is released and checked the
same way. See `tools/socair-sigstore/README.md` for what it does.
