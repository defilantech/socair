# Releasing Socair

Releases are cut from a tag. The workflow (`.github/workflows/release.yml`)
builds, proves the build reproduces, attests provenance, and creates a
**draft**. Publishing the draft is a deliberate step.

1. Make sure `main` is green and the changelog-worthy PRs are merged.
2. Tag the release commit and push the tag:

   ```
   git tag -s v0.2.0 -m "Socair 0.2.0"
   git push origin v0.2.0
   ```

3. The workflow then:
   - builds `socair` and `socair-sigstore` for linux and darwin, amd64 and
     arm64, with `scripts/build-release.sh` (vendored modules, no network,
     no cgo, `-trimpath`, an empty build id, Go `GO_VERSION` from the
     workflow), stamping the version into the binaries and so into every
     report's `tool_versions`;
   - builds everything a second time from an empty cache and fails if a single
     byte differs;
   - attaches a GitHub build-provenance attestation (SLSA) to every binary;
   - creates a draft release holding the binaries and `SHA256SUMS`, with
     generated notes.
4. Review the draft (notes, assets, attestations), then publish it.

Keep `GO_VERSION` in the workflow pinned to an exact Go release. It is part of
what makes a release reproducible, and `go version -m <binary>` reports it to
anyone checking.
