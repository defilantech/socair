# Releasing Socair

Releases are cut from a tag. The workflow (`.github/workflows/release.yml`)
builds, proves the build reproduces, attests provenance, and creates a
**draft**. Publishing the draft is a deliberate step, and it is the step that
puts the release in the Helm repository and the Homebrew tap
(`.github/workflows/distribute.yml`).

Release tags and releases cannot be changed once they exist: a ruleset
("Protect release tags") blocks moving, deleting, or force-pushing any `v*`
tag, with no bypass, and the repository has immutable releases on, so a
published release's assets and tag are locked and GitHub records a signed
release attestation (`gh release verify <tag>`). A mistake is fixed with the
next version, not by re-tagging.

1. Make sure `main` is green and the changelog-worthy PRs are merged.
2. Tag the release commit and push the tag:

   ```
   git tag -a v0.2.0 -m "Socair 0.2.0"
   git push origin v0.2.0
   ```

   The tag is not signed; nothing checks a tag signature. What a user can
   check is the provenance of each artifact, which names the workflow, commit,
   and run that built it.

3. The workflow then:
   - builds `socair` and `socair-sigstore` for linux and darwin, amd64 and
     arm64, with `scripts/build-release.sh` (vendored modules, no network,
     no cgo, `-trimpath`, an empty build id, Go `GO_VERSION` from the
     workflow), stamping the version into the binaries and so into every
     report's `tool_versions`;
   - builds everything a second time from an empty cache and fails if a single
     byte differs;
   - attaches a GitHub build-provenance attestation (SLSA) to every binary;
   - writes Socair's own SBOM (`socair_<version>.cdx.json`, CycloneDX: the Go
     modules linked into each binary, read from the binaries) and attests it
     for every binary;
   - creates a draft release holding the binaries, `SHA256SUMS`, the SBOM,
     and `socair_<version>.intoto.jsonl` (the attestations as one file, for
     tools that read release assets), with generated notes; a version with a
     suffix (`-rc.1`) is marked as a pre-release;
   - builds the container image from those binaries and the wizard for
     linux/amd64 and linux/arm64, pushes it to `ghcr.io/defilantech/socair:<version>`,
     and attests it;
   - packages the Helm chart with the tag's version as both its version and
     its appVersion, pushes it to `oci://ghcr.io/defilantech/charts/socair`,
     attaches the archive to the draft, attests both, and adds the archive's
     attestation to `socair_<version>.intoto.jsonl`.

   Unlike the binaries, the image and the chart have no draft step: the push
   publishes them. The first push of each creates a private GHCR package, so
   make `socair` and `charts/socair` public in the organization's package
   settings once, and link them to this repository.
4. Review the draft (notes, assets, attestations), then publish it. Replace
   the generated notes, a list of every pull request, with a short summary for
   people: what changed, how to install and verify, and known limitations.
   Publishing locks the release, so this is the last chance to change it.
5. Publishing runs `distribute.yml`, which checks the release's assets
   against their attestations and then:
   - adds the chart to `index.yaml` on the `gh-pages` branch, served as the
     Helm repository `https://defilantech.github.io/socair` (as LLMKube's is
     at `https://defilantech.github.io/LLMKube`); the entry points at the
     release's `socair-<version>.tgz`;
   - writes `Formula/socair.rb` in `defilantech/homebrew-tap`
     (`scripts/publish-homebrew-formula.sh`), so
     `brew install defilantech/tap/socair` installs the release's binary.

   Pre-releases go to both. Helm lists a pre-release only with `--devel` or
   an explicit `--version`; Homebrew has one version per formula, so the tap
   follows the newest published release.

The Homebrew job pushes to another repository, which the workflow's own token
cannot do: it needs the `HOMEBREW_TAP_TOKEN` secret, a fine-grained token with
read and write access to the contents of `defilantech/homebrew-tap` only.
Without it the job fails and says so; add the secret and re-run the job. The
Helm repository needs GitHub Pages serving the `gh-pages` branch.

GitHub artifact attestations need the repository to be public, or a GitHub
plan that supports them on private repositories. On a private repository
without one, the publish job fails at the attest step, before the draft is
created.

Keep `GO_VERSION` in the workflow pinned to an exact Go release. It is part of
what makes a release reproducible, and `go version -m <binary>` reports it to
anyone checking.
