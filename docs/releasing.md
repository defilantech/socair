# Releasing Socair

A release is cut by merging a release pull request, and published by a
maintainer. release-please (`.github/workflows/release-please.yml`,
`release-please-config.json`) keeps that pull request open on `main`. Merging
it creates the tag and a draft release. The tag starts
`.github/workflows/release.yml`, which builds, proves the build reproduces,
attests provenance, and attaches the assets to the draft. Publishing the draft
is a deliberate step, and it is the step that puts the release in the Helm
repository and the Homebrew tap (`.github/workflows/distribute.yml`).

Release tags and releases cannot be changed once they exist: a ruleset
("Protect release tags") blocks moving, deleting, or force-pushing any `v*`
tag, with no bypass, and the repository has immutable releases on, so a
published release's assets and tag are locked and GitHub records a signed
release attestation (`gh release verify <tag>`). A mistake is fixed with the
next version, not by re-tagging.

1. **Pull requests carry conventional titles.** `main` takes squash merges
   only, with the pull request's title as the commit's subject, and the
   `pr-title` check asks for `type(scope): what changed`, such as
   `fix(chattemplate): a tuple trigger is no longer missed`. release-please
   reads those subjects: `feat`, `fix`, `perf`, `revert`, `docs`, and `deps`
   are listed in the changelog, and the other types are left out of it.
2. **release-please keeps the release pull request current.** After each merge
   to `main` it updates `chore: release <version>` with:
   - the next version: while the version is a release candidate, the next
     `-rc.N` (`versioning: prerelease`);
   - its `CHANGELOG.md` entry;
   - the version in `charts/socair/Chart.yaml` and in the commands in
     `README.md`, `docs/kubernetes.md`, and `docs/verify-release.md`, between
     `x-release-please` markers.

   To release a version other than the next candidate, such as 0.1.0, merge a
   pull request that sets `"release-as": "0.1.0"` in the package's entry in
   `release-please-config.json`, and remove it after that release.

   It runs as the `defilantech-release` GitHub App, whose client id
   (`RELEASE_APP_CLIENT_ID`) and private key (`RELEASE_APP_PRIVATE_KEY`) are a
   variable and a secret of the `release` environment, which only `main` can
   use. With the default `GITHUB_TOKEN`, neither the tag nor the release pull
   request would start a workflow, so `release.yml` would not run and the pull
   request would never get its required checks.
3. **Merge the release pull request** when `main` is green and what should ship
   is merged. release-please creates the tag `v<version>` on the merge commit
   and a draft release whose notes are the changelog entry
   (`draft` and `force-tag-creation`: GitHub creates a draft's tag only on
   publishing, which an immutable release would lock before any asset is
   attached).

   The tag is not signed; nothing checks a tag signature. What a user can
   check is the provenance of each artifact, which names the workflow, commit,
   and run that built it, and the tag as its source ref.

4. The tag starts `release.yml`, which:
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
   - attaches to the draft release the binaries, `SHA256SUMS`, the SBOM, and
     `socair_<version>.intoto.jsonl` (the attestations as one file, for tools
     that read release assets); a version with a suffix (`-rc.1`) is marked
     as a pre-release. A tag pushed by hand has no draft, so it creates one
     with generated notes, and a release already published is refused;
   - builds the container image from those binaries and the wizard for
     linux/amd64 and linux/arm64, pushes it to `ghcr.io/defilantech/socair:<version>`,
     and attests it;
   - packages the Helm chart with the tag's version as both its version and
     its appVersion (and sets Artifact Hub's image and pre-release
     annotations from the tag), pushes it to `oci://ghcr.io/defilantech/charts/socair`,
     attaches the archive to the draft, attests both, and adds the archive's
     attestation to `socair_<version>.intoto.jsonl`.

   Unlike the binaries, the image and the chart have no draft step: the push
   publishes them. The first push of each creates a private GHCR package, so
   make `socair` and `charts/socair` public in the organization's package
   settings once, and link them to this repository.
5. Review the draft (notes, assets, attestations), then publish it. The notes
   are the changelog entry; rewrite them as a short summary for people where
   that helps: what changed, how to install and verify, and known limitations.
   Publishing locks the release, so this is the last chance to change it.
6. Publishing runs `distribute.yml`, which checks the release's assets
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

## Tagging by hand

If release-please cannot run, a maintainer can still tag a commit on `main`
(`git tag -a v<version> -m "Socair <version>"` and `git push origin v<version>`):
`release.yml` then creates the draft itself. Set `.release-please-manifest.json`
to that version in the next pull request, so release-please counts from it.
