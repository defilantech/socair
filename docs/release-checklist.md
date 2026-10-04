# Pre-release checklist: the Tier 1 OSS reveal (#24)

This checklist covers flipping `defilantech/socair` public. Each item is either
verified (with the date and how) or open, in which case it names who decides.
Nothing here is done by an automated session: the reveal, the tag, and every
public change are the owner's call.

State as of 2026-10-03, measured on `main` at 4ba09d2 plus the open PRs listed
in section 2.

## 1. Gate from #24

- [x] **License chosen.** `LICENSE` is Apache-2.0, and the README says so.
- [x] **M6.5 Hardening closed.** No M6.5 issue is open.
- [x] **#63 and #64 closed.** Promotion is gated on a verified signature:
  `airlock promote` takes a DSSE envelope signed by a key in
  `<store>/trusted-keys`, never a bare report.
- [x] **The free tier's output carries no Defilan signature.** No key ships in
  the tree or the history (searched for `.key`, `.pem`, and PEM private-key
  headers). Signing uses the operator's own key from `socair key gen`, and the
  README says Defilan-signed issuance is the paid tier and has not shipped.
  Re-check after the last merge before the reveal.
- [ ] **Public docs claim only what ships (#62).** One known miss: the README
  calls `docs/detection-ceiling.json` "the source for socair.ai/ceiling", and
  `https://socair.ai/ceiling` did not respond on 2026-10-03. Either publish the
  page or reword the README. *Owner.*
- [ ] **The Tier 1 tool installs and runs from a clean machine.** See section 4.

## 2. Merge what is in flight

Open PRs, each green in CI and each falling back to NOT_TESTED rather than a
guess:

| PR | Issue | Merge order |
|---|---|---|
| #100 | #69 name what a report did not examine | any time |
| #101 | #67 GGUF tensor-table validation, observed quant | before #102 |
| #102 | #82 GGUF tokenizer inspection | after #101, stacked |
| #103 | #70 provenance bound to the hash and a commit | after #102, stacked |
| #104 | #72 hash-chained airlock log | any time |
| #105 | #71 part 1, acceptance expiry enforced | any time |
| #106 | #73 CycloneDX ML-BOM export | any time; adds a test-only dependency |

Dependabot #94 to #99 are major-version bumps (actions v7, TypeScript 7,
Vitest 5, @types/node 26). They need a human read, not an automatic merge.

Decide which remaining M6.6 issues gate the reveal. Tier 1 is complete without
them: #65 OMS signature verification, #66 (canonical-template diff remains),
#68 multi-file repos, #71 part 2 signed acceptance (design question open on the
issue), #74 OCI attachment, #75 LLMKube gate (LLMKube#1968 in review), #76
Ollama, #86 Sigstore. *Owner.*

## 3. Repository contents

- [x] **No internal infrastructure in the tree or the history.** No private
  IPs, internal hostnames, home-directory paths, or key material in any commit,
  checked with `git log --all -S` and `git grep` on 2026-10-03.
- [x] **One author identity** across all 77 commits.
- [ ] **Session links in commit trailers.** 38 commits carry
  `Claude-Session: https://claude.ai/code/session_...` trailers. These links
  are not readable without the owner's account, but they become public text.
  Keep them (honest AI-assistance disclosure) or rewrite history before the
  first public push (a squash or filter-repo; never a force-push to a public
  main). *Owner.*
- [ ] **`docs/overnight/status*.md`** are historical slice reports. CLAUDE.md
  already says they are not specs. Keep them as history or remove them before
  the reveal. *Owner.*
- [ ] **`docs/false-positive-baseline.md`** names local model directories
  (`~/models` and others). These are harmless but read as one person's machine.
  Optionally reword. *Owner.*
- [x] **The demo report is marked SAMPLE** in every render
  (`internal/demo`), so it cannot pass as a real attestation.
- [x] **The brand and trademark note** (`docs/brand.md`) states its own
  caveats and is not presented as clearance.

## 4. Install and run, from nothing

Run on a machine that has never seen the repo, after it is public:

- [ ] `go install github.com/defilantech/socair/cmd/socair@<tag>` builds. The
  module needs Go 1.27; `vendor/` is committed, so an air-gapped build is
  `go build -mod=vendor ./cmd/socair` from a checkout.
- [ ] `socair scan <model.gguf>`, `socair render`, `socair key gen`,
  `socair sign`, `socair verify`, and the airlock round trip
  (`init`, `pull` or `ingest`, `trust add`, `promote`, `log --verify`) behave as
  `docs/airlock.md` describes.
- [ ] `socair serve --web web/build` serves the wizard after `npm ci && npm run
  build` in `web/`.
- [x] **The version string.** Set from the tag at build time
  (`engine.Version`, `-ldflags -X`); source builds say `dev` (#124).
- [x] **Release artifacts.** A tag builds reproducible binaries for linux and
  darwin, amd64 and arm64, with `SHA256SUMS` and SLSA build-provenance
  attestations, into a draft release (#124; `docs/releasing.md`,
  `docs/verify-release.md`).

## 5. Public-repository settings (on the flip)

- [ ] Branch protection on `main`: required CI checks, no force-push, and
  reviews if collaborators join. `main` is not protected today.
- [ ] Private vulnerability reporting enabled, with a `SECURITY.md`: a scanner
  for hostile model files will get reports, and they should not land as public
  issues. There is no `SECURITY.md` today.
- [ ] `CONTRIBUTING.md` (DCO sign-off, as LLMKube uses) and a code of conduct.
- [ ] Secret scanning and push protection on; Dependabot alerts on.
- [ ] CI already runs with read-only `permissions:` and SHA-pinned actions. Keep
  it that way for fork PRs: no `pull_request_target`.

## 6. Announce

- [ ] The reveal post points at the bounded statement and the detection ceiling,
  not at "secure". The audience is security people; overclaiming is the fastest
  way to lose them.
- [ ] The public `socair-verify` module (already public, v0.1.0) and the LLMKube
  gate are referenced together, so a reader sees the end-to-end path: scan,
  sign, promote, admit.
