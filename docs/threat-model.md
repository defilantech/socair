# Threat model

What Socair protects, whom it trusts for what, which mechanism defends each
boundary, and what it does not defend against. It describes the code as it
is. Where a defence depends on how you deploy Socair, it says so; the
deployment itself is in [intake-host.md](intake-host.md) and
[kubernetes.md](kubernetes.md).

## What it protects

- **The binding between the verdict and the bytes.** An attestation must
  describe exactly the bytes that were checked, and only those bytes may
  cross into the clean store on it.
- **The promotion decision.** Only an artifact whose attestation, signed by a
  key the store trusts, authorizes promotion reaches `clean/`. A conditional
  promotion also needs a signed acceptance from a separate key.
- **The keys:**
  - the operator key, which signs attestations and inventory snapshots;
  - the acceptor key, which signs acceptances of untested rows;
  - the feed signer's key, which signs reference data;
  - the publisher keys and roots an operator trusts for OpenSSF Model Signing
    signatures.

  No private key needs to be on the airlock host: the store holds public
  keys only.
- **The record:** the activity log (`log.jsonl`) and exported inventory
  snapshots.

## Who is trusted for what

| Party | Trusted for | Not trusted for |
|---|---|---|
| Model publisher | Nothing by default. Its files are hostile input. A publisher signature counts only when the operator trusts the publisher's key or root, and then as origin and integrity, not safety. | Anything about the file's contents |
| Model hub and CDN | Listing hashes and serving bytes that match them | Being uncompromised: a hub that lists the hashes of whatever it serves is not caught by the pull itself |
| Network | Nothing | Everything: only `pull` reaches it, through an allowlist |
| Operator | Running the checks and signing the report they stand behind. The operator key is the root of trust for promotion. | Making a report say more than its rows: a signed report must still validate, and its promotion state must follow from its check rows |
| Acceptor | Accepting named untested rows of one report, until an expiry | Clearing a FAIL or a LEAD, which no acceptance clears; signing an acceptance with the key that signed the report |
| Feed signer | The reference data it signs, until the feed expires | Clearing structural evidence: a reviewed template clears language leads only, and code reach still FAILs |
| Scan host and store | Not being compromised (an assumption, below) | — |
| Verifier (`socair verify`, `airlock promote`, LLMKube's gate through `socair-verify`) | Checking signature, statement, subject digest, and promotion state against the keys it was given | Trusting any key it was not given |
| Local API caller | Nothing beyond the loopback interface: the API has no authentication | Reaching it from another origin or host |
| Socair's release pipeline | Building the release binaries from the tag | Being taken on faith: each binary is checkable ([verify-release.md](verify-release.md)) |

## What each mechanism defends

| Mechanism | Defends against |
|---|---|
| **Scan snapshot.** The engine copies the artifact into a private read-only file, hashing while it copies, and every check reads the copy (`internal/engine/snapshot.go`). | A file swapped or rewritten between hashing and checking, which would earn a report under the hash of other bytes |
| **Hashing on promote.** `promote` hashes while copying into `clean/`, and a directory is renamed into place only when its recomputed manifest digest is the attested subject. | Bytes crossing on an attestation for other bytes |
| **Signed promotion and validation.** `promote` checks the signature against `trusted-keys/`, the statement and predicate types, the subject against the document's hash, the recorded document hash, and that the document validates, including that its promotion state follows from its check rows (`report.Validate`). | A bare or hand-edited report; an "authorized" state over a FAIL, a LEAD, or an unaccepted gap |
| **Acceptance key separation.** Acceptances verify against `acceptor-keys/`, a list separate from `trusted-keys/`, must be signed by a different key than the attestation, must name exactly the report's untested rows, and must be current. | Self-acceptance; an acceptance stretched to rows nobody reviewed; a stale acceptance |
| **Issuer check.** The store names each trusted key, and `promote` and `verify` refuse an attestation whose claimed issuer contradicts that name. | An attestation that claims to come from someone the key does not belong to |
| **Controlled egress.** Every host a pull touches, including each redirect hop, must be on the allowlist; an https-to-http redirect is refused; `SOCAIR_EGRESS=deny` refuses everything. | Socair itself fetching from, or being redirected to, an unexpected host |
| **Pinned pulls.** A whole-repo pull must name a full commit or the expected digest, and every file is checked against the hub's hash at that commit. | A branch delivering different bytes later; a corrupted or substituted transfer, the CDN included |
| **Token host binding.** `HF_TOKEN` is sent only to the endpoint's own host and port over https (or loopback), stripped on any cross-host redirect, and never logged or put in an error. API pulls never send it. | The token leaking to a CDN, another host, the log, or a page that can reach the API |
| **Path and shape checks.** Hashes, repo ids, revisions, and file names are checked before any path is built, and paths must stay under the store or cache root. | Path traversal through a crafted hash, name, or listing |
| **Hash-chained log.** Each entry carries the hash of the line before it; `log --verify --expect-head` checks the chain to a head recorded off the box. | Careless edits to the log, and, with a recorded head, a rewrite of anything before that head |
| **Signed feeds.** A feed verifies against `SOCAIR_FEED_KEYS`, every file must match its signed digest, no unlisted file may be present, and an expired or unverified feed stops the scan. | Tampered, padded, or stale reference data changing verdicts |
| **Private key permissions.** A private key file readable by other users is refused. | A signing key exposed to other users on the machine |
| **Local API defences.** It binds loopback, refuses a non-loopback bind unless `SOCAIR_API_ALLOW_PUBLIC=1`, serves only a loopback `Host`, and refuses cross-origin and cross-site requests ([api.md](api.md)). | DNS rebinding and cross-origin requests from a page in the operator's browser |
| **Parser hardening.** The readers are bounded against hostile counts, lengths, and nesting, and fuzz targets for the GGUF, safetensors, pickle, Jinja, OMS, acceptance, and feed parsers run in CI. An audit against the bug classes other model loaders have had CVEs for is open ([#166](https://github.com/defilantech/socair/issues/166)). | A small hostile file crashing or hanging the scanner |
| **Release pipeline.** Builds are reproducible from the tag with vendored dependencies and no network, every binary, the chart, and the image carry a build-provenance attestation, releases are immutable, and release tags cannot be moved or deleted. | A tampered Socair binary, chart, or image |

## Assumptions

- The scan host, the store's file system, and the user Socair runs as are not
  compromised. Within Socair only `promote` writes to `clean/`; make the store
  writable only by that user.
- Private keys are kept off the airlock host, or at least readable only by
  their owner.
- Whoever adds a key to a trust list checks whose key it is. A key's issuer
  name is a claim until the store names it.
- Serving machines load models only from the clean store, mounted read-only,
  or through an admission gate that checks the attestation. The clean store is
  a directory of bytes and attestations, not a gate by itself.
- If a rewrite of the log matters to you, you record its head somewhere the
  airlock host cannot change.

## Out of scope

- **An attacker who controls the scan host, the store, or a trusted private
  key.** They can sign what they like or rewrite the log after the last head
  you recorded.
- **What a model does when it runs.** Tier 1 checks files, not behavior. Tier 2
  measurements can withhold promotion but never show that something is
  absent ([tier2.md](tier2.md)).
- **Anything on the [detection ceiling](detection-ceiling.json).** It lists
  what Socair does not claim to catch.
- **A compromised hub serving consistent hashes.** The pull checks the hub's
  own hashes; only a provenance record or a trusted publisher signature
  speaks to origin.
- **Resource use proportional to a large input.** A small input that crashes
  or hangs the scanner, or makes it allocate far more than its size, is in
  scope ([SECURITY.md](../SECURITY.md)).
