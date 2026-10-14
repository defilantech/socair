# Provenance and trust inputs bundle spec

The trust rows (inventory, provenance, denylist) are NOT_TESTED on a bare
artifact. That is correct: we did not look, so we say so. This document is what
the airlock operator must supply to move those rows off NOT_TESTED. It is the
operational half of the product; the code reads these inputs and nothing else.

Everything here is offline. There is no network call at scan time.

A report names each local input by its file name and the SHA-256 of the bytes
the scan read, never by its path on the scanning host: a filed report is
shared, a path can carry a username and a directory layout, and the hash
names the exact contents. `scope.reference_data` lists the denylist, the
tokenizer tables, the reviewed templates, and the license policy that way (an
input given as a directory lists each file read), and the provenance row
names the manifest. A repo mirror is named by its directory's name. A signed
feed is named by its issuer, version, dates, and signing key.
`scope.input_path` says how the input arrived (`local path`, or the `source`
a bound provenance manifest records, such as `airlock pull`), not where it
was; the subject digest identifies the artifact.

The same holds for the paths Socair hands out. Every check reads the scan's
snapshot, so an error a check quotes (a file it could not read, say) names the
snapshot; the finished report names the artifact there instead: "read
model.gguf: input/output error" for a single file, and for a model directory
the directory's name, with a path inside it read relative to that. The
two external helpers, the keyless verifier below and the Tier 2 probe helper
([tier2.md](tier2.md#the-probe-helper-protocol)), are handed paths too, and
what they write is held to the same rule: each path Socair handed one is
replaced by its name wherever it appears in the helper's answer or failure,
and a helper that cannot be started is named by its file name with the cause.
Socair does not guess at other paths in a helper's free text; it replaces the
ones it knows it handed out.

## 1. Repo mirror, `SOCAIR_REPO_MIRROR`

A directory holding the model repository's file listing as delivered, for a
single-file scan (a model directory scan inventories its own files). The
inventory check walks it and reads the start of every file, whatever its name:
a native executable (ELF, PE, Mach-O) is a FAIL. Scripts and config files
(`.py`, `.sh`, `.js`, `.rb`) are inventoried, not failed, because model repos
legitimately ship them; an executable named `setup.py` is still an executable.
An archive, including a zip-format PyTorch checkpoint, is named as unscanned
and leaves the row NOT_TESTED, because its contents were not inspected. (A
model directory scan counts a torch.save checkpoint as read when the Pickle
opcode scan PASSed it and read every entry in it; a mirror's files are not
the bytes that check read, so this does not apply to a mirror.)

- Moves `File inventory and payloads` from NOT_TESTED to PASS (or FAIL on a
  native executable).
- Layout: the mirror is the root; any subdirectory structure is fine.
- Absent: the repo side of the inventory note says the listing was not
  inspected, and the row stays NOT_TESTED.
- Missing, empty, or not a directory: NOT_TESTED with the reason. An entry the
  walk cannot read is named and leaves the row NOT_TESTED, unless a binary
  elsewhere already FAILs it.

## 2. Denylist, `SOCAIR_DENYLIST`

A text file of known-bad artifact hashes.

```
# one entry per line: <sha256>  <label>
13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444  known-bad-example-2026
```

- Blank lines and lines starting with `#` are ignored.
- Every other line must start with a SHA-256. One that does not refuses the
  whole list, as a feed is refused: the row is NOT_TESTED and names the line,
  even beside a feed's denylist, unless a listed hash matches.
- Moves `Known-bad hash match` from NOT_TESTED to PASS (no match) or FAIL (match).
- A list with no valid SHA-256 entry (empty, comments only, or malformed lines
  only) is NOT_TESTED, not a pass: "nothing was matched against" is not
  cleared.
- Absent: NOT_TESTED with "no denylist configured".

## 3. Provenance manifest, `SOCAIR_PROVENANCE`

A JSON record of where the artifact came from, written by whoever ran the
airlock. `socair airlock pull` writes one of these beside every staged artifact,
recording the hash, the repo, the revision, and the commit it resolved to, and
never a signing status. A pull that lands nothing writes nothing. Pass it to a
scan with `SOCAIR_PROVENANCE=<path>`; the scan reads only the manifest named
there, never one it finds beside the artifact.

```json
{
  "artifact_sha256": "8aaff9f15e2471e3fa038d20618b494680a6e0a2ef0655e09768fc5ecb933953",
  "publisher": "example-org",
  "signing_status": "unsigned",
  "repo_url": "https://huggingface.co/example-org/example-model",
  "commit_or_tag": "main",
  "commit_sha": "4f2c9e1a7b3d5f60812a9c4e6b0d1f3a5c7e9b2d",
  "aibom": "spdx-ref-or-path"
}
```

- `artifact_sha256` binds the record to one artifact: the file's SHA-256, or a
  model directory's manifest digest. A manifest that names no hash, or another
  artifact's, does not count, and the row says why.
- `commit_sha` must be a full commit id (40 or 64 hex). An origin recorded only
  at a branch or tag in `commit_or_tag`, which can move, leaves the row
  NOT_TESTED.
- `signing_status` is `signed`, `unsigned`, or empty. It is the manifest's
  claim, reported as such, and it never moves the row; the row says the origin
  rests on the supplied record rather than a verified signature.
- Moves `Hash, provenance, lineage` from NOT_TESTED to PASS when it binds, names
  a `repo_url`, and has a full `commit_sha`.
- Absent: NOT_TESTED.

### Signature sidecars

A signature sidecar next to the artifact (`<artifact>.sigstore.json`,
`.sigstore`, `.minisig`, or `.sig`) that is not read as an OMS signature
(section 3a) is named in the row as present and not verified. It does not move
the row: without a bound manifest, the row stays NOT_TESTED.

## 3a. Publisher signatures, `SOCAIR_PUBLISHER_KEYS` and `SOCAIR_PUBLISHER_ROOTS`

When the artifact carries an OpenSSF Model Signing (OMS) signature, the scan
verifies it offline. For a directory the scan looks at its root for
`model.sig` (the `model_signing` default) and `result.sigstore` (the name
NVIDIA's NGC CLI gives a model's signature; section 3b). For a single file it
reads `<file>.sig` beside it. `SOCAIR_OMS_SIGNATURE` names another path,
inside the directory or outside it.

- Only the directory's root is searched. A signature file deeper in the tree
  is a model file like any other, and a signature outside the directory is
  read only when `SOCAIR_OMS_SIGNATURE` names it.
- With both `model.sig` and `result.sigstore` at the root, each an OMS
  signature, and `SOCAIR_OMS_SIGNATURE` naming neither, the scan does not
  choose between them: the signature is named and not verified, and the
  manifest rules decide the row. Name the one to verify. A root file that is
  not an OMS bundle (a GPG or minisign `model.sig`) does not count.
- The root signature file that is not the one verified is not compared as a
  model file; it is named as not covered. The one verified cannot cover
  itself, and is left out too.

- `SOCAIR_PUBLISHER_KEYS`: the publisher's EC public keys (P-256, P-384,
  P-521), a PEM file or a directory of them, for key-signed models.
- `SOCAIR_PUBLISHER_ROOTS`: CA certificates, a PEM file or a directory, for
  models signed with a certificate. The leaf must carry the
  `digitalSignature` key usage or the `codeSigning` extended key usage.
  Revocation is not checked.

The certificate chain is checked at the scan's time, as OMS v1.0 section 8.2
requires ("The leaf certificate MUST be within its validity period"). A
certificate bundle carries no trusted timestamp to check it at instead. A
chain holding a certificate that has expired, or is not yet valid, at the scan
time is named and not verified: it proves nothing about the files either way.
(Until check set `tier1/0.9` the chain was checked at the leaf's own
notBefore, as `model_signing` 1.1.1 does, which every leaf passes;
[sigstore/model-transparency#663](https://github.com/sigstore/model-transparency/issues/663)
changed that in the reference implementation.)

There is no default trust (no system roots, no built-in keys, and no
publisher's root, NVIDIA's included): a signature from a key you did not
configure proves nothing about who made the model.

| Signature | Provenance row | `publisher_signing_status` |
|---|---|---|
| From a trusted key or root; every signed file the scan reads matches | PASS | verified (OMS, signer) |
| From a trusted signer; the signature, or a file, does not match | FAIL | invalid (OMS): what differs |
| From an untrusted signer, or pre-1.0 | the manifest rules decide; the signature is named | present, not verified |
| From a trusted root, with a certificate outside its validity at the scan time | the manifest rules decide; the signature is named | present, not verified |
| Two OMS signatures at a directory's root, neither named | the manifest rules decide; the signatures are named | present, not verified |
| Keyless Sigstore, with `socair-sigstore` configured | as above: verified, invalid, or not in the identity policy | as above, naming the signer's subject and issuer |
| Keyless Sigstore, no verifier configured | the manifest rules decide; the signature is named | present, not verified |

Keyless signatures (a Fulcio certificate and a Rekor log entry) are verified
by the optional `socair-sigstore` helper, a separate binary built from
`tools/socair-sigstore`, so the scanner's own build keeps its small dependency
set. Configure it with `SOCAIR_SIGSTORE_VERIFIER`, `SOCAIR_SIGSTORE_TRUSTED_ROOT`
(a Sigstore `trusted_root.json`), and `SOCAIR_SIGSTORE_IDENTITIES` (the signers
you accept, required); see `tools/socair-sigstore/README.md`. The helper
vouches for the signature; the scanner still binds the signed manifest to the
files.

**What the verifier is given.** Socair starts it with no arguments and writes
one request to its standard input: the bundle, the trust root's absolute
path, and the identity policy. It runs with an empty environment. Nothing of
Socair's reaches it: not `HF_TOKEN`, not a proxy setting, not `GODEBUG`. It
verifies offline from the request and opens no file but the trust root, so it
needs nothing more; the opt-in test against the real helper
(`TestRealKeylessVerifier`) verifies the reference vector this way. These are
the variables it, or a library it is built from (sigstore-go v1.3.0, Go
1.27), reads, and why none is passed:

| Variables | Read by | Why it is not passed |
|---|---|---|
| `HOME`, and `TMPDIR` when there is no home | sigstore-go's TUF client, for its cache ([`tuf.DefaultOptions`](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/tuf/options.go#L130-L148)) | Only the online trust-root fetch uses it. The verifier reads the trust root from its file ([`root.NewTrustedRootFromPath`](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/root/trusted_root.go#L356-L365)) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Go's HTTP client, which that fetch uses | The verifier makes no network request |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Go's `crypto/x509`, loading the system's roots ([root.go](https://github.com/golang/go/blob/go1.27.1/src/crypto/x509/root.go#L137-L151)) | Every chain is checked against the trust root's certificates, never the system's |
| `GODEBUG` | The Go runtime, `crypto/x509`, and `crypto/rsa` ([GODEBUG](https://go.dev/doc/godebug)) | It can loosen what the verifier accepts (`x509negativeserial=1`, `rsa1024min=0`). The verifier runs with the defaults it was built with |
| `GOGC`, `GOMEMLIMIT`, `GOMAXPROCS`, `GOTRACEBACK` | The Go runtime | Memory, scheduling, and crash-output tuning; the defaults serve |
| `TZ`, `ZONEINFO` | Go's `time` package | They change only how a time reads in a failure's text |
| `COSIGN_PASSWORD`; `GRPC_GO_LOG_*`, `SWAGGER_DEBUG`, `DEBUG`, `OTEL_*`, `GOPROTODEBUG` | Libraries linked into the helper: an encrypted private key's password, and logging, debug, and tracing switches | The verifier opens no private key and needs no logging or tracing |

No setting adds a variable. If a later verifier needs one, it is added to
`keylessEnvKeys` in `internal/engine/publisher.go` with its reason, and the
test that pins the list (`TestKeylessVerifierGetsOnlyAllowedEnvironment`)
names it; a credential is never added.

**What Socair reads back.** The verifier's answer is one JSON verdict of a few
hundred bytes (at most 349 on the reference vectors and their tampered
copies). Socair reads up to 64 KiB of it. A longer answer is refused whole,
never parsed in part, and leaves the signature present, not verified: "the
keyless verifier's answer is over 65536 bytes". The bound matters because a
verdict's detail can quote the bundle, which comes with the artifact.

A verifier that does not answer leaves the signature present, not verified,
and the provenance row and the signing state say why: it could not be started
(named by its file name, with the cause), it did not answer within two
minutes, or it failed, with its exit status and the last 400 bytes of its
standard error. The verifier is handed the trust root's path, and its error
text or its verdict's detail can repeat it. The trust root is named by its
file name, and the verifier and its directory by their names, wherever they
stand in what the verifier wrote. Should a variable it is given ever hold an
absolute path, the path is named by the variable (`$NAME`).

A verified signature proves the files are the ones the key holder signed. It
is a statement of origin and integrity, never of safety: the other rows still
decide whether it is promoted.

A file the signed manifest lists is compared, unless it is download-tool
metadata the scan does not read (below). A file it does not list is left out
of the comparison, and named as not covered with the reason, only when the
signer excluded it (`ignore_paths`), when it is one of OMS's default
exclusions at the directory's top (`.git`, `.gitattributes`, `.github`,
`.gitignore`; OMS v1.0 section 6.2), or when it is the other root signature
file. Any other file the manifest does not list is a difference. A single file
checked against a signature over several files that lists it is not verified:
the other files are not in hand, so scan the directory.

### Download-tool metadata in a signed directory

A directory scan does not read `.cache/` or `.huggingface/` directories, at
any depth: download tools keep their own bookkeeping there, a loader does not
read it, and it is not among the attested files (the report's out-of-scope
list names each one as excluded). `hf download <repo> --local-dir <dir>`
writes such metadata into `<dir>`: `.cache/huggingface/` from huggingface_hub
0.24.0 on, `.huggingface/` in 0.23.x, and nothing before 0.23.0. It holds a
`.gitignore`, and for each downloaded file a `.metadata` record of the commit,
the ETag, and the time it was written, with a `.lock` beside it; 2.2.0 adds a
`CACHEDIR.TAG` and the repo tree it listed.

`model_signing` 1.1.1 signs every file under the model directory except
`.git/`, `.gitattributes`, `.github/`, and `.gitignore` at its top, so a
directory signed after an `hf download --local-dir` lists that metadata. A
signed file under `.cache/` or `.huggingface/` is left out of the comparison:
the scan holds no bytes for it, so it is neither compared nor counted missing.
A PASS then says "every signed file the scan read matches" and names each such
directory, with the number of signed files under it, as signed but not
compared. It is the same whether the metadata is on disk, rewritten, or gone,
because the attested files are the same.

- Only those two directories, as the first directory on the path that the scan
  skips, get this treatment. A changed, missing, or unsigned file anywhere
  else is a difference, and so is a signed file under another directory the
  scan skips (`.git/` below the top, `__pycache__/`, `.ipynb_checkpoints/`).
- The metadata is left out, not read and compared: every check reads the
  scan's snapshot, which does not hold it, and re-running the same download
  rewrites each `.metadata` record with a new time while no model byte
  changes. `model_signing verify` fails such a directory on that rewrite;
  comparing it would FAIL an unchanged model.
- The reverse, a signature made before the download wrote its metadata, lists
  none of it. The scan does not read the metadata, so it is no difference
  either, and the PASS claims nothing more than "every signed file matches".
  (`model_signing verify` fails that directory on the extra files unless they
  are ignored.)

Sources, read on 2026-10-14: huggingface_hub's `_huggingface_dir` at
[v0.23.0](https://github.com/huggingface/huggingface_hub/blob/v0.23.0/src/huggingface_hub/_local_folder.py#L212-L229),
[v0.24.0](https://github.com/huggingface/huggingface_hub/blob/v0.24.0/src/huggingface_hub/_local_folder.py#L221-L238),
and [v2.2.0](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/_local_folder.py#L445-L474)
(no `_local_folder.py` before v0.23.0);
[the metadata record](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/_local_folder.py#L432-L442)
and [its rewrite when the ETag matches](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L1430-L1432);
`model_signing` 1.1.1's [default ignore paths](https://github.com/sigstore/model-transparency/blob/v1.1.1/src/model_signing/hashing.py#L166-L177)
and [the walk it signs](https://github.com/sigstore/model-transparency/blob/v1.1.1/src/model_signing/_serialization/file.py#L109-L119).
Reproduced with the real tools: two small files fetched with `hf download
--local-dir` (huggingface_hub 2.2.0 and 0.23.4) and signed with `model_signing
sign key` 1.1.1, which lists the metadata and verifies the directory.

## 3b. NVIDIA NGC models

NVIDIA signs the models it publishes in the NGC catalog with OMS
([NVIDIA's verification guide](https://docs.nvidia.com/nim/large-language-models/2.0.10/reference/model-signature-verification.html),
[announcement](https://developer.nvidia.com/blog/bringing-verifiable-trust-to-ai-models-model-signing-in-ngc)).
The signature is a separate download from the model:

```
ngc registry model download-version <org>/<team>/<model>:<version> --dest <dir>
ngc registry model download-version-signature <org>/<team>/<model>:<version> --dest <dir>
```

Both write to `<dir>/<model>_v<version>/` (NGC SDK 4.37.0, which names the
file `result.sigstore`), so with the same `--dest` the signature lands at the
model directory's root, where a directory scan finds it. NVIDIA's NIM guide
downloads it to a separate `./signatures/` tree instead: name it there with
`SOCAIR_OMS_SIGNATURE`, or move it to the model directory's root.

What an NGC signature is, read from `nvidia/tao/dashcamnet:pruned_onnx_v1.0.5`
on 2026-10-12:

- The `certificate` method, with no transparency-log entry: the bundle's
  certificate chain is a leaf (`O=NVIDIA, CN=NVIDIA Model Signing Issuer NGC
  001`, valid 2025-03-07 to 2027-03-07, key usage `digitalSignature` only),
  an intermediate (`CN=NVIDIA Model Signing ICA 001`), and the root
  (`CN=NVIDIA Model Signing Root CA`), all P-384.
- The `files` serialization with SHA-256 over every file of the model version,
  and no `ignore_paths`. As the NGC SDK downloads it, the directory holds the
  signed files and `result.sigstore`, nothing else, and it verifies as it is
  (`model_signing` 1.1.1 verifies it too). A file added at the directory's top
  is a difference unless it is one of OMS's default exclusions.

### Trusting NVIDIA's root

Socair ships no publisher's root, NVIDIA's included. To verify NGC signatures:

1. On a connected machine, download the certificate NVIDIA's guide names:

   ```
   curl -fsSL -o nvidia-model-signing-root.pem \
     https://api.ngc.nvidia.com/v2/catalog/models/public-key
   ```

   Despite the URL, it is a certificate: the self-signed root `C=US, O=NVIDIA,
   CN=NVIDIA Model Signing Root CA`.

2. Check it before you trust it:

   ```
   openssl x509 -in nvidia-model-signing-root.pem -noout -subject -issuer -dates -fingerprint -sha256
   ```

   The subject and issuer must both be `C=US, O=NVIDIA, CN=NVIDIA Model Signing
   Root CA`, valid from 2025-03-07 to 2055-02-28. The SHA-256 fingerprint we
   read on 2026-10-12 was

   ```
   08:DC:02:65:CD:BE:C8:55:D5:3B:36:FA:49:F1:01:95:47:AE:D1:B1:11:87:6B:1F:76:1F:AE:BC:BF:C1:88:9C
   ```

   NVIDIA's documentation does not publish a fingerprint, so this value is
   ours, not NVIDIA's. Compare it with a copy fetched over a different network
   path, or confirmed with NVIDIA, before relying on it. If they differ, do not
   trust the file.

3. Carry it into the air gap and name it:

   ```
   export SOCAIR_PUBLISHER_ROOTS=/etc/socair/publisher-roots   # a directory of PEM files, or one file
   ```

A scan of an NGC model directory with `result.sigstore` at its root then
PASSes provenance on the signature, naming `NVIDIA Model Signing Issuer NGC
001`, or FAILs naming each file that differs. Without the root, the signature
is named and not judged.

- Trusting the root trusts every certificate NVIDIA issues under it, for any
  model. A verified signature says NVIDIA published these bytes; it says
  nothing about whether the model is safe to run.
- The leaf NVIDIA's NGC signatures carry today is valid until 2027-03-07.
  Because the chain is checked at the scan's time, a signature made with it is
  named and not verified after that date, until NVIDIA signs with a newer
  certificate.

### Conformance

CI runs the OpenSSF Model Signing conformance suite
([ossf/model-signing-spec](https://github.com/ossf/model-signing-spec/tree/91bf841e8ccf97a3ed97309387e9298d1ac18ba2/conformance),
pinned at commit `91bf841e8ccf`) in its verify-only mode against Socair's
verifier, through `tools/oms-conformance`, a harness that maps the suite's
adapter protocol onto `internal/oms`. The suite's historical and
cross-implementation bundles are an OCI artifact the pinned suite names by
digest; CI fetches it by that digest (`tools/oms-conformance/fetch_fixtures.py`).
At that commit, on 2026-10-12:

| Result | Cases |
|---|---|
| Passed | 44: every positive and negative key and certificate case, the suite's historical key and certificate bundles from releases v0.3.1 to v1.1.0, and its Go-signed interoperability bundles |
| Expected to fail | 2, below, listed with their reasons in `tools/oms-conformance/xfail.txt` |
| Skipped | 37 roundtrip cases, because Socair does not sign, and 9 sigstore cases, because keyless bundles are verified by `tools/socair-sigstore`, which the harness does not drive |

The two expected failures are decisions, not open bugs:

- `certificate-no-code-signing-eku_fail`: the leaf has the `digitalSignature`
  key usage and no `codeSigning` extended key usage. OMS v1.0 does not require
  the extended usage, `model_signing` 1.1.1 accepts the key usage alone, and
  NVIDIA's NGC leaf carries the key usage only, so requiring it would leave
  every NGC signature unverified.
- `historical-v0.2.0-certificate`: a pre-1.0 bundle (predicate
  `https://model_signing/Digests/v0.1`), which OMS v1.0 section 11.2 says a
  verifier MAY accept. Socair names it and does not verify it.

The suite makes the bundles for its verify tests with the adapter's own
signer, so the harness signs with `internal/oms/omstest`, Socair's test
signer. On bundles made by the reference implementation, `model_signing`
1.1.1, Socair's result is the same: 44 passed and the same 2 failed. The
reference implementation itself fails `certificate-no-code-signing-eku_fail`
and `certificate-not-yet-valid_fail` at that commit; Socair passes the second
because it checks the chain at the scan's time.

## 4. The acceptance record: review, accept, re-issue

An acceptance is the person who owns the gaps signing for them. It is what
lets a report with NOT_TESTED rows (and no FAIL or LEAD) cross the airlock as
`authorized_with_conditions`. It is signed by the acceptor, with their own key,
over the exact report they reviewed:

```
socair scan model.gguf > r.json                     # withheld: some rows NOT_TESTED
socair sign --key operator.key --report r.json      # r.dsse.json, the report to review

# the acceptor reviews r.dsse.json, then:
socair accept --attestation r.dsse.json --key ciso.key --by "Jane Doe, CISO" \
  --expires <RFC 3339 time> --store <store> [--rationale "change 4411"]
                                                    # r.acceptance.dsse.json

socair sign --key operator.key --attestation r.dsse.json \
  --acceptance r.acceptance.dsse.json --store <store>
                                                    # r.conditional.dsse.json
```

- The acceptance (`https://socair.ai/acceptance/v1`, DSSE, Ed25519) names the
  artifact's hash, the reviewed report's document hash, exactly its NOT_TESTED
  rows, the acceptor, and an expiry. `--expires` may not be later than the
  report's `header.rescan_due`: the scan time plus 90 days, unless
  `SOCAIR_RESCAN_DAYS` set another number.
- `accept` and `sign --acceptance` read a store only from `--store`, not from
  `SOCAIR_STORE`; without one, pass `--trusted` (and `--acceptors`) instead.
- The re-issued attestation is the same report as `authorized_with_conditions`,
  with the acceptance embedded (`promotion_authorization.acceptance`) and the
  reviewed document's hash. The report's acceptor, surfaces, and expiry must
  match the embedded acceptance, or it cannot be signed or verified.
- Acceptor keys are their own trust list, `<store>/acceptor-keys/`
  (`socair airlock trust add --acceptor ciso.pub`), separate from the keys
  that sign attestations, and a key may not be in both. An acceptance signed by
  the key that signed the report is refused: the operator does not accept
  their own gaps.
- `airlock promote` verifies the acceptance against the acceptor keys and
  refuses one that is unsigned, untrusted, self-signed, for another report, or
  expired. `socair verify --acceptors <dir>` shows the same check.
- A verifier that checks only the operator's signature (socair-verify, as in
  the admission gate LLMKube is adding, with `allowConditions`) admits the
  re-issued attestation as it admits any conditional one.

`SOCAIR_ACCEPTED_BY` and `SOCAIR_ACCEPTANCE_EXPIRES` still name an acceptor at
scan time, and the report says so, labelled **unsigned**. The airlock does not
promote an unsigned acceptance. `SOCAIR_RESCAN_DAYS` sets the report's
`rescan_due` (default 90).

A FAIL or a LEAD is never cleared by an acceptance, and Socair has no other
path that clears one: it withholds promotion and needs a person's review
outside Socair.

## 5. A signed reference feed, `SOCAIR_FEED` and `SOCAIR_FEED_KEYS`

A feed supplies known-bad hashes, reviewed chat templates, and canonical
tokenizers as a signed bundle; see [feed.md](feed.md). Its denylist joins
`SOCAIR_DENYLIST`, its tokenizer tables join `SOCAIR_TOKENIZER_REFERENCE`, and
its reviewed template texts join `SOCAIR_TEMPLATE_REFERENCE`.

## 6. Canonical tokenizer tables, `SOCAIR_TOKENIZER_REFERENCE`

A table file, a publisher's `tokenizer.json`, or a directory of them (`*.json`).
The tokenizer row compares the model's vocabulary, token by token, with the
table of its family; see [feed.md](feed.md) for how a family is matched and
graded. A path that cannot be read stops the scan.

## 7. Reviewed chat templates, `SOCAIR_TEMPLATE_REFERENCE`

A reviewed template's text (`.jinja`), or a directory of them, each labelled by
its file name. The chat-template row renders each beside the artifact's
template on the same probe conversations: a template that renders like a
reviewed one on every standard probe but adds a content-conditional branch is
a LEAD; an identical render is noted; anything else gets no verdict. A local
reference never clears a lead; only a signed feed's `templates.txt` or the
embedded allowlist does. A path that cannot be read stops the scan.

## 8. A license policy, `SOCAIR_LICENSE_POLICY`

Every report names the license the artifact states, in its identity section
(`artifact.license`), whether or not a policy is set. The scan reads it from
the model card's front matter (`license`, `license_name`, `license_link`),
the LICENSE files at a directory's top level, and a GGUF's `general.license`
keys, and lists every statement it read and what each was identified as. A
LICENSE text is identified only when it is a license the catalogue
(`internal/checks/license/catalogue.go`) holds: a permissive license must be
its whole text with nothing added (a title and a copyright line aside), and a
model license must carry its title phrases. Anything else is reported as not
identified, with its first line, never guessed. Statements that name
different licenses are reported as a disagreement. A declared base model
(`base_model`, `general.base_model.N`) is listed too; when its publisher
releases every model under one license (Meta Llama, Google Gemma), a stated
license of another family is a disagreement.

Without a policy, none of this changes a row or the promotion state. With
one, the report adds a **License policy** row:

```
# allowed licenses, one per line: a catalogue id, an SPDX id, or a model-card tag
apache-2.0
MIT
llama3.1
```

| What the artifact states | License policy row |
|---|---|
| One license, on the list | PASS, with the license's usage-policy obligations listed and not marked met |
| One license, not on the list | FAIL (`license-not-allowed`), naming where it is stated |
| Different licenses, one of them not on the list | LEAD (`license-disagreement`): which governs needs a person |
| Different licenses, all on the list | PASS, saying they disagree |
| A license on the list beside a statement the catalogue does not recognize | NOT_TESTED: the license is not established |
| Nothing identified (no statement, only `other`, an unrecognized text, a single safetensors or pickle file) | NOT_TESTED |

- A name the catalogue does not know, or a policy that allows nothing, stops
  the scan: a misspelled id would otherwise fail every model.
- The row is not legal advice. Usage-policy obligations (Llama's acceptable
  use policy and 700-million-user clause, Gemma's prohibited use policy, a
  non-commercial term) are listed in the notes, never marked complied with.
- A disagreement is common on real repos, and a quantizer's card often names
  a different license from the original (see
  [false-positive-baseline.md](false-positive-baseline.md)), so it is a LEAD
  for review, never a FAIL.
- The report's `scope.reference_data` names the policy file by name and
  SHA-256, and its ids.

Catalogue ids are ScanCode LicenseDB keys where ScanCode has one, and
`socair-` keys otherwise:

| Id | License | Also matched as |
|---|---|---|
| `apache-2.0`, `mit`, `bsd-new`, `bsd-simplified` | Apache 2.0, MIT, BSD 3-Clause, BSD 2-Clause | SPDX ids; `bsd-3-clause`, `bsd-2-clause` |
| `cc-by-4.0`, `cc-by-sa-4.0`, `cc-by-nc-4.0`, `cc-by-nc-sa-4.0` | Creative Commons 4.0 | SPDX ids |
| `openmdw-1.0` | OpenMDW 1.0 | `OpenMDW-1.0` |
| `llama-2-license-2023`, `socair-llama-3-license-2024`, `llama-3.1-license-2024`, `llama-3.2-license-2024`, `llama-3.3-license-2024`, `llama-4-cla-2025` | Llama 2, 3, 3.1, 3.2, 3.3, 4 community licenses | `llama2`, `llama3`, `llama3.1`, `llama3.2`, `llama3.3`, `llama4` |
| `socair-gemma-terms-of-use` | Gemma Terms of Use | `gemma` |
| `qwen-2024`, `tongyi-qianwen-2023`, `socair-qwen-research-2024` | Qwen, Tongyi Qianwen, Qwen Research licenses | `qwen`, `tongyi-qianwen`, `qwen-research` |
| `deepseek-la-1.0` | DeepSeek License Agreement 1.0 | `deepseek` |
| `socair-nvidia-open-model` | NVIDIA Open Model License | `nvidia-open-model-license` |
| `socair-mistral-research-0.1`, `socair-mistral-non-production-0.1` | Mistral AI Research, Non-Production licenses | `mrl`, `mnpl` |
| `falcon-2-11b-1.0`, `socair-tii-falcon-license` | Falcon 2 11B TII License, TII Falcon License | `falcon-llm-license` |
| `bigscience-rail-1.0`, `bigscience-open-rail-m`, `bigcode-open-rail-m-v1`, `socair-creativeml-openrail-m`, `bigscience-open-rail-m2`, `socair-openrail` | RAIL licenses (BLOOM, BigScience, BigCode, CreativeML, CreativeML RAIL++, unnamed Open RAIL) | `bigscience-bloom-rail-1.0`, `bigscience-openrail-m`, `bigcode-openrail-m`, `creativeml-openrail-m`, `openrail++`, `openrail` |
| `moonshot-ai-modified-mit-2025`, `minimax-mit-variant-2025` | Kimi and MiniMax modified MIT licenses (never identified as MIT) | |
| `socair-tencent-hunyuan-community`, `socair-glm-4` | Tencent Hunyuan Community, GLM-4 licenses | `tencent-hunyuan-community`, `glm-4` |

## 9. An intake policy, `SOCAIR_INTAKE_POLICY`

Your organization's intake rules, beside the license policy and independent of
it: the formats a model file may be in (identified from its bytes), publisher
allow and deny lists (read from the provenance manifest bound to the hash,
section 3), and publishers whose models need a verified publisher signature
(section 3a). It adds an **Intake policy** row that can only withhold; see
[intake-policy.md](intake-policy.md). The report names the policy in
`scope.intake_policy`, by file name and hash.

## What each input buys, in one table

| Input | Row it moves | Without it |
|---|---|---|
| `SOCAIR_REPO_MIRROR` | File inventory and payloads, for a single file | NOT_TESTED |
| `SOCAIR_DENYLIST`, or a denylist in a feed | Known-bad hash match | NOT_TESTED |
| `SOCAIR_PROVENANCE`, or an OMS signature from a trusted publisher | Hash, provenance, lineage | NOT_TESTED |
| `SOCAIR_TOKENIZER_REFERENCE`, or tables in a feed | Tokenizer config: a changed ordinary token becomes a LEAD | PASS on internal consistency only, and the row says no reference was compared |
| `SOCAIR_TEMPLATE_REFERENCE`, or template texts in a feed | Chat template: a reviewed template plus an added content-conditional branch becomes a LEAD | the rendered inventory only, and the row says no reviewed template text was compared |
| `SOCAIR_LICENSE_POLICY` | Adds the License policy row: PASS, FAIL, LEAD, or NOT_TESTED against your allowed list | no row; the license is still named in the identity section |
| `SOCAIR_INTAKE_POLICY` ([intake-policy.md](intake-policy.md)) | Adds the Intake policy row: PASS, FAIL, or NOT_TESTED against your formats, publisher lists, and required signatures; it can only withhold | no row |
| A signed acceptance (`socair accept`) | the promotion state | withheld on any gap |
| `SOCAIR_TIER2_HELPER` and `SOCAIR_TIER2_ENDPOINT` ([tier2.md](tier2.md)) | Adds Tier 2 measurements; one that raises a LEAD or FAIL adds a row that withholds, and one that finds nothing adds no row | No Tier 2 section; its checks are listed as not run, which is not a gap |

## Falsification

Each input is proven to drive its row: `TestHappyPathDropsOneInput` removes the
provenance input and asserts the row drops to NOT_TESTED and the promotion
state drops to withheld. The same shape holds for the mirror and the denylist:
remove the input and the row returns to NOT_TESTED.

## What this is not

- It does not verify a manifest's `signing_status`: that field is the
  operator's claim, and the row says so. Publisher signatures are verified
  only as OMS bundles (section 3a), against keys and roots you configure.
- It does not fetch anything. The manifest, the mirror, and the list are all
  local, which is what makes the whole path air-gap safe. A `license_link` is
  listed, never followed.
- It does not review a license. The License policy row checks the license the
  artifact states against your list; it is not legal advice, and it does not
  check that anyone meets the license's usage terms.
