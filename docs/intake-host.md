# Running Socair as your model intake host

When a team puts GPU servers on-prem, security usually asks for the same
thing: the GPU servers should not pull models from the internet themselves.
Instead, one controlled host brings each model in, checks it, and keeps a
record. The servers then read only what that host approved.

This guide sets that up with Socair. It covers the network shape, the one-time
setup, the routine for bringing a model in, and the record it leaves behind.
The commands are the same ones documented in [airlock.md](airlock.md); this
page puts them in order for this deployment.

## The shape

```
 Hugging Face                    intake host                         GPU cluster
 (or a mirror)                   (socair airlock)                    (no internet)

 huggingface.co  ── pull ──▶  incoming/<sha256>/   staging
                              scan, sign
                              promote ──────────▶  clean/<sha256>/  ── read-only mount ──▶  serving
                              log.jsonl            the record
```

- **The intake host** is the only machine that reaches the model hub, and only
  the hub: Socair's egress allowlist covers `huggingface.co`, `hf.co`, and their
  CDN subdomains, and every redirect is checked against it.
- **The clean store** (`<store>/clean/`) is exported to the GPU servers
  read-only (NFS, SMB, or a read-only volume). The GPU servers never write to
  it and never reach the internet.
- **Nothing reaches `clean/` except through `promote`**, and `promote` admits
  only bytes whose hash matches an attestation signed by a key you trust.

## What each requirement maps to

| A security team asks for | Socair does |
|---|---|
| The GPU servers don't pull from the hub | Only `socair airlock pull` reaches the network, from the intake host, through an allowlist |
| Models pinned to a known version | A whole-repo pull must name a full commit (or the expected digest); a branch alone is refused |
| Hash checks | Every file is checked against the hub's own hash for it at that commit, and hashed again while it is copied into `clean/` |
| Approved formats only | Formats Socair does not parse are NOT_TESTED, so the model is withheld until a named person signs an acceptance of exactly those gaps. To forbid a format outright, never accept it. |
| No remote code | `auto_map` entries and `.py` files are a LEAD. A LEAD cannot be accepted away; only escalated review clears it, so such a model does not cross. |
| Automated scanning | The Tier 1 checks run on every model: structure, embedded payloads, chat template, tokenizer, pickle, quantization label, provenance, known-bad hashes |
| A record of every model brought in | Each promoted model keeps its signed attestation beside its bytes, and `log.jsonl` records every pull, promotion, and refusal in a hash chain |

## One-time setup

**1. Install Socair on the intake host.** Use a release binary and check it
before you run it; see [verify-release.md](verify-release.md). Releases are
reproducible, so you can also rebuild one from source and compare checksums.

**2. Create the store, on a volume with room.** A model is written twice at
its peak. A scan copies it into a private snapshot beside the staged copy, and
a promotion copies it into `clean/` before the staged copy is removed. Put the
scan snapshot on the store's volume too; its default is the system temp
directory, which is usually too small:

```
export SOCAIR_STORE=/srv/socair/store
export SOCAIR_SCAN_TMP=/srv/socair/scan
socair airlock init "$SOCAIR_STORE"
mkdir -p "$SOCAIR_SCAN_TMP"
```

Plan for about twice the largest model's size free, beyond what `clean/`
already holds: a 755 GB model needs roughly 1.5 TB free while it moves
through. Pull, scan, and promote each check for room before they start and
refuse with the shortfall, rather than failing partway through a long copy.

**3. Create the signing key, ideally on a different machine.** The operator key
signs attestations. Keep the private key off the intake host if you can; the
store needs only the public key.

```
socair key gen --out operator --issuer "Acme ML Platform"   # operator.key (mode 0600), operator.pub
socair airlock trust add operator.pub --name "Acme ML Platform"
```

**4. Create the acceptor key for your security reviewer.** Acceptances of
untested surfaces are signed by a person, with a key that is not the operator
key. The airlock refuses a self-accepted attestation.

```
socair key gen --out ciso --issuer "Security review"        # held by the reviewer
socair airlock trust add --acceptor ciso.pub
```

**5. Export `clean/` read-only to the GPU servers.** Mount
`$SOCAIR_STORE/clean` on each server read-only. Do not export `incoming/`,
`trusted-keys/`, `acceptor-keys/`, or the log.

**6. Optional: a mirror.** If the intake host reaches the hub through a mirror,
set `SOCAIR_HF_ENDPOINT` (its host joins the allowlist) and, if it redirects,
`SOCAIR_EGRESS_ALLOW`.

**7. Optional: a Hugging Face token, for gated repos.** Llama, Gemma, and
other gated repos refuse an anonymous download and hide their file hashes. Accept
the repo's terms on the hub with the account, create a read-only token for
it, and set it on the intake host:

```
export HF_TOKEN=hf_...
```

The token is sent only to the hub's own host, never across a redirect to the
CDN, and never written to the log or an error.

## Bringing a model in

The console shows each step below as it happens: run
`socair serve --store "$SOCAIR_STORE" --web web/build` on the intake host and
open it on that machine. It lists what is staged and approved, scans a staged
model, files a signed attestation, and prints the exact CLI command for any
step that needs a key (promote, sign, accept). It does not hold keys, so those
steps stay in the commands below. See [wizard.md](wizard.md).

**1. Pull it, pinned to a commit.** Take the commit from the model's page on
the hub. The pull verifies every file and prints the scan command to run next.

```
socair airlock pull --repo Qwen/Qwen2.5-7B-Instruct --revision <40-hex commit>
```

Large repos often carry more than the serving stack loads: reference code,
papers, a build for another platform, a second copy of the weights. Leave
those out with `--exclude`, or name what to keep with `--include`. The patterns
work like `hf download`'s: `*` crosses directories, and a trailing `/` means
the whole directory. Flags repeat, or take a comma-separated list.

```
# 65 GB instead of 195 GB: skip the Metal build and the original checkpoint
socair airlock pull --repo openai/gpt-oss-120b --revision <commit> \
  --exclude metal/ --exclude original/

# the weights, configs, tokenizer, and chat template, without the reference code
socair airlock pull --repo deepseek-ai/DeepSeek-V4.1-Flash --revision <commit> \
  --exclude inference/,encoding/,evaluation/,assets/ --exclude '*.pdf'
```

Left-out files are never fetched. The attestation covers exactly the files
that were pulled, and the provenance manifest and the log name every file left
out. Leave code out only when the serving stack does not run it: DeepSeek's
`inference/` scripts are a reference implementation that a serving engine with
native support never imports. A repo whose `config.json` has an `auto_map`
entry loads its own code, so it still shows a Remote code LEAD, and it should.

For a single file (one GGUF, for example), name the file and its expected
SHA-256, which the hub shows on the file's page:

```
socair airlock pull --repo <org/name> --file <name.gguf> --sha256 <hash>
```

**2. Scan it, with the provenance the pull recorded.**

```
export SOCAIR_PROVENANCE=$SOCAIR_STORE/incoming/<id>/provenance.json
socair scan   $SOCAIR_STORE/incoming/<id>/<name> > report.json
socair render $SOCAIR_STORE/incoming/<id>/<name> > report.html   # the same checks, for a person to read
```

`<id>` is the artifact's hash for a single file, or the manifest digest for a
whole repository; the pull prints the exact paths.

Read the report's promotion state and its rows. Each row says what it looked
for, what it found, and what its PASS means.

**3. Sign it** (on the signing machine):

```
socair sign --key operator.key --report report.json            # report.dsse.json
```

**4. Act on the promotion state.**

Expect most models to arrive withheld on a row or two at first. A check that
needs reference data you have not supplied is NOT_TESTED rather than a silent
pass. For example, Known-bad hash match needs a denylist or a signed feed
(`SOCAIR_DENYLIST`, `SOCAIR_FEED`; see [feed.md](feed.md)). Supply the
reference data once, and these rows start to PASS.

- **Authorized** (every row PASS): promote it.

  ```
  socair airlock promote $SOCAIR_STORE/incoming/<id>/<name> --attestation report.dsse.json
  ```

- **Withheld, with NOT_TESTED rows only:** the security reviewer reads the
  signed report and, if they accept those gaps, signs an acceptance for exactly
  them, with an expiry. The operator re-issues the attestation with the
  acceptance inside it, and that one promotes as "authorized with conditions".
  The conditions travel with the bytes into `clean/`. See
  [provenance-bundle.md](provenance-bundle.md) for the full flow.

  ```
  socair accept --attestation report.dsse.json --key ciso.key --by "Jane Doe, CISO" \
    --expires 2027-01-31T00:00:00Z --store "$SOCAIR_STORE"          # report.acceptance.dsse.json
  socair sign --key operator.key --attestation report.dsse.json \
    --acceptance report.acceptance.dsse.json --store "$SOCAIR_STORE" # report.conditional.dsse.json
  socair airlock promote $SOCAIR_STORE/incoming/<id>/<name> --attestation report.conditional.dsse.json
  ```

- **Withheld, with a FAIL or a LEAD:** stop. The airlock will not promote it,
  and no acceptance clears it. A FAIL carries its evidence; a LEAD needs a
  person to review it. Choose a different model or version, or escalate.

**5. Point the serving stack at the clean copy.** The model is at
`clean/<sha256>/<file>` (or `clean/<digest>/<name>/` for a whole repository).
Serve from that path, read-only.

## Reading the clean store

"In `clean/`" does not mean "clean": a conditional promotion crosses too. Any
listing should show each model's attestation state, not just its presence.

```
for a in "$SOCAIR_STORE"/clean/*/attestation.json; do
  jq -r '[.promotion_authorization.state, .artifact.name, .artifact.sha256] | @tsv' "$a"
done
```

## The record

- **Per model:** `clean/<id>/attestation.dsse.json` is the signed attestation
  that let the bytes in, and `attestation.json` is its readable report. Anyone
  can verify the attestation offline against your public key:
  `socair verify attestation.dsse.json --trusted operator.pub --artifact <file>`.
- **For leadership:** a dated snapshot of what is approved, for filing or for
  someone who cannot reach the host.

  ```
  socair airlock export --out snapshot-2026-10 --key operator.key
  socair inventory verify snapshot-2026-10 --trusted operator.pub
  ```

  The snapshot holds the approved list, each model's attestation and report,
  and the log with its head, with no model bytes. It is signed with the
  operator key, and `inventory verify` checks it offline. See
  [airlock.md](airlock.md).
- **Per action:** `log.jsonl` records every pull, ingest, trust change,
  promotion, and refusal. Each line carries the hash of the line before it, so
  an edited or deleted line breaks the chain:

  ```
  socair airlock log --verify          # prints the head
  ```

  A chain cannot show lines cut off its end, so record the head somewhere the
  intake host cannot rewrite (a ticket, a change record), and check against it
  later with `--expect-head <head>`.

## Kubernetes

If the GPU cluster runs Kubernetes with [LLMKube](https://github.com/defilantech/LLMKube),
its admission gate can refuse to serve a model without an admitted Socair
attestation, so a model copied around the airlock is still stopped at serve
time.

## What this does not do

The intake host makes sure the GPU servers run only bytes that were pulled
from a pinned source, checked, signed for, and recorded. It does not tell you
how the model behaves. Tier 1 checks the file: it does not test the weights for
backdoors or poisoning, behavior that appears only after quantization or on
particular hardware, or jailbreak susceptibility, and it does not check
licensing. Every attestation states this, and the full list is the
[detection ceiling](detection-ceiling.json).
