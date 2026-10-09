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
  the hub. Enforce that at the host: restrict its egress with a firewall to the
  hub (or your mirror). Socair's own egress allowlist covers `huggingface.co`,
  `hf.co`, and their CDN subdomains, and checks every redirect, but it governs
  only Socair's own requests. Within Socair, `socair airlock pull` and the
  API's pull route are the only code paths that reach the network.
- **The clean store** (`<store>/clean/`) is exported to the GPU servers
  read-only (NFS, SMB, or a read-only volume). The GPU servers never write to
  it and never reach the internet.
- **Within Socair, only `promote` writes to `clean/`**, and it admits only
  bytes whose hash matches an attestation signed by a key you trust. Make the
  store writable only by the user Socair runs as, so nothing else on the host
  writes there either.

## What each requirement maps to

| A security team asks for | Socair does |
|---|---|
| The GPU servers don't pull from the hub | Socair reaches the network only through `airlock pull` (the CLI command or the API route), from the intake host, through an allowlist; the host firewall enforces the same |
| Models pinned to a known version | A whole-repo pull must name a full commit (or the expected digest); a branch alone is refused |
| Hash checks | Every file is checked against the hub's own hash for it at that commit, and hashed again while it is copied into `clean/` |
| Approved formats only | Formats Socair does not parse are NOT_TESTED, so the model is withheld until a named person signs an acceptance of exactly those gaps. To forbid a format outright, never accept it. |
| No remote code | `auto_map` entries and `.py` files are a LEAD. No acceptance clears a LEAD and Socair has no other path that does, so a model whose `config.json` has `auto_map` ends at a Remote code LEAD and cannot cross. |
| Scanning before promotion | The Tier 1 checks run on every model you scan: structure, embedded payloads, chat template, tokenizer, pickle, quantization label, provenance, known-bad hashes. Nothing scans automatically: you run `socair scan`, or the console's scan, and `promote` needs a signed attestation from that scan |
| A record of every model brought in | Each promoted model keeps its signed attestation beside its bytes, and `log.jsonl` records every pull, promotion, and refusal in a hash chain |

## One-time setup

**1. Install Socair on the intake host.** Use a release binary and check it
before you run it; see [verify-release.md](verify-release.md). Releases are
reproducible, so you can also rebuild one from source and compare checksums.

**2. Create the store, on a volume with room.** A model is written twice at
its peak: a scan copies the staged copy into a private snapshot, and a
promotion copies it into `clean/`. `promote` does not delete the staged copy,
so a promoted model also stays in `incoming/<id>/` until you remove it by
hand. Put the scan snapshot on the store's volume too; its default is the
system temp directory, which is usually too small:

```
export SOCAIR_STORE=/srv/socair/store
export SOCAIR_SCAN_TMP=/srv/socair/scan
socair airlock init "$SOCAIR_STORE"
mkdir -p "$SOCAIR_SCAN_TMP"
```

Size the volume for `clean/` and `incoming/` together, and plan for about
twice the largest model's size free beyond what both already hold: a 755 GB
model needs roughly 1.5 TB free while it moves through. Socair never deletes
a staged copy, so remove `incoming/<id>/` by hand once you no longer need it,
or staged copies accumulate. Keep it while you may need to re-scan: a clean
entry whose acceptance expires is re-scanned and re-accepted from its staged
copy. Pull, scan, and promote each check for room before they start and
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

Promoted files are private to the user that ran `promote`: a single file is
mode 0600, and a model directory's files are 0400 inside 0700 directories. A
serving user with another uid cannot read them through a plain export. Either
export with uid mapping, such as NFS `all_squash` with `anonuid` and
`anongid` set to the Socair user's uid and gid, or run the serving process as
that uid.

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

The token is sent only to the hub's own host over https, never across a
redirect to the CDN, and never written to the log or an error.

## Bringing a model in

The console shows each step below as it happens: run
`socair serve --store "$SOCAIR_STORE" --web web/build` on the intake host and
open it on that machine. It lists what is staged and approved, scans a staged
model, files a signed attestation, and prints the exact CLI command for any
step that needs a key (promote, sign, accept). It does not hold keys, so those
steps stay in the commands below. The console is the static web app in
`web/`, built with npm from a checkout (`cd web && npm ci && npm run build`
writes `web/build`); a release binary alone does not include it. See
[wizard.md](wizard.md).

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
that were pulled, and the provenance manifest, the log, and the report's
provenance row name every file left out. Leave code out only when the serving stack does not run it: DeepSeek's
`inference/` scripts are a reference implementation that a serving engine with
native support never imports. A repo whose `config.json` has an `auto_map`
entry loads its own code, so it still shows a Remote code LEAD, and it should.

For a single file (one GGUF, for example), name the file and its expected
SHA-256, which the hub shows on the file's page. `--file` takes a plain file
name at the repo's root; for a file in a subfolder, pull the repo with
`--include <path>` instead.

```
socair airlock pull --repo <org/name> --file <name.gguf> --sha256 <hash>
```

**2. Scan it, with the provenance the pull recorded.** Write the report into
the staging entry, where the console reads it:

```
E=$SOCAIR_STORE/incoming/<id>          # the staging entry
export SOCAIR_PROVENANCE=$E/provenance.json
socair scan   $E/<name> > $E/report.json
socair render $E/<name> > report.html   # the same checks, for a person to read
```

`<id>` is the artifact's hash for a single file, or the manifest digest for a
whole repository; the pull prints the exact paths.

The console shows a staging entry's evidence from `incoming/<id>/` only:
`report.json`, `report.dsse.json`, `report.acceptance.dsse.json`, and
`report.conditional.dsse.json`. `sign`, `accept`, and `sign --acceptance`
write their output next to their input, so starting from `$E/report.json`
puts every step where the console shows it. A report written anywhere else
works for every command below, but the console will not show it.

Read the report's promotion state and its rows. Each row says what it looked
for, what it found, and what its PASS means.

**3. Sign it** (on the signing machine):

```
socair sign --key operator.key --report $E/report.json         # $E/report.dsse.json
```

If the signing machine is not the intake host, copy `report.json` to it and
bring `report.dsse.json` back into `$E`, or upload it in the console.

**4. Act on the promotion state.**

Expect most models to arrive withheld on a row or two at first. A check that
needs reference data you have not supplied is NOT_TESTED rather than a silent
pass. For example, Known-bad hash match needs a denylist or a signed feed
(`SOCAIR_DENYLIST`, `SOCAIR_FEED`; see [feed.md](feed.md)). Supply the
reference data once, and these rows start to PASS.

- **Authorized** (every row PASS): promote it.

  ```
  socair airlock promote $E/<name> --attestation $E/report.dsse.json
  ```

- **Withheld, with NOT_TESTED rows only:** the security reviewer reads the
  signed report and, if they accept those gaps, signs an acceptance for exactly
  them, with an expiry. The operator re-issues the attestation with the
  acceptance inside it, and that one promotes as "authorized with conditions".
  The conditions travel with the bytes into `clean/`. See
  [provenance-bundle.md](provenance-bundle.md) for the full flow.

  ```
  socair accept --attestation $E/report.dsse.json --key ciso.key --by "Jane Doe, CISO" \
    --expires <RFC 3339 time> --store "$SOCAIR_STORE"                 # $E/report.acceptance.dsse.json
  socair sign --key operator.key --attestation $E/report.dsse.json \
    --acceptance $E/report.acceptance.dsse.json --store "$SOCAIR_STORE" # $E/report.conditional.dsse.json
  socair airlock promote $E/<name> --attestation $E/report.conditional.dsse.json
  ```

  `--expires` may not be later than the report's `header.rescan_due`, which
  is the scan time plus 90 days unless `SOCAIR_RESCAN_DAYS` set another
  number: `jq -r .header.rescan_due $E/report.json`. `accept` and
  `sign --acceptance` read the store only from `--store`, not from
  `SOCAIR_STORE`.

- **Withheld, with a FAIL or a LEAD:** stop. The airlock will not promote it,
  no acceptance clears it, and Socair has no other path that does. A FAIL
  carries its evidence; a LEAD needs a person to review it outside Socair.
  Choose a different model or version. A model whose `config.json` has an
  `auto_map` entry ends here, at a Remote code LEAD, and cannot cross.

**5. Point the serving stack at the clean copy.** The model is at
`clean/<sha256>/<file>` (or `clean/<digest>/<name>/` for a whole repository).
Serve from that path, read-only, through the uid-mapped export from setup
step 5 or as the Socair user.

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
  a careless edit or deletion breaks the chain:

  ```
  socair airlock log --verify          # prints the head
  ```

  The chain is unkeyed SHA-256. Whoever can write `log.jsonl` can rewrite it
  and recompute every link, an edit to the last line leaves nothing to break,
  and a chain cannot show lines cut off its end. Only a head recorded off the
  box catches that: record the head somewhere the intake host cannot rewrite
  (a ticket, a change record), and check against it later with
  `--expect-head <head>`. That covers every entry up to the recorded head.

## Kubernetes

[LLMKube](https://github.com/defilantech/LLMKube) is adding an admission gate
that refuses to serve a model without an admitted Socair attestation. On a GPU
cluster that runs it, a model copied around the airlock would then still be
stopped at serve time.

## What this does not do

The intake host makes sure the GPU servers run only bytes that were pulled
from a pinned source, checked, signed for, and recorded. It does not tell you
how the model behaves. Tier 1 checks the file: it does not test the weights for
backdoors or poisoning, behavior that appears only after quantization or on
particular hardware, or jailbreak susceptibility, and it is not a legal
review of the model's license: it names the license the artifact states, and
checks it only against an allowed list you configure
(`SOCAIR_LICENSE_POLICY`). Every attestation states this, and the full list is the
[detection ceiling](detection-ceiling.json).
