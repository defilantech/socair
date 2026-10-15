# Signed reference feeds

Some checks compare an artifact against reference data: known-bad artifact
hashes, reviewed known-good chat templates, and canonical tokenizers. A
**feed** delivers that data as a signed bundle, so an air-gapped site can
import it and know who vouched for it and until when.

A feed is your organization's own. Your security team builds it, signs it
with its own key using the `socair` CLI, and every intake host verifies it
against that key: one review, enforced on every host, under your name. The
Socair project publishes no feed and signs no reference data, just as it
signs no one's attestation: whoever signs is the issuer
([Your organization's feed](#your-organizations-feed)).

Without a feed or a local list, the Known-bad hash match check does not run.
The report names it under Out of scope, with the reason, and it withholds
nothing: there is no standing public list of malicious model files to default
to, and a match against nothing would say nothing.

## Using a feed

```
export SOCAIR_FEED=/opt/socair/feed            # the feed directory
export SOCAIR_FEED_KEYS=/opt/socair/feed-keys  # public key(s) the feed must be signed by
socair scan model.gguf
```

Check a feed before importing it: `socair feed verify <dir> --keys <key.pub|dir>`.
With `--store <path>` it also says whether a scan with that store would take
it ([Rollback protection](#rollback-protection)).

A configured feed that does not verify, or has expired, **stops the scan**: a
feed changes verdicts, so Socair never runs on unverified reference data and
never quietly drops it either. The report names the feed it used, in
`scope.reference_data`: its issuer, version, issue and expiry times, and signing
key.

With a store, a feed issued before the newest one that store has used stops
the scan too ([Rollback protection](#rollback-protection)). A feed in the last
third of its validity is still used, with a warning that names when it expires
([Before a feed expires](#before-a-feed-expires)).

A new feed changes the scans that run with it. Models already in an airlock's
clean store are re-checked against it with `socair airlock recheck`, which
flags a model whose hash the new denylist names ([airlock.md](airlock.md),
"Rechecking the clean store").

## Before a feed expires

A feed past `expires` stops every scan and recheck that uses it. So that a site
hears about it first, Socair warns from the start of the last third of the
feed's validity, counted from `issued` to `expires`: 30 days ahead for a 90-day
feed, 10 days ahead for a 30-day one. A fraction, rather than a fixed number of
days, scales with the issuer's cadence: a 90-day feed released monthly warns
only once two releases have been missed, and a 7-day feed warns about two days
ahead instead of for its whole life.

The warning names the feed, when it expires, and that scans will then stop:

```
warning: feed Example Intel 2026.10.1 expires at 2026-12-30T00:00:00Z, in 12 days: after that, every scan and recheck that uses it stops. Import a newer feed before then
```

It appears in:

- `socair scan`, `socair airlock ingest --scan`, and `socair airlock recheck`,
  on stderr;
- `socair feed verify`, on stderr, after the verified line;
- the console, as a line under the header, from `GET /api/feed`
  ([api.md](api.md)). The same line shows a feed that has expired, does not
  verify, or that the store would refuse.

The warning changes nothing else. It is not a check row, it changes no verdict
and not the bounded statement, and the report gains no field: its
`scope.reference_data` already names the feed's expiry time. `socair health`
does not report it: health is the container's liveness and readiness probe, and
failing it for a feed that still works would restart the pod or take it out of
service. A monitor can read `GET /api/feed`.

## Rollback protection

A configured feed can be swapped for an older release that is still inside its
validity window, so that the older denylist and reviews apply again: a hash
added since is no longer known-bad, and a review withdrawn since clears a lead
again. [TUF][tuf] (The Update Framework, specification 1.0.37) names this a
rollback attack: "An attacker cannot trick clients into installing software
that is older than that which the client previously knew to be available"
(section 1.5.2). Its clients keep the metadata they trust and refuse an older
version: "Clients MUST NOT replace a metadata file with a version number less
than the one currently trusted" (section 4.3), and the timestamp step aborts on
a lower version and reports a rollback (section 5.4, step 3). How long an old
feed can be replayed is bounded by its expiry, as TUF's expiry check bounds a
freeze attack (section 5.4, step 4).

Socair applies the same rule to a feed wherever a store is in use.

- **What is compared: the signed `issued` time.** A feed issued after the one
  the store last used replaces it. The same feed (the same signed statement)
  passes. A feed issued before it, or a different feed issued in the same
  second, is refused. `version` is a free-form label with no defined order
  (`2026.10.1`, `oct-b`), so it names a feed but is not compared. TUF orders by
  an integer version; this format has none, and adding one would change the
  format for every issuer.
- **One record per store, across issuers and keys.** A feed signed by another
  key in `SOCAIR_FEED_KEYS`, or naming another issuer, is held to the same
  order, so an old key left trusted after a rotation does not reopen older
  feeds. The cost: switching to another issuer whose newest feed was issued
  before the one in use needs the explicit acceptance below.
- **Where it applies.** Every scan and recheck that runs with a store:
  `socair scan --store <path>` (or with `SOCAIR_STORE` set), `socair airlock
  ingest --scan`, `socair airlock recheck` (before it writes any evidence, and
  again in each rescan), and `socair serve --store`, for `POST /api/scan` and
  the console's scan alike.
- **A refusal is a stop, not a verdict.** The scan stops before it reads the
  artifact, as for an expired feed, and no report is made. The error names
  both feeds by issuer, version, and issue time. The store logs it
  (`action: feed`, `outcome: refused`).

### Where the record lives

The store keeps `feed-record.json` in its root, written through a temp file and
a rename, and appends a `feed` entry to its activity log each time the record
changes, carrying the same fields under the log's hash chain:

```json
{"format":"socair.feed-record/v1","issuer":"Example Intel","version":"2026.10.1",
 "issued":"2026-10-01T00:00:00Z","expires":"2026-12-30T00:00:00Z","key_id":"…",
 "statement_sha256":"…","recorded_utc":"2026-10-03T09:12:44Z"}
```

`statement_sha256` is the SHA-256 of the feed's signed statement, so it names
the exact feed: its predicate and every data file's digest.

The file and the log must agree. A scan replays the log's feed entries in
order, where each `ok` entry must be newer than the one before and only an
`accepted` entry may go back, and compares the result with the file. A missing
or unreadable file, a log with no feed entry while the file names one, a file
that names another feed than the log, or a log that goes back without an
accepted entry stops the scan with that reason. None of them resets the record.

So deleting or editing one of the two does not downgrade a store. Doing it to
both means changing the log: an edited or removed entry breaks its hash chain,
which `socair airlock log --verify` reports, and a log cut short or rewritten
whole shows only against a head recorded off the box (`--expect-head`; see
[airlock.md](airlock.md), "Hash chain"). An appended `accepted` entry is let
through, as it must be for a real rollback, and shows in the log and the
console's activity as one.

### Going back on purpose

When a feed release is withdrawn, for example because it listed a false
positive, the site goes back to the release before it:

```
socair airlock feed accept <feed dir> --keys <key.pub|dir> --reason "<why>" [--store <path>]
```

It verifies the feed as `feed verify` does (an expired feed cannot be
accepted), records it as the store's newest whatever the record held, and logs
`action: feed`, `outcome: accepted`, naming the feed it replaced and the
reason. The reason is required. The same command repairs a record whose two
witnesses disagree, once the log has been checked. No environment variable
skips the comparison, and the API cannot accept a feed.

### What is and is not protected

- **A scan with no store keeps no state**, so it cannot tell an older feed from
  a newer one. `socair scan` without `--store` or `SOCAIR_STORE`, and `socair
  serve` without `--store`, refuse only a feed that has expired or does not
  verify. To protect the scans on a box, run them with its store.
- A store that has never recorded a feed takes the first one it is given. So
  does a store whose record and log are both gone, which only a log head
  recorded off the box reveals. A store created before this check existed has
  no record until its first scan with a feed.
- The record holds feeds back; it does not require one. A scan with
  `SOCAIR_FEED` unset uses no feed, and its report's `scope.reference_data`
  says which reference data it did use.
- A freeze, where a site is kept on its current feed and never shown a newer
  one, is bounded by the feed's expiry and the warning above, not by the
  record.
- The order trusts the issuer's clock: `feed sign` stamps `issued` with the
  signing machine's time. A feed issued in the future is refused at load (five
  minutes of skew are allowed), so a feed cannot push the record ahead unless
  the scanning host's clock is ahead too. If that happened, `feed accept`
  brings the record back, as a TUF client recovers from a fast-forward attack
  by discarding the metadata it trusted (section 5.3, step 11).

[tuf]: https://theupdateframework.github.io/specification/latest/

## Your organization's feed

What goes into it is your organization's decisions, recorded once:

- **Known-bad hashes** (`denylist.txt`): files your incident response, your
  threat intelligence, or a vendor's published report names. There is no
  standing public list of malicious model files; the few public sources are
  one-off vendor and researcher reports that print hashes. Any changed byte
  gives a new hash, so this catches exact copies only; the Pickle, Format and
  structure, and Chat template checks do the main work.
- **Reviewed chat templates** (`templates.txt`, `templates/<sha256>.jinja`):
  templates your reviewers have read. A listed template clears a *language*
  lead on that exact template at every host that imports the feed (never
  structural evidence), so a reviewer reads a model's template once, not at
  every scan.
- **Canonical tokenizers** (`tokenizers.txt`, `tokenizers/<name>.json`): the
  tokenizers of models you have approved, so a fine-tune that remaps tokens
  shows as a LEAD.

Keep the signing key off the machines that import the feed, and set an expiry
your hosts can import within ([Before a feed expires](#before-a-feed-expires)).

## What a feed changes

| Data file | Check | Effect |
|---|---|---|
| `denylist.txt` | Known-bad hash match | Combined with any local `SOCAIR_DENYLIST`. A match is a FAIL. In a model directory, the manifest digest and every file's hash are matched. |
| `templates.txt` | Chat template | Added to the embedded reviewed-template allowlist. A template whose SHA-256 is listed clears *language* leads to PASS, and the row notes it is byte-identical to the reviewed template, by its label. It never clears structural evidence: code-execution reach still FAILs. |
| `templates/<sha256>.jinja` | Chat template | A reviewed template's text, listed in `templates.txt` under the same hash. The check renders it beside the artifact's template on the same probe conversations. A template that renders identically on every probe is noted as matching it; one that renders like it on every standard probe but adds a content-conditional branch (it renders differently only when a message carries a literal one of its own conditions tests) is a LEAD with the first difference as evidence; any other template gets no verdict from it, only a note that it matched none. `SOCAIR_TEMPLATE_REFERENCE` (a `.jinja` file or a directory of them, labelled by file name) supplies texts locally, without a feed; those are compared with but never clear a lead. |
| `tokenizers.txt` | Tokenizer config | Informational. The row notes whether the tokenizer's hash matches a canonical tokenizer, and by name. A hash alone cannot say which tokens changed, so it does not change the row's status. |
| `tokenizers/<name>.json` | Tokenizer config | A canonical tokenizer table: the family's vocabulary in id order. The check picks the table that agrees with the model's vocabulary on at least 98% of ids (anything less is another family, not compared), then compares every id. A changed ordinary token, or a vocabulary that ends early, is a LEAD with the ids as evidence. Renamed special or reserved tokens and tokens added past the table are notes: fine-tunes do both legitimately. `SOCAIR_TOKENIZER_REFERENCE` supplies the same tables locally, without a feed. |

## Format

A feed is a directory:

```
feed/
  feed.dsse.json    the signed statement
  denylist.txt      optional
  templates.txt     optional
  tokenizers.txt    optional
  tokenizers/       optional: <name>.json canonical tokenizer tables
  templates/        optional: <sha256>.jinja reviewed template texts
```

A reviewed template's text is named by its SHA-256 and must hash to its name,
and that hash must be listed in `templates.txt`, whose label names it in a
report. Like a tokenizer table, a text the signature does not cover refuses
the feed.

A tokenizer table is `{"format": "socair.tokenizer-table/v1", "name": "qwen3",
"tokens": [...]}`, the vocabulary in id order, or a publisher's
`tokenizer.json` as it ships. Table names are lowercase (`[a-z0-9._-]`), and
every table is listed in the signed statement like the other data files: a
table the signature does not cover refuses the feed. Build one from a trusted
`tokenizer.json` or GGUF:

```
socair feed tokenizer-table tokenizer.json --name qwen3 > feed/tokenizers/qwen3.json
```

Each data file holds one entry per line; blank lines and lines starting with
`#` are ignored. Signed data is held to its format: a malformed line refuses
the feed.

```
# denylist.txt: <sha256> <label>
3f1a…9c  trojaned community quant, reported 2026-09

# templates.txt: <sha256> [label]
8e0b…41  Qwen/Qwen3-8B@a1b2c3d, reviewed 2026-09

# tokenizers.txt: <sha256> <name>
c038…f2  qwen2.5
```

Template hashes are the full SHA-256 (64 hex characters) of the template text.
For a GGUF's default template, the report's `artifact.chat_template_hash`
holds it. `socair template <path>` prints only the first 16 hex characters, so
do not copy a feed line from it. For a template in its own file, such as
`chat_template.jinja`, the file's SHA-256 (`sha256sum chat_template.jinja`) is
the hash. Tokenizer hashes are what the report's `artifact.tokenizer_hash`
holds: the SHA-256 of `tokenizer.json` for a model directory, or of the
vocabulary for a GGUF.

`feed.dsse.json` is a DSSE envelope, signed with Ed25519, over an in-toto
Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "denylist.txt", "digest": {"sha256": "…"}},
    {"name": "templates.txt", "digest": {"sha256": "…"}}
  ],
  "predicateType": "https://socair.ai/feed/v1",
  "predicate": {
    "issuer": "Example Intel",
    "version": "2026.10.1",
    "issued": "2026-10-01T00:00:00Z",
    "expires": "2026-11-01T00:00:00Z",
    "description": "optional"
  }
}
```

The feed verifies when all of these hold:
- the signature is from a key in `SOCAIR_FEED_KEYS`;
- every data file matches its subject digest;
- no data file is present that the statement does not list;
- the current time falls between `issued` and `expires` (five minutes of clock
  skew are allowed on `issued`).

## Building a feed

```
socair key gen --out feed-signer
socair feed sign ./feed --key feed-signer.key --issuer "Example Intel" \
  --version 2026.10.1 --expires <RFC 3339 time>
socair feed verify ./feed --keys feed-signer.pub
```

`--expires` is when importing sites stop accepting the feed, in RFC 3339
(`YYYY-MM-DDTHH:MM:SSZ`); a feed past it stops every scan that uses it, and
sites are warned from the start of its last third.

`feed sign` stamps `issued` with the current time, and a site with a store
orders feeds by it: sign each release after the one before, on a machine whose
clock is right. A site that has used a release refuses one issued before it.

`feed sign` lists every data file present in the directory and signs it. Keep
the signing key off the machines that import the feed. Those machines only need
`feed-signer.pub`.
