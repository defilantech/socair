# SARIF

Socair renders every report as a SARIF 2.1.0 log (`internal/render/sarif`) for
code-scanning tools such as GitHub code scanning. Like the other renderings,
it is derived from the report and says nothing the report does not.

```
socair render model.gguf --sarif report.sarif    # scan, write the SARIF log
```

`POST /api/render` with `"format": "sarif"` returns the log for a report
document ([api.md](api.md)).

## What the log says

One run, whose tool is `Socair`, with one rule and one result per check row,
in the report's order.

| Field | Holds |
|---|---|
| `ruleId` | The row's name in lower case, with every run of other characters written as `-` (`hash-provenance-lineage`). |
| `kind` | `pass` for a PASS. Absent otherwise, which SARIF reads as `fail` (section 3.27.9). |
| `level` | `error` for a FAIL, `warning` for a LEAD, `note` for a NOT_TESTED, `none` for a PASS. |
| `message.text` | The status, then the row's evidence, or its notes when it has none. |
| `locations` | The artifact's file name (for a model directory, the directory's name) as a relative URI reference, percent-encoded where RFC 3986 requires. No region: a model file and a directory have no lines to point at. Left out when the report names no file. |
| `partialFingerprints` | `socairFindingHash/v1` and `primaryLocationLineHash`, both holding the row's fingerprint (below). Left out when the report records no artifact SHA-256, as a header-only sweep does. |

Each rule carries the row's name, what the check looks for, and in
`properties` the framework tags and the `security-severity` of a FAIL or LEAD
([attestation-template.md](attestation-template.md)). The run's properties are
`socairPromotionState`, `socairArtifactSHA256`, and `socairFrameworkEditions`.

A NOT_TESTED keeps SARIF's default kind, `fail`, at level `note`. SARIF's
kinds for an undecided result, `open` and `review`, require level `none`, and
GitHub code scanning reads the level and not the kind, so a NOT_TESTED written
that way could pass for a PASS there.

The log validates against the OASIS SARIF 2.1.0 schema (Errata 01), by test.
It is byte-stable for a fixed report. `internal/render/sarif/testdata/report.sarif.json`
is the log of `testdata/report.json`; `go test ./internal/render/sarif -run
TestGoldenSARIF -update` rewrites it.

## Fingerprints

Successive scans can report the same finding. Deciding which results are the
same is the job of the system the results go to (SARIF 2.1.0 section 3.27.2),
and a producer contributes to that decision with partial fingerprints
(section 3.27.17). GitHub code scanning reads only `primaryLocationLineHash`
([GitHub][gh-sarif]). Its `upload-sarif` action fills that value in by hashing
the text at the line a result points at, but it skips a result with no region,
a file not in the checkout, and a directory, and keeps a value the log already
has ([`fingerprints.ts`][gh-fingerprints]). A model file has no lines to hash,
so without a value from Socair a result reaches GitHub with no fingerprint,
and GitHub warns that results uploaded without fingerprint data can show up as
duplicate alerts.

A row's fingerprint is the SHA-256, in lower-case hex, of five values in
order, each written as a [netstring][netstrings] (its length in bytes in
decimal, `:`, the bytes, `,`):

1. `socairFindingHash/v1`
2. the artifact's SHA-256 as the report records it (for a model directory, the
   digest of its manifest)
3. the row's name
4. the row's status
5. the row's evidence: each finding's pattern, span, and detail as the report
   writes them, or empty for a row without findings

For example, a Chat template FAIL with the evidence
`dunder-reach: ''.__class__ (attribute reach into Python internals)` on the
artifact `13d44e37...c4e8f444` hashes

```
20:socairFindingHash/v1,64:13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444,13:Chat template,4:FAIL,66:dunder-reach: ''.__class__ (attribute reach into Python internals),
```

`TestFingerprintKnownAnswer` pins this computation. The same value goes under
both keys: `primaryLocationLineHash` because it is the only one GitHub reads,
and `socairFindingHash/v1` because SARIF asks a producer to name a partial
fingerprint for what it hashes and to version the name. A different
computation will get a new name, `socairFindingHash/v2`.

Nothing else goes in. The document id, the issue and scan times, the input
path, the execution context, and the tool and check-set versions change
between scans of the same bytes without the finding changing. The file name
is left out because the hash already identifies the bytes, and a code-scanning
tool keeps locations apart anyway (GitHub opens a new alert when the path
changes). The notes explain a row (a NOT_TESTED reason, a Tier 2 score) and
can be reworded or vary between runs. The severity is derived from the status
and the evidence, and the framework mappings are editorial.

What counts as the same finding:

- **The same bytes, row, status, and evidence**: the same fingerprint, on any
  host and at any time. Rescanning a model does not open new alerts.
- **A new revision of the model**: any changed byte changes the artifact's
  SHA-256, and for a model directory any changed file changes its digest, so
  every row gets a new fingerprint. The finding is new, and the old alert
  closes when an analysis no longer reports it. The attestation, an
  acceptance, and the airlock are all bound to the artifact's hash; a
  dismissal in a code-scanning tool is a review of the bytes it was raised on,
  and it does not carry over to bytes nobody reviewed.
- **Another status**: a new fingerprint. A LEAD that becomes a FAIL is a
  different finding.
- **Other evidence**: a new fingerprint, so a dismissed alert never hides
  evidence nobody has seen. The cost is a new alert for an unchanged finding
  when a Socair release rewords a finding's detail ([check-set.md](check-set.md)
  records such changes), when reference data names its own version in the
  evidence (a denylist entry from a feed carries the feed's version in its
  label), or when a Tier 2 measurement matches different model output on a
  later run.
- **A row with no evidence**, as a PASS or a NOT_TESTED usually is: its
  fingerprint is the artifact, the row, and the status.

SARIF's Appendix B says a tool should not put into a partial fingerprint what
a result management system could work out from the log itself, a file hash
for example. Socair puts the artifact's hash in because GitHub does not read
file hashes: of the partial fingerprints it uses only
`primaryLocationLineHash`, so the artifact's identity has to be in that value.

## Uploading to GitHub code scanning

- **One category per model.** GitHub separates analyses by category, read
  from `runAutomationDetails.id` ([GitHub][gh-sarif]). Socair leaves it unset
  for the uploader: `upload-sarif` sets it from its `category` input, and a
  value already in the log would take precedence over that input
  ([`upload-lib.ts`][gh-upload]). The action refuses a second upload of one
  tool and category in a job, and on github.com two runs of one category in
  one upload. A workflow that scans several models gives each its own
  category, and keeps it across revisions (for example the model's path), so
  the analysis of a new revision closes the alerts the last one raised.
- **The location is a file name, not a path.** GitHub reads a relative URI as
  relative to the repository's root ([GitHub][gh-sarif]). The log names the
  artifact's file name, so for a model committed below the root, alerts point
  at a path that does not exist unless the uploader rewrites it.

[gh-sarif]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
[gh-fingerprints]: https://github.com/github/codeql-action/blob/eb94de7c5cfc51dc10fff26d52210eb23a589b0e/src/fingerprints.ts
[gh-upload]: https://github.com/github/codeql-action/blob/eb94de7c5cfc51dc10fff26d52210eb23a589b0e/src/upload-lib.ts
[netstrings]: https://cr.yp.to/proto/netstrings.txt

The SARIF sections cited are from the OASIS Standard with Errata 01:
<https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html>.
