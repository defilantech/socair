# Security policy

Socair reads hostile files for a living: model artifacts, chat templates,
pickle streams, and signatures crafted by whoever published them. A bug that
lets a file crash the scanner, hide from a check, or earn a PASS it should not
is a vulnerability, and we want to hear about it privately first.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository. If you cannot use
GitHub, email **security@socair.ai** instead. Please do not open a public
issue, pull request, or discussion for a suspected vulnerability.

Include what you can of: the affected version or commit, the input or steps
that reproduce it, what you expected, and what happened. A minimal file that
triggers it is the most useful thing you can send.

**Send a defanged proof of concept, never live malware.** Keep the structure
that triggers the bug (the gadget, the opcodes, the archive trick, the
template construct) and replace any payload with something harmless, such as
`echo socair-poc`. That is how the cases in the
[detection benchmark](docs/detection-benchmark.md) are built: Socair's static
checks read a file's structure and never load it, so a defanged file shows the
bug as well as the original would. Several related findings can go in one report.

We aim to acknowledge a report within **3 business days** and to give an
assessment within **10 business days**. We will keep you informed while we
fix it, agree a disclosure date with you, and credit you in the advisory
unless you ask us not to.

## Advisories and CVEs

A confirmed vulnerability, including a bypass of a check's documented rules,
gets a GitHub security advisory on this repository. We request a CVE for it
when you or we think one is warranted; when in doubt, we request one. The fix
updates the affected check, its benchmark case, and the detection ceiling
where the finding changes what Socair claims.

## Severity

We assess each report on its impact; this is where we start:

| Finding | Severity |
|---|---|
| Bytes cross into the clean store, or pass a verifier, without the attestation (and, for a conditional crossing, the signed acceptance) that should be required | Critical |
| A forged or altered attestation, acceptance, feed, or publisher signature verifies | Critical |
| A file earns a PASS where a check's documented rules say FAIL or LEAD | High |
| A FAIL or a LEAD comes out as NOT_TESTED. This is a bypass too: a signed acceptance can clear NOT_TESTED, never a FAIL or a LEAD | High |
| `HF_TOKEN` or a private key leaks to a log, an error, or another host | High |
| The local API answers a request from another origin, or through a non-loopback `Host`, that it should refuse | High |
| A small input crashes or hangs the scanner, or makes it allocate far more than its size | Medium |

## Safe harbor

We will not pursue or support legal action against anyone for security
research done in good faith under this policy: testing against your own
installation and your own files, not other people's systems or data, without
disrupting any service, reporting to us privately, and giving us reasonable
time to fix the issue before you disclose it. If you are unsure whether
something is covered, ask at **security@socair.ai** first.

## What is in scope

- The `socair` engine, checks, readers, renderers, CLI, HTTP API, and wizard
  in this repository.
- The airlock: anything that lets bytes cross into the clean store without the
  attestation (and, for a conditional crossing, the signed acceptance) that
  should be required.
- Attestation, acceptance, and publisher-signature verification
  (`internal/attest`, `internal/acceptance`, `internal/oms`,
  `tools/socair-sigstore`), and `github.com/defilantech/socair-verify`.
- A detection bypass: a file that should FAIL or LEAD under a check's
  documented rules but PASSes. Socair's published detection ceiling
  (`docs/detection-ceiling.json`) lists what it does not claim to catch; a
  bypass of something on that list is a feature request, not a vulnerability.

Out of scope: findings that need an attacker to already control the machine
running the scan or the airlock store, and time or memory use proportional to
a large input. A small input that crashes or hangs the scanner, or makes it
allocate far more than its size, is in scope.

## Supported versions

Security fixes go to the latest release. Before 1.0, older releases are not
patched.
