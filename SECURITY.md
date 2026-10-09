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

We aim to acknowledge a report within **3 business days** and to give an
assessment within **10 business days**. We will keep you informed while we
fix it, agree a disclosure date with you, and credit you in the advisory
unless you ask us not to.

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
