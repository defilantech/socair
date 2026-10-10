# Governance

Socair is open source under the Apache License 2.0 and maintained by Defilan
Technologies. This file says who decides what, how changes are made, and what
the project commits to.

## Who decides

- The maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). They review
  and merge pull requests, triage issues, and cut releases.
- The lead maintainer, Chris Maher ([@Defilan](https://github.com/Defilan)),
  sets the project's direction and makes the final call when maintainers
  disagree.
- Socair is run by one company today. It is not a foundation project and does
  not claim vendor-neutral governance. If it joins a foundation, this file
  changes to that foundation's model then.

## How work happens

Work happens in public: issues, pull requests, design discussion, and the
[roadmap](ROADMAP.md). Security reports are the exception and go privately
(see below).

A small fix needs only a pull request. Anything larger starts with an issue,
so the approach is agreed before the work is done.

## Changes to the contract

Some parts of Socair are a contract with the people who file its reports and
verify its attestations. A change to any of them starts with a design issue,
agreed by a maintainer before a pull request:

- the report format, `socair.report/v1` (`docs/report-schema/v1.json`), and
  the attestation's predicate type;
- what a verdict means (PASS, FAIL, LEAD, NOT_TESTED) and the promotion
  states;
- the check rules, versioned by the check-set version
  ([check-set.md](docs/check-set.md));
- the detection ceiling ([detection-ceiling.json](docs/detection-ceiling.json)),
  which changes only with a new version;
- the verifier module,
  [`github.com/defilantech/socair-verify`](https://github.com/defilantech/socair-verify),
  which other projects run (LLMKube's admission gate). A format change lands
  there first.

The change then follows the rules in [CONTRIBUTING.md](CONTRIBUTING.md): a
falsification test for every check, false positives measured on real models
before a detector changes, and a check-set version bump for any change that
can alter a verdict.

## Commitments

These hold for as long as Defilan maintains Socair:

- **No paid edition.** Every feature is in this repository under Apache-2.0.
  Nothing is held back for a commercial version.
- **Defilan never issues attestations for others.** The issuer of an
  attestation is whoever signs it, with their own key. An unsigned report
  says that no one has signed it. Socair, the tool, is never the issuer of a
  report it was only used to produce.
- **The reference data and the verifier are built in the open.** The
  project's reference feed (known-bad hashes, reviewed chat templates,
  canonical tokenizers) and the `socair-verify` module are developed in
  public, with their sources.

## Becoming a maintainer

See [MAINTAINERS.md](MAINTAINERS.md).

## Vulnerabilities and detection bypasses

Report them privately, as [SECURITY.md](SECURITY.md) describes. A file that
earns a PASS where a check's documented rules say it should not is a
vulnerability, not a feature request.

## The name

The code is free to use under Apache-2.0. The name "Socair" and the cairn
logo are trademarks of Defilan Technologies; [TRADEMARKS.md](TRADEMARKS.md)
says how to use them.

## Changing this file

Changes to this file are made by pull request, in public, and merged by the
lead maintainer.
