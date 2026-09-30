# Socair

Socair is a signed, fileable model assurance attestation for open-weight AI models. It sits in front of an on-premises or air-gapped inference stack and answers one question for a security buyer: is this exact artifact, this quant, this chat template, this tokenizer, clean enough to serve on our hardware, at a defined assurance level and with the untested surface named. The buyer who signs is a CISO or Head of AI Ops, not a researcher, so the deliverable is a graded report they can file, not a JSONL dump. Socair is a Defilan Technologies product; the name is Irish for at ease, settled, secure.

The report comes before the engine. The current core artifact is [docs/attestation-template.md](docs/attestation-template.md). The scanner is designed to produce that document honestly, not the reverse.

- [docs/attestation-template.md](docs/attestation-template.md): the v1 attestation document, section by section.
- [docs/brand.md](docs/brand.md): name meaning, domain set, trademark status.
- [docs/stack.md](docs/stack.md): engine and frontend stack, and the report contract.
- [docs/airlock.md](docs/airlock.md): the controlled junction between egress and the clean store.
- [docs/api.md](docs/api.md): the stateless engine HTTP/JSON API the wizard consumes.
- [docs/wizard.md](docs/wizard.md): the click-ops scan wizard.
- [docs/dev.md](docs/dev.md): build, test, and layout conventions.

License: Apache-2.0.
