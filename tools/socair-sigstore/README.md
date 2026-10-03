# socair-sigstore

The optional keyless verifier for Socair. It verifies OpenSSF Model Signing
(OMS) signatures made keylessly with Sigstore (a Fulcio certificate and a
Rekor transparency-log entry), offline, against a trust root you supply.

It is a separate Go module, built and shipped apart from `socair`, so the
scanner's default build keeps its four vendored dependencies; this one carries
`sigstore-go` and about 70 modules in its own `vendor/`. Socair runs it only
when it is configured. Without it, a keyless signature is reported "present,
not verified".

## Build

```
cd tools/socair-sigstore
go build -mod=vendor -o socair-sigstore .
```

The build fetches nothing; it works air-gapped like `socair`.

## Configure the scanner

```
SOCAIR_SIGSTORE_VERIFIER=/usr/local/bin/socair-sigstore
SOCAIR_SIGSTORE_TRUSTED_ROOT=/etc/socair/trusted_root.json
SOCAIR_SIGSTORE_IDENTITIES=/etc/socair/sigstore-identities
```

- `SOCAIR_SIGSTORE_TRUSTED_ROOT` is a Sigstore `trusted_root.json`: the Fulcio
  certificate authorities, Rekor and certificate-transparency log keys, and
  timestamp authorities, with their validity windows. For the public-good
  instance, fetch it on a connected machine (for example `cosign trusted-root
  create` or from the Sigstore TUF repository) and carry it in. Refresh it when
  Sigstore rotates keys.
- `SOCAIR_SIGSTORE_IDENTITIES` names the signers you accept, one per line, as
  the OIDC issuer then the certificate subject; either may be `regexp:<re>`:

  ```
  # issuer                                   subject
  https://token.actions.githubusercontent.com  https://github.com/acme/models/.github/workflows/release.yml@refs/heads/main
  https://accounts.google.com                  regexp:^releases@acme\.com$
  ```

  The policy is required. Anyone can sign keylessly with an account at a
  public OIDC provider, so a keyless signature with no identity policy proves
  nothing about who published the model.

## What it decides

| Bundle | Verdict |
|---|---|
| Signer in the policy; certificate chains to the trust root with its CT proof; signature in the transparency log, made while the certificate was valid | verified |
| Signer in the policy, but any of that does not hold | invalid |
| Signer not in the policy, or not a keyless bundle | unverified |

It verifies the signature over the DSSE envelope only. Socair reads the
signed OMS manifest from the same bytes and checks it against the model's
files itself.

## Protocol

One JSON request on stdin, one JSON verdict on stdout:

```
{"bundle": "<base64>", "trusted_root": "<path>", "identities": [{"issuer": "...", "san": "..."}]}
{"state": "verified" | "invalid" | "unverified", "signer": "<subject> (<issuer>)", "detail": "..."}
```

A malformed request exits 2 with the reason on stderr.

## Tests

`testdata/` holds keyless OMS signatures from the reference implementation's
own test suite (sigstore/model-transparency, `scripts/tests/v1.*-sigstore`,
signed through IBM's Sigstore OIDC issuer) and the public-good trusted root
from sigstore-go v1.3.0. `go test ./...` verifies them, rejects them for other
identities, and rejects tampered copies.
