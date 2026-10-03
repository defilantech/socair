Interop vectors produced by the reference implementation,
`model_signing` 1.1.1 (sigstore/model-transparency), and verified with it before
being committed:

- `key256/`, `key384/`: directories signed with `model_signing sign key` (P-256, P-384).
- `cert/`: signed with `model_signing sign certificate`, leaf issued by `keys/ca.crt`
  (keyUsage digitalSignature, extendedKeyUsage codeSigning).
- `shards/`: signed through the library with shard serialization, shard_size 1024.
- `single/model.bin`: a single file signed with the P-256 key; the signature is
  `single/model.bin.sig`.

The model files are random bytes, not models. Only public keys and the CA
certificate are kept; the private keys were discarded.
- `keyless/`: a keyless (Sigstore) OMS signature from the reference
  implementation's own test suite (`scripts/tests/v1.1.0-sigstore`), signed by
  `stefanb@us.ibm.com` through `https://sigstore.verify.ibm.com/oauth2`. Verify it
  with `tools/socair-sigstore` and `keys/trusted-root-public-good.json` (the
  public-good trusted root from sigstore-go v1.3.0).
