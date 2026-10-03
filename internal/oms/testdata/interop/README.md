Interop vectors produced by the reference implementation,
`model_signing` 1.1.1 (sigstore/model-transparency), and verified with it before
being committed:

- `key256/`, `key384/`: directories signed with `model_signing sign key` (P-256, P-384).
- `cert/`: signed with `model_signing sign certificate`, leaf issued by `keys/ca.pem`
  (keyUsage digitalSignature, extendedKeyUsage codeSigning).
- `shards/`: signed through the library with shard serialization, shard_size 1024.
- `single/model.gguf`: a single file signed with the P-256 key; the signature is
  `single/model.gguf.sig`.

The model files are random bytes, not models. Only public keys and the CA
certificate are kept; the private keys were discarded.
