# Socair Helm repository

```
helm repo add socair https://defilantech.github.io/socair
helm install intake socair/socair --version <version>
```

This branch holds only `index.yaml`. Each chart archive is an asset of its
[GitHub release](https://github.com/defilantech/socair/releases), with a
build-provenance attestation. A published release adds its chart here
(`.github/workflows/distribute.yml`); see
[docs/kubernetes.md](https://github.com/defilantech/socair/blob/main/docs/kubernetes.md)
to verify and install it.
