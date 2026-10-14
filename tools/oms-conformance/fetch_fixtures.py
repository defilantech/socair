#!/usr/bin/env python3
"""Fetch the OMS conformance suite's pre-signed fixtures, pinned by digest.

The suite's historical and cross-implementation bundles (signed by older
model_signing releases and the Go implementation) are an OCI artifact on
ghcr.io, named by digest in conformance/config/fixtures.yaml at the pinned
suite commit. The suite's own action pulls it with oras after a cosign check;
this does the same pull with the standard library: the manifest and the
tarball are fetched by digest and their SHA-256 must match, so the bytes are
the ones the pinned suite names. It extracts the tarball into
conformance/test/test-cases/verify/ and writes the marker the suite reads.

Usage: fetch_fixtures.py <model-signing-spec checkout>
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ACCEPT = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def fetch(url: str, token: str, accept: str | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    if accept:
        req.add_header("Accept", accept)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def by_digest(data: bytes, digest: str, what: str) -> bytes:
    algo, _, want = digest.partition(":")
    if algo != "sha256" or hashlib.sha256(data).hexdigest() != want:
        raise SystemExit(f"{what} does not match its digest {digest}")
    return data


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    spec = Path(sys.argv[1])
    cfg = yaml.safe_load((spec / "conformance/config/fixtures.yaml").read_text())
    image, digest = cfg["image"], cfg["digest"]
    host, _, repo = image.partition("/")
    if host != "ghcr.io":
        raise SystemExit(f"fixtures are on {host}, not ghcr.io")

    scope = urllib.parse.quote(f"repository:{repo}:pull", safe="")
    with urllib.request.urlopen(f"https://ghcr.io/token?scope={scope}", timeout=60) as resp:
        token = json.load(resp)["token"]

    manifest = by_digest(fetch(f"https://ghcr.io/v2/{repo}/manifests/{digest}", token, ACCEPT), digest, "the manifest")
    layers = [layer for layer in json.loads(manifest)["layers"]
              if layer.get("annotations", {}).get("org.opencontainers.image.title", "").endswith(".tar.gz")]
    if len(layers) != 1:
        raise SystemExit(f"want one .tar.gz layer in {image}@{digest}, found {len(layers)}")
    blob = by_digest(fetch(f"https://ghcr.io/v2/{repo}/blobs/{layers[0]['digest']}", token), layers[0]["digest"], "the fixture tarball")

    verify_dir = spec / "conformance/test/test-cases/verify"
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        tf.extractall(path=verify_dir, filter="data")
    (verify_dir / ".fixtures-downloaded").write_text(digest + "\n")
    print(f"fixtures from {image}@{digest}: {sum(1 for _ in verify_dir.rglob('bundle.sig'))} bundles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
