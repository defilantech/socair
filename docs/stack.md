# Stack decision

Decided before M1. Rationale recorded here so it survives handoff.

## Engine: Go

Chosen over Rust for v1.

- Go is already memory-safe for our threat model. The Rust-over-C safety argument is real; the Rust-over-Go one is much smaller, since Go is bounds-checked and garbage-collected.
- Tier 1 has no compute bottleneck. The static scanner is I/O-bound: read multi-GB files, hash them, parse metadata. Rust's performance edge pays off in hot loops, and there are none. Hashing is near-parity between the two.
- Solo-founder velocity and existing fluency. LLMKube and Infercost are Go. A second language taxes iteration speed for little return here.
- Native fit with LLMKube and Kubernetes. The v2 admission webhook and anything operator-shaped will be Go and controller-runtime.
- Trivial single-binary multi-arch builds for the airlock box (Apple Silicon, CUDA nodes, GB10).

**Carve-out.** The artifact parser sits behind a narrow interface, `ReadArtifact(path) -> ArtifactManifest`, so a later Rust crate is a bounded change, not a rewrite. Rust is not adopted for a performance claim we cannot demonstrate.

## Frontend: SvelteKit

The engine exposes a CLI and a small HTTP/JSON API. SvelteKit consumes that API, so the frontend language is independent of the engine language. The later MCP wrapper is another client of the same API.

## Report rendering: HTML/CSS to PDF

The report is rendered as HTML/CSS and converted to PDF, rather than built with a PDF library. This keeps the layout where SvelteKit already lives and keeps the report visually maintainable.

## Report data model: the contract

The report data model is the cross-stack contract: a versioned JSON schema. The Go engine produces it, the CLI prints it, SvelteKit renders it, and the MCP wrapper serves it later. No component may invent a divergent report shape. A2 owns the first version of the schema.

## Open-source posture

Tier 1 is intended to be open source. The repository and the work stay private until the reveal, and the reveal is a working product, not a plan. The OSS tier output is unsigned; the Defilan signature is the paid product.
