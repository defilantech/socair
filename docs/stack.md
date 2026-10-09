# Stack decision

Why the engine is Go, the wizard SvelteKit, and the report a versioned JSON
document.

## Engine: Go

Chosen over Rust for v1.

- Go is already memory-safe for our threat model. The Rust-over-C safety argument is real; the Rust-over-Go one is much smaller, since Go is bounds-checked and garbage-collected.
- Tier 1 has no compute bottleneck. The static scanner is I/O-bound: read multi-GB files, hash them, parse metadata. Rust's performance edge pays off in hot loops, and there are none. Hashing is near-parity between the two.
- Fluency and iteration speed. LLMKube is Go, and a second language would tax iteration for little return here.
- Native fit with LLMKube and Kubernetes. An admission webhook and anything operator-shaped will be Go and controller-runtime.
- Trivial single-binary multi-arch builds for the airlock box (Apple Silicon, CUDA nodes, GB10).

**Carve-out.** The artifact parser sits behind a narrow function, `gguf.ReadArtifact(path) (*gguf.Manifest, error)`, so a later Rust crate is a bounded change, not a rewrite. Rust is not adopted for a performance claim we cannot demonstrate.

## Frontend: SvelteKit

The engine exposes a CLI and a small HTTP/JSON API. SvelteKit consumes that API, so the frontend language is independent of the engine language. Any later client uses the same API.

## Report rendering: Go, HTML and PDF

The HTML report is rendered in Go with `html/template`. The PDF is drawn directly in pure Go with the vendored `go-pdf/fpdf` (`internal/render/pdf`), not converted from HTML, so it renders air-gapped with no browser or external tool. Both are byte-stable for a fixed input.

## Report data model: the contract

The report data model is the cross-stack contract: a versioned JSON schema. The Go engine produces it, the CLI prints it, the renderers and the wizard consume it. No component may invent a divergent report shape.

## Open-source posture

Socair is open source. A report is unsigned, or signed by the operator's own key.

License: Apache-2.0 (see `LICENSE`).
