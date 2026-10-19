# socair-preview

The page's half of Socair's browser preview: a read-only filesystem over a
Hugging Face repo whose reads are HTTP range requests (`hffs.js`), and the
code that lists a repo, mounts it, and runs the engine on it (`preview.js`).
The engine half is `cmd/socair-preview`, built for js/wasm.

What a preview is and is not, what it reads, and how it was measured:
[docs/preview.md](../../docs/preview.md).

```
./build.sh                         # dist/: socair-preview.wasm, wasm_exec.js
node try.mjs org/name [revision] [--all]
node --test preview.test.mjs       # against a fake hub, no network
```

Releases carry `hffs.js` and `preview.js` beside the wasm, attested, so a page
can load all of it from one release.
