## What

<!-- Brief description of the change -->

## Why

<!-- Why is this change needed? Link to issue if applicable -->

Fixes #

## How

<!-- How was this implemented? Any design decisions worth noting? For a
     detection change, say what it now catches, what it still misses, and what
     the real-corpus gate showed. -->

## Checklist

- [ ] Tests added/updated, with a falsification test for any new or changed check
- [ ] `go test -race ./...` and `go vet ./...` pass locally
- [ ] `gofmt -l cmd internal` prints nothing
- [ ] `npm run check && npm run test` pass in `web/` (if the wizard changed)
- [ ] A detection change is measured on its real-corpus gate and recorded in `docs/false-positive-baseline.md`, and its benchmark case and `docs/detection-benchmark.md` are updated together
- [ ] A rule change has a row in `docs/check-set.md`, and a `CheckSetVersion` bump if it can alter a verdict
- [ ] A report shape change updates the Go model, the JSON schema, the TypeScript types, and the golden report together
- [ ] Commit messages describe the change
- [ ] All commits are signed off (`git commit -s`) per [DCO](https://developercertificate.org/)
- [ ] AI assistance (if any) is disclosed above, per [CONTRIBUTING.md](../CONTRIBUTING.md#ai-assisted-contributions)
- [ ] Documentation updated (if user-facing change)
