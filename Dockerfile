# Socair's container image: the release binaries and the wizard on a
# distroless base, as a non-root user. The Go binaries are not compiled here:
# they come from scripts/build-release.sh, which builds them reproducibly, so
# the image carries the same bytes as the release's SHA256SUMS. Only the
# wizard's static files are built in this file.
#
#   scripts/build-release.sh <version> dist
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=<version> -t socair:<version> .
#
# The chart in charts/socair runs it; docs/kubernetes.md explains the design.

# The wizard is plain static files, so it builds once on the build host.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# static-debian13:nonroot: CA certificates for a hub pull, no shell, uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG VERSION
ARG TARGETARCH
COPY --chmod=0555 dist/socair_${VERSION}_linux_${TARGETARCH} /usr/local/bin/socair
COPY --chmod=0555 dist/socair-sigstore_${VERSION}_linux_${TARGETARCH} /usr/local/bin/socair-sigstore
COPY --from=web /src/web/build /usr/share/socair/web
LABEL org.opencontainers.image.title="socair" \
      org.opencontainers.image.description="Model assurance attestations for open-weight models: the airlock and the wizard" \
      org.opencontainers.image.source="https://github.com/defilantech/socair" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/socair"]
CMD ["serve", "--web", "/usr/share/socair/web"]
