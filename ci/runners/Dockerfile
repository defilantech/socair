# Self-hosted runner image for defilantech CI on the homelab microk8s cluster.
# The official runner image, plus what the jobs need that it lacks:
#   - build-essential: `go test -race` needs cgo and a C toolchain;
#   - Chrome's system libraries: socair-web's pa11y accessibility test.
# Go and Node come from actions/setup-go and setup-node at job time, pinned by
# each workflow, so they are not baked in here.
FROM ghcr.io/actions/actions-runner:2.337.0

USER root
# Ubuntu 24.04 renamed several Chrome libraries to *-t64, so the set depends on
# the base image's release (the same split socair-web's workflow makes).
RUN . /etc/os-release \
 && COMMON="libnss3 libnspr4 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libcairo2 libpango-1.0-0 libx11-xcb1 libxcb-dri3-0 libxshmfence1 libxss1 fonts-liberation" \
 && case "${VERSION_ID:-}" in \
      24.04|24.10|25.*) CHROME="$COMMON libatk1.0-0t64 libatk-bridge2.0-0 libasound2t64" ;; \
      *) CHROME="$COMMON libatk1.0-0 libatk-bridge2.0-0 libasound2" ;; \
    esac \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git unzip xz-utils $CHROME \
 && rm -rf /var/lib/apt/lists/*
USER runner
