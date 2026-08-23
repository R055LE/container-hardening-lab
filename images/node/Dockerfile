# =============================================================================
# Stage 1 — builder
#
# Installs production npm dependencies in an isolated stage so that the
# package manager, lock-file tooling, and devDependencies never appear in
# the final image. Only the resulting node_modules and application source
# are promoted to stage 2.
#
# Node 24 in both stages. Native addons compile against a specific module
# ABI, so a builder on a different major produces a node_modules the runtime
# cannot load. node:24-slim is paired with distroless nodejs24-debian13
# deliberately.
# =============================================================================
FROM node:24-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS builder

WORKDIR /build

# Copy manifests before source so Docker can cache the npm ci layer.
# If package.json and package-lock.json are unchanged, this layer is reused
# even when application source changes — dramatically faster rebuilds.
COPY package.json package-lock.json ./

# npm ci — prefer over npm install in CI/build contexts:
#   --omit=dev      only production dependencies in the final image
#   --ignore-scripts  disables postinstall/preinstall lifecycle scripts,
#                     which are a documented supply-chain attack vector
#   ci (vs install) fails if package-lock.json is out of sync, preventing
#                     silent dependency drift
RUN npm ci --omit=dev --ignore-scripts

COPY . .


# =============================================================================
# Stage 2 — final
#
# Distroless: node binary, application source, production node_modules. No
# shell, no npm, no package manager, no coreutils.
#
# This replaces a long list of hardening steps that are now unnecessary rather
# than merely passing. The previous stage removed wget/curl/perl, force-purged
# the perl-base dpkg record, stripped SUID/SGID bits, and deleted npm's bundled
# node_modules. None of those packages exist in this base image, so the work is
# gone rather than done. The CVE cluster that kept this red (util-linux family,
# ncurses, gzip, zlib1g) went with them.
#
# Consequences of having no shell, all deliberate:
#   - HEALTHCHECK must be exec-array form.
#   - The runtime user is the image's built-in `nonroot` (65532), not the
#     `appuser` (10001) the previous image created with useradd.
#   - `node` is not on PATH. The binary lives at /nodejs/bin/node.
# =============================================================================
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:ffab599740d4aaa66029d02b9e6d3de4f622fefb7410081c5ef69c86430f364d AS final

# --- Known findings ------------------------------------------------------
# CVE-2026-14456 remains in libssl3t64 with no Debian fix. It affects OpenSSL's
# QUIC server listener, which this HTTP reference app does not use. It is not
# suppressed; see docs/known-findings.md for the gate evidence.

LABEL org.opencontainers.image.title="hardened-node" \
      org.opencontainers.image.description="CIS-hardened Node.js 24 runtime on distroless" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="gcr.io/distroless/nodejs24-debian13:nonroot"

WORKDIR /app

# Copy only production artifacts from the builder — node_modules and source.
# Nothing else from the builder (npm, package-lock.json, .npmrc) is included.
COPY --from=builder --chown=nonroot:nonroot /build/node_modules ./node_modules
COPY --from=builder --chown=nonroot:nonroot /build/src ./src

# --- CIS 4.1: Run as non-root ---------------------------------------------
# Declared explicitly even though the base image already defaults to it, so the
# guarantee is visible here and survives a base image change.
USER nonroot

# Non-privileged port — no CAP_NET_BIND_SERVICE required (CIS 5.7)
EXPOSE 3000

# Health check using Node's built-in http module — no curl/wget dependency.
# Exec-array form: no shell exists to interpret a string command. The absolute
# path is required because `node` is not on PATH in this base image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/nodejs/bin/node", "-e", "require('http').get('http://localhost:3000/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

ENTRYPOINT ["/nodejs/bin/node"]
CMD ["src/index.js"]
