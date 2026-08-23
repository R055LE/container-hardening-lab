# =============================================================================
# Stage 1 — builder
# Compile the Go binary. The Go toolchain never reaches the final image.
# =============================================================================
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS builder

WORKDIR /build

# Copy module files first — Docker caches the download layer when only source
# files change. go.sum is not present because this app has zero dependencies.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a statically linked binary with no libc dependency,
# enabling use of distroless (which has no libc) as the final base.
# -trimpath removes build-machine paths from the binary (reproducibility).
# -ldflags="-s -w" strips the symbol table and DWARF debug info (smaller binary).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o app ./cmd/server


# =============================================================================
# Stage 2 — final
# Minimal runtime: only the static binary and CA certificates.
# gcr.io/distroless/static-debian12 contains no shell, no package manager,
# no libc, and no SUID binaries — the smallest possible attack surface.
# =============================================================================
FROM gcr.io/distroless/static-debian12:nonroot@sha256:5074667eecabac8ac5c5d395100a153a7b4e8426181cca36181cd019530f00c8 AS final

# --- OCI labels ---------------------------------------------------------------
LABEL org.opencontainers.image.title="hardened-go" \
      org.opencontainers.image.description="CIS-hardened Go runtime on distroless" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

# Copy the statically linked binary from the builder stage.
# distroless/static ships a `nonroot` user (UID 65532) — chown to it.
COPY --from=builder --chown=nonroot:nonroot /build/app /app

# --- CIS 4.1: Run as non-root ------------------------------------------------
# distroless :nonroot tag sets the default user to UID 65532. The explicit
# USER instruction makes this visible in the Dockerfile and satisfies the
# OPA no-root policy.
USER nonroot

# Non-privileged port — no CAP_NET_BIND_SERVICE required (CIS 5.7)
EXPOSE 8080

# --- CIS 4.6: HEALTHCHECK ----------------------------------------------------
# distroless has no curl, wget, or shell. The binary's -healthcheck flag
# probes its own /healthz endpoint using Go's net/http client.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app", "-healthcheck"]

ENTRYPOINT ["/app"]
