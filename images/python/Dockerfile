# =============================================================================
# Stage 1: builder
# Install dependencies in a throwaway stage so build tooling never reaches
# the final image. This reduces attack surface and final image size.
#
# The builder's Python minor version must match the runtime's exactly. Wheels
# with compiled extensions are tagged for one ABI (`cpython-313`), so a builder
# on a different minor version produces a site-packages the runtime silently
# cannot import. python:3.13-slim is paired with distroless python3-debian13
# for that reason, not by coincidence.
# =============================================================================
FROM python:3.13-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6 AS builder

WORKDIR /build

# Upgrade pip in the builder only; not needed at runtime
RUN pip install --upgrade pip --no-cache-dir

# Install application dependencies into a prefix that can be copied wholesale
# into the final stage. The mkdir guarantees the path exists even when
# requirements.txt installs nothing, so the COPY below can't fail on a fresh
# clone of this reference repo.
COPY requirements.txt .
RUN mkdir -p /install/lib/python3.13/site-packages \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# =============================================================================
# Stage 2: final
#
# Distroless: no shell, no package manager, no coreutils. The CVE cluster that
# kept this image red was entirely OS packages a runtime never calls (the
# util-linux family, ncurses, login, mount, gzip). They were unfixable by
# patching because Debian had no fix released. Removing the packages removes
# the finding, which is the honest resolution rather than suppressing it.
#
# Consequences of having no shell, all deliberate:
#   - HEALTHCHECK must be exec-array form. There's no shell to parse
#     `CMD ... || exit 1`, so the command's own exit status is the result.
#   - The runtime user is the image's built-in `nonroot` (65532). Creating
#     `appuser` needed groupadd/useradd, which no longer exist here.
#   - Debugging is `docker cp` and reading logs, not `docker exec sh`.
# =============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:6bfc400d0a6d89f50f5bbc0a4b4ff57214ae5c01647c3a74c2a0c8d830b4cc00 AS final

# --- Known findings ------------------------------------------------------
# This image reports 5 CVEs that have no Debian fix released: three in the
# Python stdlib (tarfile extraction filters, html.parser, expat), one in
# ncurses, and one in OpenSSL's unused QUIC server path. None are suppressed. `make scan`
# evaluates each against the evidence policy in docs/known-findings.md.
#
# Each is recorded in docs/known-findings.md with the evidence for why it isn't
# urgent *for this reference application* and what would resolve it. Read that
# before deriving from this image: the stdlib parser findings are properties of
# the application, not of the image, and they apply at full severity to anything
# built here that does parse untrusted XML, HTML, or tar archives.

# --- OCI / CIS 4.1: Apply standard labels ---------------------------------
LABEL org.opencontainers.image.title="hardened-python" \
      org.opencontainers.image.description="CIS-hardened Python 3.13 runtime on distroless" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="gcr.io/distroless/python3-debian13:nonroot"

# --- Dependencies ---------------------------------------------------------
# Distroless python has no site-packages directory on sys.path at all, and no
# /usr/local. Copying the prefix to /usr/local (the usual slim-image pattern)
# puts packages somewhere the interpreter never looks, and nothing fails: the
# image builds, starts, and only breaks when an application actually imports a
# dependency. PYTHONPATH is set explicitly so the path is declared rather than
# assumed.
COPY --from=builder --chown=nonroot:nonroot /install/lib/python3.13/site-packages /app/site-packages
ENV PYTHONPATH=/app/site-packages

WORKDIR /app

# Copy application source (update this COPY for your actual source layout)
COPY --chown=nonroot:nonroot app/ ./

# --- CIS 4.1: Run as non-root ---------------------------------------------
# Declared explicitly even though the base image already defaults to it, so the
# guarantee is visible here and survives a base image change.
USER nonroot

# Expose only the necessary port (adjust for your application)
EXPOSE 8000

# --- CIS 4.6: Define a HEALTHCHECK ----------------------------------------
# Exec-array form: no shell exists to interpret a string command.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/python3.13", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"]

# Default entrypoint — override in child images or compose files.
#
# This runs app/main.py, which serves /healthz. It previously ran
# `-m http.server 8000`, the stdlib directory server, which has no /healthz and
# answered the HEALTHCHECK above with a 404. The container therefore never
# reached `healthy` and would eventually be marked unhealthy, in an image whose
# whole point is demonstrating CIS 4.6. Declaring a HEALTHCHECK satisfied the
# control; nothing ran the container to find out whether it passed.
ENTRYPOINT ["/usr/bin/python3.13"]
CMD ["main.py"]
