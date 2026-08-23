# Adding a new hardened image

This walkthrough adds a fourth hardened image to the lab — a Go runtime — from scratch. Follow the same steps for any other language or base image.

By the end you will have:
- A hardened Dockerfile following the lab's CIS benchmark pattern
- OPA/Conftest policy coverage (automatic — policies apply to all images)
- A container structure test config with runtime assertions
- CI integration (automatic — the matrix picks up new images via `find`)
- SBOM and Trivy scan outputs

---

## 1. Create the image directory

```bash
mkdir images/go
```

The Makefile discovers images by finding subdirectories of `images/` that contain a `Dockerfile`:

```makefile
ALL_IMAGES := $(shell find $(IMAGES_DIR) -maxdepth 2 -name Dockerfile \
                | xargs -I{} dirname {} \
                | xargs -I{} basename {} \
                | sort)
```

No Makefile changes are needed — `make all` will pick up `go` automatically once a `Dockerfile` exists.

---

## 2. Write the Dockerfile

Follow the pattern established in the existing images. The minimum requirements for CI to pass are:

| Requirement | CIS Control | How to satisfy |
|---|---|---|
| Non-root `USER` | 4.1 | Create a dedicated user; set `USER` before `CMD` |
| Approved base image | 4.2 | Use an image from the [allowlist](../policies/opa/image-source-allowlist.rego) |
| Multi-stage build | 4.4 | Build tooling must not appear in the final stage |
| No wget/curl | 4.7 | Remove or never install download utilities |
| No SUID/SGID bits | 4.8 | Run `find / -xdev ... -exec chmod ug-s {}` in the final stage |
| Non-privileged port | 5.7 | `EXPOSE` a port ≥ 1024 |
| `HEALTHCHECK` | 4.6 | Define a `HEALTHCHECK` instruction |

**Example `images/go/Dockerfile`:**

```dockerfile
# =============================================================================
# Stage 1 — builder
# Compile the Go binary. The Go toolchain never reaches the final image.
# =============================================================================
FROM golang:1.26-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 produces a statically linked binary with no libc dependency,
# enabling use of scratch or distroless as the final base.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o app ./cmd/server

# =============================================================================
# Stage 2 — final
# Minimal runtime. The binary is statically linked — no libc required.
# =============================================================================
FROM gcr.io/distroless/static-debian12 AS final

LABEL org.opencontainers.image.title="hardened-go" \
      org.opencontainers.image.description="CIS-hardened Go runtime" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12"

COPY --from=builder --chown=nonroot:nonroot /build/app /app

# distroless/static ships a `nonroot` user (UID 65532) for exactly this purpose
USER nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app", "-healthcheck"]

ENTRYPOINT ["/app"]
```

> **Note on distroless:** `gcr.io/distroless/static-debian12` contains only the Go binary and CA certificates — no shell, no package manager, no SUID binaries. It is already on the [approved registry allowlist](../policies/opa/image-source-allowlist.rego). SUID stripping is not needed because there are no binaries to strip.

---

## 3. Verify the OPA policies pass

```bash
make lint IMAGE=go
```

The three policies check all images automatically:

- **`no-root.rego`** — verifies a `USER` instruction exists and is not root
- **`no-privileged.rego`** — warns on ports < 1024, `--privileged` flags, `--chown=root`
- **`image-source-allowlist.rego`** — verifies the base image is from an approved registry

Fix any `FAIL` outputs before continuing. `WARN` outputs (e.g. unpinned digest) are advisory.

---

## 4. Build the image

```bash
make build IMAGE=go
```

If the build fails, the error is from Docker — fix the Dockerfile and retry.

---

## 5. Run the Trivy scan

```bash
make scan IMAGE=go
```

This prints every CRITICAL or HIGH CVE, then evaluates it against the evidence
gate. Common responses:

| Finding type | Action |
|---|---|
| OS package with a fix available | Upgrade the base image or run `apt-get upgrade` in the Dockerfile |
| OS package `will_not_fix` | Add an evidence-backed entry to `docs/known-findings.md`; missing metadata fails closed |
| Application dependency with a fix | Update the dependency in `go.sum` |
| False positive / not exploitable | Document the reachability evidence in `docs/known-findings.md`; do not suppress the scanner output |

Register metadata format:

```
gate: cve=CVE-YYYY-NNNNN reviewed=YYYY-MM-DD fix-available=none
```

Wrap the completed line in an HTML comment. Placeholder lines must not use the
gate comment marker because every marked line is parsed as policy input.

The gate blocks CISA KEV findings, EPSS above 0.1, fixes available for at least
30 days, and entries not reviewed in 90 days. Missing feeds or metadata block.

---

## 6. Write structure tests

Create `tests/structure/go.yaml`. Structure tests assert runtime properties of the built image — things that can only be verified by actually running a container.

```yaml
schemaVersion: "2.0.0"

metadataTest:
  user: "nonroot"
  exposedPorts:
    - "8080"
  labels:
    - key: "org.opencontainers.image.title"
      value: "hardened-go"

commandTests:

  - name: "runtime user is non-root"
    # distroless has no `id` binary — check /proc/self/status instead
    command: "/app"
    args: ["-whoami"]          # add a -whoami flag to your binary, or use a different probe
    expectedOutput:
      - "nonroot"

fileExistenceTests:

  - name: "binary exists"
    path: "/app"
    shouldExist: true

  - name: "no shell"
    path: "/bin/sh"
    shouldExist: false

  - name: "no wget"
    path: "/usr/bin/wget"
    shouldExist: false
```

> **Tip for distroless:** distroless images have no shell, so `commandTests` that use `sh -c "..."` will fail. Probe the binary directly, or use `fileExistenceTests` for most assertions.

Run with:

```bash
make test-structure IMAGE=go
```

---

## 7. Generate the SBOM

```bash
make sbom IMAGE=go
```

Outputs `reports/go/sbom.cyclonedx.json` and `reports/go/sbom.spdx.json`. These are gitignored and generated fresh on each CI run.

---

## 8. CI integration

No workflow changes needed. The `image-pipeline` job matrix is hardcoded to `[python, node, nginx]`:

```yaml
matrix:
  image: [python, node, nginx]
```

Add `go` to the list:

```yaml
matrix:
  image: [python, node, nginx, go]
```

The full pipeline — lint, build, scan, SARIF upload, SBOM, structure tests, artifact upload — runs automatically for the new image.

---

## 9. Write the image README

Create `images/go/README.md` following the pattern in [images/python/README.md](../images/python/README.md). Cover:

- Base image choice and rationale
- Each hardening decision with the CIS control and the attack it mitigates
- Before/after CVE scan result (if applicable)
- How to use the image as a base in a real project
- Runtime flags

---

## Checklist

```
[ ] images/go/Dockerfile          — hardened, passes make lint
[ ] docs/known-findings.md        — every reported CVE has current evidence
[ ] images/go/.dockerignore       — excludes local build artifacts
[ ] tests/structure/go.yaml       — runtime assertions, make test-structure passes
[ ] images/go/README.md           — documents decisions and usage
[ ] .github/workflows/container-security.yml      — go added to matrix
[ ] make build IMAGE=go           — builds successfully
[ ] make scan  IMAGE=go           — evidence gate passes
[ ] make sbom  IMAGE=go           — SBOM generated
```
