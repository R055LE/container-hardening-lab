# hardened-go

**Base image:** `gcr.io/distroless/static-debian12:nonroot`
**Runtime user:** `nonroot` (UID 65532)
**Exposed port:** 8080

The most aggressively hardened image in the lab. A statically compiled Go binary runs on Google's distroless base — no shell, no package manager, no libc, no SUID binaries. There is almost nothing for an attacker to work with if they achieve code execution.

---

## Hardening decisions

### Multi-stage build with static linking (CIS 4.4)

```
builder stage  →  compiles Go binary with CGO_ENABLED=0
final stage    →  copies only the static binary; no Go toolchain
```

`CGO_ENABLED=0` produces a binary with no libc dependency, which means the final stage does not need glibc or musl. This unlocks `distroless/static` as the base — the smallest possible image containing only CA certificates, timezone data, and `/etc/passwd`.

Build flags:
- `-trimpath` — removes build-machine filesystem paths from the binary (reproducibility, information disclosure)
- `-ldflags="-s -w"` — strips the symbol table and DWARF debug info (smaller binary, harder to reverse-engineer)

---

### Distroless base (CIS 4.7, 4.8)

`gcr.io/distroless/static-debian12` contains:
- CA certificates (for HTTPS)
- Timezone data
- `/etc/passwd` with a `nonroot` user (UID 65532)
- Nothing else

What is absent and why it matters:

| Absent | Attack it prevents |
|---|---|
| Shell (`sh`, `bash`) | Attacker cannot get an interactive session or run shell commands |
| Package manager (`apt`, `apk`) | Attacker cannot install tools (curl, netcat, python) |
| `wget` / `curl` | Cannot download second-stage payloads |
| libc | Cannot run dynamically linked exploits |
| SUID/SGID binaries | No privilege escalation path via setuid |

SUID stripping is unnecessary — there are no binaries to strip.

---

### Non-root user: `nonroot` UID 65532 (CIS 4.1)

The distroless `:nonroot` tag sets the default user to UID 65532. The explicit `USER nonroot` instruction in the Dockerfile makes this visible and satisfies the OPA no-root policy.

UID 65532 is Google's convention for distroless — it avoids collision with all standard system and application UID ranges.

---

### Self-probing HEALTHCHECK (CIS 4.6)

```dockerfile
HEALTHCHECK CMD ["/app", "-healthcheck"]
```

With no shell, curl, or wget available, the binary probes its own `/healthz` endpoint via Go's `net/http` client. The `-healthcheck` flag makes the binary act as its own health checker — a common pattern in distroless deployments.

---

## CVE scan result

```
hardened-go:latest — Trivy scan (CRITICAL, HIGH)

Total: 0
```

Distroless images carry near-zero CVEs because there are almost no OS packages
to be vulnerable. Any future finding stays visible and must be recorded with
current evidence in [`docs/known-findings.md`](../../docs/known-findings.md).

---

## Using this as a base pattern

```dockerfile
FROM golang:1.26-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o app ./cmd/yourapp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder --chown=nonroot:nonroot /build/app /app
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
```

If your application uses CGO (e.g., SQLite via `mattn/go-sqlite3`), use `gcr.io/distroless/base-debian12` instead — it includes glibc.

---

## Runtime flags

```bash
docker run \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 65532:65532 \
  hardened-go:latest
```

| Flag | CIS control | What it prevents |
|---|---|---|
| `--read-only` | 5.12 | Filesystem tampering; attacker cannot write malware to disk |
| `--cap-drop=ALL` | 5.4 | Removes all Linux capabilities |
| `--security-opt no-new-privileges` | 5.4 | Prevents privilege escalation via `execve` |

No `--tmpfs /tmp` is needed unless the application writes temp files — the binary in this example does not.

---

## Quick reference

```bash
make build IMAGE=go          # Build the image
make scan  IMAGE=go          # Trivy CVE scan (fails on CRITICAL/HIGH)
make sbom  IMAGE=go          # Generate CycloneDX + SPDX SBOM
make lint  IMAGE=go          # OPA/Conftest policy check on the Dockerfile
make test-structure IMAGE=go # Runtime assertions against the built image
```
