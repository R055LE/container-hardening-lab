# hardened-python

**Base image:** `gcr.io/distroless/python3-debian13:nonroot` (Python 3.13)
**Builder:** `python:3.13-slim` (must match the runtime minor version)
**Runtime user:** `nonroot` (UID 65532)
**Exposed port:** 8000

The reference implementation for the hardening pattern used throughout this lab. Every decision made here — multi-stage build, non-root user, SUID stripping, package removal — is documented with the CIS Docker Benchmark control it satisfies and the attack it mitigates.

---

## Hardening decisions

### Multi-stage build (CIS 4.4)

```
builder stage  →  installs pip deps into /install prefix
final stage    →  copies /install only; no pip, gcc, or build tools
```

Build tooling is the single largest contributor to container attack surface that isn't required at runtime. A compromised container with `pip` and `gcc` can download and compile arbitrary code. The builder stage installs dependencies into a prefix (`/install`) that is copied wholesale into the final image — leaving the build toolchain behind.

---

### Non-root user: `appuser` UID 10001 (CIS 4.1)

```dockerfile
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser
```

Containers run as `root` by default. If an attacker exploits a vulnerability in the application, they inherit the process's UID. Running as UID 10001 limits what that attacker can do inside the container and on any mounted volumes.

- **UID above 10000** — avoids collision with system service accounts (typically 0–999) and application accounts (typically 1000–9999)
- **No home directory** — no `~/.ssh`, `~/.bash_history`, or credential files for an attacker to find or write to
- **`/sbin/nologin` shell** — the account cannot be used for interactive login even if credentials were somehow obtained

---

### Removed attack-surface packages (CIS 4.7)

| Package | Why removed |
|---|---|
| `wget` / `curl` | Download utilities — primary tools for pulling second-stage payloads in post-exploitation |
| `perl` | Scripting runtime — `perl -e` one-liners are a standard persistence technique; `perl-base` ships the binary even after `apt remove`, so it is deleted directly |
| `gcc` / `binutils` | Compiler toolchain — eliminates compile-and-run attacks inside the container |

---

### SUID/SGID bits stripped (CIS 4.8)

```dockerfile
find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} +
```

SUID binaries (e.g. `su`, `passwd`, `ping`) run as their *owner* (usually root) regardless of who calls them. An attacker who finds an exploitable SUID binary can escalate from the app user to root without leaving the container. Stripping these bits closes that path entirely.

The structure tests assert this at runtime:

```
✓ no SUID binaries present  (find / -xdev -perm /4000 | wc -l = 0)
✓ no SGID binaries present  (find / -xdev -perm /2000 | wc -l = 0)
```

---

### Cleaned APT cache (CIS 4.7)

```dockerfile
&& apt-get clean \
&& rm -rf /var/lib/apt/lists/*
```

Each `RUN` instruction creates an image layer. Cleaning the APT cache in the *same* layer as the `apt-get` operations ensures the package index never appears in any layer — reducing image size and preventing an attacker from using `apt-get install` inside the container.

---

### HEALTHCHECK (CIS 4.6)

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1
```

Without a `HEALTHCHECK`, Docker and Kubernetes cannot distinguish a running-but-deadlocked container from a healthy one. The health check uses Python's standard library — no `curl` or `wget` required, consistent with their removal.

---

## Debugging without a shell

This image is distroless. There is no `sh`, no `bash`, no coreutils, so
`docker exec -it <container> sh` does not work and never will. That is the
point: an attacker who gets code execution has the same nothing to work with.

What to use instead:

```bash
# Pull files out of a running or stopped container
docker cp <container>:/app/somefile ./somefile

# Inspect the whole filesystem without running anything in it
docker export <container> | tar -tv | less

# Run the interpreter that is present, since it can do most of what you want
docker run --rm --entrypoint /usr/bin/python3.13 <image> -c "import os; print(os.listdir('/app'))"
```

`docker debug`, or an ephemeral debug container sharing the process namespace,
covers the rest:

```bash
docker run --rm -it --pid=container:<container> --network=container:<container> \
    nicolaka/netshoot
```

If you need a shell in the image itself for a one-off investigation, build from
the `:debug` distroless tag, which adds busybox. Do not ship it.

## CVE scan result
> **No findings are suppressed.** There is no `.trivyignore` in this repo.
> Everything the scanner reports is listed in [`docs/known-findings.md`](../../docs/known-findings.md)
> with evidence and a resolution condition. `make scan` evaluates every finding
> against KEV, EPSS, fix age, and review age.


```
hardened-python:latest — Trivy scan (CRITICAL, HIGH)

Total: 15 HIGH findings (5 unique CVEs)
```

The findings remain visible and are documented in
[`docs/known-findings.md`](../../docs/known-findings.md). None currently has a
Debian fix; missing or stale evidence blocks the gate.

---

## Using this as a base image

```dockerfile
FROM hardened-python:latest

# Your application already owns /app as nonroot
COPY --chown=nonroot:nonroot src/ ./src/

# If you need additional pip packages, install them as root in a
# preceding build stage and copy the result — do not run pip at runtime
```

For a full multi-stage pattern extending this image, see the builder stage in [`Dockerfile`](Dockerfile).

---

## Runtime flags

The image is designed to run with a fully locked-down security context. The Kyverno admission policies in [`policies/kyverno/`](../../policies/kyverno/) enforce these at the cluster level.

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  hardened-python:latest
```

| Flag | CIS control | What it prevents |
|---|---|---|
| `--read-only` | 5.12 | Filesystem tampering; attacker cannot write malware to disk |
| `--tmpfs /tmp` | 5.12 | Provides a writable temp space with `noexec` — scripts dropped here cannot be executed |
| `--cap-drop=ALL` | 5.4 | Removes all Linux capabilities; add back only what the app explicitly needs |
| `--security-opt no-new-privileges` | 5.4 | Prevents privilege escalation via `execve` — a child process cannot gain more privileges than the parent |

---

## Quick reference

```bash
make build IMAGE=python          # Build the image
make scan  IMAGE=python          # Trivy CVE scan (fails on CRITICAL/HIGH)
make sbom  IMAGE=python          # Generate CycloneDX + SPDX SBOM
make lint  IMAGE=python          # OPA/Conftest policy check on the Dockerfile
make test-structure IMAGE=python # 14 runtime assertions against the built image
```
