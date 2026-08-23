# hardened-node

**Base image:** `gcr.io/distroless/nodejs24-debian13:nonroot` (Node 24)
**Builder:** `node:24-slim` (must match the runtime major version)
**Runtime user:** `nonroot` (UID 65532)
**Exposed port:** 3000

A hardened Node.js 24 runtime for Express-based APIs and background services. Follows the same pattern as [hardened-python](../python/README.md) with Node-specific considerations around npm's bundled package surface and supply-chain risk from install scripts.

---

## Hardening decisions

### Multi-stage build — production deps only (CIS 4.4)

```
builder stage  →  npm ci --omit=dev  (lock-file reproducible, no devDeps)
final stage    →  copies node_modules + src only; no npm, no package managers
```

`npm ci` is used instead of `npm install` for two reasons:
1. **Lock file enforced** — `npm ci` fails if `package-lock.json` is out of sync with `package.json`, preventing silent dependency drift
2. **Clean install** — always starts from scratch, no leftover state from a previous install

`--omit=dev` ensures test frameworks, bundlers, and linters never reach the runtime image.

---

### npm stripped from the final image

```dockerfile
&& rm -rf /usr/local/lib/node_modules/npm \
&& rm -f /usr/local/bin/npm /usr/local/bin/npx
```

This is the most impactful single hardening step for Node.js images, and the one most commonly skipped.

`npm` ships its own bundled copy of packages — `glob`, `minimatch`, `tar`, `cross-spawn` — completely independent of your application's `node_modules`. These bundled packages are not updated when you run `npm update`. They accumulate CVEs silently.

**Before removing npm:**
```
hardened-node:latest — Trivy scan (CRITICAL, HIGH)

Node.js (node-pkg)
Total: 11 (HIGH: 11, CRITICAL: 0)

cross-spawn  CVE-2024-21538  HIGH  ReDoS
glob         CVE-2025-64756  HIGH  Command injection via malicious filenames
minimatch    CVE-2026-26996  HIGH  ReDoS via crafted glob patterns
minimatch    CVE-2026-27903  HIGH  ReDoS via recursive backtracking
minimatch    CVE-2026-27904  HIGH  ReDoS via catastrophic backtracking
tar          CVE-2026-23745  HIGH  Arbitrary file overwrite via symlink
tar          CVE-2026-23950  HIGH  Arbitrary file overwrite via race condition
...
```

**After removing npm:**
```
hardened-node:latest — Trivy scan (CRITICAL, HIGH)

Total: 0
```

The application never calls `npm` at runtime. Removing it eliminates 11 CVEs and roughly 20 MB from the image with zero functional impact.

---

### `--ignore-scripts` on install (supply-chain)

```dockerfile
RUN npm ci --omit=dev --ignore-scripts
```

npm post-install scripts (`postinstall`, `preinstall`) execute arbitrary shell commands during `npm install`. This is a documented supply-chain attack vector — several high-profile compromises have used malicious `postinstall` scripts to exfiltrate credentials from CI environments.

`--ignore-scripts` disables all lifecycle scripts. If your application's dependencies genuinely require install scripts (e.g. native modules that need to compile), evaluate each one explicitly and add them back individually.

---

### Non-root user: `nonroot` UID 65532 (CIS 4.1)

Same pattern as Python. Node.js web servers have no legitimate need for root. Express binds to port 3000 (above 1024), so `CAP_NET_BIND_SERVICE` is not required.

---

### Removed attack-surface packages (CIS 4.7)

| Package | Why removed |
|---|---|
| `wget` / `curl` | Post-exploitation download utilities |
| `perl` | `perl-base` ships `/usr/bin/perl` even after `apt remove perl`; deleted directly |

---

### SUID/SGID bits stripped (CIS 4.8)

```dockerfile
find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} +
```

Verified at runtime by structure tests:
```
✓ no SUID binaries present
✓ no SGID binaries present
```

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
docker run --rm --entrypoint /nodejs/bin/node <image> -e "console.log(require('fs').readdirSync('/app'))"
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
hardened-node:latest — Trivy scan (CRITICAL, HIGH)

Total: 1 HIGH (CVE-2026-14456, OpenSSL QUIC server path)
```

The finding has no Debian fix, is not suppressed, and is documented with its
reachability evidence in [`docs/known-findings.md`](../../docs/known-findings.md).

---

## Application structure

The image expects:

```
images/node/
├── package.json
├── package-lock.json      # required — npm ci will fail without it
└── src/
    └── index.js           # entrypoint
```

The included `src/index.js` is a minimal Express server with `/healthz` and `/api/items` endpoints demonstrating the expected structure. Replace it with your application.

---

## Using this as a base image

```dockerfile
FROM hardened-node:latest

# node_modules are already in /app from the build stage
# Copy only your application source
COPY --chown=nonroot:nonroot src/ ./src/

# The entrypoint is already set to `node`
CMD ["src/server.js"]
```

For the full multi-stage pattern (builder + final), see [`Dockerfile`](Dockerfile).

---

## Runtime flags

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 65532:65532 \
  -p 3000:3000 \
  hardened-node:latest
```

---

## Quick reference

```bash
make build IMAGE=node          # Build the image
make scan  IMAGE=node          # Trivy scan plus evidence gate
make sbom  IMAGE=node          # Generate CycloneDX + SPDX SBOM
make lint  IMAGE=node          # OPA/Conftest policy check on the Dockerfile
make test-structure IMAGE=node # 14 runtime assertions against the built image
```
