# CLAUDE.md

## What this project is

A portfolio project demonstrating production-grade container hardening, vulnerability scanning, and policy-as-code enforcement. It is not a library or application — it is a reference implementation of container security practices aligned with CIS Docker Benchmark and DoD Iron Bank standards.

## Quick commands

```bash
# Run policy tests (no Docker required) — the first thing to run after any change
make test

# Run all tests including Falco validation (requires Docker)
make test-all

# Individual test layers
make test-opa          # 47 OPA/Rego unit tests
make test-kyverno      # 13 Kyverno admission policy tests
make test-falco        # Falco rule syntax validation (requires Docker)

# Build, scan, SBOM for a single image
make build IMAGE=python
make scan  IMAGE=python
make sbom  IMAGE=python

# Lint a Dockerfile against OPA policies
make lint IMAGE=python

# Container structure tests (image must be built first)
make test-structure IMAGE=python

# Full pipeline for all images
make all

# Available images: python, node, nginx, go
```

## Project structure

- `images/<name>/Dockerfile` — hardened container images (python, node, nginx)
- `policies/opa/*.rego` — Conftest/OPA policies evaluated against Dockerfiles
- `policies/kyverno/*.yaml` — Kubernetes admission policies
- `tests/opa/*_test.rego` — OPA unit tests (one file per policy)
- `tests/kyverno/` — Kyverno test fixtures (one Pod manifest per violation)
- `tests/structure/*.yaml` — container-structure-test configs (one per image)
- `examples/unhardened/` — deliberately insecure Dockerfile for failure demo
- `falco/` — Falco runtime detection rules + docker-compose demo
- `.github/workflows/container-security.yml` — CI pipeline

## Conventions

- **Dockerfiles follow CIS Docker Benchmark controls.** Each control is commented with its CIS section number (e.g., `# CIS 4.1`). Maintain this mapping when adding or modifying controls.
- **All images use non-root users** with UID >= 10001 and expose only unprivileged ports (>= 1024).
- **OPA policies use Rego v1 keywords** (`contains`, `if`, `in` via `import future.keywords.*`).
- **Every policy has unit tests.** OPA policies in `tests/opa/`, Kyverno policies in `tests/kyverno/`. No policy change without a corresponding test update.
- **Trivy CVEs are never suppressed.** Record each current finding in
  `docs/known-findings.md`; the evidence gate fails closed when metadata or
  external risk data is missing.
- **Base images are pinned to digests** for reproducibility and supply-chain integrity.
- **Annotations/comments are for portfolio readability.** Policy files and Dockerfiles include explanatory annotations aimed at reviewers who may not be familiar with the tools.

## Commit style

```
Short summary (<= 72 chars)

Longer explanation of why, not what. Reference CIS controls or CVE IDs where relevant.
```

Prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`.

## CI pipeline

The workflow (`.github/workflows/container-security.yml`) runs three jobs:
1. **policy-tests** — OPA + Kyverno (no Docker, fast feedback)
2. **failure-demo** — asserts the unhardened Dockerfile IS rejected (inverted test)
3. **image-pipeline** — lint, build, Trivy scan, SBOM, structure tests, push + Cosign sign (matrix: python/node/nginx)

Images are pushed to `ghcr.io` and signed with Cosign (keyless/Sigstore) on pushes to main only.

## Adding a new image

See `docs/adding-an-image.md` for the full walkthrough. Short version:
1. Create `images/<name>/Dockerfile` following existing hardening patterns
2. `make lint IMAGE=<name>` must pass
3. `make scan IMAGE=<name>` must pass the vulnerability evidence gate
4. Add `tests/structure/<name>.yaml`
5. Add `<name>` to the matrix in `.github/workflows/container-security.yml`
