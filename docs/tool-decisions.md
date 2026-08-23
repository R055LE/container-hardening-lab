# Tool decisions

Every tool in this project was chosen over at least one credible alternative. This document records those decisions — what was evaluated, what was chosen, and why.

---

## Vulnerability scanning — Trivy over Grype

**Chosen:** [Trivy](https://github.com/aquasecurity/trivy) (Aqua Security)
**Evaluated:** [Grype](https://github.com/anchore/grype) (Anchore)

Both are excellent open-source scanners with broad OS and language ecosystem coverage. The deciding factors:

| | Trivy | Grype |
|---|---|---|
| SARIF output | Native (`--format sarif`) | Native |
| GitHub Actions integration | Official action (`aquasecurity/trivy-action`) | Official action (`anchore/scan-action`) |
| Scan scope | Images, filesystems, repos, Kubernetes clusters, IaC | Images, filesystems, SBOMs |
| Secret scanning | Built-in (alongside CVE scan) | Separate tool |
| `.trivyignore` suppression | Structured ignore file with expiry date support | Separate file format |

> The suppression row is kept because it was part of the original comparison, but it is **not used**. This repo suppresses nothing; see [known-findings.md](known-findings.md). It is listed here as a Trivy capability, not as a practice.

Trivy's broader scan scope (IaC, Kubernetes cluster scanning) makes it the natural choice if this lab expands into infrastructure scanning. The single-binary, multi-mode design also keeps the CI pipeline simpler — one tool, multiple scan types.

Grype's advantage is its tight integration with Syft (same ecosystem) and arguably cleaner output formatting. It remains a strong choice and the decision could reasonably go either way.

---

## SBOM generation — Syft over Trivy SBOM

**Chosen:** [Syft](https://github.com/anchore/syft) (Anchore)
**Evaluated:** Trivy's built-in SBOM generation (`trivy image --format cyclonedx`)

Trivy can generate SBOMs directly, which would reduce the tool count. Syft was chosen separately because:

- **Richer SBOM output:** Syft produces more complete package metadata (licenses, CPEs, source locations) than Trivy's SBOM mode, which is optimised for vulnerability correlation rather than supply-chain audit
- **Both CycloneDX and SPDX:** Syft generates either format natively; Trivy's SBOM output is primarily CycloneDX
- **SBOM as a first-class artifact:** Keeping SBOM generation as an explicit step signals that SBOMs are a deliberate output, not a side effect of scanning
- **Grype compatibility:** Syft SBOMs can be fed directly to Grype for vulnerability scanning against an SBOM rather than a live image — useful for air-gapped environments

---

## Dockerfile policy enforcement — OPA/Conftest over Hadolint and Checkov

**Chosen:** [OPA](https://www.openpolicyagent.org/) + [Conftest](https://www.conftest.dev/)
**Evaluated:** [Hadolint](https://github.com/hadolint/hadolint), [Checkov](https://www.checkov.io/)

**Hadolint** is purpose-built for Dockerfile linting and is excellent at what it does — it catches common mistakes, enforces best practices, and integrates easily into CI. The reason it was not used here:

- Rules are fixed. Adding a custom policy (e.g. "only approved registries") requires patching Hadolint or combining it with a second tool
- The lab is explicitly about *policy-as-code* — policies should be readable, testable, version-controlled Rego, not configuration flags

**Checkov** supports Dockerfile checks via its built-in rules and can be extended with custom Python checks. It was not chosen because:

- Custom checks are Python, not a dedicated policy language — less expressive for complex conditions and harder to unit test in isolation
- Checkov's primary strength is IaC (Terraform, CloudFormation, Kubernetes manifests); Dockerfile coverage is secondary

**OPA/Conftest** was chosen because:

- **Rego is purpose-built for policy** — it handles set operations, comprehensions, and multi-stage reasoning naturally
- **`opa test` provides a proper unit test framework** — policies are tested with the same rigour as application code
- **The same policy language is used at both layers** — Rego for Dockerfile lint (via Conftest) and Rego is also the underlying language for OPA Gatekeeper (a Kubernetes admission controller), making the knowledge directly transferable
- **Conftest is format-agnostic** — the same workflow works for Dockerfiles, Kubernetes manifests, Terraform, and any other structured input

The tradeoff: Rego has a steeper learning curve than Hadolint configuration. For a team adopting Hadolint for the first time, it's the faster path to value. For a project where policies are a first-class artifact worth reading and testing, OPA is the right tool.

---

## Kubernetes admission control — Kyverno over OPA Gatekeeper

**Chosen:** [Kyverno](https://kyverno.io/)
**Evaluated:** [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)

Both are CNCF projects for Kubernetes admission control. The key differences:

| | Kyverno | OPA Gatekeeper |
|---|---|---|
| Policy language | YAML + JMESPath | Rego |
| Learning curve | Lower — YAML is familiar to Kubernetes users | Higher — requires learning Rego on top of Kubernetes concepts |
| Mutation support | Built-in (`mutate` rules) | Requires separate tooling |
| Test CLI | `kyverno test` (built-in) | `conftest` or custom tooling |
| Policy library | [kyverno.io/policies](https://kyverno.io/policies/) — large, maintained | [github.com/open-policy-agent/gatekeeper-library](https://github.com/open-policy-agent/gatekeeper-library) |
| Generate rules | Built-in (create resources from policy) | Not supported |

Kyverno was chosen primarily for the `kyverno test` CLI, which enables the same test-driven workflow used for OPA policies. Having `kyverno test tests/kyverno/` run 13 deterministic pass/fail assertions in CI provides a concrete verification signal that the policies work as intended.

OPA Gatekeeper is the choice for teams that already use Rego for other policies and want a unified language. In environments where both Dockerfile lint (OPA/Conftest) and admission control (Gatekeeper) use Rego, there is significant knowledge reuse and the policy taxonomy is consistent. That is a legitimate reason to prefer Gatekeeper.

---

## Container structure testing — container-structure-test over custom scripts

**Chosen:** [container-structure-test](https://github.com/GoogleContainerTools/container-structure-test) (Google)
**Evaluated:** Custom bash scripts using `docker run`

Custom scripts would work: `docker run --rm image sh -c "id | grep uid=10001"` is not complicated. The reasons for using container-structure-test instead:

- **Declarative test definitions** — YAML test configs are readable artifacts that document what the image is expected to contain, without mixing test logic and assertions
- **Multiple test types in one tool** — `commandTests`, `fileExistenceTests`, `fileContentTests`, `metadataTest` cover the full assertion surface without separate scripts for each
- **Structured output and exit codes** — clean pass/fail output with counts, compatible with CI without parsing
- **No shell required** — file existence and metadata tests run without invoking a shell inside the container, which matters for distroless images that have no shell

The tradeoff: one more tool to install. For a single assertion, a `docker run` one-liner is simpler. For 13–14 assertions per image, a declarative config file is significantly more maintainable.

---

## Base image selection — distroless for Python, Node and Go; alpine for nginx

> **Reversed 2026-08-08 for Python and Node.** This section previously chose
> Debian slim over distroless for both. The reasoning is kept below because it
> was sound in the abstract; it just didn't survive the CVE data. What follows
> first is why it changed, then the original argument and which part of it was
> wrong.
>
> The two images sat at 11 and 10 unfixable HIGH findings for months. Every one
> was an OS package the runtime never calls: the `util-linux` family, `ncurses`,
> `login`, `mount`, `gzip`. Debian had no fix released for any of them, so
> patching was not available and the only remaining options were suppressing
> them or removing the packages. Suppression was refused deliberately. Moving to
> distroless removed the packages.
>
> Measured before and after with the same Trivy version, no suppression, and
> the full CRITICAL and HIGH inventory evaluated by the gate:
>
> | image | before | after |
> |---|---|---|
> | node | 10 (3 unique CVEs) | **1** (1 unique) |
> | python, excluding the interpreter | 11 | **1** |
> | python, total | 11 | 13 |
>
> The python total going *up* is the interesting part, and it isn't a
> regression. `python:3.12-slim` compiles CPython from source into
> `/usr/local`, so the interpreter has no dpkg record and Trivy's Debian
> scanner never reported on it. `dpkg -l | grep python` returns nothing in that
> image. Distroless uses Debian's `python3.13` packages, which are registered,
> so the interpreter's own CVEs became visible for the first time — 3 unique,
> reported across 4 packages. The old image was not safer, it was unmeasured.
>
> **The specific claim that was wrong** is the third bullet under "slim
> variants" below: that multi-stage builds get close to distroless. They don't.
> Multi-stage controls what the *build* adds. It has no effect on the packages
> the base image already ships, and those were the entire problem.
>
> **What was given up, honestly.** The node image previously ran
> `apt-get upgrade -y` to pick up Debian fixes released since the base was last
> rebuilt upstream. Distroless has no package manager, so that lever is gone.
> That became concrete when the Node 20 image retained CVE-2026-45447 for more
> than 30 days after Debian released a fix. The image moved to Node 24 on
> 2026-08-23 rather than weakening the gate. The trade is "I can patch ahead of
> upstream" for "there is far less to patch." It is a trade, not a free win.
>
> Debugging also genuinely gets worse, exactly as the original text warned. See
> the notes on `docker cp` in each image's README.

**Python and Node:** `gcr.io/distroless/python3-debian13` and
`gcr.io/distroless/nodejs24-debian13`
**nginx:** `nginx:1.27-alpine` (Alpine)
**Evaluated:** Full images, Debian slim, Chainguard Images (`cgr.dev/chainguard/*`)

**Full images** (e.g. `python:3.12`, `node:20`) include a complete Debian environment with package managers, compilers, and debugging tools. These are eliminated immediately — the goal is the opposite.

**Distroless** is the most hardened option: no shell, no package manager, no OS utilities. An attacker who achieves code execution in a distroless container has almost nothing to work with. The tradeoff:

- No shell means `docker exec` debugging doesn't work — you need a separate debug container or an ephemeral container
- Some applications require OS libraries that distroless doesn't include (e.g. `glibc` for native extensions)
- Structure tests that use `commandTests` with `sh -c "..."` cannot run inside distroless

Distroless is used in [docs/adding-an-image.md](adding-an-image.md) as the recommended final stage for a statically compiled Go binary, where it is the natural fit.

**slim variants** (Debian slim) were chosen for Python and Node because, as of the original decision:

- Application dependencies frequently require OS packages that distroless doesn't provide
- The slim base allows `apt-get install` in the Dockerfile when genuinely needed
- ~~Multi-stage builds achieve a result close to distroless by stripping everything added by the build stage — the final image contains only what was explicitly copied~~ **This is the claim that was wrong.** Multi-stage controls what the build adds. It does nothing about the packages the base already ships, and those accounted for every one of the 21 findings across the two images.

**Alpine** was chosen for nginx because:

- The nginx Alpine image is maintained by the nginx project and is the standard production nginx image
- Alpine's musl libc and minimal package set result in a significantly smaller image (~50 MB vs ~190 MB for Debian nginx)
- nginx as a static file server has no native extension requirements that would make Alpine's libc a concern

**Chainguard Images** (`cgr.dev/chainguard/`) are on the approved registry allowlist and are a strong choice for new images — they are rebuilt daily, signed with Sigstore, and maintain near-zero CVE counts. They were not used as the primary base for the existing images because the Python and Node Chainguard images are minimalist by design and require more configuration to use as drop-in replacements.

---

## Image signing — Cosign (keyless) over key-based signing

**Chosen:** [Cosign](https://github.com/sigstore/cosign) with keyless signing (Sigstore)
**Evaluated:** Cosign with a static key pair, Notary v2 (Docker Content Trust)

**Static key signing** is the traditional approach: generate a key pair, store the private key in a secrets manager, sign with it in CI. The problems:

- Long-lived private keys are a persistent target for compromise
- Key rotation requires re-signing all existing images
- Key storage in CI secrets adds a management surface (rotation schedule, access audits)

**Keyless signing** (Sigstore) replaces the long-lived key with a short-lived certificate tied to a workload identity — in this case, GitHub Actions OIDC:

1. CI requests a certificate from Sigstore Fulcio using the GitHub OIDC token as proof of identity
2. Fulcio issues a certificate valid for ~10 minutes, embedding the workflow URL as the subject
3. Cosign signs the image with the ephemeral key and records the signature in the Sigstore Rekor transparency log
4. The ephemeral key is discarded — there is nothing to rotate or protect

Verification requires no keys: the verifier checks the certificate subject (the workflow URL) and the issuer (GitHub Actions OIDC) against the Rekor log entry.

**Notary v2** (Docker Content Trust) is the OCI-standard signing mechanism and is the right choice for air-gapped environments or organisations that run their own Notary server. For a project using GitHub Actions and ghcr.io, keyless Cosign is simpler to operate with no infrastructure to run.

The tradeoff: keyless signing depends on Sigstore's public infrastructure (Fulcio, Rekor). An air-gapped environment needs to run its own Sigstore stack or fall back to key-based signing.

---

## Runtime security — Falco over alternatives

**Chosen:** [Falco](https://falco.org/) (CNCF graduated)
**Evaluated:** Tetragon (Cilium), Tracee (Aqua), Sysdig

All four tools monitor container behaviour at the syscall level. The key differences:

| | Falco | Tetragon | Tracee |
|---|---|---|---|
| Mechanism | kernel module or eBPF | eBPF only | eBPF only |
| Rule language | YAML + Falco condition syntax | YAML + CEL | Rego or YAML |
| Kubernetes integration | DaemonSet + Helm chart | Kubernetes-native (operator) | DaemonSet |
| Docker-only support | Yes (docker socket enrichment) | Requires Kubernetes | Yes |
| CNCF status | Graduated | Incubating | Sandbox |
| Community size | Largest (8k+ GitHub stars, Falco ecosystem) | Growing | Smaller |

**Falco** was chosen primarily for the Docker-socket enrichment mode, which allows it to run alongside containers in a plain Docker environment without Kubernetes. This matches the lab's docker-compose demo setup. Falco's rule language is purpose-built for condition matching on syscall fields, which makes the rules readable and easy to extend.

**Tetragon** would be the choice for a Kubernetes-first deployment. Its eBPF implementation can enforce policies (kill a process, drop a network packet) rather than only alerting, which is a stronger security posture. It is the natural Falco replacement as eBPF tooling matures. For this lab, it was not chosen because it requires a Kubernetes cluster — the docker-compose demo would not work.

**Tracee** supports Rego rules, which would have created consistency with the OPA/Conftest policies in this project. It was not chosen because its Rego integration is an additional layer on top of its event system, and the Falco rule language is more natural for syscall condition matching.
