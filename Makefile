# Makefile — Container Hardening Lab
# Primary interface for build, scan, SBOM generation, policy linting, and tests.
#
# Usage:
#   make all              # build + scan + sbom for all images
#   make test             # run all test layers (OPA + Kyverno + structure)
#   make test-opa         # OPA unit tests only
#   make test-kyverno     # Kyverno policy tests only
#   make test-structure   # container structure tests (requires built images)
#   make build IMAGE=python
#   make scan  IMAGE=python
#   make sbom  IMAGE=python
#   make lint  IMAGE=python
#   make clean

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IMAGE_PREFIX  := hardened
IMAGES_DIR    := images
REPORTS_DIR   := reports
POLICIES_DIR  := policies/opa
TESTS_DIR     := tests

# Discover all images by finding subdirectories with a Dockerfile
ALL_IMAGES := $(shell find $(IMAGES_DIR) -maxdepth 2 -name Dockerfile \
                | xargs -I{} dirname {} \
                | xargs -I{} basename {} \
                | sort)

# Allow overriding with IMAGE=<name> on the command line
ifdef IMAGE
  TARGETS := $(IMAGE)
else
  TARGETS := $(ALL_IMAGES)
endif

TRIVY_SEVERITY := CRITICAL,HIGH
SBOM_FORMATS   := cyclonedx-json spdx-json

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: all build scan sbom lint test test-all test-opa test-kyverno test-vulnerability-gate test-falco test-structure clean help $(ALL_IMAGES)

# ---------------------------------------------------------------------------
# all: full pipeline for every (or one) image
# ---------------------------------------------------------------------------
all: build scan sbom  ## Build, scan, and generate SBOMs for all images (or IMAGE=x)

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
build:  ## Build container image(s). Use IMAGE=<name> for a single image.
	@for img in $(TARGETS); do \
	    echo ""; \
	    echo "==> Building $(IMAGE_PREFIX)-$$img:latest"; \
	    docker build \
	        --tag "$(IMAGE_PREFIX)-$$img:latest" \
	        --label "org.opencontainers.image.created=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	        --file "$(IMAGES_DIR)/$$img/Dockerfile" \
	        "$(IMAGES_DIR)/$$img"; \
	done

# ---------------------------------------------------------------------------
# scan: Trivy vulnerability scan
# ---------------------------------------------------------------------------
scan:  ## Run Trivy CVE scan and evidence gate. Use IMAGE=<name> for one image.
	@for img in $(TARGETS); do \
	    echo ""; \
	    echo "==> Scanning $(IMAGE_PREFIX)-$$img:latest"; \
	    mkdir -p "$(REPORTS_DIR)/$$img"; \
	    trivy image \
	        --format json \
	        --output "$(REPORTS_DIR)/$$img/trivy.json" \
	        --severity "$(TRIVY_SEVERITY)" \
	        --exit-code 0 \
	        "$(IMAGE_PREFIX)-$$img:latest"; \
	    trivy image \
	        --format table \
	        --severity "$(TRIVY_SEVERITY)" \
	        --exit-code 0 \
	        "$(IMAGE_PREFIX)-$$img:latest"; \
	    python3 scripts/vulnerability_gate.py \
	        --trivy-report "$(REPORTS_DIR)/$$img/trivy.json" \
	        --register docs/known-findings.md; \
	    echo "    Report: $(REPORTS_DIR)/$$img/trivy.json"; \
	done

# ---------------------------------------------------------------------------
# sbom: generate Software Bill of Materials with Syft
# ---------------------------------------------------------------------------
sbom:  ## Generate SBOM (CycloneDX + SPDX) for all images. Use IMAGE=<name> for one.
	@for img in $(TARGETS); do \
	    echo ""; \
	    echo "==> Generating SBOM for $(IMAGE_PREFIX)-$$img:latest"; \
	    mkdir -p "$(REPORTS_DIR)/$$img"; \
	    syft "$(IMAGE_PREFIX)-$$img:latest" \
	        --output "cyclonedx-json=$(REPORTS_DIR)/$$img/sbom.cyclonedx.json"; \
	    syft "$(IMAGE_PREFIX)-$$img:latest" \
	        --output "spdx-json=$(REPORTS_DIR)/$$img/sbom.spdx.json"; \
	    echo "    CycloneDX: $(REPORTS_DIR)/$$img/sbom.cyclonedx.json"; \
	    echo "    SPDX:      $(REPORTS_DIR)/$$img/sbom.spdx.json"; \
	done

# ---------------------------------------------------------------------------
# lint: OPA/Conftest policy check on Dockerfiles
# ---------------------------------------------------------------------------
lint:  ## Run Conftest OPA policies against Dockerfile(s). Use IMAGE=<name> for one.
	@command -v conftest >/dev/null 2>&1 || { \
	    echo "ERROR: conftest not found. Install from https://www.conftest.dev/"; exit 1; }
	@for img in $(TARGETS); do \
	    echo ""; \
	    echo "==> Linting $(IMAGES_DIR)/$$img/Dockerfile"; \
	    conftest test "$(IMAGES_DIR)/$$img/Dockerfile" \
	        --policy "$(POLICIES_DIR)" \
	        --namespace docker.security; \
	done

# ---------------------------------------------------------------------------
# test: fast policy tests — no Docker required
# ---------------------------------------------------------------------------
test: test-opa test-kyverno test-vulnerability-gate  ## Run policy tests only. No Docker required.
	@echo ""
	@echo "==> Policy tests passed."

# ---------------------------------------------------------------------------
# test-all: all test layers including Docker-dependent tests
# ---------------------------------------------------------------------------
test-all: test test-falco  ## Run all tests including Falco validation (requires Docker).
	@echo ""
	@echo "==> All tests passed."

# ---------------------------------------------------------------------------
# test-opa: OPA unit tests for Rego policies
# ---------------------------------------------------------------------------
test-opa:  ## Run OPA unit tests for all Rego policies (requires: opa).
	@command -v opa >/dev/null 2>&1 || { \
	    echo "ERROR: opa not found. Install from https://www.openpolicyagent.org/docs/latest/#1-download-opa"; exit 1; }
	@echo ""
	@echo "==> OPA unit tests: no-root"
	opa test \
	    $(POLICIES_DIR)/no-root.rego \
	    $(TESTS_DIR)/opa/no-root_test.rego \
	    --verbose
	@echo ""
	@echo "==> OPA unit tests: no-privileged"
	opa test \
	    $(POLICIES_DIR)/no-privileged.rego \
	    $(TESTS_DIR)/opa/no-privileged_test.rego \
	    --verbose
	@echo ""
	@echo "==> OPA unit tests: image-source-allowlist"
	opa test \
	    $(POLICIES_DIR)/image-source-allowlist.rego \
	    $(TESTS_DIR)/opa/image-source-allowlist_test.rego \
	    --verbose

# ---------------------------------------------------------------------------
# test-kyverno: Kyverno CLI policy tests against fixture Pods
# ---------------------------------------------------------------------------
test-kyverno:  ## Run Kyverno policy tests against fixture manifests (requires: kyverno).
	@command -v kyverno >/dev/null 2>&1 || { \
	    echo "ERROR: kyverno CLI not found. Install from https://kyverno.io/docs/kyverno-cli/"; exit 1; }
	@echo ""
	@echo "==> Kyverno policy tests"
	kyverno test $(TESTS_DIR)/kyverno/ --detailed-results

# ---------------------------------------------------------------------------
# test-vulnerability-gate: evidence gate unit and mutation tests
# ---------------------------------------------------------------------------
test-vulnerability-gate:  ## Run vulnerability evidence gate tests (requires: python3).
	python3 -m unittest discover -s $(TESTS_DIR)/scripts -p 'test_*.py' -v

# ---------------------------------------------------------------------------
# test-falco: validate Falco custom rules (syntax, macros, field references)
# ---------------------------------------------------------------------------
test-falco:  ## Validate Falco custom rules load without errors (requires: docker).
	@echo ""
	@echo "==> Falco rule validation"
	docker run --rm \
	    -v "$(CURDIR)/falco/rules:/etc/falco/rules.d:ro" \
	    falcosecurity/falco:latest \
	    falco --dry-run \
	          -r /etc/falco/falco_rules.yaml \
	          -r /etc/falco/rules.d/container-hardening-lab.yaml
	@echo "    Falco rules validated successfully."

# ---------------------------------------------------------------------------
# test-structure: container structure tests (image must be built first)
# ---------------------------------------------------------------------------
test-structure:  ## Run container structure tests. Requires built images and container-structure-test.
	@command -v container-structure-test >/dev/null 2>&1 || { \
	    echo "ERROR: container-structure-test not found."; \
	    echo "       Install: https://github.com/GoogleContainerTools/container-structure-test"; \
	    exit 1; }
	@for img in $(TARGETS); do \
	    cfg="$(TESTS_DIR)/structure/$$img.yaml"; \
	    if [ ! -f "$$cfg" ]; then \
	        echo "  [skip] No structure test config for $$img ($$cfg not found)"; \
	        continue; \
	    fi; \
	    echo ""; \
	    echo "==> Structure tests: $(IMAGE_PREFIX)-$$img:latest"; \
	    container-structure-test test \
	        --image "$(IMAGE_PREFIX)-$$img:latest" \
	        --config "$$cfg"; \
	    echo "==> SUID/SGID check (CIS 4.8): $(IMAGE_PREFIX)-$$img:latest"; \
	    ./scripts/check-suid.sh "$(IMAGE_PREFIX)-$$img:latest"; \
	done

# The SUID/SGID assertion runs here rather than inside the structure test
# configs because it used to shell out to `find` inside the container, which
# distroless images can't do. See the header of scripts/check-suid.sh. Keeping
# it in this target means `make test-structure` still covers CIS 4.8 for every
# image, including the two that no longer have a shell.

# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
clean:  ## Remove built images and report artifacts.
	@echo "==> Removing report artifacts"
	rm -rf "$(REPORTS_DIR)"
	@echo "==> Removing built images"
	@for img in $(TARGETS); do \
	    if docker image inspect "$(IMAGE_PREFIX)-$$img:latest" >/dev/null 2>&1; then \
	        docker rmi "$(IMAGE_PREFIX)-$$img:latest"; \
	    fi; \
	done

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------
help:  ## Show this help message.
	@echo ""
	@echo "Container Hardening Lab — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Available images: $(ALL_IMAGES)"
	@echo "Override with:    make <target> IMAGE=<name>"
	@echo ""
