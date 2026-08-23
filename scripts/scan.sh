#!/usr/bin/env bash
# scripts/scan.sh
# Build each container image, run Trivy vulnerability scan, and generate an
# SBOM with Syft. Exits non-zero when the vulnerability evidence gate blocks.
#
# Usage:
#   ./scripts/scan.sh                   # scan all images
#   ./scripts/scan.sh python            # scan a single image
#   IMAGE=node ./scripts/scan.sh        # scan via env var
#
# Dependencies: docker, trivy, syft
# Optional:     conftest (OPA Dockerfile linting)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_DIR="${REPO_ROOT}/images"
REPORTS_DIR="${REPO_ROOT}/reports"
POLICIES_DIR="${REPO_ROOT}/policies/opa"

# Image tag prefix (e.g. hardened-python:latest)
IMAGE_PREFIX="hardened"

# Severity levels evaluated by the evidence gate
TRIVY_SEVERITY="CRITICAL,HIGH"

# SBOM formats to generate
SBOM_FORMATS=("cyclonedx-json" "spdx-json")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m  %s\n' "$*" >&2; }

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        fail "Required tool not found: $1"
        fail "Install it and re-run. See README.md for setup instructions."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Determine which images to process
# ---------------------------------------------------------------------------
if [[ -n "${1:-}" ]]; then
    TARGETS=("$1")
elif [[ -n "${IMAGE:-}" ]]; then
    TARGETS=("${IMAGE}")
else
    # Discover all subdirectories under images/ that contain a Dockerfile
    mapfile -t TARGETS < <(
        find "${IMAGES_DIR}" -maxdepth 2 -name Dockerfile \
            | xargs -I{} dirname {} \
            | xargs -I{} basename {} \
            | sort
    )
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    fail "No images found under ${IMAGES_DIR}"
    exit 1
fi

log "Images to process: ${TARGETS[*]}"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require_tool docker
require_tool trivy
require_tool syft
require_tool python3

CONFTEST_AVAILABLE=false
if command -v conftest &>/dev/null; then
    CONFTEST_AVAILABLE=true
fi

# ---------------------------------------------------------------------------
# Per-image pipeline
# ---------------------------------------------------------------------------
FAILED_IMAGES=()

process_image() {
    local name="$1"
    local image_dir="${IMAGES_DIR}/${name}"
    local tag="${IMAGE_PREFIX}-${name}:latest"
    local report_dir="${REPORTS_DIR}/${name}"

    if [[ ! -d "${image_dir}" ]]; then
        fail "Image directory not found: ${image_dir}"
        return 1
    fi

    if [[ ! -f "${image_dir}/Dockerfile" ]]; then
        fail "Dockerfile not found: ${image_dir}/Dockerfile"
        return 1
    fi

    mkdir -p "${report_dir}"

    # -----------------------------------------------------------------------
    # Step 1: OPA/Conftest Dockerfile lint
    # -----------------------------------------------------------------------
    if [[ "${CONFTEST_AVAILABLE}" == "true" ]]; then
        log "[${name}] Running Conftest OPA policy check..."
        if conftest test "${image_dir}/Dockerfile" \
                --policy "${POLICIES_DIR}" \
                --output json \
                > "${report_dir}/conftest.json" 2>&1; then
            ok "[${name}] Conftest: all policies passed"
        else
            warn "[${name}] Conftest: policy violations found — see ${report_dir}/conftest.json"
            # Policy failures are warnings here; treat as non-blocking unless
            # you want to enforce: change 'warn' to 'return 1' above
        fi
    else
        warn "[${name}] conftest not found — skipping OPA Dockerfile lint"
    fi

    # -----------------------------------------------------------------------
    # Step 2: Docker build
    # -----------------------------------------------------------------------
    log "[${name}] Building ${tag}..."
    if ! docker build \
            --tag "${tag}" \
            --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --file "${image_dir}/Dockerfile" \
            "${image_dir}" \
            2>&1 | tee "${report_dir}/build.log"; then
        fail "[${name}] Docker build failed"
        return 1
    fi
    ok "[${name}] Build succeeded: ${tag}"

    # -----------------------------------------------------------------------
    # Step 3: Trivy vulnerability scan
    # -----------------------------------------------------------------------
    log "[${name}] Running Trivy scan (severity: ${TRIVY_SEVERITY})..."

    # JSON report is evaluated after the full table is printed. Nothing is
    # suppressed, so every finding remains visible in both artifacts.
    trivy image \
        --format json \
        --output "${report_dir}/trivy.json" \
        --severity "${TRIVY_SEVERITY}" \
        --exit-code 0 \
        "${tag}" 2>&1 | tee "${report_dir}/trivy.log"

    trivy image \
            --format table \
            --severity "${TRIVY_SEVERITY}" \
            --exit-code 0 \
            "${tag}" 2>&1 | tee -a "${report_dir}/trivy.log"

    if ! python3 "${REPO_ROOT}/scripts/vulnerability_gate.py" \
            --trivy-report "${report_dir}/trivy.json" \
            --register "${REPO_ROOT}/docs/known-findings.md" \
            2>&1 | tee -a "${report_dir}/trivy.log"; then
        fail "[${name}] Vulnerability evidence gate blocked — see ${report_dir}/trivy.json"
        return 1
    fi
    ok "[${name}] Vulnerability evidence gate passed"

    # -----------------------------------------------------------------------
    # Step 4: Syft SBOM generation
    # -----------------------------------------------------------------------
    for fmt in "${SBOM_FORMATS[@]}"; do
        local ext
        case "${fmt}" in
            cyclonedx-json) ext="cyclonedx.json" ;;
            spdx-json)      ext="spdx.json" ;;
            *)               ext="${fmt}.json" ;;
        esac

        log "[${name}] Generating SBOM (${fmt})..."
        syft "${tag}" \
            --output "${fmt}=${report_dir}/sbom.${ext}" \
            2>&1 | tee -a "${report_dir}/syft.log"
        ok "[${name}] SBOM written: ${report_dir}/sbom.${ext}"
    done

    ok "[${name}] Pipeline complete. Reports: ${report_dir}/"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
for image_name in "${TARGETS[@]}"; do
    if ! process_image "${image_name}"; then
        fail "Pipeline failed for image: ${image_name}"
        FAILED_IMAGES+=("${image_name}")
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
log "===== Scan Summary ====="
for image_name in "${TARGETS[@]}"; do
    if printf '%s\n' "${FAILED_IMAGES[@]}" | grep -qx "${image_name}"; then
        fail "  FAILED  ${image_name}"
    else
        ok   "  PASSED  ${image_name}"
    fi
done

if [[ ${#FAILED_IMAGES[@]} -gt 0 ]]; then
    fail "${#FAILED_IMAGES[@]} image(s) failed: ${FAILED_IMAGES[*]}"
    exit 1
fi

ok "All images passed."
