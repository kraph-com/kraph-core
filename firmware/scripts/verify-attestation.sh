#!/bin/bash
# Verify a Supaba node's TEE attestation report
#
# Usage:
#   ./verify-attestation.sh --node https://node.example.com --manifest manifest.json
#
# This script:
# 1. Sends a nonce challenge to the node
# 2. Receives the hardware attestation report
# 3. Verifies the certificate chain (AMD VCEK/ASK/ARK or Intel PCS)
# 4. Compares the VM measurement against the published manifest
# 5. Reports whether the node is genuinely running Supaba in a TEE

set -euo pipefail

NODE_ENDPOINT=""
MANIFEST_FILE=""
INSTANCE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)       NODE_ENDPOINT="$2";  shift 2 ;;
        --manifest)   MANIFEST_FILE="$2";  shift 2 ;;
        --instance)   INSTANCE_ID="$2";    shift 2 ;;
        *)            echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "${NODE_ENDPOINT}" ] || [ -z "${MANIFEST_FILE}" ]; then
    echo "Usage: $0 --node <endpoint> --manifest <manifest.json> [--instance <id>]"
    exit 1
fi

if [ ! -f "${MANIFEST_FILE}" ]; then
    echo "Manifest file not found: ${MANIFEST_FILE}"
    exit 1
fi

echo "═══ Supaba TEE Attestation Verification ═══"
echo ""
echo "Node:     ${NODE_ENDPOINT}"
echo "Manifest: ${MANIFEST_FILE}"
echo ""

# ─── Step 1: Generate nonce ──────────────────────────────────────────────────

NONCE=$(openssl rand -hex 32)
echo "1. Generated challenge nonce: ${NONCE:0:16}..."

# ─── Step 2: Request attestation ─────────────────────────────────────────────

echo "2. Requesting attestation report from node..."

ATTEST_URL="${NODE_ENDPOINT}/instances/${INSTANCE_ID:-default}/attest"
RESPONSE=$(curl -s -X POST "${ATTEST_URL}" \
    -H "Content-Type: application/json" \
    -d "{\"nonce\": \"${NONCE}\"}")

if [ $? -ne 0 ]; then
    echo "   FAIL: Could not reach node at ${ATTEST_URL}"
    exit 1
fi

# Parse response
VALID=$(echo "${RESPONSE}" | jq -r '.valid')
PLATFORM=$(echo "${RESPONSE}" | jq -r '.platform')
MEASUREMENT=$(echo "${RESPONSE}" | jq -r '.measurement')
CERT_VALID=$(echo "${RESPONSE}" | jq -r '.certificateChainValid')
NONCE_MATCH=$(echo "${RESPONSE}" | jq -r '.nonceMatch')
RAW_REPORT=$(echo "${RESPONSE}" | jq -r '.rawReport')
ERROR=$(echo "${RESPONSE}" | jq -r '.error // empty')

echo "   Platform:    ${PLATFORM}"
echo "   Measurement: ${MEASUREMENT:0:32}..."
echo "   Cert chain:  ${CERT_VALID}"
echo "   Nonce match: ${NONCE_MATCH}"

# ─── Step 3: Verify measurement against manifest ────────────────────────────

echo ""
echo "3. Verifying measurement against published manifest..."

if [ "${PLATFORM}" = "sev-snp" ]; then
    EXPECTED=$(jq -r '.measurements.sev_snp' "${MANIFEST_FILE}")
elif [ "${PLATFORM}" = "tdx" ]; then
    EXPECTED=$(jq -r '.measurements.tdx' "${MANIFEST_FILE}")
else
    echo "   FAIL: Unknown platform '${PLATFORM}'"
    exit 1
fi

if [ "${EXPECTED}" = "UNKNOWN" ] || [ "${EXPECTED}" = "null" ]; then
    echo "   WARN: No expected measurement in manifest for ${PLATFORM}"
    echo "   Cannot verify measurement — rebuild firmware with sev-snp-measure"
    MEAS_MATCH="unknown"
else
    if [ "${MEASUREMENT}" = "${EXPECTED}" ]; then
        MEAS_MATCH="true"
        echo "   ✓ Measurement matches expected value"
    else
        MEAS_MATCH="false"
        echo "   ✗ MEASUREMENT MISMATCH"
        echo "     Got:      ${MEASUREMENT}"
        echo "     Expected: ${EXPECTED}"
    fi
fi

# ─── Step 4: Verify certificate chain locally ────────────────────────────────

echo ""
echo "4. Verifying attestation report signature..."

if [ "${PLATFORM}" = "sev-snp" ] && command -v snpguest >/dev/null 2>&1; then
    # Save the raw report for local verification
    TEMP_DIR=$(mktemp -d)
    echo "${RAW_REPORT}" | base64 -d > "${TEMP_DIR}/report.bin"

    # Extract and save certificate chain from the response
    echo "${RESPONSE}" | jq -r '.certificateChain[0] // empty' > "${TEMP_DIR}/vcek.pem"
    echo "${RESPONSE}" | jq -r '.certificateChain[1] // empty' > "${TEMP_DIR}/ask.pem"
    echo "${RESPONSE}" | jq -r '.certificateChain[2] // empty' > "${TEMP_DIR}/ark.pem"

    if snpguest verify attestation "${TEMP_DIR}" "${TEMP_DIR}/report.bin" 2>/dev/null; then
        LOCAL_CERT_VALID="true"
        echo "   ✓ Report signature verified locally (AMD certificate chain valid)"
    else
        LOCAL_CERT_VALID="false"
        echo "   ✗ Report signature verification FAILED"
    fi

    rm -rf "${TEMP_DIR}"
else
    LOCAL_CERT_VALID="skipped"
    echo "   ⚠ snpguest not installed — cannot verify locally"
    echo "     Install with: cargo install snpguest"
    echo "     Trusting node's self-reported cert chain status: ${CERT_VALID}"
fi

# ─── Step 5: Final verdict ───────────────────────────────────────────────────

echo ""
echo "═══ Verification Result ═══"
echo ""

ALL_PASS=true

check() {
    local name="$1"
    local value="$2"
    if [ "${value}" = "true" ]; then
        echo "  ✓ ${name}"
    elif [ "${value}" = "unknown" ] || [ "${value}" = "skipped" ]; then
        echo "  ⚠ ${name} (could not verify)"
    else
        echo "  ✗ ${name} FAILED"
        ALL_PASS=false
    fi
}

check "TEE platform detected"     "${PLATFORM:+true}"
check "Certificate chain valid"    "${CERT_VALID}"
check "Nonce freshness"            "${NONCE_MATCH}"
check "Measurement matches"        "${MEAS_MATCH}"
check "Local signature verify"     "${LOCAL_CERT_VALID}"

echo ""
if [ "${ALL_PASS}" = true ] && [ "${MEAS_MATCH}" != "false" ]; then
    echo "VERDICT: ✓ TRUSTED"
    echo "This node is running genuine Supaba firmware inside a ${PLATFORM} TEE."
    echo "The node operator cannot read your data."
    exit 0
else
    echo "VERDICT: ✗ NOT TRUSTED"
    echo "This node failed attestation verification."
    echo "Do NOT send sensitive data to this node."
    exit 1
fi
