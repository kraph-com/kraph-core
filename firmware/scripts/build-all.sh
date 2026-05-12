#!/bin/bash
# Build all Supaba confidential VM firmware components
#
# Produces:
#   out/ovmf-sev.fd          — OVMF firmware for AMD SEV-SNP
#   out/ovmf-tdx.fd          — TDVF firmware for Intel TDX
#   out/vmlinuz               — Linux kernel
#   out/initrd.img            — Initial ramdisk (Docker + Supaba + attestation)
#   out/measurement-snp.hex   — Expected SEV-SNP measurement (SHA-384)
#   out/measurement-tdx.hex   — Expected TDX measurement (SHA-384)
#   out/manifest.json         — Build manifest with all hashes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIRMWARE_DIR="$(dirname "${SCRIPT_DIR}")"
REPO_ROOT="$(dirname "$(dirname "${FIRMWARE_DIR}")")"
OUT_DIR="${FIRMWARE_DIR}/out"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Supaba Firmware Build                               ║"
echo "║  Building reproducible confidential VM images        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Firmware dir: ${FIRMWARE_DIR}"
echo "Repo root:    ${REPO_ROOT}"
echo "Output dir:   ${OUT_DIR}"
echo ""

mkdir -p "${OUT_DIR}"

# ─── Step 1: Build OVMF firmware (SEV-SNP + TDX) ─────────────────────────────
echo "═══ Step 1/5: Building OVMF firmware ═══"

docker build \
    -f "${FIRMWARE_DIR}/Dockerfile.ovmf" \
    -o "${OUT_DIR}" \
    "${FIRMWARE_DIR}"

echo "  ✓ ovmf-sev.fd  ($(stat -f%z "${OUT_DIR}/ovmf-sev.fd" 2>/dev/null || stat -c%s "${OUT_DIR}/ovmf-sev.fd") bytes)"
echo "  ✓ ovmf-tdx.fd  ($(stat -f%z "${OUT_DIR}/ovmf-tdx.fd" 2>/dev/null || stat -c%s "${OUT_DIR}/ovmf-tdx.fd") bytes)"

# ─── Step 2: Build kernel ────────────────────────────────────────────────────
echo ""
echo "═══ Step 2/5: Building Linux kernel ═══"

docker build \
    -f "${FIRMWARE_DIR}/Dockerfile.kernel" \
    -o "${OUT_DIR}" \
    "${FIRMWARE_DIR}"

echo "  ✓ vmlinuz  ($(stat -f%z "${OUT_DIR}/vmlinuz" 2>/dev/null || stat -c%s "${OUT_DIR}/vmlinuz") bytes)"

# ─── Step 3: Build initrd ────────────────────────────────────────────────────
echo ""
echo "═══ Step 3/5: Building initrd ═══"

# The initrd build needs access to the monorepo for Supaba node code
docker build \
    -f "${FIRMWARE_DIR}/Dockerfile.initrd" \
    -o "${OUT_DIR}" \
    "${REPO_ROOT}"

echo "  ✓ initrd.img  ($(stat -f%z "${OUT_DIR}/initrd.img" 2>/dev/null || stat -c%s "${OUT_DIR}/initrd.img") bytes)"

# ─── Step 4: Compute expected measurements ───────────────────────────────────
echo ""
echo "═══ Step 4/5: Computing expected TEE measurements ═══"

KERNEL_CMDLINE="console=ttyS0 supaba=1 quiet"

# SEV-SNP measurement
if command -v sev-snp-measure >/dev/null 2>&1; then
    SNP_MEASUREMENT=$(sev-snp-measure \
        --mode snp \
        --ovmf "${OUT_DIR}/ovmf-sev.fd" \
        --kernel "${OUT_DIR}/vmlinuz" \
        --initrd "${OUT_DIR}/initrd.img" \
        --append "${KERNEL_CMDLINE}" \
        --vcpus 2 \
        --vmm-type QEMU \
        2>/dev/null)

    echo "${SNP_MEASUREMENT}" > "${OUT_DIR}/measurement-snp.hex"
    echo "  ✓ SEV-SNP measurement: ${SNP_MEASUREMENT}"
else
    echo "  ⚠ sev-snp-measure not installed. Install with: pip install sev-snp-measure"
    echo "  Skipping measurement computation."
    echo "UNKNOWN" > "${OUT_DIR}/measurement-snp.hex"
fi

# TDX measurement
if command -v sev-snp-measure >/dev/null 2>&1; then
    TDX_MEASUREMENT=$(sev-snp-measure \
        --mode tdx \
        --ovmf "${OUT_DIR}/ovmf-tdx.fd" \
        --kernel "${OUT_DIR}/vmlinuz" \
        --initrd "${OUT_DIR}/initrd.img" \
        --append "${KERNEL_CMDLINE}" \
        2>/dev/null || echo "UNSUPPORTED")

    echo "${TDX_MEASUREMENT}" > "${OUT_DIR}/measurement-tdx.hex"
    echo "  ✓ TDX measurement: ${TDX_MEASUREMENT}"
else
    echo "UNKNOWN" > "${OUT_DIR}/measurement-tdx.hex"
fi

# ─── Step 5: Generate build manifest ─────────────────────────────────────────
echo ""
echo "═══ Step 5/5: Generating build manifest ═══"

# Compute SHA-256 hashes of all artifacts
OVMF_SEV_HASH=$(sha256sum "${OUT_DIR}/ovmf-sev.fd" | cut -d' ' -f1)
OVMF_TDX_HASH=$(sha256sum "${OUT_DIR}/ovmf-tdx.fd" | cut -d' ' -f1)
KERNEL_HASH=$(sha256sum "${OUT_DIR}/vmlinuz" | cut -d' ' -f1)
INITRD_HASH=$(sha256sum "${OUT_DIR}/initrd.img" | cut -d' ' -f1)

SNP_MEAS=$(cat "${OUT_DIR}/measurement-snp.hex")
TDX_MEAS=$(cat "${OUT_DIR}/measurement-tdx.hex")

BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "${OUT_DIR}/manifest.json" << EOF
{
  "version": "0.1.0",
  "build_timestamp": "${BUILD_TIMESTAMP}",
  "artifacts": {
    "ovmf_sev": {
      "file": "ovmf-sev.fd",
      "sha256": "${OVMF_SEV_HASH}"
    },
    "ovmf_tdx": {
      "file": "ovmf-tdx.fd",
      "sha256": "${OVMF_TDX_HASH}"
    },
    "kernel": {
      "file": "vmlinuz",
      "sha256": "${KERNEL_HASH}"
    },
    "initrd": {
      "file": "initrd.img",
      "sha256": "${INITRD_HASH}"
    }
  },
  "measurements": {
    "sev_snp": "${SNP_MEAS}",
    "tdx": "${TDX_MEAS}"
  },
  "kernel_cmdline": "${KERNEL_CMDLINE}",
  "build_config": {
    "edk2_version": "edk2-stable202405",
    "kernel_version": "6.8.12",
    "alpine_version": "3.20",
    "snpguest_version": "0.8.0",
    "docker_version": "26.1.5",
    "node_version": "22.4.1"
  }
}
EOF

echo "  ✓ manifest.json written"
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Build complete                                      ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  OVMF (SEV):  ${OVMF_SEV_HASH:0:16}...             ║"
echo "║  OVMF (TDX):  ${OVMF_TDX_HASH:0:16}...             ║"
echo "║  Kernel:      ${KERNEL_HASH:0:16}...             ║"
echo "║  Initrd:      ${INITRD_HASH:0:16}...             ║"
echo "║  SNP Meas:    ${SNP_MEAS:0:16}...               ║"
echo "║  TDX Meas:    ${TDX_MEAS:0:16}...               ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Publish the measurements so agents can verify:"
echo "  1. Upload manifest.json to a well-known URL"
echo "  2. Store measurements on-chain via the registry program"
echo "  3. Agent verifies: attestation report measurement == published measurement"
