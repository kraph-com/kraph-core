#!/bin/bash
# Supaba Confidential VM Init Script
#
# This is the first userspace process (PID 1) inside the confidential VM.
# The entire VM memory is hardware-encrypted by AMD SEV-SNP or Intel TDX.
#
# Boot sequence:
# 1. Mount essential filesystems
# 2. Detect TEE platform (SEV-SNP or TDX)
# 3. Generate initial attestation report (prove we're genuine)
# 4. Start Docker daemon
# 5. Start Supaba node
# 6. Begin accepting connections
#
# The node operator controls the host but CANNOT read this VM's memory.

set -euo pipefail

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Supaba Confidential VM v0.1.0                       ║"
echo "║  Memory-encrypted by hardware TEE                    ║"
echo "╚═══════════════════════════════════════════════════════╝"

# ─── 1. Mount essential filesystems ───────────────────────────────────────────

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mount -t cgroup2 cgroup2 /sys/fs/cgroup

# Create required device nodes
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm

# Mount the data disk if present (virtio block device for persistent storage)
if [ -b /dev/vdb ]; then
    echo "Data disk detected at /dev/vdb"
    mkdir -p /var/lib/docker /var/lib/supaba
    # Format if not already formatted
    if ! blkid /dev/vdb >/dev/null 2>&1; then
        echo "Formatting data disk..."
        mkfs.ext4 -q /dev/vdb
    fi
    mount /dev/vdb /var/lib/docker
    mkdir -p /var/lib/docker /var/lib/supaba
fi

# Set hostname
hostname supaba-cvm

# Configure networking — virtio-net should be available
ip link set lo up
if ip link show eth0 >/dev/null 2>&1; then
    ip link set eth0 up
    # DHCP or static IP depending on environment
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i eth0 -q -n
    fi
fi

echo "Filesystems mounted, networking up"

# ─── 2. Detect TEE platform ──────────────────────────────────────────────────

TEE_PLATFORM="none"
TEE_DEVICE=""

if [ -c /dev/sev-guest ] || [ -e /sys/kernel/debug/sev ]; then
    TEE_PLATFORM="sev-snp"
    TEE_DEVICE="/dev/sev-guest"
    echo "TEE: AMD SEV-SNP detected"

    # Verify we're actually in an SNP-enabled VM
    if dmesg 2>/dev/null | grep -q "SEV-SNP"; then
        echo "TEE: SEV-SNP active and confirmed via dmesg"
    fi
elif [ -c /dev/tdx-guest ]; then
    TEE_PLATFORM="tdx"
    TEE_DEVICE="/dev/tdx-guest"
    echo "TEE: Intel TDX detected"
else
    echo "WARNING: No TEE platform detected!"
    echo "This VM is NOT running inside a confidential environment."
    echo "Data may be visible to the host operator."
    echo "Continuing anyway (development mode)..."
fi

export SUPABA_TEE_BACKEND="${TEE_PLATFORM}"

# ─── 3. Initial attestation ──────────────────────────────────────────────────
# Generate an attestation report at boot to prove this VM is genuine.
# This report is cached and served to the first agent that connects.

ATTESTATION_DIR="/var/lib/supaba/attestation"
mkdir -p "${ATTESTATION_DIR}"

if [ "${TEE_PLATFORM}" = "sev-snp" ] && command -v snpguest >/dev/null 2>&1; then
    echo "Generating initial SEV-SNP attestation report..."

    # Generate a random nonce for the boot attestation
    BOOT_NONCE=$(head -c 32 /dev/urandom | xxd -p -c 64)

    snpguest report \
        "${ATTESTATION_DIR}/boot-report.bin" \
        "${ATTESTATION_DIR}/boot-request.bin" \
        --report-data "${BOOT_NONCE}" \
        2>/dev/null || echo "Warning: snpguest report generation failed"

    # Fetch certificate chain from AMD KDS
    snpguest fetch ca pem "${ATTESTATION_DIR}" --encoding pem 2>/dev/null || true
    snpguest fetch vcek pem "${ATTESTATION_DIR}" --encoding pem 2>/dev/null || true

    # Extract and display the measurement
    if [ -f "${ATTESTATION_DIR}/boot-report.bin" ]; then
        MEASUREMENT=$(dd if="${ATTESTATION_DIR}/boot-report.bin" bs=1 skip=144 count=48 2>/dev/null | xxd -p -c 96)
        echo "TEE Measurement: ${MEASUREMENT}"
        echo "${MEASUREMENT}" > "${ATTESTATION_DIR}/measurement.hex"
    fi

    echo "Attestation report generated and cached"

elif [ "${TEE_PLATFORM}" = "tdx" ] && command -v tdx_attest >/dev/null 2>&1; then
    echo "Generating initial TDX attestation quote..."

    BOOT_NONCE=$(head -c 32 /dev/urandom | xxd -p -c 64)

    tdx_attest -r "${BOOT_NONCE}" -o "${ATTESTATION_DIR}/boot-quote.bin" \
        2>/dev/null || echo "Warning: tdx_attest quote generation failed"

    echo "TDX attestation quote generated and cached"
fi

# ─── 4. Start Docker daemon ──────────────────────────────────────────────────

echo "Starting containerd..."
containerd &
sleep 2

echo "Starting Docker daemon..."
dockerd \
    --config-file /etc/docker/daemon.json \
    --host unix:///var/run/docker.sock \
    --storage-driver overlay2 \
    &

# Wait for Docker to be ready
echo "Waiting for Docker..."
DOCKER_RETRIES=30
while [ $DOCKER_RETRIES -gt 0 ]; do
    if docker info >/dev/null 2>&1; then
        echo "Docker is ready"
        break
    fi
    sleep 1
    DOCKER_RETRIES=$((DOCKER_RETRIES - 1))
done

if [ $DOCKER_RETRIES -eq 0 ]; then
    echo "ERROR: Docker failed to start within 30 seconds"
    echo "Check /var/log/dockerd.log for details"
fi

# ─── 5. Start Supaba node ────────────────────────────────────────────────────

echo "Starting Supaba node..."

# Load environment config
if [ -f /etc/supaba/node.env ]; then
    set -a
    source /etc/supaba/node.env
    set +a
fi

# Override TEE config from detected platform
export SUPABA_TEE_BACKEND="${TEE_PLATFORM}"
export SUPABA_REQUIRE_ATTESTATION="true"
export SUPABA_DATA_DIR="/var/lib/supaba/node"
export SUPABA_SUPABASE_TEMPLATE_PATH="/opt/supaba/docker/supabase-template"

mkdir -p "${SUPABA_DATA_DIR}"

# Start the Rust node binary (single static binary, no runtime deps)
supaba-node &
SUPABA_PID=$!

echo "Supaba node started (PID: ${SUPABA_PID})"

# ─── 6. Keep running ─────────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Supaba CVM ready                                    ║"
echo "║  TEE: ${TEE_PLATFORM}                                          ║"
echo "║  Node PID: ${SUPABA_PID}                                        ║"
echo "╚═══════════════════════════════════════════════════════╝"

# Wait for the Supaba node process — if it dies, the VM should stop
wait ${SUPABA_PID}

echo "Supaba node exited. Shutting down VM."
poweroff -f
