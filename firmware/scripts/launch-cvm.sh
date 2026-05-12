#!/bin/bash
# Launch a Supaba confidential VM using QEMU with SEV-SNP or TDX
#
# Usage:
#   ./launch-cvm.sh --platform sev-snp [options]
#   ./launch-cvm.sh --platform tdx [options]
#
# Options:
#   --platform    sev-snp | tdx (required)
#   --cpus        Number of vCPUs (default: 4)
#   --memory      RAM in MB (default: 8192)
#   --disk        Path to data disk image (created if absent)
#   --disk-size   Data disk size (default: 100G)
#   --port        Host port to forward to guest port 3401 (default: 3401)
#   --firmware    Path to firmware dir (default: ../out)
#   --debug       Enable serial console output

set -euo pipefail

# ─── Parse arguments ──────────────────────────────────────────────────────────

PLATFORM=""
CPUS=4
MEMORY=8192
DISK=""
DISK_SIZE="100G"
HOST_PORT=3401
FIRMWARE_DIR="$(dirname "$0")/../out"
DEBUG=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)   PLATFORM="$2";      shift 2 ;;
        --cpus)       CPUS="$2";          shift 2 ;;
        --memory)     MEMORY="$2";        shift 2 ;;
        --disk)       DISK="$2";          shift 2 ;;
        --disk-size)  DISK_SIZE="$2";     shift 2 ;;
        --port)       HOST_PORT="$2";     shift 2 ;;
        --firmware)   FIRMWARE_DIR="$2";  shift 2 ;;
        --debug)      DEBUG=true;         shift ;;
        *)            echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "${PLATFORM}" ]; then
    echo "Usage: $0 --platform <sev-snp|tdx> [options]"
    exit 1
fi

# ─── Validate firmware files ─────────────────────────────────────────────────

KERNEL="${FIRMWARE_DIR}/vmlinuz"
INITRD="${FIRMWARE_DIR}/initrd.img"

case "${PLATFORM}" in
    sev-snp)
        OVMF="${FIRMWARE_DIR}/ovmf-sev.fd"
        ;;
    tdx)
        OVMF="${FIRMWARE_DIR}/ovmf-tdx.fd"
        ;;
    *)
        echo "Unsupported platform: ${PLATFORM}. Use sev-snp or tdx."
        exit 1
        ;;
esac

for file in "${OVMF}" "${KERNEL}" "${INITRD}"; do
    if [ ! -f "${file}" ]; then
        echo "Missing firmware file: ${file}"
        echo "Run ./build-all.sh first."
        exit 1
    fi
done

# ─── Create data disk if needed ──────────────────────────────────────────────

if [ -z "${DISK}" ]; then
    DISK="${FIRMWARE_DIR}/data.qcow2"
fi

if [ ! -f "${DISK}" ]; then
    echo "Creating data disk: ${DISK} (${DISK_SIZE})"
    qemu-img create -f qcow2 "${DISK}" "${DISK_SIZE}"
fi

# ─── Kernel command line ──────────────────────────────────────────────────────

CMDLINE="console=ttyS0 supaba=1 quiet"

# ─── Build QEMU command ──────────────────────────────────────────────────────

QEMU_CMD=(
    qemu-system-x86_64
    -enable-kvm
    -cpu host
    -smp "${CPUS}"
    -m "${MEMORY}"

    # Firmware (OVMF)
    -drive "if=pflash,format=raw,unit=0,file=${OVMF},readonly=on"

    # Direct boot (kernel + initrd in the measurement)
    -kernel "${KERNEL}"
    -initrd "${INITRD}"
    -append "${CMDLINE}"

    # Data disk (not in measurement — used for Docker images and instance data)
    -drive "file=${DISK},format=qcow2,if=virtio,cache=writeback,discard=unmap"

    # Networking: virtio-net with port forwarding
    -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:3401"
    -device "virtio-net-pci,netdev=net0"

    # Console
    -serial stdio
    -nographic

    # RNG (needed for crypto operations inside the VM)
    -device virtio-rng-pci

    # Balloon (memory management)
    -device virtio-balloon-pci
)

# ─── Platform-specific options ────────────────────────────────────────────────

case "${PLATFORM}" in
    sev-snp)
        echo "Launching AMD SEV-SNP confidential VM..."

        # SEV-SNP machine configuration
        QEMU_CMD+=(
            -machine "q35,confidential-guest-support=sev0,memory-backend=ram1"
            -object "memory-backend-memfd-private,id=ram1,size=${MEMORY}M,share=true"
            -object "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000"
        )
        ;;

    tdx)
        echo "Launching Intel TDX confidential VM..."

        # TDX machine configuration
        QEMU_CMD+=(
            -machine "q35,kernel-irqchip=split,confidential-guest-support=tdx0,memory-backend=ram1"
            -object "memory-backend-memfd-private,id=ram1,size=${MEMORY}M,share=true"
            -object "tdx-guest,id=tdx0"
        )
        ;;
esac

# ─── Debug options ────────────────────────────────────────────────────────────

if [ "${DEBUG}" = true ]; then
    QEMU_CMD+=(-d guest_errors)
    echo "Debug mode enabled"
fi

# ─── Launch ──────────────────────────────────────────────────────────────────

echo ""
echo "Configuration:"
echo "  Platform:  ${PLATFORM}"
echo "  vCPUs:     ${CPUS}"
echo "  Memory:    ${MEMORY} MB"
echo "  Data disk: ${DISK}"
echo "  API port:  localhost:${HOST_PORT} → guest:3401"
echo "  Firmware:  ${OVMF}"
echo "  Kernel:    ${KERNEL}"
echo "  Initrd:    ${INITRD}"
echo ""
echo "The VM memory is hardware-encrypted. The host cannot read it."
echo "Press Ctrl-A X to terminate the VM."
echo ""

exec "${QEMU_CMD[@]}"
