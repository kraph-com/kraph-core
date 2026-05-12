# Kraph Confidential VM Firmware

This package builds the reproducible, measured firmware image for Kraph nodes
running inside AMD SEV-SNP or Intel TDX confidential VMs.

## What gets measured

The AMD PSP (or Intel TDX module) computes a SHA-384 hash of everything loaded
into guest memory before the VM starts. This measurement is signed by hardware
and included in the attestation report. Agents verify this measurement to
confirm the node is running unmodified Kraph software.

The measurement covers:
- **OVMF firmware** — UEFI boot firmware with SEV-SNP/TDX support
- **Linux kernel** — Minimal kernel with confidential VM guest drivers
- **initrd** — Contains Docker, containerd, Kraph node, attestation agent

## Build

```bash
# Build everything (requires Docker)
./scripts/build-all.sh

# Output:
#   out/ovmf-sev.fd          — OVMF firmware binary
#   out/ovmf-tdx.fd          — TDVF firmware binary
#   out/vmlinuz               — Linux kernel
#   out/initrd.img            — Initial ramdisk
#   out/measurement-snp.hex   — Expected SEV-SNP measurement (SHA-384)
#   out/measurement-tdx.hex   — Expected TDX measurement (SHA-384)
#   out/disk.qcow2            — Full disk image for cloud deployment
```

## Reproducibility

The build is fully Dockerized with pinned versions:
- edk2 commit: pinned in `Dockerfile.ovmf`
- Linux kernel version: pinned in `Dockerfile.kernel`
- Alpine base: pinned version
- All packages: pinned versions

Anyone can rebuild and verify they get the same measurement.

## Verification

```bash
# Pre-compute expected measurement
pip install sev-snp-measure
sev-snp-measure --mode snp \
  --ovmf out/ovmf-sev.fd \
  --kernel out/vmlinuz \
  --initrd out/initrd.img \
  --append "console=ttyS0 supaba=1"

# Compare with out/measurement-snp.hex
```

## Cloud Deployment

For Azure/GCP confidential VMs, firmware is provider-managed. Use `out/disk.qcow2`
as the boot disk. The provider's OVMF measurement is verified against their published
reference values; Kraph's kernel + initrd are measured via the boot chain.
