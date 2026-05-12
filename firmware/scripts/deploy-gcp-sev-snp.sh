#!/usr/bin/env bash
#
# deploy-gcp-sev-snp.sh — one-shot deployment of a Supaba node onto a real
# AMD SEV-SNP confidential VM on Google Cloud.
#
# This script is the bridge from "mock TEE on a regular VM" to "real
# attestable confidential compute". It provisions an n2d confidential VM
# with SEV-SNP enabled, installs the toolchain (Docker, Rust, snpguest),
# builds the supaba-node binary, configures systemd, and verifies that the
# `snpguest` tool can fetch a real on-die attestation report from the AMD
# PSP via /dev/sev-guest.
#
# Once this script finishes, the node produces genuine SEV-SNP reports
# rather than the mock ones. The supaba-node binary's existing
# `TeeBackend::SevSnp` path (in packages/node-rs/src/tee/mod.rs) shells out
# to `snpguest report` and `snpguest fetch` for the attestation flow, so
# this single environment switch (SUPABA_TEE_BACKEND=sev-snp) is all the
# binary needs.
#
# Requirements on the machine running this script:
#   - gcloud CLI authenticated (`gcloud auth login`)
#   - A GCP project with billing enabled and the Compute Engine API on
#   - SSH key already in your GCP project (`gcloud compute ssh` should work)
#
# Usage:
#   PROJECT_ID=my-project ZONE=us-central1-a ./deploy-gcp-sev-snp.sh
#
# Optional env:
#   INSTANCE_NAME       (default: supaba-snp-node)
#   MACHINE_TYPE        (default: n2d-standard-4)
#   DISK_SIZE_GB        (default: 100)
#   IMAGE_FAMILY        (default: ubuntu-2404-lts-amd64)
#   IMAGE_PROJECT       (default: ubuntu-os-cloud)
#   SUPABA_REPO         (default: https://github.com/piske-alex/superba.git)
#   SUPABA_BRANCH       (default: main)
#   SUPABA_REGION       (default: gcp-us-central1)
#   SUPABA_API_PORT     (default: 3401)
#   OPERATOR_KEYPAIR    Path to a Solana keypair JSON to upload to the VM.
#                       If unset, a fresh one is generated on the VM.

set -euo pipefail

PROJECT_ID="${PROJECT_ID:?must set PROJECT_ID}"
ZONE="${ZONE:?must set ZONE (e.g. us-central1-a)}"
INSTANCE_NAME="${INSTANCE_NAME:-supaba-snp-node}"
MACHINE_TYPE="${MACHINE_TYPE:-n2d-standard-4}"
DISK_SIZE_GB="${DISK_SIZE_GB:-100}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"
SUPABA_REPO="${SUPABA_REPO:-https://github.com/piske-alex/superba.git}"
SUPABA_BRANCH="${SUPABA_BRANCH:-main}"
SUPABA_REGION="${SUPABA_REGION:-gcp-us-central1}"
SUPABA_API_PORT="${SUPABA_API_PORT:-3401}"
OPERATOR_KEYPAIR="${OPERATOR_KEYPAIR:-}"

c_blue=$'\e[34m'
c_green=$'\e[32m'
c_yellow=$'\e[33m'
c_red=$'\e[31m'
c_reset=$'\e[0m'

step() { printf "\n%s── %s ──%s\n" "${c_blue}" "$*" "${c_reset}"; }
ok()   { printf "%s  [OK]%s %s\n" "${c_green}" "${c_reset}" "$*"; }
warn() { printf "%s  [WARN]%s %s\n" "${c_yellow}" "${c_reset}" "$*"; }
die()  { printf "%s  [ERR]%s %s\n" "${c_red}" "${c_reset}" "$*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────
# 0. Sanity checks
# ─────────────────────────────────────────────────────────────────────────

step "0. Sanity"

command -v gcloud >/dev/null || die "gcloud CLI not installed"
gcloud auth list --format="value(account)" --filter=status:ACTIVE | grep -q . \
    || die "no active gcloud account; run \`gcloud auth login\`"

ok "gcloud authenticated as: $(gcloud auth list --format='value(account)' --filter=status:ACTIVE)"
ok "project: $PROJECT_ID, zone: $ZONE"
ok "machine type: $MACHINE_TYPE (must support SEV-SNP)"

# Confirm machine type supports SEV-SNP. n2d, c3d are SNP-capable.
case "$MACHINE_TYPE" in
    n2d-*|c3d-*) ok "machine family supports SEV-SNP" ;;
    *) warn "machine type $MACHINE_TYPE may not support SEV-SNP — n2d-* and c3d-* are the safe choices" ;;
esac

# ─────────────────────────────────────────────────────────────────────────
# 1. Create the confidential VM
# ─────────────────────────────────────────────────────────────────────────

step "1. Create confidential VM"

if gcloud compute instances describe "$INSTANCE_NAME" \
        --project="$PROJECT_ID" --zone="$ZONE" >/dev/null 2>&1; then
    warn "instance $INSTANCE_NAME already exists, skipping create"
else
    gcloud compute instances create "$INSTANCE_NAME" \
        --project="$PROJECT_ID" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --confidential-compute-type=SEV_SNP \
        --maintenance-policy=TERMINATE \
        --image-family="$IMAGE_FAMILY" \
        --image-project="$IMAGE_PROJECT" \
        --boot-disk-size="${DISK_SIZE_GB}GB" \
        --boot-disk-type=pd-ssd \
        --tags=supaba-node,http-server \
        --metadata=enable-oslogin=FALSE \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring
    ok "VM created"
fi

# Open the API port via a firewall rule (idempotent).
if ! gcloud compute firewall-rules describe supaba-api \
        --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute firewall-rules create supaba-api \
        --project="$PROJECT_ID" \
        --direction=INGRESS \
        --action=ALLOW \
        --rules="tcp:${SUPABA_API_PORT}" \
        --target-tags=supaba-node \
        --source-ranges=0.0.0.0/0
    ok "firewall rule supaba-api created (tcp:${SUPABA_API_PORT})"
else
    ok "firewall rule supaba-api already exists"
fi

EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --project="$PROJECT_ID" --zone="$ZONE" \
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
ok "external IP: $EXTERNAL_IP"

# Wait for SSH to come up.
step "1b. Wait for SSH"
for i in $(seq 1 30); do
    if gcloud compute ssh "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" \
            --command='echo ready' --quiet 2>/dev/null | grep -q ready; then
        ok "ssh up after ${i} attempts"
        break
    fi
    sleep 5
done

# ─────────────────────────────────────────────────────────────────────────
# 2. Bootstrap the VM
# ─────────────────────────────────────────────────────────────────────────

step "2. Upload + run bootstrap script"

REMOTE_BOOTSTRAP=$(mktemp)
cat > "$REMOTE_BOOTSTRAP" <<'BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[0m'
say()  { printf "%s[remote]%s %s\n" "$c_g" "$c_r" "$*"; }
warn() { printf "%s[remote-warn]%s %s\n" "$c_y" "$c_r" "$*"; }

say "verifying SEV-SNP guest device exists"
if [ ! -e /dev/sev-guest ]; then
    warn "/dev/sev-guest missing — kernel may not have AMD-SEV-SNP guest support compiled in"
    warn "checking dmesg for SEV-SNP init lines"
    sudo dmesg | grep -i 'sev-snp' || true
    warn "if blank, the VM was not booted with SEV-SNP — re-create with --confidential-compute-type=SEV_SNP"
else
    say "/dev/sev-guest exists ✓"
    ls -la /dev/sev-guest
fi

say "installing apt deps"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -yqq \
    ca-certificates curl gnupg lsb-release \
    build-essential pkg-config libssl-dev \
    git sqlite3 jq python3-cryptography

say "installing docker engine"
if ! command -v docker >/dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yqq \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER"
fi
say "docker version: $(docker --version 2>&1 || sudo docker --version)"

say "installing rust toolchain"
if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustc --version

say "installing snpguest (AMD SEV-SNP attestation tool)"
if ! command -v snpguest >/dev/null; then
    cargo install --locked snpguest || warn "snpguest install failed (continuing)"
fi
if command -v snpguest >/dev/null; then
    say "snpguest version: $(snpguest --version)"
else
    warn "snpguest not on PATH; real attestation will fall back to mock"
fi

say "cloning supaba"
if [ ! -d "$HOME/supaba" ]; then
    git clone --depth=1 --branch "${SUPABA_BRANCH:-main}" "${SUPABA_REPO:-https://github.com/piske-alex/superba.git}" "$HOME/supaba"
else
    cd "$HOME/supaba" && git fetch --depth=1 origin "${SUPABA_BRANCH:-main}" && git reset --hard FETCH_HEAD
fi

say "building supaba-node (release)"
cd "$HOME/supaba/packages/node-rs"
cargo build --release 2>&1 | tail -5

say "preparing data dirs + operator keypair"
mkdir -p "$HOME/supaba-data"
mkdir -p "$HOME/.config/solana"
if [ ! -f "$HOME/.config/solana/id.json" ]; then
    say "no operator keypair present, generating one with python+cryptography"
    python3 - <<'PYEOF'
import json, os
from cryptography.hazmat.primitives.asymmetric import ed25519
seed = os.urandom(32)
sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes_raw()
bytes64 = list(seed) + list(pk)
import os.path
path = os.path.expanduser("~/.config/solana/id.json")
open(path, "w").write(json.dumps(bytes64))
print("operator keypair written to", path)
PYEOF
fi
chmod 600 "$HOME/.config/solana/id.json" 2>/dev/null || true

say "writing systemd unit"
sudo tee /etc/systemd/system/supaba-node.service > /dev/null <<UNIT
[Unit]
Description=Supaba decentralized node (SEV-SNP)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
User=$USER
Group=docker
WorkingDirectory=$HOME/supaba/packages/node-rs
ExecStart=$HOME/supaba/packages/node-rs/target/release/supaba-node
Restart=on-failure
RestartSec=5
Environment=SUPABA_API_PORT=${SUPABA_API_PORT:-3401}
Environment=SUPABA_HOSTNAME=0.0.0.0
Environment=SUPABA_DATA_DIR=$HOME/supaba-data
Environment=SUPABA_REGION=${SUPABA_REGION:-gcp-us-central1}
Environment=SUPABA_TEE_BACKEND=sev-snp
Environment=SUPABA_REQUIRE_ATTESTATION=true
Environment=SUPABA_OPERATOR_KEYPAIR_PATH=$HOME/.config/solana/id.json
Environment=SUPABA_SUPABASE_TEMPLATE_PATH=$HOME/supaba/packages/node/docker/supabase-template
Environment=SUPABA_PORT_RANGE_START=10000
Environment=SUPABA_PORT_RANGE_END=10100
Environment=SUPABA_MAX_INSTANCES=5
Environment=SUPABA_WAL_REPLICATION_INTERVAL_SECS=10
Environment=PATH=$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable supaba-node.service
sudo systemctl restart supaba-node.service

sleep 3
say "service status:"
sudo systemctl status supaba-node.service --no-pager -l | head -20 || true

say "fetching a real SEV-SNP attestation report (proves /dev/sev-guest works)"
if command -v snpguest >/dev/null && [ -e /dev/sev-guest ]; then
    TMPDIR=$(mktemp -d)
    head -c 64 /dev/urandom > "$TMPDIR/req.bin"
    if sudo snpguest report "$TMPDIR/report.bin" "$TMPDIR/req.bin" 2>&1 | tail; then
        say "real SEV-SNP report fetched: $(wc -c < "$TMPDIR/report.bin") bytes"
        xxd -l 64 "$TMPDIR/report.bin" || true
    else
        warn "snpguest report failed — see above"
    fi
    sudo rm -rf "$TMPDIR"
else
    warn "skipping report fetch: snpguest=$(command -v snpguest >/dev/null && echo yes || echo no), /dev/sev-guest=$([ -e /dev/sev-guest ] && echo yes || echo no)"
fi

say "supaba-node bootstrap complete"
BOOTSTRAP

# Push the optional operator keypair first.
if [ -n "$OPERATOR_KEYPAIR" ] && [ -f "$OPERATOR_KEYPAIR" ]; then
    step "2a. Upload operator keypair"
    gcloud compute ssh "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" \
        --command="mkdir -p ~/.config/solana" --quiet
    gcloud compute scp "$OPERATOR_KEYPAIR" "$INSTANCE_NAME":~/.config/solana/id.json \
        --project="$PROJECT_ID" --zone="$ZONE" \
        --quiet
    gcloud compute ssh "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" \
        --command="chmod 600 ~/.config/solana/id.json" --quiet
    ok "operator keypair uploaded"
fi

step "2b. Run bootstrap on remote"
gcloud compute scp "$REMOTE_BOOTSTRAP" "$INSTANCE_NAME":/tmp/bootstrap.sh \
    --project="$PROJECT_ID" --zone="$ZONE" --quiet
rm -f "$REMOTE_BOOTSTRAP"

gcloud compute ssh "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" --quiet \
    --command="SUPABA_REPO='$SUPABA_REPO' SUPABA_BRANCH='$SUPABA_BRANCH' SUPABA_REGION='$SUPABA_REGION' SUPABA_API_PORT='$SUPABA_API_PORT' bash /tmp/bootstrap.sh"

# ─────────────────────────────────────────────────────────────────────────
# 3. Verify the live node
# ─────────────────────────────────────────────────────────────────────────

step "3. Verify the live node"

sleep 5
HEALTH=$(curl -sf --max-time 10 "http://${EXTERNAL_IP}:${SUPABA_API_PORT}/health" 2>&1 || echo "FAIL")
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    ok "node health: $HEALTH"
else
    warn "node health check failed: $HEALTH"
    warn "check the systemd logs: gcloud compute ssh $INSTANCE_NAME --zone=$ZONE -- sudo journalctl -u supaba-node -f"
fi

cat <<EOF

${c_green}═══════════════════════════════════════════════════════════════════${c_reset}
  Supaba SEV-SNP node deployed
${c_green}═══════════════════════════════════════════════════════════════════${c_reset}

  Instance:    $INSTANCE_NAME ($MACHINE_TYPE in $ZONE)
  External:    http://${EXTERNAL_IP}:${SUPABA_API_PORT}
  TEE backend: sev-snp (require_attestation=true)
  Repo:        $SUPABA_REPO@$SUPABA_BRANCH

  Tail logs:
    gcloud compute ssh $INSTANCE_NAME --project=$PROJECT_ID --zone=$ZONE \\
      -- sudo journalctl -u supaba-node -f

  Provision a Supabase instance:
    curl -X POST http://${EXTERNAL_IP}:${SUPABA_API_PORT}/instances \\
      -H "Content-Type: application/json" \\
      -d '{"wallet_pubkey":"<your-pubkey>","name":"first-snp-instance"}'

  Fetch a fresh attestation report (proves real SEV-SNP):
    curl -X POST http://${EXTERNAL_IP}:${SUPABA_API_PORT}/instances/<id>/attest

  Tear down:
    gcloud compute instances delete $INSTANCE_NAME --project=$PROJECT_ID --zone=$ZONE

EOF
