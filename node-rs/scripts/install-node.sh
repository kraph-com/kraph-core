#!/usr/bin/env bash
# One-shot Kraph node installer for bare-metal / non-TEE Linux hosts.
#
# What this does:
#   1. Builds packages/node-rs in release mode (uses the cargo on PATH).
#   2. Writes a systemd unit that points SUPABA_SUPABASE_TEMPLATE_PATH at
#      THIS checkout — never a copy. So `git pull && systemctl restart` is
#      the upgrade story; there is no second template directory that can
#      drift.
#   3. Drops a stub /etc/supaba/node.env with placeholders that an operator
#      must fill in (public IP, region, operator keypair path, etc).
#
# Idempotent: safe to re-run after `git pull`. Existing node.env is not
# overwritten — only the systemd unit and the binary are refreshed.
#
# Run as root (or via sudo). The systemd unit will run node-rs as the
# invoking user so the cargo build cache and the operator keypair stay
# in that user's $HOME.
#
# For SEV-SNP / TDX confidential VM nodes, do NOT use this script —
# those nodes boot from the firmware-baked initrd. See
# packages/firmware/README.md.

set -euo pipefail

# ─── Sanity ──────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "error: this script writes to /etc/systemd/system; run with sudo" >&2
  exit 1
fi
INVOKER=${SUDO_USER:-$(whoami)}
if [[ -z "${INVOKER}" || "${INVOKER}" == "root" ]]; then
  echo "error: refuse to run node as root; run via 'sudo bash $0' from a regular user" >&2
  exit 1
fi
INVOKER_HOME=$(getent passwd "${INVOKER}" | cut -d: -f6)
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TEMPLATE="${REPO}/packages/node/docker/supabase-template"
NODE_BIN="${REPO}/packages/node-rs/target/release/supaba-node"

if [[ ! -f "${TEMPLATE}/docker-compose.yml" ]]; then
  echo "error: docker-compose template not found at ${TEMPLATE}" >&2
  echo "  Expected: $(realpath --no-symlinks "${TEMPLATE}/docker-compose.yml" 2>/dev/null || echo "${TEMPLATE}/docker-compose.yml")" >&2
  exit 1
fi

# ─── Build node-rs ───────────────────────────────────────────────────────────
echo "[1/5] Building supaba-node (release)"
sudo -u "${INVOKER}" -H bash -c "cd '${REPO}/packages/node-rs' && cargo build --release"

if [[ ! -x "${NODE_BIN}" ]]; then
  echo "error: build did not produce ${NODE_BIN}" >&2
  exit 1
fi

# ─── Kubo (IPFS) sidecar ─────────────────────────────────────────────────────
# kraph_pin_frontend pins agent content to real IPFS via this daemon's
# HTTP RPC API on 127.0.0.1:5001. The gateway on 127.0.0.1:8080 serves
# the content back through node-rs's /ipfs/:cid route. libp2p (4001)
# is left on 0.0.0.0 so peers can dial in for content propagation —
# without this the CIDs we mint never propagate to ipfs.io / public
# gateways.
KUBO_NAME="supaba-kubo"
KUBO_DATA="/var/lib/supaba/ipfs"
echo "[2/5] Ensuring Kubo container is running"
mkdir -p "${KUBO_DATA}"
chown "${INVOKER}":"${INVOKER}" "${KUBO_DATA}"
if ! command -v docker >/dev/null; then
  echo "error: docker is not installed; required for the Kubo IPFS sidecar" >&2
  exit 1
fi
if ! docker inspect "${KUBO_NAME}" >/dev/null 2>&1; then
  docker run -d \
    --name "${KUBO_NAME}" \
    --restart unless-stopped \
    -v "${KUBO_DATA}:/data/ipfs" \
    -p 127.0.0.1:5001:5001 \
    -p 127.0.0.1:8080:8080 \
    -p 4001:4001 \
    -p 4001:4001/udp \
    ipfs/kubo:v0.30.0 \
    >/dev/null
  echo "      → started ${KUBO_NAME}"
else
  echo "      → ${KUBO_NAME} already exists; not recreating"
fi

# ─── Stub env file (only on first install) ───────────────────────────────────
mkdir -p /etc/supaba
if [[ ! -f /etc/supaba/node.env ]]; then
  echo "[3/5] Writing /etc/supaba/node.env (placeholders — fill these in)"
  cat > /etc/supaba/node.env <<EOF
# Required: edit these before starting the service
SUPABA_HOSTNAME=<PUBLIC_IP_OR_DNS>
SUPABA_REGION=<region-tag>
SUPABA_OPERATOR_KEYPAIR_PATH=/etc/supaba/operator.json

# Networking
SUPABA_API_PORT=3401
SUPABA_PORT_RANGE_START=10000
SUPABA_PORT_RANGE_END=20000

# Storage
SUPABA_DATA_DIR=/var/lib/supaba

# Capacity
SUPABA_MAX_INSTANCES=10
SUPABA_AVAILABLE_CPU_CORES=4
SUPABA_WARM_POOL_SIZE=1

# TEE: 'mock' for devnet bare-metal; 'sev-snp' or 'tdx' is firmware-only
SUPABA_TEE_BACKEND=mock
SUPABA_REQUIRE_ATTESTATION=false

# Solana
SUPABA_SOLANA_NETWORK=devnet
SUPABA_SOLANA_RPC_URL=https://api.devnet.solana.com

# Template path — points at THIS checkout. Do not copy the template
# elsewhere; keep this and \`git pull\` is the upgrade path.
SUPABA_SUPABASE_TEMPLATE_PATH=${TEMPLATE}

# Kubo (IPFS) sidecar — installed by this script as a docker container
SUPABA_KUBO_API_URL=http://127.0.0.1:5001
SUPABA_KUBO_GATEWAY_URL=http://127.0.0.1:8080
EOF
  chmod 640 /etc/supaba/node.env
  chown root:"${INVOKER}" /etc/supaba/node.env
else
  echo "[3/5] /etc/supaba/node.env exists — leaving as-is"
  # Ensure SUPABA_SUPABASE_TEMPLATE_PATH points at THIS checkout, even on upgrade.
  if grep -q '^SUPABA_SUPABASE_TEMPLATE_PATH=' /etc/supaba/node.env; then
    sed -i "s|^SUPABA_SUPABASE_TEMPLATE_PATH=.*|SUPABA_SUPABASE_TEMPLATE_PATH=${TEMPLATE}|" /etc/supaba/node.env
    echo "      → pinned SUPABA_SUPABASE_TEMPLATE_PATH=${TEMPLATE}"
  else
    echo "SUPABA_SUPABASE_TEMPLATE_PATH=${TEMPLATE}" >> /etc/supaba/node.env
    echo "      → appended SUPABA_SUPABASE_TEMPLATE_PATH=${TEMPLATE}"
  fi
fi

# Backfill SUPABA_KUBO_* if older node.env predates this script
if ! grep -q '^SUPABA_KUBO_API_URL=' /etc/supaba/node.env; then
  cat >> /etc/supaba/node.env <<'EOF'

# Kubo (IPFS) sidecar
SUPABA_KUBO_API_URL=http://127.0.0.1:5001
SUPABA_KUBO_GATEWAY_URL=http://127.0.0.1:8080
EOF
  echo "      → appended SUPABA_KUBO_*"
fi

# ─── systemd unit ────────────────────────────────────────────────────────────
echo "[4/5] Writing systemd unit"
cat > /etc/systemd/system/supaba-node.service <<EOF
[Unit]
Description=Kraph decentralized node (supaba-node)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
User=${INVOKER}
Group=docker
WorkingDirectory=${REPO}/packages/node-rs
ExecStart=${NODE_BIN}
Restart=on-failure
RestartSec=5
EnvironmentFile=/etc/supaba/node.env
# Hardening
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# ─── Enable + start ──────────────────────────────────────────────────────────
echo "[5/5] Reloading systemd and enabling service"
systemctl daemon-reload
systemctl enable supaba-node.service

cat <<EOF

  Install complete.

  Next steps:
    1. Edit /etc/supaba/node.env — fill in SUPABA_HOSTNAME, SUPABA_REGION,
       and place the operator Solana keypair at SUPABA_OPERATOR_KEYPAIR_PATH.
    2. Start the service:
         sudo systemctl start supaba-node
    3. Watch logs:
         sudo journalctl -u supaba-node -f
    4. Verify:
         curl http://127.0.0.1:\${SUPABA_API_PORT:-3401}/health

  To upgrade (from this checkout):
    cd ${REPO} && git pull
    sudo bash ${REPO}/packages/node-rs/scripts/install-node.sh
    sudo systemctl restart supaba-node

EOF
