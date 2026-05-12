# Kraph Core

Open-source protocol primitives for **Kraph** — a decentralized full-stack cloud for AI agents. Postgres + REST + Auth + Realtime + Storage + Edge Functions + IPFS hosting + encrypted env vars, provisioned and paid per-call by agents over x402 USDC on Solana.

This repo ships the parts of Kraph that anyone should be able to read, audit, build, and run independently:

| Component | What it is |
|---|---|
| [`node-rs/`](./node-rs) | Node operator software (Rust, axum, SQLite, bollard). Orchestrates per-tenant Supabase stacks via Docker Compose, ships encrypted WAL to replicas, exposes the operator HTTP API. |
| [`contracts/`](./contracts) | Solana program `supaba_registry` (Anchor). On-chain node directory, instance commitments, and integrity roots. Program ID `9B6JGBf3djjquA5mx9VsnTb9GTyMMjL1c4F2wpY5W9dv`. |
| [`crypto/`](./crypto) | Encryption primitives shared by node + clients (TypeScript). Wallet → DEK derivation, XChaCha20-Poly1305 WAL encryption with hash chain, Merkle roots. |
| [`firmware/`](./firmware) | Reproducible SEV-SNP / TDX firmware build (OVMF + kernel + initrd) so node measurements are independently verifiable. |
| [`WHITEPAPER.md`](./WHITEPAPER.md) | Protocol spec. |

## What is NOT in this repo

The operator-side surface — the gateway (x402 settlement, Privy delegation, Cloudflare integration), the dashboard, and the kraph.com landing site — is operated by Kraph and lives elsewhere. The node, contracts, crypto lib, and firmware are everything a third party needs to inspect the protocol or run their own node.

## Quick start — run a node

```bash
git clone https://github.com/kraph-com/kraph-core.git
cd kraph-core/node-rs
cargo build --release
sudo bash scripts/install-node.sh    # writes systemd unit + starts the binary
```

The node will start in **mock TEE mode** by default. To enable real SEV-SNP attestation on AMD EPYC hardware, see [`node-rs/README.md`](./node-rs/README.md) and [`firmware/README.md`](./firmware/README.md).

## Build the Solana program

```bash
cd contracts
anchor build
anchor deploy   # or anchor test for a localnet round-trip
```

## Build the crypto lib

```bash
cd crypto
pnpm install
pnpm build
pnpm test
```

## Build the firmware (reproducible)

```bash
cd firmware
./scripts/build-all.sh    # produces measurement-snp.hex, measurement-tdx.hex, disk.qcow2
```

The SHA-384 measurement output is what agents verify on-chain via `kraph_attest` before trusting a node with confidential workloads.

## License

[MIT](./LICENSE).

## Contributing

Issues and PRs welcome. Anything touching the on-chain program, encryption primitives, or attestation flow needs a paired note in `WHITEPAPER.md` if it changes the protocol surface.
