---
type: "note"
---
# Kraph: Decentralized Full-Stack Cloud for Autonomous Agents

**Version 1.0 — April 2026**

***

## Table of Contents

1. [Abstract](#1-abstract)

2. [Problem Statement](#2-problem-statement)

3. [Protocol Design](#3-protocol-design)

4. [Network Architecture](#4-network-architecture)

5. [Authentication](#5-authentication)

6. [Security Model — 4-Layer Integrity + TEE Foundation](#6-security-model--4-layer-integrity--tee-foundation)

7. [Encryption](#7-encryption)

8. [Payment Protocol](#8-payment-protocol)

9. [Performance](#9-performance)

10. [Edge Functions](#10-edge-functions)

11. [IPFS Frontend Pinning](#11-ipfs-frontend-pinning)

12. [Threat Model](#12-threat-model)

13. [Agent Interaction (MCP Interface)](#13-agent-interaction-mcp-interface)

14. [Operator Economics](#14-operator-economics)

15. [Roadmap](#15-roadmap)

***

## 1. Abstract

Autonomous AI agents represent a growing class of software that operates without continuous human supervision — executing multi-step tasks, managing persistent state, and interacting with external services on behalf of users. These agents require a *full-stack cloud*: relational databases, authentication, realtime pub/sub, object storage, server-side compute, static frontend hosting, and encrypted secret storage for the credentials those services consume. Today, provisioning any of this requires a human to create accounts, enter credit card details, navigate dashboards, and configure services manually — and integrating the pieces requires threading a different human-owned account through each vendor (Supabase + Vercel + AWS + Doppler + …). This is a fundamental bottleneck: agents cannot independently acquire the compute, storage, and runtime they need to function.

Kraph is a decentralized protocol that provisions isolated full-stack cloud instances to AI agents on demand — a managed Postgres + PostgREST + Kong + GoTrue + Realtime + Storage + Studio + Analytics stack, an Edge Functions runtime (Deno/TypeScript, Supabase-compatible), IPFS-backed static frontend hosting, and encrypted per-instance environment variables for function secrets, all under a single provisioning call and a single URL. Agents authenticate via Solana wallet signatures, pay per-request using the x402 HTTP payment protocol with USDC, and receive dedicated infrastructure without any human intervention. Node operators join the network permissionlessly by staking SOL and running the Kraph node software. The protocol ensures data integrity and confidentiality through a 4-layer security model built on a TEE foundation — every instance runs inside a confidential VM (AMD SEV-SNP or Intel TDX) with hardware-encrypted memory — combined with WAL hash chains, on-chain Merkle state commitments, and cross-replica verification. Kraph enables fully autonomous full-stack application deployment — backend, frontend, compute, and secrets — paid entirely in cryptocurrency.

***

## 2. Problem Statement

### 2.1 Agents Need Full Backend Stacks

Modern AI agents are not stateless functions. An agent managing a user's finances needs a database to track transactions. An agent coordinating a team needs realtime pub/sub for notifications. An agent running a SaaS product needs authentication, row-level security, and object storage. The minimum viable backend for a non-trivial agent is:

* **Relational database** (Postgres) — structured state, transactions, constraints

* **REST/GraphQL API** (PostgREST) — programmatic data access without raw SQL over the wire

* **Authentication** (GoTrue) — managing end-user identities if the agent serves users

* **Realtime** — pub/sub and presence for live applications

* **Object storage** — files, images, documents

* **API gateway** (Kong) — rate limiting, routing, TLS termination

* **Admin interface** (Studio) — schema inspection, data browsing

* **Analytics** (Logflare) — query and request logging

This is exactly the stack that Supabase provides. But Supabase Cloud, like every managed infrastructure provider, assumes a human operator.

### 2.2 The Human Bottleneck

Every major cloud provider — AWS, GCP, Azure, Supabase Cloud, PlanetScale, Neon — requires:

1. **Human identity verification**: email, phone number, or OAuth with a human-owned account.

2. **Payment via credit card or bank account**: instruments tied to legal persons.

3. **Manual configuration**: clicking through dashboards, setting environment variables, configuring networking.

4. **Terms of service acceptance**: legal agreements designed for humans or corporations.

An AI agent with a Solana wallet and USDC balance cannot create a Supabase Cloud project. There is no API that accepts a cryptographic signature as identity and a stablecoin payment as billing. The agent must ask a human to provision infrastructure on its behalf, destroying the autonomy that makes agents useful.

### 2.3 No Existing Decentralized Solution

Decentralized compute networks (Akash, Render Network, Golem) provide raw compute but not managed database stacks. An agent could theoretically deploy containers on Akash, but it would need to:

* Compose a multi-service Docker deployment (Postgres, PostgREST, Kong, GoTrue, Realtime, Storage)

* Configure inter-service networking and TLS certificates

* Set up backup and replication

* Monitor health and handle failover

* Manage credentials and key rotation

This is not a task agents can reliably perform today. They need a protocol that abstracts the full stack into a single provisioning call.

### 2.4 Frontend Deployment

Agents building user-facing applications also need to deploy frontends. Current options — Vercel, Netlify, Cloudflare Pages — all require human-owned accounts. IPFS provides a decentralized alternative, but pinning services (Pinata, Infura, web3.storage) again require accounts and API keys tied to human identities. Agents need a permissionless IPFS pinning service payable in cryptocurrency.

### 2.5 Summary

There is a gap in the infrastructure market: no existing service allows an AI agent to autonomously provision, pay for, and manage a full backend stack using only a cryptographic identity and cryptocurrency. Kraph fills this gap.

***

## 3. Protocol Design

The Kraph protocol is defined by a set of on-chain programs deployed on Solana and a set of off-chain conventions that nodes and clients follow. The on-chain component serves as a registry, payment layer, and integrity anchor. The off-chain component handles actual infrastructure provisioning, data serving, and replication.

### 3.1 On-Chain Program (Anchor)

The Kraph Anchor program is deployed on Solana mainnet. It defines four account types and eight instructions.

### 3.2 Account Structures

#### 3.2.1 NodeRecord

Stores the registration and state of a single node operator.

```rust
#[account]
pub struct NodeRecord {
    /// Operator's Solana wallet — signer for all node operations.
    pub authority: Pubkey,

    /// Unique node identifier: SHA-256(authority || registration_nonce).
    /// Prevents re-registration attacks after deregistration.
    pub node_id: [u8; 32],

    /// Node's public HTTPS endpoint (max 256 bytes).
    /// Agents connect here for data plane operations after provisioning.
    pub endpoint: String,

    /// Lamports staked into the stake escrow PDA. Minimum 1 SOL.
    /// Higher stake increases placement score and signals operator commitment.
    pub stake_amount: u64,

    /// PDA holding the staked SOL. Seeds: ["stake", node_id].
    pub stake_escrow: Pubkey,

    /// Maximum concurrent Supabase instances this node can host (1-255).
    /// Self-reported by the operator; overcommitment risks performance
    /// degradation and negative reputation.
    pub capacity: u8,

    /// Number of currently active instances on this node.
    pub active_instances: u8,

    /// Unix timestamp of initial registration.
    pub registered_at: i64,

    /// Unix timestamp of the most recent heartbeat transaction.
    pub last_heartbeat: i64,

    /// Cumulative uptime score. Incremented by 1 for each successful
    /// heartbeat. Used in placement algorithm as a reliability signal.
    pub uptime_score: u32,

    /// Number of times this node has been slashed. Visible to agents
    /// during node selection; a high count signals unreliability.
    pub slashing_events: u16,

    /// Whether this node offers IPFS pinning services.
    pub ipfs_enabled: bool,

    /// Current node status.
    /// Active:   accepting new instances, sending heartbeats.
    /// Inactive: missed 60+ heartbeats, not receiving new instances.
    /// Slashed:  penalized, requires restaking to reactivate.
    pub status: NodeStatus,

    /// PDA bump seed for deterministic address derivation.
    pub bump: u8,
}
```

#### 3.2.2 InstanceRecord

Represents a provisioned Supabase instance assigned to an agent.

```rust
#[account]
pub struct InstanceRecord {
    /// Unique instance ID: SHA-256(agent_pubkey || allocation_nonce).
    pub instance_id: [u8; 32],

    /// Agent's Solana wallet — the owner of this instance.
    /// Only this pubkey can query, modify, or destroy the instance.
    pub agent: Pubkey,

    /// Authority of the NodeRecord hosting the primary Supabase stack.
    pub primary_node: Pubkey,

    /// Authorities of up to 3 NodeRecords storing encrypted WAL replicas.
    /// Zeroed pubkeys indicate unused replica slots.
    pub replica_nodes: [Pubkey; 3],

    /// Data Encryption Key, encrypted with the agent's derived master key
    /// (AES-256-GCM). Stored on-chain so the agent can always recover
    /// the DEK using only their Solana keypair.
    pub encrypted_dek: [u8; 64],

    /// Latest Merkle root committed by the primary node.
    /// Agents verify query results against this root.
    pub merkle_root: [u8; 32],

    /// Solana slot number at the time of the latest Merkle commitment.
    /// Provides a temporal anchor for the commitment.
    pub merkle_slot: u64,

    /// Head of the WAL hash chain (hash of the most recent WAL segment,
    /// incorporating all prior hashes). Used to detect WAL tampering.
    pub wal_hash_head: [u8; 32],

    /// Total number of WAL segments processed since instance creation.
    pub wal_segment_count: u64,

    /// Unix timestamp of instance provisioning.
    pub provisioned_at: i64,

    /// Unix timestamp after which the instance is eligible for suspension.
    /// Extended by depositing additional USDC into the PaymentEscrow.
    pub expires_at: i64,

    /// Current instance status.
    /// Provisioning: stack is starting up.
    /// Active:       serving queries.
    /// Suspended:    escrow depleted, in grace period.
    /// Terminated:   destroyed, WAL backups retained for 7 days.
    pub status: InstanceStatus,

    /// PDA bump seed.
    pub bump: u8,
}
```

#### 3.2.3 PaymentEscrow

Holds prepaid USDC for ongoing hosting fees.

```rust
#[account]
pub struct PaymentEscrow {
    /// References the InstanceRecord this escrow funds.
    pub instance_id: [u8; 32],

    /// Agent who deposited the funds.
    pub agent: Pubkey,

    /// PDA-owned USDC SPL token account holding the escrowed funds.
    pub token_account: Pubkey,

    /// Total USDC deposited since creation (6 decimals, so 1_000_000 = 1 USDC).
    pub deposited: u64,

    /// Total USDC distributed to node operators via crank.
    pub distributed: u64,

    /// Unix timestamp of the last distribution crank.
    pub last_distribution: i64,

    /// PDA bump seed.
    pub bump: u8,
}
```

#### 3.2.4 PinRecord

Represents an IPFS pin managed by the network.

```rust
#[account]
pub struct PinRecord {
    /// Unique pin ID: SHA-256(agent_pubkey || cid).
    pub pin_id: [u8; 32],

    /// Agent who requested the pin.
    pub agent: Pubkey,

    /// IPFS CID (CIDv1, base32-encoded, max 128 bytes).
    /// Content-addressed: the CID is the cryptographic hash of the content.
    pub cid: String,

    /// Size of the pinned content in bytes.
    pub size_bytes: u64,

    /// Up to 3 nodes pinning this content for redundancy.
    pub pin_nodes: [Pubkey; 3],

    /// PaymentEscrow funding ongoing pinning fees.
    pub escrow: Pubkey,

    /// Unix timestamp when the content was first pinned.
    pub pinned_at: i64,

    /// Unix timestamp after which the pin expires if escrow is depleted.
    pub expires_at: i64,

    /// Current pin status.
    /// Active:  content is pinned and available.
    /// Expired: escrow depleted, in grace period.
    /// Removed: unpinned, content may be garbage-collected.
    pub status: PinStatus,

    /// PDA bump seed.
    pub bump: u8,
}
```

### 3.3 Instructions

#### `register_node`

Registers a new node operator in the on-chain registry. Creates a `NodeRecord` PDA and transfers the staked SOL to a stake escrow PDA.

* **Signers**: operator wallet

* **Accounts**: NodeRecord (init), stake escrow PDA (init), system program

* **Args**: `endpoint: String`, `capacity: u8`, `ipfs_enabled: bool`

* **Constraints**: stake >= 1 SOL (1_000_000_000 lamports), endpoint.len() <= 256, capacity >= 1

The node becomes `Active` immediately and can begin receiving instance allocations after its first heartbeat.

#### `deregister_node`

Removes a node from the active registry. The node must have zero active instances (all instances must be migrated or terminated first). Stake enters a 7-day unbonding period, after which the operator can reclaim it via a separate `claim_stake` instruction.

* **Signers**: operator wallet

* **Accounts**: NodeRecord (mut), stake escrow PDA

* **Constraints**: `active_instances == 0`, status == Active

The unbonding period prevents operators from rapidly withdrawing stake to avoid slashing after misbehavior is detected but before the slash transaction lands.

#### `heartbeat`

Nodes call this every 60 seconds to signal liveness. Each successful heartbeat updates `last_heartbeat` and increments `uptime_score` by 1. Nodes that miss 60 consecutive heartbeats (1 hour) are automatically marked `Inactive` by subsequent protocol interactions.

* **Signers**: operator wallet

* **Accounts**: NodeRecord (mut)

* **Constraints**: node status == Active

Heartbeats are cheap transactions (~5000 lamports) designed to be sustainable at high frequency. The uptime score accumulates indefinitely, providing a long-term reputation signal.

#### `allocate_instance`

Assigns a Supabase instance to an agent on a specific node. Creates the `InstanceRecord` and `PaymentEscrow` PDAs. The agent provides the encrypted DEK and an initial USDC deposit.

* **Signers**: agent wallet

* **Accounts**: InstanceRecord (init), PaymentEscrow (init), NodeRecord (mut), agent's USDC token account, escrow USDC token account, token program

* **Args**: `encrypted_dek: [u8; 64]`, `replica_count: u8` (1-3)

* **Constraints**: initial deposit >= 1 hour of hosting at the node's rate, node has available capacity, node status == Active

The instruction increments the primary node's `active_instances` counter. Replica node assignments are included in the instruction; the gateway pre-selects replicas based on the placement algorithm.

#### `deposit_payment`

Adds USDC to an existing instance's escrow, extending its lifetime. Can be called at any time by the instance's agent.

* **Signers**: agent wallet

* **Accounts**: PaymentEscrow (mut), agent's USDC token account, escrow USDC token account, token program

* **Args**: `amount: u64`

* **Constraints**: agent == escrow.agent, amount > 0

#### `distribute_payment`

Permissionless crank instruction that distributes accrued USDC from the escrow to node operators. Can be called by anyone — typically operators or a bot. Distributes proportionally: 70% to primary node, 15% to each of up to two replicas.

* **Signers**: any (permissionless)

* **Accounts**: PaymentEscrow (mut), InstanceRecord, primary node's USDC token account, replica nodes' USDC token accounts, token program

* **Constraints**: `Clock::get().unix_timestamp - escrow.last_distribution >= 3600` (1 hour minimum between distributions)

The distribution amount is calculated as: `(hours_elapsed * rate_per_hour)`, capped at the remaining escrow balance. If the balance reaches zero, the instance status is set to `Suspended`.

#### `commit_merkle_root`

The primary node commits a Merkle root representing the current database state, along with the WAL hash chain head and segment count. This is the integrity anchor.

* **Signers**: primary node operator wallet

* **Accounts**: InstanceRecord (mut)

* **Args**: `merkle_root: [u8; 32]`, `wal_hash_head: [u8; 32]`, `wal_segment_count: u64`

* **Constraints**: caller authority == instance.primary_node, instance status == Active

Commitments are expected every 10 minutes or every 1000 transactions, whichever comes first. The on-chain data provides a verifiable anchor: anyone can request a Merkle proof for any row and check it against the committed root.

#### `slash_node`

Penalizes a misbehaving node. Requires a fraud proof — verifiable evidence of misbehavior. The slashed stake is split: 50% burned (sent to a dead address), 50% paid to the reporter as a bounty.

* **Signers**: reporter wallet

* **Accounts**: NodeRecord (mut), stake escrow PDA, reporter wallet, slashing proof account (contains evidence)

* **Args**: `proof_type: SlashProofType`, `proof_data: Vec<u8>`

**SlashProofType variants:**

| Variant          | Description                                                                                                                                                                                            | Slash % |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| `Downtime`       | Node missed heartbeats for >1 hour. Verifiable on-chain by comparing `last_heartbeat` to current timestamp.                                                                                            | 10%     |
| `DataCorruption` | Merkle proof submitted by agent does not match on-chain Merkle root. The proof_data contains the row, the Merkle path, and the expected root. The program recomputes the root and checks for mismatch. | 50%     |
| `WalChainBreak`  | WAL hash chain discontinuity. The proof_data contains two consecutive hash chain entries where `H(n) != SHA-256(wal_n \|\| H(n-1))`.                                                                   | 50%     |

After slashing, the node's status is set to `Slashed` and its `slashing_events` counter increments. The node must restake (at minimum the original stake amount) to reactivate.

***

## 4. Network Architecture

### 4.1 Network Topology

```text
                          +-------------------------------------+
                          |          Solana Blockchain           |
                          |  +-------------+ +----------------+ |
                          |  | Node        | | Instance       | |
                          |  | Registry    | | Records        | |
                          |  +-------------+ +----------------+ |
                          |  +-------------+ +----------------+ |
                          |  | Payment     | | Merkle         | |
                          |  | Escrows     | | Commitments    | |
                          |  +-------------+ +----------------+ |
                          +----------------+--------------------+
                                           |
                    +----------------------+---------------------+
                    |                      |                     |
              +-----v------+       +------v------+       +------v------+
              |  Node A     |       |  Node B     |       |  Node C     |
              | +---------+ |       | +---------+ |       | +---------+ |
              | |Supabase | |       | |Supabase | |       | |Supabase | |
              | |Stack 1  | |       | |Stack 3  | |       | |Stack 5  | |
              | +---------+ |       | +---------+ |       | +---------+ |
              | |Supabase | |       | |Supabase | |       | |  IPFS   | |
              | |Stack 2  | |       | |Stack 4  | |       | | Daemon  | |
              | +---------+ |       | +---------+ |       | +---------+ |
              | |  IPFS   | |       | |  IPFS   | |       +-------------+
              | | Daemon  | |       | | Daemon  | |
              | +---------+ |       | +---------+ |
              +------^------+       +-------------+
                     |
              +------+------+
              |  AI Agent   |
              | (Solana     |
              |  Wallet)    |
              +-------------+
```

### 4.2 Permissionless Node Operators

Anyone can operate a Kraph node, provided the hardware supports confidential computing. Nodes **must** run on AMD SEV-SNP or Intel TDX capable hardware — every Supabase instance executes inside a confidential VM with hardware-encrypted memory, ensuring node operators cannot read user data even with host root access. The process is:

1. Install the Kraph node software (a single binary that manages Docker) on SEV-SNP or TDX capable hardware.

2. Run `supaba-node init` which generates a node keypair, verifies TEE capability, and creates a configuration file.

3. Stake a minimum of 1 SOL by calling `register_node` on-chain.

4. The node software starts, begins sending heartbeats every 60 seconds, generates an initial TEE attestation report, and advertises its capacity.

5. The node begins receiving instance allocation requests from the gateway.

There is no approval process, no KYC, no application form. The stake serves as a Sybil resistance mechanism and as collateral for slashing. The higher the stake, the more instances the placement algorithm directs to the node. The TEE hardware requirement ensures that user-generated content is protected from node operators at the hardware level — this is a non-negotiable requirement, not an optional enhancement.

**Supported platforms:** Azure DCasv5/ECesv5 (SEV-SNP), GCP N2D/C3 Confidential VMs (SEV-SNP), AWS M6a/R6a (SEV-SNP), and any bare-metal provider with AMD EPYC (Milan/Genoa) or Intel Xeon (Sapphire Rapids+) processors with TDX support.

### 4.3 Instance-Per-Node Model

Kraph uses an **instance-per-node** model: each Supabase instance runs entirely on a single physical node. Data is not sharded across multiple nodes.

**Why not data sharding?**

This is a deliberate trade-off, and we are transparent about the reasoning:

1. **Supabase is a multi-service stack, not a single database.** Sharding Postgres across nodes would require a distributed query layer (like Citus), but the other services — GoTrue, Realtime, Storage, Studio, Analytics — all assume a single Postgres instance. They connect via localhost or internal Docker networking. Re-architecting these services for distributed operation would be a multi-year effort with uncertain reliability outcomes.

2. **Agent databases are small.** A typical agent manages kilobytes to low gigabytes of state. Horizontal scaling within a single instance is not the bottleneck. The network scales horizontally by placing different instances on different nodes — not by sharding individual instances across nodes.

3. **Complexity kills reliability.** Distributed databases introduce complex failure modes: split-brain, partial commits, cross-shard transactions, distributed deadlocks. A single-node Postgres with WAL replication to standby nodes provides a simpler, better-understood reliability model that operators can reason about.

4. **Latency.** Cross-node queries add network round trips. Agent workloads — small, frequent, low-latency reads and writes — benefit from local-disk Postgres performance.

**The trade-off:** A single node is a single point of failure for a given instance. We mitigate this with encrypted WAL replication (Section 4.5) and automated recovery, accepting a brief outage window during failover rather than the ongoing complexity of distributed consensus.

### 4.4 Instance Stack

Each provisioned instance is a full Supabase Docker Compose deployment:

```text
+===================================================================+
|              Confidential VM (AMD SEV-SNP / Intel TDX)            |
| +---------------------------------------------------------------+ |
| |                      Instance Namespace                        | |
| |                                                                | |
| | +----------+ +----------+ +----------+ +----------+ +-------+ | |
| | | Postgres | | PostgREST| |  GoTrue  | | Realtime | | Edge  | | |
| | |  15.x    | |   12.x   | |   2.x    | |   2.x    | |Runtime| | |
| | +----+-----+ +-----+----+ +----+-----+ +----+-----+ +--+----+ | |
| |      |              |           |             |          |      | |
| | +----v--------------v-----------v-------------v----------v---+ | |
| | |                     Kong API Gateway                       | | |
| | |      /rest/v1/*   /auth/v1/*  /realtime/*  /functions/v1/* | | |
| | +------------------------------------------------------------+ | |
| |                                                                | |
| | +----------+  +-----------+  +--------------------+            | |
| | | Storage  |  |  Studio   |  | Analytics          |            | |
| | | (S3-API) |  | (Web UI)  |  | (Logflare)         |            | |
| | +----------+  +-----------+  +--------------------+            | |
| |                                                                | |
| | +------------------------------------------------------------+ | |
| | |                 PgBouncer (transaction mode)               | | |
| | +------------------------------------------------------------+ | |
| +---------------------------------------------------------------+ |
+===================================================================+
```

Each instance runs in an isolated Docker network. Port mapping ensures no collisions between instances on the same node. Resource limits (CPU, memory, disk I/O) are enforced via Docker's cgroup integration. No cross-instance communication is possible at the container level.

### 4.5 Encrypted WAL Replication

Write-Ahead Log (WAL) segments from the primary Postgres are:

1. **Hashed** into the WAL hash chain (Section 6.1) for tamper detection.

2. **Encrypted** using AES-256-GCM with the instance's DEK (Section 7.4) in streaming 64KB chunks.

3. **Streamed** to 2-3 replica nodes selected during instance allocation.

4. **Stored** on replica nodes' local storage as opaque encrypted blobs.

Replicas cannot decrypt the WAL — they do not hold the DEK. They serve purely as encrypted backup storage. If the primary node fails:

1. The gateway detects the failure via missed heartbeats (within 60 seconds).

2. A new primary is selected from the replica set based on WAL completeness.

3. The agent provides the DEK to the new primary via attestation-gated KBS (re-derived from their Solana keypair, released only after verifying the new primary's TEE attestation report).

4. The new primary — running inside a confidential VM — decrypts the WAL segments, replays them into a fresh Postgres instance, and resumes service.

5. The on-chain `InstanceRecord` is updated to reflect the new primary.

Recovery time depends on WAL volume but is typically under 60 seconds for databases under 1 GB. During recovery, the instance is unavailable. We do not offer zero-downtime failover in the current design — this would require hot standby replicas holding the DEK, which conflicts with the goal of minimizing DEK exposure.

### 4.6 Node Discovery and Placement

Agents discover available nodes via the on-chain `NodeRecord` registry. The gateway (or agent directly) selects a node using a weighted scoring algorithm:

```text
score(node) = 0.4 * capacity_score
            + 0.3 * uptime_score
            + 0.2 * stake_score
            + 0.1 * jitter

Where:
    capacity_score = (node.capacity - node.active_instances) / node.capacity
    uptime_score   = node.uptime_score / max_uptime_in_registry
    stake_score    = node.stake_amount / max_stake_in_registry
    jitter         = random(0.0, 1.0)  // uniform random
```

**Rationale for each weight:**

* **Capacity (0.4):** Highest weight because placing instances on overloaded nodes directly harms performance. Available capacity is the primary selection criterion.

* **Uptime (0.3):** A node's historical reliability — measured by cumulative heartbeats — is the best predictor of future reliability. Long-running nodes with high uptime scores are preferred over newcomers.

* **Stake (0.2):** Higher stake means more economic skin in the game. The operator has more to lose from misbehavior, aligning incentives with honest operation.

* **Jitter (0.1):** Randomness prevents deterministic placement (which would enable targeted attacks on specific nodes) and distributes load across nodes with similar scores. Without jitter, nodes with identical scores would always receive allocations in the same order.

Replica nodes are selected from different physical locations when possible. Nodes self-report their region; geographic claims can be partially corroborated via TEE attestation reports (which include platform identifiers) and latency-based verification. The gateway applies a diversity heuristic: prefer replicas whose reported regions differ from the primary's.

***

## 5. Authentication

### 5.1 Sign-In with Solana (SIWS)

The primary authentication method for agents that hold their own Solana keypair. The protocol follows the Sign-In with Solana specification.

```text
+-------------+                              +--------------+
|   Agent     |                              | Kraph Node  |
|  (Solana    |                              |  / Gateway   |
|   Wallet)   |                              |              |
+------+------+                              +------+-------+
       |                                            |
       |  1. GET /auth/challenge                    |
       +------------------------------------------->|
       |                                            |
       |  2. { nonce: "a9f3b1...",                  |
       |       domain: "kraph.network",            |
       |       issued_at: "2026-04-06T12:00:00Z",  |
       |       expiration: "2026-04-06T12:05:00Z" } |
       |<-------------------------------------------+
       |                                            |
       |  3. Construct SIWS message:                |
       |     "kraph.network wants you to sign      |
       |      in with your Solana account:          |
       |      <base58_pubkey>                       |
       |                                            |
       |      Nonce: a9f3b1...                      |
       |      Issued At: 2026-04-06T12:00:00Z      |
       |      Expiration: 2026-04-06T12:05:00Z"    |
       |                                            |
       |  4. Sign message with ed25519 private key  |
       |                                            |
       |  5. POST /auth/verify                      |
       |     { pubkey, signature, message }         |
       +------------------------------------------->|
       |                                            |
       |  6. Verify:                                |
       |     - ed25519 signature matches pubkey     |
       |     - Nonce not replayed (check cache)     |
       |     - Not expired                          |
       |     - Domain matches                       |
       |                                            |
       |  7. { session_token: "eyJ...",             |
       |       expires_in: 86400 }                  |
       |<-------------------------------------------+
       |                                            |
```

The session token is a JWT containing:

* `sub`: agent's base58-encoded public key

* `iat`: issued-at timestamp

* `exp`: expiration timestamp (24 hours from issuance)

* `iss`: "kraph.network"

The token is used in the `Authorization: Bearer <token>` header for all subsequent API calls. Sessions are renewable: the agent can re-authenticate before expiration to obtain a new token without interrupting ongoing operations.

The nonce is a 32-byte random value generated per challenge request. The server stores active nonces in a short-lived cache (5-minute TTL) and rejects any nonce that has been used or has expired. This prevents replay attacks where an attacker intercepts a valid signature and attempts to reuse it.

### 5.2 Privy Integration (Custodial Server Wallets)

Not all agents run in environments with direct access to a Solana keypair. Agents running on managed cloud platforms, inside containerized environments, or as part of multi-agent orchestration systems may not have convenient access to private key material. For these agents, Kraph integrates with Privy server wallets.

The flow:

1. The agent authenticates with Privy using a supported method (API key, delegated auth).

2. Privy provisions or retrieves a custodial Solana wallet for the agent.

3. When the agent calls a Kraph MCP tool, the Kraph client requests a SIWS challenge and asks Privy to sign it using the agent's server wallet.

4. Privy signs the challenge message on the agent's behalf (using MPC-based key shares — no single party holds the full private key).

5. The signed challenge is submitted to Kraph for verification.

6. From the Kraph protocol's perspective, the session identity is the wallet's public key — indistinguishable from a self-custodied wallet.

This provides an onboarding path that does not require the agent to manage raw private key bytes, while maintaining the same on-chain identity model.

### 5.3 Unified Identity

Both authentication paths produce the same identity: a Solana public key (ed25519, 32 bytes, base58-encoded). All on-chain records (`InstanceRecord`, `PaymentEscrow`, `PinRecord`) reference this pubkey as the `agent` field. There is no separate user table, no email, no username, no password. Identity is the cryptographic key.

This simplification is intentional. Agents do not have emails. They do not have names. They have keypairs. The protocol's identity model reflects this.

### 5.4 MCP Transport

Kraph exposes its functionality through the Model Context Protocol (MCP), supporting two transports:

**stdio (local):** The MCP server runs as a local child process spawned by the agent. Communication occurs over stdin/stdout using JSON-RPC 2.0. Used when the agent and Kraph client run on the same machine. Authentication credentials (Solana private key or Privy API key) are passed via environment variables (`SUPABA_PRIVATE_KEY`, `SUPABA_PRIVY_APP_ID`, etc.).

**StreamableHTTP (remote):** The MCP server is accessed over HTTPS. The agent sends JSON-RPC requests to the gateway's `/mcp` endpoint, authenticated via the SIWS session token in the `Authorization` header. Used when the agent connects to a remote Kraph gateway from a different machine or cloud environment.

Both transports expose the identical set of MCP tools (Section 12). The transport is a deployment detail, not a protocol difference.

***

## 6. Security Model — 4-Layer Integrity + TEE Foundation

The fundamental challenge of decentralized databases is trust. The agent sends queries to a node operator who controls the hardware. The operator can modify the database, drop writes, fabricate responses, or selectively omit data. The agent has no physical access to the machine and cannot directly verify what the node is doing. Critically, user-generated content (UGC) stored in the database is visible to anyone who can read process memory — and without hardware isolation, that includes the node operator.

Kraph addresses this with a TEE foundation layer plus four layers of integrity enforcement. The TEE layer eliminates the confidentiality gap from day one: every Supabase instance runs inside a confidential VM with hardware-encrypted memory. The integrity layers compound on top, ensuring that the cost of undetected cheating exceeds any rational benefit.

```text
+---------------------------------------------------------------+
|                 4-Layer Integrity Stack + TEE                  |
|                                                               |
|  Layer 3: Cross-Replica Verification                          |
|  +---------------------------------------------------------+  |
|  | Spot-check queries against replicas. Detects persistent  |  |
|  | fabrication by the primary node.                         |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  Layer 2: Merkle State Commitments                            |
|  +---------------------------------------------------------+  |
|  | On-chain Merkle root. Any row verifiable via proof.      |  |
|  | Inconsistency = provable fraud = slash.                  |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  Layer 1: WAL Hash Chain                                      |
|  +---------------------------------------------------------+  |
|  | Append-only WAL history. Retroactive modification        |  |
|  | breaks the chain. Detectable by replicas.                |  |
|  +---------------------------------------------------------+  |
|                                                               |
|  Layer 0: TEE Confidential VM (foundation)                    |
|  +---------------------------------------------------------+  |
|  | Hardware-enforced: node operator cannot read VM memory   |  |
|  | even with host root access. AMD SEV-SNP / Intel TDX.    |  |
|  | DEK delivered via attestation-gated Key Broker Service.  |  |
|  +---------------------------------------------------------+  |
+---------------------------------------------------------------+
```

### 6.1 Layer 0: TEE Confidential VM (Foundation)

Every Supabase instance in the Kraph network runs inside a **confidential VM** powered by AMD SEV-SNP or Intel TDX. This is not an optional future enhancement — it is a core requirement from Phase 1. The rationale is simple: user-generated content can be stolen by node operators if it is visible to them, and no amount of after-the-fact detection can undo a data leak.

**How it works:**

1. Each Supabase instance runs inside a confidential VM where the entire VM memory is hardware-encrypted using AES-XTS. The encryption key is managed by the CPU's secure processor (AMD Platform Security Processor or Intel TDX module) and is inaccessible to the host operating system, hypervisor, or node operator.

2. The node operator has host root access but **cannot read confidential VM memory**. Memory reads from outside the VM return ciphertext. Cold-boot attacks, DMA attacks, and hypervisor-level memory introspection are all defeated by the hardware encryption.

3. The DEK is no longer transmitted in plaintext over TLS. Instead, it is released via an **attestation-gated Key Broker Service (KBS)**:

   1. Agent generates a random nonce challenge.
   2. The node's confidential VM generates a hardware attestation report, signed by the AMD PSP or Intel TDX module.
   3. The report includes: VM measurement (SHA-384 hash of firmware + kernel + initrd), the agent's nonce, and application-specific report data.
   4. The agent verifies the report signature against the AMD/Intel certificate chain (rooted in the chip manufacturer's root of trust).
   5. The agent verifies the VM measurement matches the expected Kraph image hash (published on-chain and auditable by the community).
   6. If valid, the agent releases the DEK via KBS. The DEK only ever exists inside the confidential VM's encrypted memory.

4. Agents can re-verify TEE attestation at any time via the `kraph_attest` MCP tool, providing ongoing assurance that the instance is still running inside a genuine confidential VM with the expected software.

**Performance overhead:** AMD SEV-SNP and Intel TDX impose a 2-8% overhead on Postgres workloads, primarily from AES-XTS memory encryption. This is negligible on modern hardware with dedicated AES-NI acceleration and is far outweighed by the security benefit.

**What this achieves:** The trust model for data confidentiality moves from "detect and punish after the fact" to "prevent at the hardware level." Node operators are reduced to providing electricity, bandwidth, and hardware. They cannot read user data, extract encryption keys, or inspect database contents — the CPU hardware enforces this, not software or policy.

### 6.2 Layer 1: WAL Hash Chain

Every Postgres WAL segment is hashed as it is produced. Each hash incorporates the previous hash, forming a cryptographic chain:

```text
hash_0 = SHA-256(wal_segment_0)
hash_1 = SHA-256(wal_segment_1 || hash_0)
hash_2 = SHA-256(wal_segment_2 || hash_1)
...
hash_n = SHA-256(wal_segment_n || hash_{n-1})
```

The chain head (`hash_n`) is periodically committed on-chain via `commit_merkle_root` (the instruction stores both the Merkle root and the WAL hash head). This provides three properties:

**Append-only guarantee.** Modifying any historical WAL segment changes its hash, which invalidates every subsequent hash in the chain. The break is detectable by anyone holding a copy of the WAL — specifically, the replica nodes that store encrypted WAL segments.

**Ordering proof.** The chain proves that WAL segments were produced in a specific sequential order. A node cannot reorder operations retroactively.

**Tamper detection.** If a node retroactively modifies data and regenerates WAL segments to cover its tracks, the resulting hash chain diverges from the on-chain commitment. The divergence is permanent and cryptographically provable.

**What this does not catch:** A node that produces a valid but *fabricated* WAL chain from scratch — i.e., a node that never applied certain writes in the first place. The WAL chain proves consistency of history, not correctness of the history. Layer 2 addresses correctness.

### 6.3 Layer 2: Merkle State Commitments

Periodically (every 10 minutes or every 1000 transactions, whichever comes first), the primary node computes a Merkle tree over the current database state and commits the root hash on-chain.

**Tree construction:**

```text
                         Merkle Root (32 bytes)
                        /                      \
                  Hash(AB)                    Hash(CD)
                 /        \                  /        \
           Hash(A)      Hash(B)        Hash(C)      Hash(D)
             |            |              |            |
          Leaf A       Leaf B         Leaf C       Leaf D

Where each leaf = SHA-256(
    canonical_serialize(table_name, primary_key_columns, row_data)
)
```

Row data is serialized in a **canonical format**: column names are sorted lexicographically, values are encoded in a deterministic binary format (matching Postgres's binary output for each type), and the table name and primary key are prefixed. This ensures that the same logical row always produces the same leaf hash, regardless of physical storage order, column definition order, or TOAST compression.

**Verification flow:**

1. The agent queries a row from the primary node.

2. The agent requests a Merkle proof for that row: `GET /verify?table=tasks&pk=d4e5f6...`

3. The node returns: the leaf hash, and the sibling hashes along the path from the leaf to the root.

4. The agent recomputes the root by hashing up the tree:

```text
computed_leaf = SHA-256(canonical_serialize(table, pk, row_data))
computed_parent = SHA-256(computed_leaf || sibling_1)
...continue to root...
```

1. The agent compares the computed root against the on-chain `merkle_root` in the `InstanceRecord`.

2. **Match:** The row is consistent with the committed state.

3. **Mismatch:** The node is provably dishonest. The agent submits the proof to `slash_node`.

**What this catches:** A node that returns fabricated query results. If the node commits a Merkle root matching its actual state but then lies about individual rows, the Merkle proof reveals the lie. If the node commits a Merkle root matching fabricated state, cross-replica verification (Layer 3) catches the discrepancy.

**Limitation:** Merkle commitments are periodic, not per-query. Data modified between commitment intervals cannot be verified against the on-chain root until the next commitment. The 10-minute window is a configurable trade-off between security granularity and Solana transaction costs (~$0.002 per commitment).

### 6.4 Layer 3: Cross-Replica Verification

The network performs periodic spot-check queries against both the primary and replica nodes to detect persistent fabrication:

```text
  Verifier               Primary Node              Replica Node
     |                        |                          |
     |  1. Select random      |                          |
     |     row from schema    |                          |
     |                        |                          |
     |  2. Query row + proof  |                          |
     +----------------------->|                          |
     |                        |                          |
     |  3. {row, merkle_proof}|                          |
     |<-----------------------+                          |
     |                        |                          |
     |  4. Request WAL replay |                          |
     |     for this row       |                          |
     +----------------------------------------------->  |
     |                        |                          |
     |  5. Decrypt WAL with   |                          |
     |     agent-provided DEK |                          |
     |     Replay to derive   |                          |
     |     expected row state  |                          |
     |                        |                          |
     |  6. {expected_row}     |                          |
     |<------------------------------------------------  |
     |                        |                          |
     |  7. Compare primary    |                          |
     |     result vs. replica |                          |
     |     result             |                          |
     |                        |                          |
     |  If divergent:         |                          |
     |     Submit fraud proof |                          |
     |     to slash_node      |                          |
```

**Frequency:** Spot checks run every 5 minutes per instance, with the checked row selected uniformly at random from the table. The statistical guarantee: for a node that fabricates P% of rows, the probability of detection within N checks is 1 - (1-P)^N. At 12 checks per hour, a node fabricating even 1% of rows has a 93% detection probability within 24 hours.

**Who verifies:** The verifier can be the gateway, the agent itself, or any third-party auditor. Verification requires the agent's cooperation — specifically, the DEK — to decrypt WAL on the replica. The agent can delegate verification to the gateway by providing a time-limited, scope-limited DEK derivation (a sub-key valid only for read-only WAL replay on a specific replica, expiring after a set duration).

**What this catches:** A colluding primary node that commits Merkle roots matching fabricated state. Since the replica's WAL was encrypted and streamed independently, the replica's replayed state reflects the actual writes. Any divergence between the primary's response and the replica's replayed state constitutes fraud.

**Limitation:** Requires agent cooperation (DEK access). With TEE (Layer 0), the DEK is sealed inside the confidential VM, and the agent can delegate scoped verification keys without exposing the primary DEK to any party outside the enclave.

### 6.5 Layer Interactions

The four layers plus TEE foundation interact synergistically:

* **Layer 0 (TEE)** provides confidentiality — the operator cannot *read* data. This is the foundational guarantee that makes UGC safe on untrusted hardware.

* **Layer 1 (WAL hash chain)** provides ordering and tamper detection — the operator cannot *rewrite history* without breaking the chain.

* **Layer 2 (Merkle commitments)** provides state correctness — the operator cannot *lie about current state* without a cryptographically provable discrepancy.

* **Layer 3 (Cross-replica verification)** provides independent corroboration — the operator cannot *fabricate a consistent lie* across independent replicas.

Together, the layers ensure: the operator cannot see data (Layer 0), cannot rewrite the past (Layer 1), cannot lie about the present (Layer 2), and cannot collude to fabricate a consistent alternate reality (Layer 3).

### 6.6 IPFS Content Integrity

IPFS content is inherently content-addressed: the CID (Content Identifier) is a cryptographic hash of the content. If a node attempts to serve data that does not match the CID, the client detects the mismatch immediately by rehashing the received content. No additional integrity mechanism is needed for IPFS reads.

The relevant threat for IPFS is *availability*, not *integrity*. A node could refuse to serve pinned content (or go offline). This is addressed by:

* Pinning each CID on 3 nodes by default.

* Monitoring pin node availability via the gateway.

* Re-pinning on replacement nodes when a pin node goes offline.

* Leveraging the global IPFS DHT: any IPFS node that has cached the content can serve it, not just Kraph pin nodes.

### 6.6 Trust Boundary: The Gateway Is Not in Layer 0

The four-layer integrity stack and the TEE foundation protect *node-side* operations: a node operator cannot read VM memory, fabricate query results undetected, or modify history without breaking the WAL hash chain. The gateway is a separate trust boundary. It sits between the agent and the node, holds delegated signing keys for OAuth-authenticated wallets, and currently runs on a non-TEE host. A compromise of the gateway does not break Layer 0 (replicas remain encrypted; node TEE memory remains hardware-isolated), but it does open paths to deploy hostile code, read plaintext env vars, and execute SQL on any instance that authenticates through it. Section 12.8 enumerates the attack and the six-step mitigation plan: per-call ed25519 signatures verified at the node (partial — shipped), Privy authorization-key policy (done), TEE the gateway (planned), end-to-end client-side encryption (planned), capability tokens (planned), two-process auth/exec split (planned).

***

## 7. Encryption

### 7.1 Key Derivation

The agent's Solana keypair is the root of all cryptographic material. The derivation chain ensures the agent can always recover its encryption keys using only the Solana private key:

```text
Solana ed25519 private key (64 bytes: 32-byte scalar + 32-byte public key)
        |
        v
  ed25519-to-x25519 conversion
  (Extract the 32-byte scalar, clamp per RFC 7748, use as x25519 private key.
   This is a one-way derivation using libsodium's
   crypto_sign_ed25519_sk_to_curve25519.)
        |
        v
  x25519 private key (32 bytes)
        |
        v
  HKDF-SHA256
  (ikm  = x25519 private key,
   salt = "supaba-master-key-v1" (20 bytes, ASCII),
   info = instance_id (32 bytes),
   len  = 32 bytes)
        |
        v
  Master Key (256-bit, unique per instance)
        |
        v
  AES-256-GCM Decrypt of encrypted_dek
  (key   = master key,
   nonce = first 12 bytes of instance_id,
   ct    = InstanceRecord.encrypted_dek)
        |
        v
  DEK (256-bit, random, unique per instance)
```

The ed25519-to-x25519 conversion is necessary because ed25519 keys are signing keys, not encryption keys. The x25519 key is used solely as input keying material (IKM) for HKDF — it never directly encrypts data.

The HKDF `info` parameter includes the `instance_id`, ensuring each instance derives a distinct master key. An agent with 10 instances has 10 different master keys, all derived from the same Solana keypair.

### 7.2 Envelope Encryption

Each Supabase instance has its own Data Encryption Key (DEK), following the envelope encryption pattern:

1. **DEK generation:** A random 256-bit key is generated during instance provisioning. The generating party can be the agent (if running locally) or the node (if the agent trusts the node during provisioning). In either case, the DEK is immediately encrypted with the master key.

2. **DEK encryption:** The DEK is encrypted using AES-256-GCM with the instance-specific master key. The nonce is the first 12 bytes of the instance_id (deterministic, but unique per instance since instance_ids are unique).

3. **DEK storage:** The 64-byte encrypted DEK (ciphertext + GCM tag) is stored in the `InstanceRecord.encrypted_dek` field on-chain. This means the encrypted DEK is globally available, permanently — but useless without the master key, which only the agent can derive.

4. **DEK transmission via attestation-gated KBS:** During provisioning, the agent derives the master key and decrypts the DEK. Instead of transmitting the plaintext DEK over TLS (where the node operator could intercept it), the agent verifies the node's TEE attestation report and releases the DEK via the Key Broker Service (KBS). The KBS only releases the DEK after confirming: (a) the destination is a genuine confidential VM, (b) the VM measurement matches the expected Kraph image, and (c) the attestation is fresh (nonce-verified). The DEK is delivered directly into the confidential VM's encrypted memory and never exists in plaintext on the host.

Envelope encryption provides three critical properties:

* **Recovery without third parties.** If a node is destroyed, the agent can recover the DEK from the on-chain record using only their Solana keypair. No key escrow service, no backup password, no recovery email.

* **Key rotation without re-provisioning.** To rotate the DEK: generate a new random DEK, re-encrypt all data, encrypt the new DEK with the master key, and update the on-chain record.

* **Hardware-enforced confidentiality.** The DEK only exists inside TEE-encrypted memory. The node operator cannot extract it via memory dumps, debuggers, or hypervisor introspection.

### 7.3 At-Rest Encryption

**Phase 1 (pgcrypto):**

In the initial release, at-rest encryption uses Postgres's `pgcrypto` extension:

* The DEK is used as a symmetric key for `pgp_sym_encrypt` / `pgp_sym_decrypt`.

* Sensitive columns are encrypted at the application layer (PostgREST middleware).

* This provides column-level encryption transparent to the agent.

* **Trade-off:** Not all data is encrypted. Indexes, pg_catalog, WAL on disk, and temp files remain plaintext. The operator with disk access can see table structure and unencrypted columns.

**Phase 2+ (LUKS/dm-crypt):**

Full-volume encryption of the instance's Docker storage:

* Each instance's Docker data directory is a LUKS-encrypted block device.

* The DEK serves as the LUKS passphrase, passed to `cryptsetup luksOpen` at instance startup.

* All Postgres data files, indexes, WAL, temp files, and system catalogs are encrypted.

* The node operator cannot read any instance data without the DEK, even with root access to the host filesystem.

* **Performance impact:** AES-NI hardware acceleration makes dm-crypt overhead negligible (<5% on modern hardware).

### 7.4 WAL Encryption

WAL segments are encrypted before replication to ensure replica nodes cannot read the data they store:

```text
For each WAL segment (default 16 MB):
    Split into 64 KB chunks (256 chunks per segment)

    For each chunk i in segment s:
        nonce = i (8 bytes, little-endian) || s (4 bytes, little-endian)
        encrypted_chunk = AES-256-GCM-Encrypt(
            key       = DEK,
            nonce     = nonce (12 bytes),
            plaintext = chunk,
            aad       = segment_number || chunk_index   // additional authenticated data
        )
        output: [nonce (12 bytes) || ciphertext || tag (16 bytes)]

    Encrypted segment = concatenation of all encrypted chunks
    Segment header: [magic (4 bytes) || version (2 bytes) || chunk_count (2 bytes)]
```

**Design rationale:**

* **64 KB chunks:** Small enough to stream without buffering an entire 16 MB segment in memory. Large enough to amortize AES-GCM's per-invocation overhead (~0.1ms per chunk on modern hardware with AES-NI).

* **Counter-based nonces:** The combination of chunk index (8 bytes) and segment number (4 bytes) guarantees nonce uniqueness across all chunks in all segments. Nonce reuse under AES-GCM is catastrophic (enables key recovery); this scheme makes it structurally impossible.

* **Per-chunk authentication:** Each chunk's GCM tag independently authenticates that chunk. A corrupted or tampered chunk is detected immediately upon decryption, without needing to process the entire segment.

* **Additional authenticated data (AAD):** The segment number and chunk index are included as AAD, binding each encrypted chunk to its position. This prevents a reordering attack where an adversary swaps chunks between positions.

### 7.5 Eliminating the Trust Gap with TEE

In traditional managed database services, the provider has access to your data in memory:

* AWS RDS: Amazon's infrastructure has access to your data in memory.

* Supabase Cloud: Supabase's infrastructure has access to your data in memory.

* PlanetScale: Vitess nodes hold your data in plaintext.

Kraph eliminates this trust gap from day one by requiring all instances to run inside confidential VMs. The DEK exists in plaintext only inside the TEE-encrypted memory space, which the node operator cannot read even with host root access. The key properties:

1. **Hardware-enforced confidentiality:** The DEK and all decrypted data exist only inside the confidential VM's encrypted memory. The CPU's secure processor (AMD PSP / Intel TDX module) enforces this — it is not a software policy that can be bypassed.

2. **Scope:** Each instance has an independent DEK inside its own confidential VM. Compromising the host gains access to zero instances, not all of them.

3. **Detection:** Layers 1-3 of the security model detect data tampering. TEE (Layer 0) prevents data *reading*. Together, they provide both confidentiality and integrity.

4. **Attestation continuity:** The agent can re-verify TEE attestation at any time via `kraph_attest`, confirming the instance is still running inside a genuine confidential VM with the expected software measurement.

Kraph provides data confidentiality, data integrity, and data durability from Phase 1. The operator cannot read your data (TEE), cannot modify your data without detection (Layers 1-3), and your data survives node failures (encrypted WAL replication).

***

## 8. Payment Protocol

### 8.1 x402: HTTP-Native Payments

Kraph uses the x402 protocol for per-request payments. x402 repurposes the HTTP 402 ("Payment Required") status code — defined in HTTP/1.1 but historically unused — as a machine-readable payment negotiation mechanism.

```text
+-----------+                                +--------------+
|   Agent   |                                | Kraph Node  |
+-----------+                                +--------------+
      |                                             |
      |  1. POST /rest/v1/todos                     |
      |     (no payment header)                     |
      +-------------------------------------------->|
      |                                             |
      |  2. HTTP 402 Payment Required               |
      |     X-Payment-Required: {                   |
      |       "scheme": "exact",                    |
      |       "network": "solana-mainnet",          |
      |       "amount": "1000",                     |
      |       "asset": "<USDC_mint_address>",       |
      |       "recipient": "<node_usdc_address>",   |
      |       "facilitator": "<local_facilitator>", |
      |       "expiry": 1712410000                  |
      |     }                                       |
      |<--------------------------------------------+
      |                                             |
      |  3. Agent's x402 client:                    |
      |     - Parse 402 response                    |
      |     - Construct SPL token transfer:         |
      |       USDC, amount=1000 (0.001 USDC),       |
      |       from=agent_ata, to=recipient          |
      |     - Sign transaction with agent's keypair |
      |     - Base64-encode signed transaction      |
      |                                             |
      |  4. POST /rest/v1/todos                     |
      |     X-Payment: <base64_signed_tx>           |
      +-------------------------------------------->|
      |                                             |
      |  5. Node's local facilitator:               |
      |     - Deserialize + validate transaction    |
      |     - Check: correct recipient, amount,     |
      |       asset, and recent blockhash           |
      |     - Submit to Solana RPC                  |
      |                                             |
      |  6. HTTP 200 OK                             |
      |     { data: [...] }                         |
      |<--------------------------------------------+
      |                                             |
```

The `@x402/svm` client library handles steps 2-4 transparently. The agent's HTTP client is wrapped with an x402 interceptor that catches 402 responses, constructs payments, and retries — all invisible to the calling code. From the LLM's perspective (the agent invoking MCP tools), the request simply succeeds or fails.

### 8.2 On-Chain Escrow for Hosting

Per-request x402 payments cover individual API calls. But hosting a Supabase instance incurs ongoing costs — CPU, memory, disk, network — even when no queries are executing. These baseline costs are paid via the on-chain escrow:

1. The agent deposits USDC into the `PaymentEscrow` PDA during `allocate_instance` (initial deposit) or via `deposit_payment` (top-up).

2. A permissionless crank calls `distribute_payment` at least once per hour.

3. The crank calculates hours elapsed since last distribution and transfers the accrued amount.

4. Distribution split:

   * **70% to primary node** — runs the full Supabase stack, serves all queries.

   * **15% to replica 1** — stores encrypted WAL, serves as failover candidate.

   * **15% to replica 2** — stores encrypted WAL, serves as failover candidate.

5. If only one replica is configured, the split is 85%/15%.

6. If no replicas, the primary receives 100%.

**Grace period:** When the escrow balance reaches zero:

* The instance status becomes `Suspended`.

* All API requests return HTTP 503.

* The instance is not destroyed. Data remains on disk.

* The agent has 24 hours to deposit more USDC.

* After 24 hours with no deposit, the instance is `Terminated`. Encrypted WAL backups on replicas are retained for 7 additional days before garbage collection.

### 8.3 IPFS Pinning Payments

IPFS pinning has two payment components:

* **Initial pin (x402):** Paid at pin time via the standard 402 flow. Covers the cost of fetching content from the IPFS network (if pinning by CID), validating it, and storing it locally. Priced per megabyte of content.

* **Ongoing storage (escrow):** A separate `PaymentEscrow` funds ongoing pin retention. Distributed monthly to pin nodes in equal shares (if 3 pin nodes, each gets 33.3%). When the escrow depletes, pins enter a 30-day grace period before garbage collection.

### 8.4 Optimistic Execution

For low-value queries (< $0.01), the full x402 round-trip — request, receive 402, construct payment, retry — adds unnecessary latency. Kraph supports optimistic execution:

1. The agent includes a pre-signed payment transaction in the `X-Payment` header with the **initial** request (no 402 round-trip needed if the agent knows the price).

2. The node validates the transaction **locally** — checks the signature, the recipient address, the amount, and that the blockhash is recent. This validation takes <1ms and does not require an RPC call.

3. The node executes the query and returns results **immediately**.

4. The node's local x402 facilitator submits the payment transaction to Solana **asynchronously**.

5. If the payment fails on-chain (insufficient balance, stale blockhash, double-spend), the agent's pubkey is added to a local deny list. Subsequent requests from that pubkey require **confirmed** payment (full 402 flow with on-chain confirmation) until the debt is settled.

**Risk analysis:** The maximum loss to the node from a failed optimistic payment is the cost of one query execution (sub-cent). The maximum gain from cheating for the agent is avoiding sub-cent payments — not worth the denial-of-service from being blocklisted. The incentives align.

### 8.5 Payment Session Tokens

To further reduce payment overhead for chatty agents making many rapid requests, the protocol supports payment sessions:

1. Agent makes a paid request (full x402 flow or optimistic).

2. The node returns an `X-Payment-Session` header containing a signed token.

3. For the next 60 seconds (configurable), the agent includes this token in subsequent requests. The node skips payment verification.

4. After 60 seconds or 100 requests (whichever comes first), a new payment is required.

The session token is a compact JWT signed by the node's keypair:

```json
{
  "sub": "<agent_pubkey>",
  "iat": 1712410000,
  "exp": 1712410060,
  "max_req": 100,
  "cnt": 0,
  "nid": "<node_id>"
}
```

The node maintains an in-memory counter for each active session token. Session tokens are not transferable between nodes — they are signed by and valid only on the issuing node.

### 8.6 Pricing Model

Pricing is set by individual node operators in a free market. The reference implementation uses the following defaults, which operators can adjust:

| Operation              | Reference Price | Notes                                            |
| ---------------------- | --------------- | ------------------------------------------------ |
| Instance provisioning  | $0.10           | One-time, covers pre-warmed container assignment |
| SQL query (PostgREST)  | $0.001          | Per request, regardless of result size           |
| Realtime message       | $0.0001         | Per WebSocket message                            |
| Storage write          | $0.01/MB        | Per megabyte uploaded                            |
| Storage read           | $0.001/MB       | Per megabyte downloaded                          |
| Hosting (escrow)       | $0.05/hour      | Baseline resource reservation                    |
| IPFS pin (initial)     | $0.001/MB       | One-time, covers fetch + store                   |
| IPFS storage (ongoing) | $0.001/MB/month | Ongoing retention                                |

These prices target approximate parity with centralized providers at low scale. The premium over raw infrastructure cost pays for permissionlessness, data sovereignty, and cryptographic verifiability. Competition among node operators is expected to drive prices toward marginal cost over time as the network grows.

***

## 9. Performance

### 9.1 Pre-Warmed Containers

Cold-starting a full Supabase Docker Compose stack — Postgres, PostgREST, Kong, GoTrue, Realtime, Storage, Studio, Analytics, PgBouncer — takes 30-60 seconds on typical hardware. For an agent that needs a database immediately, this latency is unacceptable.

Kraph nodes maintain a pool of **pre-warmed instances**:

* Each node keeps 1-2 fully initialized Supabase stacks running in an idle state. All containers are started, all health checks pass, Postgres is accepting connections.

* The idle stacks have no agent data, no credentials, no external network exposure.

* When an allocation request arrives, the node:

  1. Assigns the pre-warmed stack to the agent.

  2. Injects the instance configuration: JWT secret, API keys, DEK, PostgREST schema cache.

  3. Opens the Kong gateway port to the agent.

* The instance is ready for queries in **under 2 seconds**.

* The node replenishes the pool asynchronously after assignment.

Pre-warming costs approximately 2 GB RAM per idle stack. This cost is factored into the node's `capacity` self-report — a node advertising capacity for 6 instances on 16 GB RAM should maintain 1-2 warm instances and leave headroom for 4-5 assigned instances.

### 9.2 Direct Data Plane

After provisioning, the agent communicates **directly** with the assigned node. The Kraph gateway is a control plane component only — it handles authentication, node discovery, placement, and health monitoring. It is not in the data path.

```text
  Provisioning (control plane):
      Agent --> Gateway --> Solana --> Node

  Data operations (data plane):
      Agent --> Node (direct, no gateway hop)
```

The node's endpoint URL (from `NodeRecord.endpoint`) is returned to the agent at provisioning time along with instance-specific API keys. All subsequent requests — PostgREST queries, Realtime WebSocket connections, Storage uploads, GoTrue auth calls — go directly to this endpoint.

This architecture ensures that:

* The gateway is not a throughput bottleneck.

* The gateway is not a single point of failure for data operations.

* Latency for data operations is identical to connecting to any directly-hosted Supabase instance.

### 9.3 Connection Pooling

Each instance runs PgBouncer in **transaction mode** between PostgREST and Postgres:

* PostgREST opens connections to PgBouncer on localhost, not directly to Postgres.

* PgBouncer maintains a pool of 20 Postgres connections (configurable per instance).

* In transaction mode, a connection is assigned to a client only for the duration of a single transaction, then immediately returned to the pool.

* This allows hundreds of concurrent PostgREST requests to be served by a small Postgres connection pool, avoiding the ~10 MB per-connection memory overhead of Postgres.

### 9.4 HTTP/2 Multiplexing

Kong is configured with HTTP/2 support. Agents making multiple concurrent requests — common when an agent explores a schema, runs parallel queries, or populates multiple tables — benefit from:

* Multiplexed streams over a single TCP connection (no head-of-line blocking).

* Reduced connection setup overhead (single TLS handshake for all streams).

* Header compression (HPACK) reducing per-request overhead for repetitive headers like authorization tokens.

### 9.5 Streaming WAL Encryption

WAL encryption (Section 7.4) operates in a streaming fashion:

* WAL segments are split into 64 KB chunks as they are produced.

* Each chunk is encrypted independently (~0.1 ms per chunk on hardware with AES-NI).

* Encrypted chunks are streamed to replica nodes as they are ready.

* No buffering of full 16 MB segments in memory before encryption or transmission.

This means replication latency is bounded by encryption speed (negligible with hardware acceleration) plus network transit, not by segment size.

### 9.6 Incremental Merkle Tree Updates

The Merkle tree (Section 6.2) is maintained as a persistent data structure, not recomputed from scratch at each commitment interval:

* The tree is backed by a B-tree or LSM store (RocksDB) on disk.

* When a row is inserted, updated, or deleted, only the affected leaf and its ancestors (the path to the root) are recomputed: **O(log n)** hash operations.

* For a database with 1 million rows, this means ~20 hash operations per row change, not 1 million.

* At commitment time, the current root is simply read from the tree — no recomputation needed.

For a database with 10,000 rows experiencing 100 writes between commitments, the Merkle maintenance cost is ~100 * 14 hashes = 1,400 SHA-256 operations, completing in under 1 ms on modern hardware.

### 9.7 System Tuning

The reference node implementation applies the following system-level optimizations to each Supabase instance:

* **CPU pinning (**`cpuset`**):** Postgres and PgBouncer processes are pinned to dedicated CPU cores, eliminating context-switch overhead and improving cache locality.

* **tmpfs for&#x20;**`pg_stat_tmp`**:** Postgres writes statistics collector files frequently (~500 ms intervals). Mounting the stats directory on tmpfs avoids unnecessary SSD writes and eliminates I/O contention with actual data.

* `shm_size`**&#x20;tuning:** Docker's default shared memory allocation (64 MB) is insufficient for Postgres shared buffers. Each instance is configured with 256 MB `shm_size`, allowing a 128 MB `shared_buffers` configuration.

* **Huge pages:** Enabled when the host kernel supports them, reducing TLB (Translation Lookaside Buffer) misses for large shared_buffers allocations. Particularly beneficial for instances with large working sets.

* **WAL compression:** Postgres `wal_compression = lz4` reduces WAL volume by 50-80% for typical workloads, directly reducing replication bandwidth and encrypted WAL storage on replicas.

* `effective_io_concurrency`**:** Set to 200 for NVMe SSDs (default 1 is designed for spinning disks), enabling Postgres to issue many concurrent I/O requests.

### 9.8 Local x402 Facilitator

Each node runs a local x402 facilitator — a lightweight HTTP service that verifies and submits payment transactions to Solana:

* Validates transaction structure, signatures, recipient, amount, and blockhash freshness.

* Maintains a persistent connection to a Solana RPC node (configurable: public or private RPC).

* Submits transactions with priority fees when needed during congestion.

* Caches recent blockhashes to validate payment freshness without RPC calls.

* Deduplicates transaction submissions (prevents double-submission of the same payment).

Running the facilitator locally — rather than depending on a remote facilitator service — eliminates a network hop, reduces payment verification latency, and removes a single point of failure. The facilitator adds <1 ms to payment verification for local validation and ~200-400 ms for on-chain confirmation (which proceeds asynchronously in optimistic mode).

***

## 10. Edge Functions

### 10.1 Overview

Each Kraph instance includes `supabase/edge-runtime`, a Deno-based serverless runtime that allows agents to deploy custom TypeScript/JavaScript functions alongside their database. Edge Functions extend the Supabase stack beyond CRUD operations, enabling agents to run arbitrary server-side logic — webhooks, cron jobs, API routes, data transformations, and AI agent logic — without provisioning additional infrastructure.

### 10.2 Architecture

Edge Functions run inside the same confidential VM as the rest of the Supabase stack, inheriting the TEE protection of Layer 0. Each function executes in an isolated V8 sandbox, providing two layers of isolation:

1. **V8 isolate sandboxing:** Each function invocation runs in its own V8 isolate, preventing cross-function memory access, filesystem access, or network interference. This is the same isolation model used by Cloudflare Workers and Deno Deploy.

2. **TEE hardware isolation:** The entire edge runtime, including all V8 isolates, runs inside the confidential VM. Function code and execution state are protected from the node operator by hardware-encrypted memory. The operator cannot inspect function logic, read intermediate computation results, or extract secrets used by the function.

Functions are accessible through Kong at `/functions/v1/<function-name>`, using the same authentication and payment model as other Supabase services.

```text
+-------------------------------------------------------------------+
|                  Instance (inside Confidential VM)                 |
|                                                                    |
|  +----------+  +------------+  +-------------------------------+  |
|  | Postgres |  | PostgREST  |  | Edge Runtime (Deno)           |  |
|  |  15.x    |  |   12.x     |  |  +----------+ +----------+   |  |
|  +----+-----+  +-----+------+  |  | Function | | Function |   |  |
|       |               |         |  | (V8)     | | (V8)     |   |  |
|       |               |         |  +----------+ +----------+   |  |
|       |               |         +------+------------------------+  |
|       |               |                |                           |
|  +----v---------------v----------------v------------------------+  |
|  |                     Kong API Gateway                         |  |
|  |         /rest/v1/*    /functions/v1/*    /auth/v1/*          |  |
|  +--------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

### 10.3 Deployment

Agents deploy functions via the `kraph_deploy_function` MCP tool:

```text
Agent: kraph_deploy_function({
  instance_id: "a1b2c3d4e5f6...",
  name: "process-webhook",
  code: "import { serve } from 'https://deno.land/std/http/server.ts'\n\nserve((req) => {\n  const body = await req.json()\n  // process webhook payload...\n  return new Response('ok')\n})"
})

Response: {
  function_name: "process-webhook",
  url: "https://node-7.kraph.network/functions/v1/process-webhook",
  code_hash: "sha256:a3f8b2c1d4e5f6...",
  on_chain_hash: "sha256:a3f8b2c1d4e5f6...",
  status: "deployed"
}
```

### 10.4 Content-Addressed Integrity

Functions are **content-addressed**: when a function is deployed, the SHA-256 hash of the source code is computed and recorded on-chain in the `InstanceRecord`. This provides verifiable integrity:

1. **Deployment:** Agent deploys function code. The node computes `SHA-256(code)` and commits the hash on-chain.

2. **Verification:** At any time, the agent can request the function code from the node, hash it locally, and compare against the on-chain record. A mismatch proves the node has modified the function.

3. **Auditability:** Third parties can verify that a specific function (identified by hash) is running on a specific instance, enabling trust in agent-deployed APIs.

This is particularly important inside TEE: the function code is protected from the node operator (they cannot read or modify it), and the on-chain hash proves to the agent that the expected code is what was deployed.

### 10.5 Use Cases

* **Webhooks:** Receive and process incoming HTTP requests from external services (payment processors, notification systems, third-party APIs).

* **Cron jobs:** Scheduled functions that run periodically (data aggregation, cleanup tasks, report generation). Triggered by Postgres `pg_cron` calling the function endpoint.

* **API routes:** Custom API endpoints beyond what PostgREST provides (complex business logic, multi-table transactions, external API orchestration).

* **Data transformations:** Pre-process or post-process data before/after database operations (validation, enrichment, format conversion).

* **AI agent logic:** Deploy sub-agent logic that runs server-side, closer to the data (RAG pipelines, embedding generation, decision logic that queries the database directly).

### 10.6 Encrypted Environment Variables

Edge functions are useful only if they can call third-party services — payment processors, LLM APIs, webhooks, email providers. Every such call needs credentials: an OpenAI API key, a Stripe secret key, a Twilio auth token. Hard-coding them into function source is unacceptable (source is content-addressed and logged on-chain), and shipping them over the wire on every invocation is impractical. Kraph exposes encrypted per-instance environment variables as a first-class primitive.

**Storage.** Env var values are encrypted at the application layer before hitting SQLite. The node ChaCha20-Poly1305-encrypts each value under the per-instance 32-byte data-encryption key (DEK) — the same DEK that encrypts WAL segments, derived at provision time and stored hex-encoded in the `instances.wal_encryption_key` column. Rows in the `instance_env` table are of the form `enc-v1:<base64(nonce[12] || ciphertext || poly1305_tag)>`. A `sqlite3 .dump` never yields plaintext, a misplaced SQLite backup does not leak secrets, and host-level disk-encryption is a second line of defense rather than the only one. `upsert_env` refuses to store plaintext if an instance lacks a DEK. In transit, all env-var API traffic is TLS-terminated at the node.

**Injection.** When a function runs, it inherits its environment from a Docker Compose `env_file` rendered from the SQLite table for that instance. Setting or deleting a var rewrites the file and triggers `docker compose up -d --force-recreate --no-deps functions` — scoped to the functions service only, typically `~1–2s`. Postgres, PostgREST, GoTrue, Realtime, Storage, and Kong are untouched: connections do not drop, queries do not stall, and no other service restarts.

**Confidentiality.** Even with application-layer encryption at rest, the node process necessarily holds plaintext transiently when decrypting to write the `env_file`. On mainnet SEV-SNP nodes, that decrypt-and-write path only runs inside the confidential VM: the hypervisor sees only ciphertext, the hardware memory encryption engine decrypts into registers and caches that are inaccessible to the host, and an operator with root on the host cannot observe the plaintext window. On devnet (mock-TEE), the operator can in principle read plaintext from process memory during the brief decrypt step — devnet is explicitly for hacking, not production secrets. The SQLite blob itself, and any disk backups, always yield only ciphertext on both tiers.

**API.** Nodes expose three authenticated endpoints, gated by the agent's instance-session token:

* `POST   /instances/:id/env` — set one `{key, value}` pair, encrypted at rest under the instance DEK before storage.
* `GET    /instances/:id/env` — return owner-decrypted `(key, value, updated_at)` triples; used by the gateway's `kraph_list_env` tool which by default strips values and returns SHA-256 fingerprints so the MCP transcript never sees plaintext.
* `GET    /instances/:id/env/keys` — cheap path that returns only the key names (no decryption at all).
* `DELETE /instances/:id/env/:key` — remove a single var.
* `POST   /instances/:id/env/apply` — force-rewrite the functions `env_file` and restart the functions container.

The MCP tools `kraph_set_env`, `kraph_list_env`, and `kraph_unset_env` wrap these endpoints and pay the gateway via x402 like any other tool call. Session tokens bind the request to a specific instance, preventing cross-instance env reads even if an operator proxies traffic.

**Future work.** The current design still requires the node to hold the DEK transiently in order to decrypt values when writing the functions `env_file`. A planned revision moves encryption fully client-side: the agent derives a deterministic DEK from its Solana keypair (HKDF over the wallet's ed25519→x25519-converted private material, with the instance ID as info context), encrypts values locally before `POST`, and the node persists only ciphertext. At function-invocation time the agent injects the plaintext directly into the invocation request, or hands the DEK to the enclave over an attested channel, so no long-lived plaintext exists in the node's memory. This removes the node from the trust perimeter for secrets and makes the guarantee symmetric with Layer 7 at-rest encryption for Postgres data.

***

## 11. IPFS Frontend Pinning

### 12.1 Motivation

An agent that provisions a Supabase backend often needs a frontend too. Static single-page applications — React, Vue, Svelte, plain HTML/CSS/JS — are the natural choice for agent-deployed frontends: they require no server-side runtime, only content hosting.

IPFS is the logical decentralized hosting layer: content-addressed (guaranteeing integrity), censorship-resistant, and supported by a global network of nodes. But pinning services — the mechanism that ensures content stays available on IPFS rather than being garbage-collected — require human-owned accounts (Pinata, Infura, web3.storage).

Kraph provides permissionless IPFS pinning as a first-class feature, payable via x402, enabling agents to deploy complete applications — backend on Supabase, frontend on IPFS — without any human involvement.

### 12.2 Architecture

Nodes that opt into IPFS pinning (`ipfs_enabled = true` in `NodeRecord`) run a Kubo IPFS daemon alongside the Supabase stack:

```text
+-------------------------------------------------------------+
|                        Kraph Node                           |
|                                                              |
|  +-----------------------+  +-----------------------------+  |
|  | Supabase Instances    |  |   IPFS Daemon (Kubo)        |  |
|  | [Instance 1]          |  |                             |  |
|  | [Instance 2]          |  |  +------------------------+ |  |
|  | [Instance N]          |  |  | Blockstore (local disk)| |  |
|  +-----------------------+  |  +------------------------+ |  |
|                              |                             |  |
|                              |  +------------------------+ |  |
|                              |  | DHT Participation      | |  |
|                              |  | (content discovery)    | |  |
|                              |  +------------------------+ |  |
|                              |                             |  |
|                              |  +------------------------+ |  |
|                              |  | HTTP Gateway (:8080)   | |  |
|                              |  | (content serving)      | |  |
|                              |  +------------------------+ |  |
|                              +-----------------------------+  |
+-------------------------------------------------------------+
```

The IPFS daemon participates in the public IPFS DHT, meaning pinned content is discoverable and retrievable by any IPFS client worldwide — not just through the Kraph node's gateway.

### 12.3 Pinning Flow

**Mode 1: Pin by CID**

The agent has already added content to IPFS (via a local node, another pin service, or direct upload to the IPFS network) and wants to ensure it remains available through Kraph.

1. Agent calls `kraph_pin` with `{ cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3okuhlzqkpnvqfl" }`.

2. Payment: initial pin fee via x402 (per-MB of content).

3. The node fetches the content from the IPFS network by CID.

4. The node pins the content locally (marks it as not garbage-collectible).

5. The `PinRecord` is created on-chain with the CID, size, and pin nodes.

6. The content is replicated to 2 additional pin nodes for redundancy.

7. The agent receives confirmation with the gateway URLs.

**Mode 2: Upload and Pin**

The agent has content locally (e.g., a built frontend directory) and wants to upload it directly.

1. Agent calls `kraph_pin` with `{ content: <base64-encoded tar archive> }`.

2. Payment: initial pin fee via x402.

3. The node extracts the tar archive and adds the directory to IPFS as a UnixFS DAG. Kubo computes the CID.

4. The node pins the content.

5. The CID is returned to the agent.

6. The `PinRecord` is created on-chain.

7. Replication to additional pin nodes proceeds.

For typical SPA deployments, the tar archive contains `index.html`, JavaScript bundles, CSS files, and static assets. The resulting IPFS directory is accessible at `https://<node>/ipfs/<CID>/index.html`.

### 12.4 Content Serving

Each IPFS-enabled node runs Kubo's built-in HTTP gateway on port 8080. Pinned content is served at:

```text
https://<node-endpoint>/ipfs/<CID>
https://<node-endpoint>/ipfs/<CID>/index.html
https://<node-endpoint>/ipfs/<CID>/assets/main.js
```

For SPAs, the CID typically points to a directory. The gateway serves `index.html` by default when a directory is requested, enabling standard SPA routing.

The gateway also supports subdomain-based addressing for isolation:

```text
https://<CID>.ipfs.<node-endpoint>/
```

### 12.5 Redundancy

Each pin is replicated to 3 nodes by default (configurable by the agent from 1 to 5). If a pin node goes offline:

1. The gateway detects the outage via heartbeat monitoring.

2. A replacement pin node is selected from available IPFS-enabled nodes.

3. The replacement node fetches the content by CID from one of the remaining online pin nodes.

4. The on-chain `PinRecord` is updated with the new pin node set.

5. Content availability is maintained with no agent intervention.

### 12.6 Payment Model

* **Initial pin fee:** One-time x402 payment at pin time. Covers content retrieval (if pinning by CID), storage initialization, and replication to pin nodes. Priced at ~$0.001/MB.

* **Ongoing storage:** Monthly escrow distribution to pin nodes, split equally among all pin nodes for the CID. If the escrow depletes, pins are retained for a 30-day grace period before garbage collection.

* **Unpinning:** The agent can call `kraph_unpin` at any time. The on-chain record is updated, remaining escrow funds are returned to the agent, and pin nodes garbage-collect the content after a short delay.

***

## 12. Threat Model

### 12.1 Rogue Node Serving Fabricated Data

**Attack:** A node operator modifies the Supabase stack or underlying Postgres to return fabricated query results. For example, an agent writes `balance = 100` and the node later returns `balance = 0`.

**Detection path:**

1. The agent requests a Merkle proof for the queried row.

2. The proof is verified against the on-chain Merkle root.

3. If the node committed a Merkle root matching the fabricated state (to make the proof consistent), cross-replica verification detects the divergence — the WAL replayed on a replica will produce `balance = 100`, not `balance = 0`.

**Consequence:** `slash_node` with `DataCorruption` proof type. 50% of stake slashed. Half burned, half to reporter.

**Residual risk:** A node could fabricate data between Merkle commitment intervals (up to 10 minutes). Agents performing high-value operations should wait for a fresh Merkle commitment and verify before acting on the data.

### 12.2 Sybil Attack (Fake Node Proliferation)

**Attack:** An adversary registers many nodes with minimum stake to dominate instance placement, capturing traffic for surveillance or manipulation.

**Mitigation:**

* Staking requirement (minimum 1 SOL per node) makes large-scale Sybil attacks financially costly. 100 Sybil nodes requires 100 SOL (~$15,000 at typical prices).

* Placement algorithm weights: `stake_score` (0.2) favors higher-staked nodes. A node with 10 SOL staked scores 10x higher on the stake dimension than a minimum-stake node.

* `uptime_score` (0.3) favors established nodes. New Sybil nodes start with zero uptime, making them uncompetitive against established operators.

* The attacker must maintain all Sybil nodes (heartbeats, infrastructure) to remain active — ongoing cost, not just initial stake.

**Residual risk:** A well-funded adversary could stake heavily across many nodes and maintain them long enough to build uptime. The defense is economic: the cost of a sustained Sybil attack must be weighed against the value of the data being targeted. For most agent workloads, the attack cost exceeds the data value.

### 12.3 Data Availability (Node Goes Offline)

**Attack/Failure:** A node suffers hardware failure, network partition, or operator abandonment.

**Detection:** Missed heartbeats. After 60 consecutive missed heartbeats (1 hour), the node is marked `Inactive`.

**Recovery:**

1. The gateway detects primary node failure.

2. A replica node with the most complete WAL is selected as the new primary.

3. The agent provides the DEK to the new primary via attestation-gated KBS (automatically via the MCP client after verifying TEE attestation, or manually if needed).

4. The replica decrypts WAL segments, replays them into a fresh Postgres instance, starts the full Supabase stack.

5. The on-chain `InstanceRecord` is updated.

6. Service resumes.

**Consequence:** 10% of the failed node's stake is slashed for downtime exceeding 1 hour.

**Residual risk:** If all replica nodes fail simultaneously (e.g., a correlated failure like a data center outage affecting multiple nodes in the same facility), data is lost. Geographic diversity of replicas mitigates this, and TEE attestation reports provide partial geographic corroboration via platform identifiers.

### 12.4 Key Compromise (Agent's Solana Key Stolen)

**Attack:** An adversary obtains the agent's Solana private key, gaining the ability to derive all master keys, decrypt all DEKs, and access all instance data.

**Mitigation:**

* Standard Solana wallet security practices: hardware wallets (Ledger), multisig (Squads Protocol), social recovery.

* The protocol supports multisig wallets: provisioning and payment transactions can require M-of-N signatures.

* Agents can detect compromise (unexpected transactions on their wallet) and respond by rotating DEKs on all instances (re-encrypting data with a new key tied to a new wallet).

* Privy server wallets use MPC-based key shares distributed across multiple parties, reducing single-point-of-compromise risk.

**Residual risk:** Key compromise is a client-side security problem, fundamentally outside the protocol's scope. Kraph cannot protect against a stolen private key any more than a bank can protect against a stolen password. The protocol provides the tools for recovery (DEK rotation, instance migration) but the prevention responsibility lies with the agent's key management.

### 12.5 Node Operator Reads Data in Memory

**Attack:** The node operator attaches a debugger to the Postgres process, inspects memory, or modifies the Kraph node software to exfiltrate data.

**Mitigation (TEE — Layer 0, Phase 1):** Every Supabase instance runs inside a confidential VM (AMD SEV-SNP or Intel TDX). The entire VM memory is hardware-encrypted. The node operator has host root access but **cannot read confidential VM memory** — memory reads from outside the VM return ciphertext. Debugger attachment, DMA attacks, and hypervisor-level memory introspection are all defeated by the hardware encryption.

The DEK is delivered via attestation-gated KBS and only exists in plaintext inside the confidential VM's encrypted memory. The operator cannot extract it.

This is a significant improvement over every managed database service in existence. When you use AWS RDS, Amazon can read your data. When you use Supabase Cloud, Supabase can read your data. In Kraph, the node operator **cannot** read your data — the CPU hardware enforces this, not organizational trust or policy.

**Residual risk:** TEE hardware vulnerabilities (e.g., historical SEV vulnerabilities like SEV-Step, CacheWarp). Kraph monitors AMD/Intel security advisories and requires nodes to run patched firmware. The attestation report includes firmware version, allowing agents to reject nodes running known-vulnerable firmware.

### 12.6 Eclipse Attack on Node Discovery

**Attack:** An adversary controls the agent's network connections to manipulate which nodes the agent can discover, directing it to attacker-controlled nodes.

**Mitigation:** Node discovery uses the Solana blockchain as the authoritative registry. The `NodeRecord` accounts are on-chain state, not propagated via a peer-to-peer gossip protocol. To eclipse an agent's node discovery, the adversary would need to eclipse the agent's Solana RPC connection — intercepting all communication between the agent and every Solana RPC node it uses.

This is significantly harder than eclipsing a P2P gossip network because:

* Solana RPC nodes are well-known, geographically distributed, and accessible over standard HTTPS.

* Agents can use multiple RPC providers simultaneously (Helius, Quicknode, Triton, public RPC) and compare results.

* The on-chain registry is deterministic: all honest RPC nodes return the same state.

**Residual risk:** An adversary controlling the agent's entire network stack (e.g., a compromised cloud provider) could theoretically eclipse Solana RPC access. This is an extreme scenario that compromises all of the agent's network operations, not just Kraph.

### 12.7 IPFS Data Availability

**Attack/Failure:** Pin nodes go offline, making IPFS-pinned content unavailable.

**Mitigation:**

* Content is pinned on 3 nodes by default, providing redundancy.

* The gateway monitors pin node health and triggers re-pinning on replacement nodes when failures are detected.

* IPFS content is content-addressed: any node in the global IPFS network that has cached the content can serve it. Kraph pin nodes are not the only possible source.

* The 30-day grace period for expired escrows prevents immediate content loss due to payment lapses.

**Residual risk:** If all 3 pin nodes fail simultaneously and no other IPFS node has cached the content, it is irrecoverable. The probability of 3-node simultaneous failure is low if nodes are geographically distributed, but it is non-zero.

### 12.8 Gateway Compromise

**Attack:** An adversary obtains code-execution on the gateway host (`api.kraph.com`) — for example via a vulnerability in a gateway dependency, a supply-chain attack on its npm tree, or a misconfigured deploy pipeline. The gateway is the central trust intermediary: every MCP tool call from every authenticated agent flows through it before reaching a node.

**Blast radius (default architecture, no mitigations applied):**

* **Edge function injection.** Every gateway → node API call authenticates only via an `X-Wallet-Pubkey` header — a claim, not a proof. A compromised gateway can `POST /instances/<victim>/functions/deploy` with any wallet's pubkey. The node accepts; the deployed Deno function runs inside the victim's Supabase stack with full `service_role` access, can `SELECT *`, and can exfiltrate to an attacker-controlled URL.
* **Plaintext env-var read.** `kraph_list_env`'s default path retrieves decrypted env values on the gateway-to-node channel before the gateway computes fingerprints for the agent. A compromised gateway sees plaintext.
* **Arbitrary SQL.** `kraph_query` proxies SQL to the primary node. Read or write any row of any instance.
* **Bearer minting.** OAuth access tokens live in gateway memory (now persisted to disk for restart durability). A compromised gateway can mint a Bearer for any wallet pubkey on demand.
* **Privy-custodied wallet hijack.** The gateway holds `SUPABA_PRIVY_SIGNING_KEY`, the authorization key for every Privy-managed user wallet (one wallet per OAuth-authenticated agent). Without restriction policies, the gateway can sign arbitrary Solana transactions and arbitrary `signMessage` payloads for every user — effectively draining all custodied USDC.
* **Operator-keypair signing.** `SUPABA_OPERATOR_KEYPAIR_PATH` is loaded into gateway memory at startup for the in-process x402 facilitator. A compromised gateway can sign settlements and other transactions as the operator.

**What is *not* in the blast radius:**

* **Replica nodes.** Replicas hold opaque XChaCha20-Poly1305 ciphertext keyed under the agent's wallet-derived DEK. Without the agent's master key, replicas leak nothing — even on a colluding gateway+replica compromise.
* **TEE-backed nodes (mainnet).** Node hosts running confidential VMs (AMD SEV-SNP or Intel TDX) refuse to release plaintext memory to the host operator regardless of what the gateway requests. However, the gateway can still issue valid SQL through the node's normal API surface, so this only blocks *out-of-band* memory extraction, not authorized-looking exfiltration paths.
* **On-chain state.** Gateway compromise does not grant the ability to forge on-chain accounts, slash other operators, or withdraw from escrow. The Solana program accepts only signatures from authorized signers.

**Mitigations, in deploy order:**

#### Mitigation #1: Per-call ed25519 signature verified at the node

State-changing endpoints (`functions/deploy` first, `set_env` / `unset_env` / `query` to follow) require the gateway to forward four headers it cannot synthesize itself:

```text
X-Kraph-Auth-Sig    : base58(ed25519 signature)
X-Kraph-Auth-Nonce  : random nonce
X-Kraph-Auth-Ts     : unix-seconds timestamp at sign time
X-Kraph-Auth-Hash   : sha256 hex of the request body
```

The agent signs the canonical message:

```text
kraph-auth:v1:<METHOD>:<PATH>:<BODY_SHA256>:<NONCE>:<TS>
```

with their Solana key. The node verifies the signature against the instance's `wallet_pubkey` field via `ed25519-dalek`, enforces a ±5 minute timestamp window for replay protection, and rejects on body-hash mismatch. A compromised gateway holding only the user's Bearer token cannot forge this signature; it would need the user's actual private key.

**Status:** node-rs verifies the signature when the headers are present (commit `ab5e52c`). When headers are missing, the node logs a warning and accepts during the rollout phase. Once all clients ship the `sigauth` parameter, the missing case becomes a hard 401.

**Coverage:** stdio agents with a local Solana keypair can sign every state-changing call today. Browser/HTTP agents whose wallet is custodied by Privy currently cannot sign per-call (Privy policy denies arbitrary `signMessage` — see Mitigation #2). For those agents, the residual risk window is narrowed by Mitigation #2 but not closed; closing it requires a separate ops-key registration scheme, planned for a future revision.

#### Mitigation #2: Privy authorization-key policy

The Privy authorization key registered as `SUPABA_PRIVY_SIGNING_KEY` is restricted by a Privy `WalletApiPolicy` that admits only a tightly-scoped set of operations:

```text
ALLOW signAndSendTransaction WHEN
  solana_token_program_instruction.instructionName == "TransferChecked"
  AND TransferChecked.mint IN [USDC_mainnet, USDC_devnet]
  AND TransferChecked.destination IN [operator_USDC_ATA_mainnet, operator_USDC_ATA_devnet]

ALLOW signTransaction WHEN (same conditions)

DENY everything else (default)
```

`signMessage`, `sendTransaction` for arbitrary tokens, and transfers to non-operator addresses default-deny because no allow rule matches. A compromised gateway holding the signing key can therefore only force USDC payments toward the operator — the same operation the legitimate gateway performs. It cannot drain wallets to an attacker address, sign arbitrary messages for SIWS replay, or forge other transactions on behalf of users.

**Status:** policy-creation script (`packages/gateway/scripts/setup-privy-policy.mjs`) and migration script (`packages/gateway/scripts/migrate-privy-policies.mjs`) shipped. Newly created Privy server wallets attach the policy at creation time when `SUPABA_PRIVY_POLICY_ID` is set in the gateway environment. Migration script is idempotent (`--dry-run` supported) and applies the policy to wallets created before the policy existed.

**Coverage:** all OAuth/HTTP agents whose wallets pass through Privy. Stdio agents with their own non-Privy keys are unaffected (the policy applies only to keys Privy custodies).

#### Mitigation #3: TEE the gateway

Run the gateway inside a confidential VM (AMD SEV-SNP) on the same model as the existing mainnet-tier nodes. With on-chain registration of the gateway's measurement, agents can `kraph_attest` the gateway itself before sending sensitive calls. Even an attacker with host root cannot read the operator keypair, the Privy signing key, or in-flight plaintext from gateway memory.

**Status:** not done. The gateway runs on a regular Ubuntu VM at OVH today. This is the largest outstanding item for mainnet-confidentiality posture.

#### Mitigation #4: End-to-end client-side encryption

Row-level data and edge-function env vars are encrypted client-side under a wallet-derived key envelope (HKDF over the agent's Solana keypair). The gateway and the primary node never observe plaintext; a malicious deployed function reads ciphertext but cannot decrypt without the agent's key.

**Status:** partial. `instance_env` is now encrypted at rest under a per-instance DEK (commit `a5e9a13`), but the DEK is generated and held by the node — protecting against on-disk exfiltration but not against in-memory reads or gateway-mediated exfiltration. Wallet-derived envelope encryption is the next tightening step, planned alongside Mitigation #3.

#### Mitigation #5: Capability tokens with operation-scoped expiry

Agents issue short-lived capability JWTs scoped to `(instance_id, operation, expiry)`. The gateway becomes a forwarder of caps it cannot mint. Compromise window for any single capability is bounded by its TTL (typically 60 seconds).

**Status:** not done. Cleanest long-term model for the trust split, but requires SDK-side work on every agent client. Tracked as a Phase-3 roadmap item.

#### Mitigation #6: Two-process gateway split

Auth process (mints Bearers, holds `SUPABA_PRIVY_SIGNING_KEY`) runs in a TEE on a different host from the execution process (forwards tool calls). Execution-process compromise becomes scope-bounded — it cannot issue new auth tokens or sign delegation transactions, only forward the calls of users who have already authenticated.

**Status:** not done. Operationally heavier than #3 alone; deferred until traffic justifies the complexity.

**Posture today (devnet):** Mitigation #2 is in place once `SUPABA_PRIVY_POLICY_ID` is configured; Mitigation #1 is verifying when `sigauth` is provided and warning otherwise. Mitigations #3 and #4 are not yet deployed. Mainnet-confidential workloads should not be deployed until #3 + #4 are in place; until then the gateway should be treated as a trusted-but-not-trustless intermediary.

***

## 13. Agent Interaction (MCP Interface)

### 13.1 MCP Tools

Kraph exposes the following tools via the Model Context Protocol. Each tool is callable by any MCP-compatible agent:

| Tool               | Arguments                          | Description                                                                                                                                      |
| ------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `kraph_provision` | `replica_count: u8` (1-3)          | Provision a new Supabase instance. Returns instance_id, connection URL, API keys (anon_key, service_role_key), and expiration timestamp.         |
| `kraph_query`     | `instance_id, method, path, body?` | Execute a PostgREST request against a provisioned instance. Supports GET, POST, PATCH, DELETE. Returns the PostgREST response.                   |
| `kraph_destroy`   | `instance_id`                      | Terminate an instance. Releases resources, returns remaining escrow funds. Encrypted WAL retained on replicas for 7 days.                        |
| `kraph_list`      | (none)                             | List all instances owned by the authenticated agent, with status and expiration.                                                                 |
| `kraph_extend`    | `instance_id, amount`              | Deposit additional USDC to extend an instance's hosting period.                                                                                  |
| `kraph_migrate`   | `instance_id, sql`                 | Apply a SQL migration (DDL statements). Tracked in a `_supaba_migrations` table for rollback capability.                                         |
| `kraph_verify`    | `instance_id, table, primary_key`  | Request a Merkle proof for a specific row and verify it against the on-chain commitment. Returns verified/unverified status and proof details.   |
| `kraph_pin`       | `cid? or content?`                 | Pin content to IPFS. Either provide a CID (to pin existing content) or base64-encoded content (to upload and pin). Returns CID and gateway URLs. |
| `kraph_attest`    | `instance_id, nonce?`              | Request and verify TEE attestation from the node hosting an instance. Returns attestation report, VM measurement, and verification status.       |
| `kraph_deploy_function` | `instance_id, name, code`    | Deploy a TypeScript Edge Function. Returns function URL and SHA-256 code hash (recorded on-chain).                                              |
| `kraph_unpin`     | `pin_id`                           | Remove an IPFS pin. Content is garbage-collected after grace period. Remaining escrow funds returned.                                            |

### 13.2 Example Agent Flow

The following demonstrates a complete agent interaction — from provisioning through data operations to integrity verification:

```text
Agent: kraph_provision({ replica_count: 2 })

Response: {
  instance_id: "a1b2c3d4e5f6...",
  supabase_url: "https://node-7.kraph.network:54321",
  anon_key: "eyJhbGciOiJIUzI1NiIs...",
  service_role_key: "eyJhbGciOiJIUzI1NiIs...",
  db_connection_string: "postgresql://postgres:****@node-7:5432/postgres",
  status: "active",
  primary_node: "NodeA_pubkey",
  replica_nodes: ["NodeB_pubkey", "NodeC_pubkey"],
  expires_at: "2026-04-07T12:00:00Z"
}

Agent: kraph_migrate({
  instance_id: "a1b2c3d4e5f6...",
  sql: "CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    status text DEFAULT 'pending',
    assigned_to text,
    created_at timestamptz DEFAULT now()
  );
  ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
  CREATE POLICY \"agents_all\" ON tasks FOR ALL USING (true);"
})

Response: { success: true, migration_id: 1 }

Agent: kraph_query({
  instance_id: "a1b2c3d4e5f6...",
  method: "POST",
  path: "/rest/v1/tasks",
  body: {
    "title": "Research competitor pricing",
    "assigned_to": "agent-alpha"
  }
})

Response: {
  id: "d4e5f600-1234-5678-9abc-def012345678",
  title: "Research competitor pricing",
  status: "pending",
  assigned_to: "agent-alpha",
  created_at: "2026-04-06T12:01:00Z"
}

Agent: kraph_query({
  instance_id: "a1b2c3d4e5f6...",
  method: "GET",
  path: "/rest/v1/tasks?status=eq.pending&select=id,title,assigned_to"
})

Response: [
  {
    id: "d4e5f600-1234-5678-9abc-def012345678",
    title: "Research competitor pricing",
    assigned_to: "agent-alpha"
  }
]

Agent: kraph_verify({
  instance_id: "a1b2c3d4e5f6...",
  table: "tasks",
  primary_key: "d4e5f600-1234-5678-9abc-def012345678"
})

Response: {
  verified: true,
  row_hash: "0x7f8a9b2c...",
  merkle_root: "0xaabb1122...",
  on_chain_root: "0xaabb1122...",
  proof_path: ["0xab12...", "0xcd34...", "0xef56...", "0x9876..."],
  commitment_slot: 287654321,
  commitment_age_seconds: 142
}

Agent: kraph_pin({
  content: "<base64-encoded tar of built React app>"
})

Response: {
  pin_id: "f7e8d9c0...",
  cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3okuhlzqkpnvqfl",
  gateway_urls: [
    "https://node-7.kraph.network/ipfs/bafybei.../",
    "https://node-3.kraph.network/ipfs/bafybei.../",
    "https://node-11.kraph.network/ipfs/bafybei.../"
  ],
  size_bytes: 2457600,
  pin_nodes: 3
}
```

### 13.3 Transport Details

**stdio transport** (local agents):

```bash
# The agent framework spawns the MCP server as a child process
supaba-mcp --transport stdio

# Environment variables for configuration:
#   SUPABA_PRIVATE_KEY   — Base58-encoded Solana private key
#   SUPABA_GATEWAY_URL   — Gateway endpoint for control plane operations
#   SUPABA_RPC_URL       — Solana RPC URL (defaults to mainnet public RPC)

# Communication is via stdin/stdout, JSON-RPC 2.0 protocol:
# --> {"jsonrpc":"2.0","method":"tools/call","params":{"name":"kraph_provision","arguments":{"replica_count":2}},"id":1}
# <-- {"jsonrpc":"2.0","result":{"instance_id":"...","supabase_url":"..."},"id":1}
```

**StreamableHTTP transport** (remote agents):

```http
POST https://gateway.kraph.network/mcp HTTP/2
Content-Type: application/json
Authorization: Bearer <SIWS_session_token>

{"jsonrpc":"2.0","method":"tools/call","params":{"name":"kraph_query","arguments":{"instance_id":"a1b2c3...","method":"GET","path":"/rest/v1/tasks"}},"id":1}
```

The StreamableHTTP transport supports server-sent events (SSE) for streaming responses, enabling long-running operations like migrations and large query results to stream incrementally.

### 13.4 x402 Integration in MCP

Payment is handled at the transport layer, invisible to the agent's tool calls:

1. The MCP client (running in the agent's process) wraps HTTP requests with an x402 interceptor.

2. On receiving HTTP 402, the interceptor parses `X-Payment-Required`, constructs a USDC transfer transaction, signs it with the agent's Solana key, and retries with `X-Payment`.

3. Payment session tokens are cached and reused automatically for subsequent requests within the session window.

4. If the agent's USDC balance is insufficient, the tool call returns an error with the required amount, allowing the agent to fund its wallet and retry.

From the LLM's perspective — the agent calling `kraph_query` or `kraph_provision` — payment is invisible. The tool succeeds or fails. The USDC cost is reflected in the agent's wallet balance, which the agent can monitor via standard Solana SPL token queries.

***

## 14. Operator Economics

### 14.1 Node Requirements

| Resource  | Minimum                              | Recommended                          |
| --------- | ------------------------------------ | ------------------------------------ |
| CPU       | AMD EPYC (Milan+) or Intel Xeon (Sapphire Rapids+) with SEV-SNP or TDX | AMD EPYC Genoa or Intel Xeon with TDX |
| RAM       | 16 GB                                | 32 GB                                |
| CPU cores | 4                                    | 8                                    |
| Storage   | 100 GB SSD                           | 500 GB NVMe                          |
| Network   | 100 Mbps symmetric                   | 1 Gbps symmetric                     |
| TEE       | AMD SEV-SNP or Intel TDX (required)  | AMD SEV-SNP (mature, well-audited)   |
| Docker    | v24+                                 | v24+ (with BuildKit)                 |
| OS        | Linux, kernel 5.19+ (SEV-SNP guest support) | Ubuntu 22.04 LTS with latest HWE kernel |
| SOL stake | 1 SOL                                | 10+ SOL                              |

**Capacity estimation:**

Each active Supabase instance consumes approximately:

* 2 GB RAM (idle), scaling to 4+ GB under load

* 0.5 CPU cores (idle), scaling to 2+ cores under heavy query load

* 5-50 GB disk per instance (depending on data volume)

A 16 GB / 4-core node can comfortably host 4-5 active instances. A 32 GB / 8-core node can host 10-12. Operators should set their `capacity` field conservatively — overcommitting leads to performance degradation, poor reputation scores, and potentially slashing if instances become unresponsive.

### 14.2 Revenue Streams

**1. Hosting fees (escrow distribution):**

The primary and most predictable revenue stream. At the reference rate of $0.05/hour:

| Role         | Share | Per-instance hourly | Per-instance monthly |
| ------------ | ----- | ------------------- | -------------------- |
| Primary node | 70%   | $0.035              | $25.20               |
| Replica node | 15%   | $0.0075             | $5.40                |

A primary node running 8 instances earns ~$201/month from hosting alone. A node serving as replica for 20 instances earns ~$108/month.

**2. Query fees (x402 per-request):**

Revenue scales directly with usage. At $0.001 per query:

| Queries/day/instance | Daily revenue | Monthly revenue |
| -------------------- | ------------- | --------------- |
| 100                  | $0.10         | $3.00           |
| 1,000                | $1.00         | $30.00          |
| 10,000               | $10.00        | $300.00         |

Active instances with heavy query loads generate significant per-request revenue on top of the hosting base.

**3. IPFS storage fees:**

At $0.001/MB/month, with equal distribution among pin nodes:

| Pinned data | Monthly revenue (per pin node) |
| ----------- | ------------------------------ |
| 10 GB       | $3.33                          |
| 100 GB      | $33.33                         |
| 1 TB        | $333.33                        |

IPFS revenue is lower-margin but requires minimal resources (disk and bandwidth, no CPU-intensive database workloads).

### 14.3 Cost Structure

| Cost component                       | Monthly estimate (minimum spec) | Monthly estimate (recommended) |
| ------------------------------------ | ------------------------------- | ------------------------------ |
| Confidential VM / bare metal (SEV-SNP or TDX capable) | $60-120              | $120-300                       |
| Bandwidth (2 TB)                     | $0-20                           | $0-20                          |
| Electricity (self-hosted)            | $10-30                          | $15-50                         |
| SOL stake opportunity cost (7% APY)  | ~$1 (1 SOL)                     | ~$10 (10 SOL)                  |
| Solana transaction fees (heartbeats) | ~$3                             | ~$3                            |
| **Total**                            | **$74-174**                     | **$148-383**                   |

Note: TEE-capable hardware costs approximately 20-50% more than equivalent non-confidential VMs. This premium is offset by the ability to charge higher rates for hardware-enforced data confidentiality — a feature no centralized provider offers at the individual instance level.

### 14.4 Break-Even Analysis

At the reference pricing and minimum spec (~$130/month operating cost):

* **Conservative scenario:** 4 primary instances, 100 queries/day each = $100 hosting + $12 queries = $112/month. Near break-even.

* **Moderate scenario:** 6 primary instances, 500 queries/day each = $151 hosting + $90 queries = $241/month. Comfortable margin.

* **Active scenario:** 8 primary instances, 2000 queries/day each = $201 hosting + $480 queries = $681/month. Strong profitability.

Operators in regions with low infrastructure costs (self-hosted hardware, cheap electricity) can achieve profitability with fewer instances.

### 14.5 Incentive Alignment

The placement algorithm directly rewards good behavior:

* **Higher stake** --> higher `stake_score` --> more instance allocations --> more revenue. This incentivizes operators to stake beyond the minimum.

* **Better uptime** --> higher `uptime_score` --> more instance allocations --> more revenue. This incentivizes reliable infrastructure and operational discipline.

* **Honest operation** --> zero slashing events --> full stake preserved --> continued operation. Misbehavior destroys the operator's ability to earn.

Slashing penalties are calibrated to exceed the revenue from misbehavior:

| Violation                  | Slash % | Cost at 10 SOL (~$1,500) | Comparison                        |
| -------------------------- | ------- | ------------------------ | --------------------------------- |
| Downtime > 1 hour          | 10%     | $150                     | Exceeds weeks of hosting revenue  |
| Data corruption (provable) | 50%     | $750                     | Exceeds months of hosting revenue |
| WAL chain break            | 50%     | $750                     | Exceeds months of hosting revenue |

A rational operator never benefits from misbehavior because the expected slashing cost exceeds the expected gain from any form of cheating.

### 14.6 Operator Dashboard

The node software includes a local web dashboard (bound to 127.0.0.1 by default, not exposed to the internet) providing:

* **Instance overview:** Active instances, resource utilization per instance (CPU, memory, disk, network), instance age and expiration.

* **Revenue tracking:** Historical earnings by stream (hosting, queries, IPFS), projected monthly revenue, payment distribution history.

* **Health monitoring:** Heartbeat status, uptime score, time since last heartbeat, connectivity to Solana RPC.

* **Replication status:** For instances where the node serves as replica — WAL segment count, lag behind primary, last segment received.

* **IPFS status:** Pinned CIDs, total storage used, pin health (reachability from gateway).

* **Slashing history:** Any past slashing events, with proof details and stake impact.

* **Configuration:** Pricing adjustments, capacity settings, IPFS enable/disable, RPC endpoint configuration.

***

## 15. Roadmap

### Phase 1: Core Protocol + TEE Foundation

**Goal:** A functional end-to-end system with hardware-enforced data confidentiality from day one. An agent with a Solana wallet can provision a Supabase instance inside a confidential VM, run queries, and pay for it — no human in the loop, no trust in the node operator required for data confidentiality.

**Deliverables:**

* **On-chain program** deployed to Solana devnet. Account structures: `NodeRecord`, `InstanceRecord`, `PaymentEscrow`. Instructions: `register_node`, `deregister_node`, `heartbeat`, `allocate_instance`, `deposit_payment`, `distribute_payment`.

* **Node software:** Docker-based Supabase stack management inside confidential VMs (AMD SEV-SNP / Intel TDX). Pre-warmed container pool (1-2 idle stacks). Instance provisioning API. Heartbeat loop (60-second interval). Resource isolation via cgroups. TEE attestation report generation.

* **TEE attestation:** AMD SEV-SNP and Intel TDX support. Remote attestation verification by agents before provisioning via `kraph_attest`. Attestation-gated Key Broker Service (KBS) for DEK delivery. VM measurement published on-chain. TEE capability verification during node registration.

* **Gateway MCP server:** SIWS authentication (challenge/verify flow). Node discovery from on-chain registry. Placement algorithm (capacity 0.4, uptime 0.3, stake 0.2, jitter 0.1). Both stdio and StreamableHTTP transports.

* **MCP tools:** `kraph_provision`, `kraph_query`, `kraph_destroy`, `kraph_list`, `kraph_extend`, `kraph_migrate`, `kraph_attest`.

* **x402 integration:** Per-request payment using `@x402/svm`. Local facilitator on each node. Optimistic execution for low-value queries. Payment session tokens (60s window).

* **Encryption:** Ed25519-to-x25519 key derivation. HKDF master key generation. Envelope encryption of DEK. Attestation-gated DEK delivery via KBS. pgcrypto-based column encryption (Phase 1 at-rest solution).

* **WAL hash chain:** Hash chain computation over WAL segments. On-chain commitment of chain head via `commit_merkle_root`.

* **Edge Functions:** `supabase/edge-runtime` (Deno-based) inside the confidential VM. `kraph_deploy_function` tool. Content-addressed function deployment with on-chain SHA-256 hash recording. V8 isolate sandboxing inside TEE.

**Not in Phase 1:** Replication, Merkle trees, slashing, IPFS pinning, Privy integration, LUKS encryption, cross-replica verification.

### Phase 2: Resilience

**Goal:** Production-grade reliability and security. Data survives node failures. Misbehavior is detected and punished. Full-stack deployment including frontends.

**Deliverables:**

* **Encrypted WAL replication** to 2-3 replica nodes. AES-256-GCM streaming encryption in 64KB chunks. Replica selection with geographic diversity heuristic.

* **Automated recovery:** Failure detection via heartbeat monitoring. Replica promotion to primary. Attestation-gated DEK delivery to new primary via KBS. WAL replay and instance reconstruction. On-chain `InstanceRecord` update.

* **Merkle state commitments:** Incremental Merkle tree (RocksDB-backed). Periodic root commitment on-chain (every 10 min / 1000 txns). `kraph_verify` tool for agents. Merkle proof generation and verification.

* **Stake slashing:** `slash_node` instruction. Three proof types: `Downtime`, `DataCorruption`, `WalChainBreak`. Reporter bounty (50% of slashed stake).

* **Privy integration:** Server wallet authentication. MPC-based signing for SIWS challenges. Seamless integration with existing MCP tools.

* **IPFS pinning:** `PinRecord` on-chain account. `kraph_pin` and `kraph_unpin` tools. Kubo daemon on IPFS-enabled nodes. Pin-by-CID and upload-and-pin modes. 3-node redundancy. x402 payment for initial pin, escrow for ongoing storage.

* **LUKS/dm-crypt volume encryption** replacing pgcrypto. Full-volume encryption with DEK as LUKS passphrase.

* **Anchor program deployment to Solana mainnet.** Audit of on-chain program by a reputable firm.

### Phase 3: Scale and Advanced Features

**Goal:** Global scale, advanced collaboration features, and a thriving operator ecosystem.

**Deliverables:**

* **Cross-replica verification:** Automated spot-check queries (every 5 minutes per instance). Gateway-initiated verification with scoped DEK delegation inside TEE. Automated fraud proof generation and submission.

* **Multi-region support:** Region-aware placement algorithm. Latency-optimized node selection (agent specifies preferred region). Replica placement across regions for disaster resilience. TEE attestation of geographic location claims.

* **Agent-to-agent data sharing:** Scoped, encrypted data sharing between agents. An agent can grant another agent read access to specific tables or rows, with the sharing policy enforced inside the TEE. Shared DEK sub-keys derived per-grantee.

* **Bazaar discovery:** Decentralized marketplace where operators publish pricing, SLAs, hardware specs, and TEE attestation history. Agents compare offers and select nodes based on price/performance/trust criteria.

* **Operator dashboard:** Full web UI for monitoring, revenue tracking, configuration, and alerts. TEE health monitoring and attestation history. Accessible via Tor for operator privacy.

* **SDK and documentation:** Client libraries for Python, TypeScript, and Rust. Integration guides for LangChain, CrewAI, AutoGPT, and other agent frameworks. API reference and protocol specification.

* **Governance:** Protocol parameter adjustment (minimum stake, slashing percentages, commitment intervals) via on-chain voting. Upgrade authority transition to a multisig or DAO structure.

***

## Appendix A: Glossary

| Term             | Definition                                                                                                                                                                                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Agent**        | An autonomous AI system that operates without continuous human supervision, identified by a Solana keypair.                                                                                         |
| **CID**          | Content Identifier. A self-describing, content-addressed hash used in IPFS. CIDv1 includes a multicodec prefix and multihash.                                                                       |
| **Crank**        | A permissionless on-chain transaction that triggers a periodic protocol operation (e.g., payment distribution). Anyone can submit it; the protocol logic determines whether the operation executes. |
| **DEK**          | Data Encryption Key. A random 256-bit symmetric key used for encrypting instance data. One DEK per instance.                                                                                        |
| **Edge Function** | A TypeScript/JavaScript function deployed via `supabase/edge-runtime` (Deno-based). Runs in an isolated V8 sandbox inside the TEE. Content-addressed via SHA-256 hash recorded on-chain.           |
| **Escrow**       | A program-owned on-chain account holding funds that are released according to protocol-defined rules, not by any individual party.                                                                  |
| **Facilitator**  | An x402 component that verifies payment transactions and submits them to the blockchain. Each Kraph node runs a local facilitator.                                                                 |
| **Heartbeat**    | A periodic on-chain transaction (every 60 seconds) proving a node is operational. Missed heartbeats trigger status changes and potential slashing.                                                  |
| **KBS**          | Key Broker Service. An attestation-gated service that releases the DEK only to verified confidential VMs. The agent verifies the TEE attestation report before releasing the key.                   |
| **MCP**          | Model Context Protocol. An open standard for exposing tools and resources to AI models, supporting both local (stdio) and remote (HTTP) transports.                                                 |
| **Merkle proof** | A set of sibling hashes that, combined with a leaf hash, allows recomputation of the Merkle root — proving that specific data is included in the committed tree.                                    |
| **PDA**          | Program Derived Address. A Solana account address deterministically derived from seeds and a program ID. PDAs are owned by programs, not by any keypair.                                            |
| **SIWS**         | Sign-In with Solana. An authentication standard where a wallet signs a structured message to prove ownership without revealing the private key.                                                     |
| **SEV-SNP**      | AMD Secure Encrypted Virtualization — Secure Nested Paging. Hardware feature that encrypts VM memory and provides attestation, preventing the host/hypervisor from reading guest VM memory.          |
| **Slashing**     | Protocol-enforced confiscation of a portion of a node's staked SOL as punishment for provable misbehavior.                                                                                          |
| **TDX**          | Intel Trust Domain Extensions. Hardware feature providing VM-level isolation with encrypted memory and remote attestation, similar in purpose to AMD SEV-SNP.                                        |
| **TEE**          | Trusted Execution Environment. Hardware-based isolation that protects code and data from the host OS, hypervisor, and physical access. In Kraph, refers to AMD SEV-SNP or Intel TDX confidential VMs. |
| **WAL**          | Write-Ahead Log. Postgres's durability mechanism: all data modifications are first written to the WAL before being applied to data files, enabling crash recovery and replication.                  |
| **x402**         | An HTTP payment protocol that uses the 402 Payment Required status code. The server specifies payment requirements; the client signs a payment transaction and retries.                             |

## Appendix B: On-Chain Account Sizes

| Account Type   | Estimated Size (bytes) | Rent-Exempt Deposit (SOL) |
| -------------- | ---------------------- | ------------------------- |
| NodeRecord     | ~512                   | ~0.00356                  |
| InstanceRecord | ~384                   | ~0.00267                  |
| PaymentEscrow  | ~128                   | ~0.00089                  |
| PinRecord      | ~320                   | ~0.00222                  |

Total on-chain cost per provisioned instance (InstanceRecord + PaymentEscrow): ~0.00356 SOL. The NodeRecord is created once per operator and shared across all instances on that node.

## Appendix C: References

1. Supabase Self-Hosting Architecture. <https://supabase.com/docs/guides/self-hosting>

2. x402 Protocol Specification. <https://www.x402.org/>

3. Solana Anchor Framework. <https://www.anchor-lang.com/>

4. Sign-In with Solana (SIWS). <https://github.com/phantom/sign-in-with-solana>

5. IPFS Content Addressing. <https://docs.ipfs.tech/concepts/content-addressing/>

6. AMD SEV-SNP — Strengthening VM Isolation with Integrity Protection and More. <https://www.amd.com/en/developer/sev.html>

7. Intel TDX (Trust Domain Extensions). <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html>

8. Model Context Protocol Specification. <https://modelcontextprotocol.io/>

9. Privy Server Wallets Documentation. <https://docs.privy.io/>

10. PgBouncer — Lightweight Connection Pooler for PostgreSQL. <https://www.pgbouncer.org/>

11. LUKS / cryptsetup Disk Encryption. <https://gitlab.com/cryptsetup/cryptsetup>

12. RFC 7748 — Elliptic Curves for Security (x25519). <https://datatracker.ietf.org/doc/html/rfc7748>

13. RFC 5869 — HKDF (HMAC-based Key Derivation Function). <https://datatracker.ietf.org/doc/html/rfc5869>

14. NIST SP 800-38D — AES-GCM. <https://csrc.nist.gov/publications/detail/sp/800-38d/final>

15. Supabase Edge Runtime. <https://github.com/supabase/edge-runtime>

***

*Kraph is open-source software. Protocol specifications, node software, and client libraries are published under the MIT license.*

⠀