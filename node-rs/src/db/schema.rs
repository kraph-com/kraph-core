/// SQL statements executed once on database creation / migration.
///
/// All `CREATE` statements are idempotent (`IF NOT EXISTS`). The `ALTER`
/// statements are run after the creates and any failure caused by the column
/// already existing is silently ignored — see `Database::new`.

pub const CREATE_INSTANCES: &str = r#"
CREATE TABLE IF NOT EXISTS instances (
    id                  TEXT PRIMARY KEY NOT NULL,
    wallet_pubkey       TEXT NOT NULL,
    name                TEXT,
    status              TEXT NOT NULL DEFAULT 'provisioning',
    kong_port           INTEGER NOT NULL,
    postgres_port       INTEGER NOT NULL,
    gotrue_port         INTEGER NOT NULL,
    realtime_port       INTEGER NOT NULL,
    storage_port        INTEGER NOT NULL,
    studio_port         INTEGER NOT NULL,
    analytics_port      INTEGER NOT NULL,
    meta_port           INTEGER NOT NULL,
    functions_port      INTEGER NOT NULL,
    anon_key            TEXT NOT NULL,
    service_role_key    TEXT NOT NULL,
    jwt_secret          TEXT NOT NULL,
    postgres_password   TEXT NOT NULL,
    dashboard_password  TEXT NOT NULL,
    url                 TEXT NOT NULL,
    studio_url          TEXT NOT NULL,
    compose_project_name TEXT NOT NULL,
    instance_dir        TEXT NOT NULL,
    cpuset_cpus         TEXT,
    wal_encryption_key  TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at          TEXT,
    destroyed_at        TEXT,
    /* Idle-suspend lifecycle. Compose containers are stopped (state
       'suspended') after SUPABA_IDLE_SUSPEND_SECS without proxy traffic
       and brought back ('starting' → 'running') on the first hit. The
       `status` column above tracks longer-term lifecycle (provisioning /
       active / destroyed); `lifecycle_state` is the live RAM state. */
    lifecycle_state     TEXT NOT NULL DEFAULT 'running',
    /* Unix epoch seconds — bumped by every proxied hit. NULL on a fresh
       provision until the first real request lands. */
    last_seen_at        INTEGER,
    /* Unix epoch seconds — when set and > now(), the idle tracker skips
       this row. Bumped by the gateway after a successful kraph_pin_instance
       payment. NULL = not pinned, idle-suspend applies normally. */
    pinned_until        INTEGER
);
"#;

pub const CREATE_PORT_ALLOCATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS port_allocations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id  TEXT,
    base_port    INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE SET NULL
);
"#;

pub const CREATE_WAL_SEGMENTS: &str = r#"
CREATE TABLE IF NOT EXISTS wal_segments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id    TEXT NOT NULL,
    segment_name   TEXT NOT NULL,
    hash           TEXT NOT NULL,
    previous_hash  TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    size           INTEGER NOT NULL,
    chain_index    INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (instance_id) REFERENCES instances(id),
    UNIQUE (instance_id, segment_name)
);
"#;

pub const CREATE_REPLICA_SHIPMENTS: &str = r#"
CREATE TABLE IF NOT EXISTS replica_shipments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id           TEXT NOT NULL,
    replica_node_endpoint TEXT NOT NULL,
    segment_name          TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending',
    attempts              INTEGER NOT NULL DEFAULT 0,
    last_attempt_at       TEXT,
    confirmed_at          TEXT,
    FOREIGN KEY (instance_id) REFERENCES instances(id),
    UNIQUE (instance_id, replica_node_endpoint, segment_name)
);
"#;

/// Per-instance replica registry. The gateway calls
/// `POST /instances/:id/replicas` after placement; node A learns about node B
/// here, then enqueues a shipment for every WAL segment that arrives.
pub const CREATE_INSTANCE_REPLICAS: &str = r#"
CREATE TABLE IF NOT EXISTS instance_replicas (
    instance_id           TEXT NOT NULL,
    replica_node_endpoint TEXT NOT NULL,
    added_at              TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (instance_id, replica_node_endpoint),
    FOREIGN KEY (instance_id) REFERENCES instances(id)
);
"#;

/// Replica-side index of received segments. Same shape as wal_segments but on
/// the receiving node. Lets the receiver enforce hash-chain continuity and
/// surface a `GET /replication/:instance_id/segments` listing.
pub const CREATE_REPLICA_SEGMENTS: &str = r#"
CREATE TABLE IF NOT EXISTS replica_segments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id    TEXT NOT NULL,
    segment_name   TEXT NOT NULL,
    hash           TEXT NOT NULL,
    previous_hash  TEXT NOT NULL,
    stored_path    TEXT NOT NULL,
    size           INTEGER NOT NULL,
    chain_index    INTEGER NOT NULL DEFAULT 0,
    received_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (instance_id, segment_name)
);
"#;

/// Per-instance edge-function environment variables. Scoped to the Supabase
/// edge-runtime container — rewritten to `{instance_dir}/volumes/functions/.env`
/// and forced-recreated via docker compose when mutated. Values are stored
/// plaintext on devnet (HTTPS in transit, encrypted volume at rest); on
/// mainnet the SEV-SNP enclave seals the backing storage.
///
/// `protected` distinguishes user-paste-in secrets (set via the dashboard
/// UI by the human, e.g. STRIPE_SECRET_KEY) from agent-set vars (set via
/// kraph_set_env). The functions container sees both at runtime; the
/// READ surface (kraph_list_env via the gateway) hides values for
/// protected entries — an agent can REFERENCE the key by name in code
/// but never sees the plaintext.
pub const CREATE_INSTANCE_ENV: &str = r#"
CREATE TABLE IF NOT EXISTS instance_env (
    instance_id    TEXT NOT NULL,
    key            TEXT NOT NULL,
    value          TEXT NOT NULL,
    protected      INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (instance_id, key),
    FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE
);
"#;

/// Migration: add protected column to existing instance_env tables. Idempotent
/// via the IF NOT EXISTS handling that runs each `Database::new`. Older rows
/// default to protected=0 (agent-set), which is the safe default — they
/// remain readable by the agent as before.
pub const ALTER_INSTANCE_ENV_ADD_PROTECTED: &str = r#"
ALTER TABLE instance_env ADD COLUMN protected INTEGER NOT NULL DEFAULT 0
"#;

/// Idempotent migrations applied in order during `Database::new`.
pub const MIGRATIONS: &[&str] = &[
    CREATE_INSTANCES,
    CREATE_PORT_ALLOCATIONS,
    CREATE_WAL_SEGMENTS,
    CREATE_REPLICA_SHIPMENTS,
    CREATE_INSTANCE_REPLICAS,
    CREATE_REPLICA_SEGMENTS,
    CREATE_INSTANCE_ENV,
];

/// `ALTER TABLE` statements applied after creates. Each is wrapped in
/// individual error handling — failures from "duplicate column name" or
/// "duplicate table" are tolerated so the binary can start cleanly against
/// older databases.
pub const SOFT_MIGRATIONS: &[&str] = &[
    // Backfill column for databases created before wal_encryption_key was added.
    "ALTER TABLE instances ADD COLUMN wal_encryption_key TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE wal_segments ADD COLUMN chain_index INTEGER NOT NULL DEFAULT 0",
    // Backfill `protected` flag on instance_env for the user-only secrets path.
    "ALTER TABLE instance_env ADD COLUMN protected INTEGER NOT NULL DEFAULT 0",
    // Idle-suspend lifecycle columns (default 'running' so existing rows
    // are treated as live and won't be eligible for suspend until they
    // accrue a last_seen_at via the proxy paths).
    "ALTER TABLE instances ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'running'",
    "ALTER TABLE instances ADD COLUMN last_seen_at INTEGER",
    "ALTER TABLE instances ADD COLUMN pinned_until INTEGER",
    // Next.js service: per-instance optional Node sidecar that joins the
    // instance's docker network and runs `node server.js` from a Next.js
    // standalone build. Port is allocated from the same pool as the
    // Supabase ports. `nextjs_service_status` is one of:
    //   NULL     — no service deployed (the default, ipfs-pinned frontends)
    //   deploying
    //   running
    //   failed
    "ALTER TABLE instances ADD COLUMN nextjs_service_port INTEGER",
    "ALTER TABLE instances ADD COLUMN nextjs_service_status TEXT",
    "ALTER TABLE instances ADD COLUMN nextjs_service_deployed_at INTEGER",
];
