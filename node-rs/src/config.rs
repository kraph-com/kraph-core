use serde::Deserialize;
use std::path::PathBuf;

/// Per-instance memory budget used by the auto-derive cap. A running
/// Supabase stack (Postgres + Kong + GoTrue + PostgREST + Realtime +
/// Storage + Studio + Analytics + meta + functions) sits at ~1.2-1.8 GB
/// resident on average, with Postgres tuned for ~512 MB shared_buffers
/// per the template's postgresql.conf. 1800 MB is a defensive single-
/// instance allowance — 1024 would let us pack more but invites OOM
/// once an instance gets warm.
const PER_INSTANCE_RAM_MB: usize = 1800;

/// Reserve at LEAST this much RAM for the OS + node-rs + kubo + docker
/// engine + warm-pool placeholders before counting instance slots. On
/// small VMs (e.g. n2d-standard-4 with 16 GB) this is the difference
/// between "9 instances safely" and "9 instances then OOMing kraph
/// itself when the 9th boots."
const SYSTEM_OVERHEAD_RAM_MB_MIN: usize = 2048;

/// Hard floor / ceiling so the auto-derive can't return weird values
/// on tiny laptops or extreme machines. Operator can always override
/// via SUPABA_MAX_INSTANCES to escape both bounds.
const AUTO_MAX_INSTANCES_FLOOR: usize = 1;
const AUTO_MAX_INSTANCES_CEILING: usize = 32;

/// Read total system RAM in MB from /proc/meminfo. Returns None on
/// non-Linux or when the file isn't readable (CI containers, weird
/// jails). Caller falls back to a conservative default.
fn detect_total_ram_mb() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: usize = rest.trim().split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Detect the number of CPUs available to the process.
fn detect_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

/// Compute a reasonable max_instances cap from host resources.
///
/// Formula: `min(memCap, cpuCap)` where:
///   - memCap = max(0, (total_ram - max(2GB, total_ram/8)) / 1800MB)
///   - cpuCap = cores * 2  (overcommit OK; Postgres is mostly idle when
///                          nobody's querying)
///
/// Logged at startup so operators can see why the cap is what it is.
/// Returns (cap, mem_mb, cores, mem_cap, cpu_cap) so the caller can
/// emit a structured log line.
pub fn auto_derive_max_instances() -> (usize, usize, usize, usize, usize) {
    let mem_mb = detect_total_ram_mb().unwrap_or(8192);
    let cores = detect_cpu_cores();

    // Reserve 12.5% of RAM or 2 GB, whichever is bigger, for system
    // overhead (kernel, docker engine, kubo, node-rs itself).
    let reserved = std::cmp::max(SYSTEM_OVERHEAD_RAM_MB_MIN, mem_mb / 8);
    let usable = mem_mb.saturating_sub(reserved);
    let mem_cap = usable / PER_INSTANCE_RAM_MB;
    let cpu_cap = cores.saturating_mul(2);

    let raw = std::cmp::min(mem_cap, cpu_cap);
    let bounded = raw
        .max(AUTO_MAX_INSTANCES_FLOOR)
        .min(AUTO_MAX_INSTANCES_CEILING);
    (bounded, mem_mb, cores, mem_cap, cpu_cap)
}

/// Node configuration loaded from environment variables.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Base directory for all persistent data (DB, instance dirs, WAL).
    pub data_dir: PathBuf,
    /// Public hostname / IP this node is reachable at.
    pub hostname: String,
    /// Port the HTTP API listens on.
    pub api_port: u16,
    /// Start of the port range allocated to Supabase instances.
    pub port_range_start: u16,
    /// End of the port range (inclusive).
    pub port_range_end: u16,

    /// Maximum concurrent Supabase instances.
    pub max_instances: usize,
    /// Number of pre-warmed instances to keep ready.
    pub warm_pool_size: usize,

    /// Solana JSON-RPC endpoint.
    pub solana_rpc_url: String,
    /// Solana network label (mainnet-beta | devnet | localnet).
    pub solana_network: String,
    /// Path to the operator Solana keypair JSON file.
    pub operator_keypair_path: PathBuf,

    /// Facilitator service URL for payment verification.
    pub facilitator_url: String,
    /// USDC SPL token mint address.
    pub usdc_mint: String,
    /// Gateway operator wallet pubkey (base58). Used as the `expected_signer`
    /// for endpoints that only the gateway should call — currently just
    /// `POST /instances/:id/pin`, where free access would defeat the
    /// $10/month pin paywall. `None` means "don't enforce operator
    /// sigauth" (early-rollout convenience; production should set
    /// `SUPABA_OPERATOR_ADDRESS`).
    pub operator_address: Option<String>,

    /// Seconds between heartbeat pings to the facilitator.
    pub heartbeat_interval_secs: u64,
    /// Seconds between expired-instance cleanup sweeps.
    pub cleanup_interval_secs: u64,
    /// Seconds an instance can go without any proxied traffic before the
    /// idle tracker docker-compose-stops it. `0` (the default) disables
    /// the idle tracker entirely — important during the rollout because
    /// the gateway needs the matching resume-on-demand path before
    /// suspending instances is safe (otherwise a suspended instance is
    /// just a broken endpoint). Set to a non-zero value (e.g. `900`
    /// = 15 min) ONLY after the gateway can resume suspended instances.
    pub idle_suspend_secs: u64,
    /// Seconds between idle-tracker sweeps. Cheap, runs whether or not
    /// the tracker is enabled — when disabled it's a no-op.
    pub idle_sweep_interval_secs: u64,
    /// Seconds between WAL archive runs.
    pub wal_archive_interval_secs: u64,
    /// Seconds between encrypted WAL replication runs (process_new_segments
    /// + ship_pending_segments). Should be ≤ wal_archive_interval_secs.
    pub wal_replication_interval_secs: u64,

    /// Docker daemon socket path.
    pub docker_socket_path: String,
    /// Total CPU cores available for instance allocation.
    pub available_cpu_cores: usize,
    /// Geographic region tag (e.g. "us-east-1").
    pub region: String,

    /// Path to the Supabase docker-compose template directory.
    pub supabase_template_path: PathBuf,

    /// TEE backend: "sev-snp", "tdx", or "none".
    pub tee_backend: String,
    /// Key Broker Service URL for remote attestation.
    pub kbs_url: String,
    /// Path to file containing the expected TEE measurement hex.
    pub expected_measurement_path: PathBuf,
    /// Whether attestation is mandatory for provisioning.
    pub require_attestation: bool,

    /// Enable TLS on the API server.
    pub tls_enabled: bool,
    /// Path to TLS certificate PEM.
    pub tls_cert_path: PathBuf,
    /// Path to TLS private key PEM.
    pub tls_key_path: PathBuf,

    /// HMAC secret shared with the gateway. Used to mint and verify the
    /// short-lived tokens that gate access to the per-instance Supabase
    /// Studio reverse proxy. MUST match the gateway's
    /// `SUPABA_STUDIO_PROXY_SECRET`. When empty, the studio proxy refuses
    /// every request — this is the safe default until an operator sets it.
    pub studio_proxy_secret: String,
    /// Wildcard subdomain apex for Studio access (e.g. "studio.kraph.network").
    /// Browsers reach `<instance_id>.<apex>`; Caddy forwards through node-rs
    /// for auth. The cookie issued at /__kraph/studio/exchange is scoped to
    /// `Domain=.<apex>` so it's valid across every `<id>.<apex>` host.
    /// MUST also be set on the gateway as the same value.
    pub studio_apex: String,

    /// Local Kubo (go-ipfs) HTTP RPC API endpoint. Used by the IPFS pin
    /// handler to add + pin content. Default assumes a Kubo container
    /// running alongside node-rs with the API bound to 127.0.0.1:5001.
    pub kubo_api_url: String,
    /// Local Kubo gateway endpoint, used to serve content back to clients
    /// who hit `/ipfs/<cid>` on this node.
    pub kubo_gateway_url: String,

    /// Public DNS suffix the gateway proxies under (e.g. "kraph.com"). When
    /// set, GoTrue's SITE_URL / API_EXTERNAL_URL on each provisioned
    /// instance is rendered as `https://<id>.<public_host>/api` so magic-
    /// link emails contain the public proxied URL, not the raw node:port.
    /// Empty string falls back to `http://hostname:kong_port` (legacy /
    /// pre-subdomain mode).
    pub public_host: String,

    /// Operator-shared SMTP relay used by every instance's GoTrue. When
    /// `smtp_host` is empty, GoTrue silently degrades to in-memory
    /// autoconfirm — usable, but magic links / password reset / signup
    /// confirmation / email change all fail to send mail. Default points
    /// at Resend's relay so `RESEND_API_KEY` is enough to wire it up.
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_admin_email: String,
    pub smtp_sender_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/supaba"),
            hostname: "127.0.0.1".into(),
            api_port: 3100,
            port_range_start: 10000,
            port_range_end: 20000,
            // Conservative fallback used only by tests / Default::default()
            // — production startup goes through Config::from_env which
            // either reads SUPABA_MAX_INSTANCES or auto-derives via
            // auto_derive_max_instances().
            max_instances: 5,
            warm_pool_size: 0,
            solana_rpc_url: "https://api.devnet.solana.com".into(),
            solana_network: "devnet".into(),
            operator_keypair_path: PathBuf::from("/etc/supaba/operator.json"),
            facilitator_url: "http://localhost:8080".into(),
            usdc_mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            operator_address: None,
            heartbeat_interval_secs: 300,
            cleanup_interval_secs: 60,
            // Disabled by default — see field doc.
            idle_suspend_secs: 0,
            idle_sweep_interval_secs: 60,
            wal_archive_interval_secs: 300,
            wal_replication_interval_secs: 10,
            docker_socket_path: "/var/run/docker.sock".into(),
            available_cpu_cores: 4,
            region: "unknown".into(),
            supabase_template_path: PathBuf::from("/opt/supaba/template"),
            tee_backend: "none".into(),
            kbs_url: String::new(),
            expected_measurement_path: PathBuf::new(),
            require_attestation: false,
            tls_enabled: false,
            tls_cert_path: PathBuf::new(),
            tls_key_path: PathBuf::new(),
            studio_proxy_secret: String::new(),
            studio_apex: String::new(),
            kubo_api_url: "http://127.0.0.1:5001".into(),
            kubo_gateway_url: "http://127.0.0.1:8080".into(),
            public_host: String::new(),
            smtp_host: "smtp.resend.com".into(),
            smtp_port: 465,
            smtp_user: "resend".into(),
            smtp_pass: String::new(),
            smtp_admin_email: String::new(),
            smtp_sender_name: "kraph".into(),
        }
    }
}

impl Config {
    /// Build configuration from environment variables.
    ///
    /// Every field can be overridden by setting the SCREAMING_SNAKE_CASE
    /// version of its name with a `SUPABA_` prefix, e.g.
    /// `SUPABA_DATA_DIR=/data supaba-node`.
    pub fn from_env() -> anyhow::Result<Self> {
        let defaults = Config::default();

        let env_or = |key: &str, fallback: String| -> String {
            std::env::var(key).unwrap_or(fallback)
        };

        let env_or_u16 = |key: &str, fallback: u16| -> u16 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(fallback)
        };

        let env_or_usize = |key: &str, fallback: usize| -> usize {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(fallback)
        };

        let env_or_u64 = |key: &str, fallback: u64| -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(fallback)
        };

        let env_or_bool = |key: &str, fallback: bool| -> bool {
            std::env::var(key)
                .ok()
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(fallback)
        };

        let env_or_path = |key: &str, fallback: PathBuf| -> PathBuf {
            std::env::var(key).map(PathBuf::from).unwrap_or(fallback)
        };

        Ok(Config {
            data_dir: env_or_path("SUPABA_DATA_DIR", defaults.data_dir),
            hostname: env_or("SUPABA_HOSTNAME", defaults.hostname),
            api_port: env_or_u16("SUPABA_API_PORT", defaults.api_port),
            port_range_start: env_or_u16("SUPABA_PORT_RANGE_START", defaults.port_range_start),
            port_range_end: env_or_u16("SUPABA_PORT_RANGE_END", defaults.port_range_end),
            // Cap: explicit env > auto-derived from /proc/meminfo + nproc.
            // Operator override via SUPABA_MAX_INSTANCES bypasses the
            // resource-aware computation entirely.
            max_instances: match std::env::var("SUPABA_MAX_INSTANCES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
            {
                Some(n) => n,
                None => {
                    let (cap, mem_mb, cores, mem_cap, cpu_cap) =
                        auto_derive_max_instances();
                    tracing::info!(
                        ram_mb = mem_mb,
                        cores,
                        mem_cap,
                        cpu_cap,
                        cap,
                        "auto-derived SUPABA_MAX_INSTANCES (set the env var to override)"
                    );
                    cap
                }
            },
            warm_pool_size: env_or_usize("SUPABA_WARM_POOL_SIZE", defaults.warm_pool_size),
            solana_rpc_url: env_or("SUPABA_SOLANA_RPC_URL", defaults.solana_rpc_url),
            solana_network: env_or("SUPABA_SOLANA_NETWORK", defaults.solana_network),
            operator_keypair_path: env_or_path(
                "SUPABA_OPERATOR_KEYPAIR_PATH",
                defaults.operator_keypair_path,
            ),
            facilitator_url: env_or("SUPABA_FACILITATOR_URL", defaults.facilitator_url),
            usdc_mint: env_or("SUPABA_USDC_MINT", defaults.usdc_mint),
            operator_address: std::env::var("SUPABA_OPERATOR_ADDRESS").ok().and_then(|v| {
                let t = v.trim();
                if t.is_empty() { None } else { Some(t.to_string()) }
            }),
            heartbeat_interval_secs: env_or_u64(
                "SUPABA_HEARTBEAT_INTERVAL_SECS",
                defaults.heartbeat_interval_secs,
            ),
            cleanup_interval_secs: env_or_u64(
                "SUPABA_CLEANUP_INTERVAL_SECS",
                defaults.cleanup_interval_secs,
            ),
            idle_suspend_secs: env_or_u64(
                "SUPABA_IDLE_SUSPEND_SECS",
                defaults.idle_suspend_secs,
            ),
            idle_sweep_interval_secs: env_or_u64(
                "SUPABA_IDLE_SWEEP_INTERVAL_SECS",
                defaults.idle_sweep_interval_secs,
            ),
            wal_archive_interval_secs: env_or_u64(
                "SUPABA_WAL_ARCHIVE_INTERVAL_SECS",
                defaults.wal_archive_interval_secs,
            ),
            wal_replication_interval_secs: env_or_u64(
                "SUPABA_WAL_REPLICATION_INTERVAL_SECS",
                defaults.wal_replication_interval_secs,
            ),
            docker_socket_path: env_or("SUPABA_DOCKER_SOCKET_PATH", defaults.docker_socket_path),
            available_cpu_cores: env_or_usize(
                "SUPABA_AVAILABLE_CPU_CORES",
                defaults.available_cpu_cores,
            ),
            region: env_or("SUPABA_REGION", defaults.region),
            supabase_template_path: env_or_path(
                "SUPABA_SUPABASE_TEMPLATE_PATH",
                defaults.supabase_template_path,
            ),
            tee_backend: env_or("SUPABA_TEE_BACKEND", defaults.tee_backend),
            kbs_url: env_or("SUPABA_KBS_URL", defaults.kbs_url),
            expected_measurement_path: env_or_path(
                "SUPABA_EXPECTED_MEASUREMENT_PATH",
                defaults.expected_measurement_path,
            ),
            require_attestation: env_or_bool(
                "SUPABA_REQUIRE_ATTESTATION",
                defaults.require_attestation,
            ),
            tls_enabled: env_or_bool("SUPABA_TLS_ENABLED", defaults.tls_enabled),
            tls_cert_path: env_or_path("SUPABA_TLS_CERT_PATH", defaults.tls_cert_path),
            tls_key_path: env_or_path("SUPABA_TLS_KEY_PATH", defaults.tls_key_path),
            studio_proxy_secret: env_or(
                "SUPABA_STUDIO_PROXY_SECRET",
                defaults.studio_proxy_secret,
            ),
            studio_apex: env_or("SUPABA_STUDIO_APEX", defaults.studio_apex),
            kubo_api_url: env_or("SUPABA_KUBO_API_URL", defaults.kubo_api_url),
            kubo_gateway_url: env_or(
                "SUPABA_KUBO_GATEWAY_URL",
                defaults.kubo_gateway_url,
            ),
            public_host: env_or("SUPABA_PUBLIC_HOST", defaults.public_host),
            smtp_host: env_or("SUPABA_SMTP_HOST", defaults.smtp_host),
            smtp_port: env_or_u16("SUPABA_SMTP_PORT", defaults.smtp_port),
            smtp_user: env_or("SUPABA_SMTP_USER", defaults.smtp_user),
            // Accept either SUPABA_SMTP_PASS directly or a RESEND_API_KEY
            // shortcut — same value, less for the operator to remember.
            smtp_pass: std::env::var("SUPABA_SMTP_PASS")
                .ok()
                .or_else(|| std::env::var("RESEND_API_KEY").ok())
                .unwrap_or(defaults.smtp_pass),
            smtp_admin_email: env_or("SUPABA_SMTP_ADMIN_EMAIL", defaults.smtp_admin_email),
            smtp_sender_name: env_or("SUPABA_SMTP_SENDER_NAME", defaults.smtp_sender_name),
        })
    }

    /// Base port block size: number of consecutive ports allocated per instance.
    /// Kong(8000), Postgres(5432), GoTrue(9999), Realtime(4000), Storage(5000),
    /// Studio(3000), Analytics(4000), Meta(8080), Functions(9000) = 9 ports.
    /// We allocate blocks of 10 for headroom.
    pub const PORTS_PER_INSTANCE: u16 = 10;
}
