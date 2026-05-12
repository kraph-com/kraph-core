pub mod schema;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Env var encryption
// ---------------------------------------------------------------------------
//
// User-set env vars (via kraph_set_env) are stored encrypted in the
// instance_env table. We use the same per-instance 32-byte DEK that encrypts
// WAL segments — it's already generated at provision time and stored in the
// `instances.wal_encryption_key` column (hex-encoded).
//
// On disk (SQLite), every row is of the form:
//     "enc-v1:" || base64(nonce[12] || ciphertext || poly1305_tag)
//
// Reads transparently decrypt; rows without the "enc-v1:" prefix are treated
// as legacy plaintext (they pre-date the encryption migration) and returned
// as-is with a warning in the logs. New writes ALWAYS go through encryption —
// if an instance somehow has no DEK, upsert_env refuses to store plaintext.

const ENV_NONCE_LEN: usize = 12;
/// Legacy format: ChaCha20-Poly1305 with NO additional-data binding.
/// Audit F58 found this allows an attacker with raw SQLite write access
/// to swap ciphertext between rows of the same instance (e.g.
/// `OPENAI_API_KEY` row ← stale `DATABASE_URL` ciphertext) — the decrypt
/// succeeds and the wrong value reaches `Deno.env.get()` in the
/// functions container. Bounded today by direct-DB-access threat model
/// (gateway → node API doesn't expose raw SQLite write), but
/// defence-in-depth via v2 below.
const ENV_FORMAT_PREFIX_V1: &str = "enc-v1:";
/// Current format: ChaCha20-Poly1305 with AAD = `instance_id|key`.
/// Swapping ciphertext to a different `(instance_id, key)` slot now
/// fails the AEAD tag check.
const ENV_FORMAT_PREFIX_V2: &str = "enc-v2:";

/// Fetch the 32-byte DEK for an instance from the `wal_encryption_key`
/// column. Returns `None` if the instance doesn't exist or was provisioned
/// before WAL encryption was added (empty key).
fn load_instance_dek(conn: &Connection, instance_id: &str) -> Result<Option<[u8; 32]>> {
    let key_hex: String = match conn.query_row(
        "SELECT wal_encryption_key FROM instances WHERE id = ?1",
        params![instance_id],
        |row| row.get(0),
    ) {
        Ok(k) => k,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if key_hex.is_empty() {
        return Ok(None);
    }
    let key_bytes =
        hex::decode(&key_hex).context("wal_encryption_key is not valid hex")?;
    if key_bytes.len() != 32 {
        bail!(
            "wal_encryption_key must be 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(Some(arr))
}

/// Build the AEAD additional-data string binding ciphertext to its row.
/// Format: `instance_id|key`. The pipe is safe because instance_id is
/// alphanumeric nanoid and key is regex-validated as `[A-Z_][A-Z0-9_]*`
/// upstream — neither contains a pipe. Audit F58.
fn env_aad(instance_id: &str, key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(instance_id.len() + 1 + key.len());
    aad.extend_from_slice(instance_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(key.as_bytes());
    aad
}

/// Encrypt a plaintext env value under the instance DEK with AAD-binding.
/// Output format: `enc-v2:<base64(nonce || ciphertext+tag)>`.
fn encrypt_env_value(
    dek: &[u8; 32],
    instance_id: &str,
    key: &str,
    plaintext: &str,
) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dek));
    let mut nonce_bytes = [0u8; ENV_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = env_aad(instance_id, key);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("env encryption failed: {:?}", e))?;
    let mut envelope = Vec::with_capacity(ENV_NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!("{}{}", ENV_FORMAT_PREFIX_V2, B64.encode(&envelope)))
}

/// Decrypt a stored env value. Three accepted forms:
///   - `enc-v2:` — AEAD with AAD = `instance_id|key` (current).
///   - `enc-v1:` — AEAD without AAD (legacy; accepted on read, will be
///     re-encrypted to v2 on next upsert).
///   - anything else — pre-encryption plaintext (oldest legacy rows).
fn decrypt_env_value(
    dek: Option<&[u8; 32]>,
    instance_id: &str,
    key: &str,
    stored: &str,
) -> Result<String> {
    if let Some(payload_b64) = stored.strip_prefix(ENV_FORMAT_PREFIX_V2) {
        let dek = dek.context(
            "encrypted env row exists but instance has no wal_encryption_key to decrypt with",
        )?;
        let envelope = B64
            .decode(payload_b64)
            .context("env envelope is not valid base64")?;
        if envelope.len() < ENV_NONCE_LEN + 16 {
            bail!(
                "env envelope too short: {} bytes (need at least {})",
                envelope.len(),
                ENV_NONCE_LEN + 16
            );
        }
        let (nonce_bytes, ciphertext) = envelope.split_at(ENV_NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(dek));
        let aad = env_aad(instance_id, key);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("env v2 decryption failed (wrong key, swapped row, or corrupted): {:?}", e))?;
        return String::from_utf8(plaintext).context("decrypted env value is not valid UTF-8");
    }
    if let Some(payload_b64) = stored.strip_prefix(ENV_FORMAT_PREFIX_V1) {
        warn!(
            instance_id,
            key,
            "env row in legacy v1 format (no AAD); will be re-encrypted to v2 on next upsert"
        );
        let dek = dek.context(
            "v1-encrypted env row exists but instance has no wal_encryption_key",
        )?;
        let envelope = B64
            .decode(payload_b64)
            .context("env envelope is not valid base64")?;
        if envelope.len() < ENV_NONCE_LEN + 16 {
            bail!("env envelope too short");
        }
        let (nonce_bytes, ciphertext) = envelope.split_at(ENV_NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(dek));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| anyhow::anyhow!("env v1 decryption failed: {:?}", e))?;
        return String::from_utf8(plaintext).context("decrypted env value is not valid UTF-8");
    }
    // Pre-encryption plaintext — still returned for backward compat.
    warn!("env row in pre-encryption plaintext format; will be encrypted on next upsert");
    Ok(stored.to_string())
}

// ---------------------------------------------------------------------------
// Domain structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    pub wallet_pubkey: String,
    pub name: Option<String>,
    pub status: String,
    pub kong_port: u16,
    pub postgres_port: u16,
    pub gotrue_port: u16,
    pub realtime_port: u16,
    pub storage_port: u16,
    pub studio_port: u16,
    pub analytics_port: u16,
    pub meta_port: u16,
    pub functions_port: u16,
    #[serde(skip_serializing)]
    pub anon_key: String,
    #[serde(skip_serializing)]
    pub service_role_key: String,
    #[serde(skip_serializing)]
    pub jwt_secret: String,
    #[serde(skip_serializing)]
    pub postgres_password: String,
    #[serde(skip_serializing)]
    pub dashboard_password: String,
    pub url: String,
    pub studio_url: String,
    pub compose_project_name: String,
    pub instance_dir: String,
    pub cpuset_cpus: Option<String>,
    /// Hex-encoded 32-byte ChaCha20-Poly1305 key for WAL segment encryption.
    /// Generated at provision time, persisted, and never sent off this node.
    /// (In the TEE-backed deployment this would be sealed to the enclave.)
    #[serde(skip_serializing)]
    pub wal_encryption_key: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub destroyed_at: Option<String>,
}

/// Zeroize secrets when the instance is dropped.
impl Drop for Instance {
    fn drop(&mut self) {
        self.anon_key.zeroize();
        self.service_role_key.zeroize();
        self.jwt_secret.zeroize();
        self.postgres_password.zeroize();
        self.dashboard_password.zeroize();
        self.wal_encryption_key.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalSegment {
    pub id: Option<i64>,
    pub instance_id: String,
    pub segment_name: String,
    /// SHA-256 of the **encrypted** segment bytes (the on-the-wire form).
    pub hash: String,
    /// Hash of the previous segment in the chain. Empty for the first segment.
    pub previous_hash: String,
    pub encrypted_path: String,
    pub size: i64,
    /// Sequence number within this instance's WAL chain. Starts at 0.
    pub chain_index: i64,
    pub created_at: Option<String>,
}

/// Replica-side row mirroring `WalSegment`. Stored on the receiving node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaSegment {
    pub id: Option<i64>,
    pub instance_id: String,
    pub segment_name: String,
    pub hash: String,
    pub previous_hash: String,
    pub stored_path: String,
    pub size: i64,
    pub chain_index: i64,
    pub received_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceReplica {
    pub instance_id: String,
    pub replica_node_endpoint: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaShipment {
    pub id: Option<i64>,
    pub instance_id: String,
    pub replica_node_endpoint: String,
    pub segment_name: String,
    pub status: String,
    pub attempts: i32,
    pub last_attempt_at: Option<String>,
    pub confirmed_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Database wrapper
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) the SQLite database inside `data_dir` and run all
    /// migrations.
    pub fn new(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data dir {:?}", data_dir))?;

        let db_path = data_dir.join("supaba.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("opening SQLite at {:?}", db_path))?;

        // Harden SQLite for concurrent use.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;

        // Run migrations.
        for ddl in schema::MIGRATIONS {
            conn.execute_batch(ddl)?;
        }

        // Soft migrations: ALTER TABLE statements that may fail because the
        // column already exists. Tolerate "duplicate column name" errors so
        // older databases upgrade cleanly.
        for stmt in schema::SOFT_MIGRATIONS {
            if let Err(e) = conn.execute_batch(stmt) {
                let msg = e.to_string();
                if msg.contains("duplicate column name") || msg.contains("already exists") {
                    debug!("soft migration already applied: {stmt}");
                } else {
                    return Err(e).with_context(|| format!("soft migration failed: {stmt}"));
                }
            }
        }

        info!(?db_path, "database initialised");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ------------------------------------------------------------------
    // Instances
    // ------------------------------------------------------------------

    pub fn insert_instance(&self, i: &Instance) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            r#"INSERT INTO instances (
                id, wallet_pubkey, name, status,
                kong_port, postgres_port, gotrue_port, realtime_port,
                storage_port, studio_port, analytics_port, meta_port, functions_port,
                anon_key, service_role_key, jwt_secret,
                postgres_password, dashboard_password,
                url, studio_url, compose_project_name, instance_dir,
                cpuset_cpus, wal_encryption_key, created_at, expires_at
            ) VALUES (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16,
                ?17, ?18,
                ?19, ?20, ?21, ?22,
                ?23, ?24, ?25, ?26
            )"#,
            params![
                i.id,
                i.wallet_pubkey,
                i.name,
                i.status,
                i.kong_port as u32,
                i.postgres_port as u32,
                i.gotrue_port as u32,
                i.realtime_port as u32,
                i.storage_port as u32,
                i.studio_port as u32,
                i.analytics_port as u32,
                i.meta_port as u32,
                i.functions_port as u32,
                i.anon_key,
                i.service_role_key,
                i.jwt_secret,
                i.postgres_password,
                i.dashboard_password,
                i.url,
                i.studio_url,
                i.compose_project_name,
                i.instance_dir,
                i.cpuset_cpus,
                i.wal_encryption_key,
                i.created_at,
                i.expires_at,
            ],
        )?;
        debug!(id = %i.id, "instance inserted");
        Ok(())
    }

    pub fn get_instance(&self, id: &str, wallet: &str) -> Result<Option<Instance>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT * FROM instances WHERE id = ?1 AND wallet_pubkey = ?2 AND destroyed_at IS NULL",
        )?;
        let mut rows = stmt.query_map(params![id, wallet], row_to_instance)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn list_instances(&self, wallet: &str, status: Option<&str>) -> Result<Vec<Instance>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        match status {
            Some(s) => {
                let mut stmt = conn.prepare(
                    "SELECT * FROM instances WHERE wallet_pubkey = ?1 AND status = ?2 AND destroyed_at IS NULL ORDER BY created_at DESC",
                )?;
                let rows = stmt.query_map(params![wallet, s], row_to_instance)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT * FROM instances WHERE wallet_pubkey = ?1 AND destroyed_at IS NULL ORDER BY created_at DESC",
                )?;
                let rows = stmt.query_map(params![wallet], row_to_instance)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub fn update_instance_status(&self, id: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE instances SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        debug!(id, status, "instance status updated");
        Ok(())
    }

    pub fn destroy_instance(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE instances SET status = 'destroyed', destroyed_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        debug!(id, "instance marked destroyed");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Port allocation
    // ------------------------------------------------------------------

    /// Find the next free port block of `PORTS_PER_INSTANCE` inside the given
    /// range.  Returns the base port.
    pub fn allocate_port_block(&self, range_start: u16, range_end: u16) -> Result<u16> {
        let block = crate::config::Config::PORTS_PER_INSTANCE;
        let conn = self.conn.lock().expect("db lock poisoned");

        // Collect all currently allocated base ports.
        let mut stmt = conn.prepare("SELECT base_port FROM port_allocations ORDER BY base_port")?;
        let allocated: Vec<u16> = stmt
            .query_map([], |row| row.get::<_, u32>(0).map(|v| v as u16))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Walk through the range looking for a gap.
        let mut candidate = range_start;
        for &used in &allocated {
            if candidate + block <= used {
                break; // gap found
            }
            if used + block > candidate {
                candidate = used + block;
            }
        }

        if candidate + block > range_end {
            anyhow::bail!("no free port block in range {range_start}..{range_end}");
        }

        conn.execute(
            "INSERT INTO port_allocations (base_port) VALUES (?1)",
            params![candidate as u32],
        )?;
        debug!(base_port = candidate, "port block allocated");
        Ok(candidate)
    }

    /// Insert a specific port block (used when reassigning a warm instance).
    pub fn allocate_port_block_at(&self, base_port: u16) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO port_allocations (base_port) VALUES (?1)",
            params![base_port as u32],
        )?;
        debug!(base_port, "port block allocated at specific port");
        Ok(())
    }

    pub fn free_port_block(&self, instance_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "DELETE FROM port_allocations WHERE instance_id = ?1",
            params![instance_id],
        )?;
        debug!(instance_id, "port block freed");
        Ok(())
    }

    /// Bind an allocated port block to a specific instance.
    pub fn bind_port_to_instance(&self, base_port: u16, instance_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE port_allocations SET instance_id = ?1 WHERE base_port = ?2",
            params![instance_id, base_port as u32],
        )?;
        Ok(())
    }

    pub fn running_instance_count(&self) -> Result<usize> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM instances WHERE status IN ('running','provisioning') AND destroyed_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    // ------------------------------------------------------------------
    // WAL segments
    // ------------------------------------------------------------------

    /// Insert a WAL segment record. Idempotent: a `(instance_id, segment_name)`
    /// pair already present is silently ignored — `process_new_segments` is
    /// safe to re-run after a crash.
    pub fn insert_wal_segment(&self, seg: &WalSegment) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            r#"INSERT OR IGNORE INTO wal_segments
                (instance_id, segment_name, hash, previous_hash, encrypted_path, size, chain_index)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                seg.instance_id,
                seg.segment_name,
                seg.hash,
                seg.previous_hash,
                seg.encrypted_path,
                seg.size,
                seg.chain_index,
            ],
        )?;
        debug!(instance_id = %seg.instance_id, segment = %seg.segment_name, "WAL segment recorded");
        Ok(())
    }

    pub fn get_latest_wal_hash(&self, instance_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT hash FROM wal_segments WHERE instance_id = ?1 ORDER BY chain_index DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![instance_id], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Largest chain_index recorded for this instance, or `None` if empty.
    pub fn get_latest_wal_chain_index(&self, instance_id: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT chain_index FROM wal_segments WHERE instance_id = ?1 ORDER BY chain_index DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![instance_id], |row| row.get::<_, i64>(0))?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    // ------------------------------------------------------------------
    // Expired-instance query
    // ------------------------------------------------------------------

    pub fn expired_instance_ids(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, wallet_pubkey FROM instances WHERE expires_at IS NOT NULL AND expires_at < datetime('now') AND status = 'running'",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Extend an instance's expiry by `duration_secs`.
    pub fn extend_instance(
        &self,
        id: &str,
        wallet: &str,
        duration_secs: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let affected = conn.execute(
            "UPDATE instances SET expires_at = datetime(COALESCE(expires_at, datetime('now')), '+' || ?1 || ' seconds') WHERE id = ?2 AND wallet_pubkey = ?3 AND destroyed_at IS NULL",
            params![duration_secs, id, wallet],
        )?;
        if affected == 0 {
            anyhow::bail!("instance {id} not found for wallet {wallet}");
        }
        debug!(id, duration_secs, "instance extended");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Instance lookups (no wallet filter)
    // ------------------------------------------------------------------

    pub fn get_instance_by_id(&self, id: &str) -> Result<Option<Instance>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT * FROM instances WHERE id = ?1 AND destroyed_at IS NULL",
        )?;
        let mut rows = stmt.query_map(params![id], row_to_instance)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn list_running_instances(&self) -> Result<Vec<Instance>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT * FROM instances WHERE status = 'running' AND destroyed_at IS NULL ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_instance)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// List all instances regardless of wallet or status (admin endpoint).
    pub fn list_all_instances(&self) -> Result<Vec<Instance>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT * FROM instances WHERE destroyed_at IS NULL ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_instance)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // ------------------------------------------------------------------
    // WAL segment queries
    // ------------------------------------------------------------------

    pub fn get_processed_wal_segments(&self, instance_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT segment_name FROM wal_segments WHERE instance_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn get_wal_segment(&self, instance_id: &str, segment_name: &str) -> Result<Option<WalSegment>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, instance_id, segment_name, hash, previous_hash, encrypted_path, size, chain_index, created_at FROM wal_segments WHERE instance_id = ?1 AND segment_name = ?2",
        )?;
        let mut rows = stmt.query_map(params![instance_id, segment_name], |row| {
            Ok(WalSegment {
                id: row.get(0)?,
                instance_id: row.get(1)?,
                segment_name: row.get(2)?,
                hash: row.get(3)?,
                previous_hash: row.get(4)?,
                encrypted_path: row.get(5)?,
                size: row.get(6)?,
                chain_index: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn list_wal_segments(&self, instance_id: &str) -> Result<Vec<WalSegment>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, instance_id, segment_name, hash, previous_hash, encrypted_path, size, chain_index, created_at FROM wal_segments WHERE instance_id = ?1 ORDER BY chain_index",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| {
            Ok(WalSegment {
                id: row.get(0)?,
                instance_id: row.get(1)?,
                segment_name: row.get(2)?,
                hash: row.get(3)?,
                previous_hash: row.get(4)?,
                encrypted_path: row.get(5)?,
                size: row.get(6)?,
                chain_index: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // ------------------------------------------------------------------
    // Per-instance replica registry
    // ------------------------------------------------------------------

    pub fn add_instance_replica(&self, instance_id: &str, endpoint: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let affected = conn.execute(
            "INSERT OR IGNORE INTO instance_replicas (instance_id, replica_node_endpoint) VALUES (?1, ?2)",
            params![instance_id, endpoint],
        )?;
        Ok(affected > 0)
    }

    pub fn list_instance_replicas(&self, instance_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT replica_node_endpoint FROM instance_replicas WHERE instance_id = ?1 ORDER BY added_at",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn remove_instance_replica(&self, instance_id: &str, endpoint: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "DELETE FROM instance_replicas WHERE instance_id = ?1 AND replica_node_endpoint = ?2",
            params![instance_id, endpoint],
        )?;
        Ok(())
    }

    /// Enqueue a shipment for a specific (instance, segment, replica) tuple.
    /// Idempotent: re-enqueueing the same triple is silently ignored.
    pub fn enqueue_replica_shipment(
        &self,
        instance_id: &str,
        endpoint: &str,
        segment_name: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let affected = conn.execute(
            r#"INSERT OR IGNORE INTO replica_shipments
                (instance_id, replica_node_endpoint, segment_name, status, attempts)
               VALUES (?1, ?2, ?3, 'pending', 0)"#,
            params![instance_id, endpoint, segment_name],
        )?;
        Ok(affected > 0)
    }

    // ------------------------------------------------------------------
    // Replica-side WAL storage
    // ------------------------------------------------------------------

    pub fn insert_replica_segment(&self, seg: &ReplicaSegment) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            r#"INSERT OR IGNORE INTO replica_segments
                (instance_id, segment_name, hash, previous_hash, stored_path, size, chain_index)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                seg.instance_id,
                seg.segment_name,
                seg.hash,
                seg.previous_hash,
                seg.stored_path,
                seg.size,
                seg.chain_index,
            ],
        )?;
        Ok(())
    }

    pub fn list_replica_segments_db(&self, instance_id: &str) -> Result<Vec<ReplicaSegment>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, instance_id, segment_name, hash, previous_hash, stored_path, size, chain_index, received_at FROM replica_segments WHERE instance_id = ?1 ORDER BY chain_index",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| {
            Ok(ReplicaSegment {
                id: row.get(0)?,
                instance_id: row.get(1)?,
                segment_name: row.get(2)?,
                hash: row.get(3)?,
                previous_hash: row.get(4)?,
                stored_path: row.get(5)?,
                size: row.get(6)?,
                chain_index: row.get(7)?,
                received_at: row.get(8)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn latest_replica_hash(&self, instance_id: &str) -> Result<Option<(String, i64)>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT hash, chain_index FROM replica_segments WHERE instance_id = ?1 ORDER BY chain_index DESC LIMIT 1",
        )?;
        let mut rows =
            stmt.query_map(params![instance_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    // ------------------------------------------------------------------
    // Replica shipments
    // ------------------------------------------------------------------

    pub fn get_pending_shipments(&self) -> Result<Vec<ReplicaShipment>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, instance_id, replica_node_endpoint, segment_name, status, attempts, last_attempt_at, confirmed_at FROM replica_shipments WHERE status = 'pending' ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ReplicaShipment {
                id: row.get(0)?,
                instance_id: row.get(1)?,
                replica_node_endpoint: row.get(2)?,
                segment_name: row.get(3)?,
                status: row.get(4)?,
                attempts: row.get(5)?,
                last_attempt_at: row.get(6)?,
                confirmed_at: row.get(7)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn mark_shipment_failed(&self, id: Option<i64>) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE replica_shipments SET status = 'failed' WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn mark_shipment_shipped(&self, id: Option<i64>) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE replica_shipments SET status = 'shipped', confirmed_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn increment_shipment_attempts(&self, id: Option<i64>) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.execute(
            "UPDATE replica_shipments SET attempts = attempts + 1, last_attempt_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Count allocated port blocks.
    pub fn allocated_port_count(&self) -> Result<usize> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM port_allocations", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ------------------------------------------------------------------
    // Per-instance edge-function env vars
    // ------------------------------------------------------------------

    /// Insert or replace a single env var for an instance. The value is
    /// encrypted under the instance DEK before storage — rows on disk are
    /// always `enc-v1:` envelopes, never plaintext. If the instance has no
    /// DEK (legacy row or missing instance), the call fails loudly rather
    /// than silently storing plaintext.
    pub fn upsert_env(&self, instance_id: &str, key: &str, value: &str) -> Result<()> {
        // Defaults to protected=false so the existing agent-set path
        // (kraph_set_env via gateway) continues to behave as before.
        self.upsert_env_with_protection(instance_id, key, value, false)
    }

    /// Same as upsert_env but with explicit `protected` flag. When true,
    /// `kraph_list_env` (the agent-facing read tool) hides the value;
    /// when false, the value is visible to the agent. Both flow into the
    /// same .env file at runtime so functions code reads them identically.
    /// On UPDATE, the protection flag of the existing row is preserved
    /// unless the caller explicitly overrides via the dedicated dashboard
    /// endpoint — agent-set updates can't downgrade a user-set secret.
    pub fn upsert_env_with_protection(
        &self,
        instance_id: &str,
        key: &str,
        value: &str,
        protected: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let dek = load_instance_dek(&conn, instance_id)?.context(
            "instance has no encryption key — cannot store env var without encryption. \
             Re-provision the instance or run the key-backfill migration.",
        )?;
        // Look up the existing row so we never let an agent-set call
        // (protected=false) overwrite a user-set secret (protected=true).
        // The agent gets a clean error and can't silently exfiltrate by
        // setting + reading.
        let existing_protected: Option<i64> = conn
            .query_row(
                "SELECT protected FROM instance_env WHERE instance_id = ?1 AND key = ?2",
                params![instance_id, key],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        if let Some(p) = existing_protected {
            if p != 0 && !protected {
                bail!(
                    "key '{key}' is reserved as a user-set secret; agent-set updates not allowed. \
                     Pick a different env var name or have the user update it via the dashboard."
                );
            }
        }
        let stored_value = encrypt_env_value(&dek, instance_id, key, value)?;
        let protected_int: i64 = if protected { 1 } else { 0 };
        conn.execute(
            r#"INSERT INTO instance_env (instance_id, key, value, protected, updated_at)
               VALUES (?1, ?2, ?3, ?4, datetime('now'))
               ON CONFLICT(instance_id, key) DO UPDATE SET
                   value = excluded.value,
                   protected = excluded.protected,
                   updated_at = datetime('now')"#,
            params![instance_id, key, stored_value, protected_int],
        )?;
        debug!(
            instance_id,
            key, protected, "env var upserted (encrypted)"
        );
        Ok(())
    }

    /// List every `(key, plaintext_value)` pair for this instance,
    /// alphabetically by key. Values are transparently decrypted under the
    /// instance DEK — caller gets plaintext and is responsible for handling
    /// it safely (logging, redaction, etc.).
    ///
    /// Used both by `GET /env` and by the `.env` renderer that writes the
    /// functions container environment.
    pub fn list_env(&self, instance_id: &str) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let dek = load_instance_dek(&conn, instance_id)?;
        let dek_ref = dek.as_ref();
        let mut stmt = conn.prepare(
            "SELECT key, value FROM instance_env WHERE instance_id = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (k, stored) = r?;
            let plain = decrypt_env_value(dek_ref, instance_id, &k, &stored).with_context(|| {
                format!("decrypting env var '{}' for instance '{}'", k, instance_id)
            })?;
            out.push((k, plain));
        }
        Ok(out)
    }

    /// List `(key, plaintext_value, updated_at)` triples — used by the
    /// owner-facing `GET /env` endpoint where the caller wants timestamps.
    /// Values are transparently decrypted, same as `list_env`.
    pub fn list_env_full(
        &self,
        instance_id: &str,
    ) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let dek = load_instance_dek(&conn, instance_id)?;
        let dek_ref = dek.as_ref();
        let mut stmt = conn.prepare(
            "SELECT key, value, updated_at FROM instance_env WHERE instance_id = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (k, stored, updated_at) = r?;
            let plain = decrypt_env_value(dek_ref, instance_id, &k, &stored).with_context(|| {
                format!("decrypting env var '{}' for instance '{}'", k, instance_id)
            })?;
            out.push((k, plain, updated_at));
        }
        Ok(out)
    }

    /// List `(key, plaintext_value, protected, updated_at)` for an
    /// instance, including the protection flag. Used by the env-render
    /// path (functions container needs both protected and unprotected
    /// values) and by the dashboard endpoints that audit a user's
    /// secrets.
    pub fn list_env_full_with_protection(
        &self,
        instance_id: &str,
    ) -> Result<Vec<(String, String, bool, String)>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let dek = load_instance_dek(&conn, instance_id)?;
        let dek_ref = dek.as_ref();
        let mut stmt = conn.prepare(
            "SELECT key, value, protected, updated_at FROM instance_env WHERE instance_id = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (k, stored, prot, updated_at) = r?;
            let plain = decrypt_env_value(dek_ref, instance_id, &k, &stored).with_context(|| {
                format!("decrypting env var '{}' for instance '{}'", k, instance_id)
            })?;
            out.push((k, plain, prot != 0, updated_at));
        }
        Ok(out)
    }

    /// Return just the keys — cheap listing for UIs that don't need values.
    pub fn get_env_keys(&self, instance_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let mut stmt = conn.prepare(
            "SELECT key FROM instance_env WHERE instance_id = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![instance_id], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Delete one env var. Returns `true` if a row was actually removed,
    /// `false` if the key was not present.
    pub fn delete_env(&self, instance_id: &str, key: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let affected = conn.execute(
            "DELETE FROM instance_env WHERE instance_id = ?1 AND key = ?2",
            params![instance_id, key],
        )?;
        debug!(instance_id, key, affected, "env var deleted");
        Ok(affected > 0)
    }

    /// Delete every env var for the given instance. Returns the number of
    /// rows removed. Called from the instance-destroy path so the DB does
    /// not accumulate orphaned env rows (also guarded by the FK `ON DELETE
    /// CASCADE`, but this makes the ordering explicit and works if FKs are
    /// ever disabled for a migration).
    pub fn delete_all_env(&self, instance_id: &str) -> Result<usize> {
        let conn = self.conn.lock().expect("db lock poisoned");
        let affected = conn.execute(
            "DELETE FROM instance_env WHERE instance_id = ?1",
            params![instance_id],
        )?;
        debug!(instance_id, affected, "all env vars deleted for instance");
        Ok(affected)
    }
}

// ---------------------------------------------------------------------------
// Row mapper
// ---------------------------------------------------------------------------

fn row_to_instance(row: &rusqlite::Row<'_>) -> rusqlite::Result<Instance> {
    Ok(Instance {
        id: row.get("id")?,
        wallet_pubkey: row.get("wallet_pubkey")?,
        name: row.get("name")?,
        status: row.get("status")?,
        kong_port: row.get::<_, u32>("kong_port")? as u16,
        postgres_port: row.get::<_, u32>("postgres_port")? as u16,
        gotrue_port: row.get::<_, u32>("gotrue_port")? as u16,
        realtime_port: row.get::<_, u32>("realtime_port")? as u16,
        storage_port: row.get::<_, u32>("storage_port")? as u16,
        studio_port: row.get::<_, u32>("studio_port")? as u16,
        analytics_port: row.get::<_, u32>("analytics_port")? as u16,
        meta_port: row.get::<_, u32>("meta_port")? as u16,
        functions_port: row.get::<_, u32>("functions_port")? as u16,
        anon_key: row.get("anon_key")?,
        service_role_key: row.get("service_role_key")?,
        jwt_secret: row.get("jwt_secret")?,
        postgres_password: row.get("postgres_password")?,
        dashboard_password: row.get("dashboard_password")?,
        url: row.get("url")?,
        studio_url: row.get("studio_url")?,
        compose_project_name: row.get("compose_project_name")?,
        instance_dir: row.get("instance_dir")?,
        cpuset_cpus: row.get("cpuset_cpus")?,
        wal_encryption_key: row.get::<_, Option<String>>("wal_encryption_key")?.unwrap_or_default(),
        created_at: row.get("created_at")?,
        expires_at: row.get("expires_at")?,
        destroyed_at: row.get("destroyed_at")?,
    })
}
