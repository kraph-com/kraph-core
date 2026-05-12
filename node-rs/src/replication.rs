//! Encrypted Write-Ahead-Log replication between Supaba nodes.
//!
//! ## Threat model
//!
//! The primary node holds the plaintext database (and the per-instance
//! `wal_encryption_key`). Replicas are *untrusted operators* on the public
//! network — we ship them opaque ciphertext that they cannot read but can
//! durably store and serve back during a failover.
//!
//! ## Flow on the primary
//!
//!   1. Postgres `archive_command` copies each rotated WAL segment into a
//!      directory inside the `db` container.
//!   2. `process_new_segments` runs every few seconds:
//!         a. Lists segments that haven't been processed yet
//!         b. Copies them out of the container
//!         c. Encrypts them in-place with ChaCha20-Poly1305 using the
//!            instance's per-instance key. The on-disk format is
//!            `nonce(12) || ciphertext || tag(16)`.
//!         d. Hashes the ciphertext (SHA-256) and links it to the previous
//!            ciphertext hash, building a tamper-evident chain.
//!         e. Records the segment in `wal_segments` and enqueues one row in
//!            `replica_shipments` per registered replica for this instance.
//!         f. Removes the plaintext from both the container and the host.
//!   3. `ship_pending_segments` runs every few seconds:
//!         - Drains `replica_shipments WHERE status='pending'`
//!         - POSTs each ciphertext to `<replica>/replication/receive` with
//!           the hash chain headers
//!         - Marks the row `shipped` on success or bumps `attempts` on
//!           failure (capped at 5 retries before `failed`).
//!
//! ## Flow on the replica
//!
//!   1. `receive_segment` accepts the POST, validates the SHA-256 against
//!      the body bytes, validates the chain link against `latest_replica_hash`,
//!      and writes the ciphertext to `<data>/replicas/<instance>/<segment>.enc`.
//!   2. `replica_segments` records the metadata.
//!
//! Restoration (decrypt + replay) is initiated by the agent via the gateway:
//! the gateway pulls segments from a replica with `GET /replication/...`,
//! the agent decrypts them locally with its own key copy, and the new
//! primary replays them with `pg_walreplay` against a fresh base backup.

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Auth gate for `/replication/receive` calls. Closes audit finding F11
/// (2026-05-10): the receive endpoint had ZERO authentication. Anyone who
/// could reach a node's HTTP port could POST 64MB blobs for any
/// instance_id, filling disk and/or breaking the hash chain.
///
/// Operator sets `SUPABA_REPLICATION_HMAC_SECRET` to the same value on
/// every peer node. Primary computes
///   sig = HMAC-SHA256(instance_id || "\n" || segment_name || "\n" ||
///                     segment_hash || "\n" || previous_hash || "\n" ||
///                     chain_index, secret)
/// and sends as `X-Replication-Sig: <hex>`. Receiver recomputes and
/// `timingSafeEqual`s. Body integrity is already covered by the existing
/// `X-Segment-Hash` chain verification, so the signature only needs to
/// cover the headers (which control where the body lands).
///
/// Rollout: if the receiver's env is UNSET, the sig is logged-as-missing
/// and accepted (so old shippers still work mid-rollout). Once every node
/// has the secret, the operator can enforce strict mode by setting
/// `SUPABA_REPLICATION_REQUIRE_HMAC=true` — receiver then 401s on missing
/// or bad sig.
fn replication_hmac_secret() -> Option<Vec<u8>> {
    let s = std::env::var("SUPABA_REPLICATION_HMAC_SECRET")
        .ok()
        .filter(|v| !v.is_empty())?;
    Some(s.into_bytes())
}

/// HMAC is required by default (audit F62). Operators can opt OUT of
/// enforcement during rollout by setting
/// `SUPABA_REPLICATION_ALLOW_MISSING_HMAC=true` — production must NEVER
/// set that. The legacy `SUPABA_REPLICATION_REQUIRE_HMAC` env var is
/// retained as a no-op for forward compatibility; the new default is
/// already strict.
fn replication_require_hmac() -> bool {
    let allow_missing = matches!(
        std::env::var("SUPABA_REPLICATION_ALLOW_MISSING_HMAC").as_deref(),
        Ok("true" | "1" | "yes")
    );
    !allow_missing
}

fn build_replication_sig(
    secret: &[u8],
    instance_id: &str,
    segment_name: &str,
    segment_hash: &str,
    previous_hash: &str,
    chain_index: i64,
) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(instance_id.as_bytes());
    mac.update(b"\n");
    mac.update(segment_name.as_bytes());
    mac.update(b"\n");
    mac.update(segment_hash.as_bytes());
    mac.update(b"\n");
    mac.update(previous_hash.as_bytes());
    mac.update(b"\n");
    mac.update(chain_index.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify the X-Replication-Sig header for a /replication/receive call.
/// Returns Ok(()) on success; Err on any mismatch. Operator-tunable via:
///   - SUPABA_REPLICATION_HMAC_SECRET  (set to enable verification)
///   - SUPABA_REPLICATION_REQUIRE_HMAC ("true" to refuse missing sigs)
pub fn verify_replication_sig(
    provided_sig: Option<&str>,
    instance_id: &str,
    segment_name: &str,
    segment_hash: &str,
    previous_hash: &str,
    chain_index: i64,
) -> Result<()> {
    let secret = replication_hmac_secret();
    let strict = replication_require_hmac();
    match (provided_sig, secret) {
        (None, None) => {
            if strict {
                bail!(
                    "X-Replication-Sig required (SUPABA_REPLICATION_REQUIRE_HMAC=true) but secret is unset on this node — operator config bug"
                );
            }
            warn!(
                instance_id,
                "replication accepted without HMAC (no secret configured; set SUPABA_REPLICATION_HMAC_SECRET on every peer to enable verification)"
            );
            Ok(())
        }
        (Some(_sig), None) => {
            warn!(
                instance_id,
                "primary sent X-Replication-Sig but receiver has no secret — accepting (rollout phase)"
            );
            Ok(())
        }
        (None, Some(_)) => {
            if strict {
                bail!("X-Replication-Sig is required on this node");
            }
            warn!(
                instance_id,
                "secret configured but X-Replication-Sig missing — accepting (mixed rollout). Set SUPABA_REPLICATION_REQUIRE_HMAC=true once all primaries have been updated."
            );
            Ok(())
        }
        (Some(sig), Some(secret)) => {
            let expected = build_replication_sig(
                &secret,
                instance_id,
                segment_name,
                segment_hash,
                previous_hash,
                chain_index,
            );
            // Hex strings are constant-time-comparable via the underlying
            // bytes once decoded. Compare as bytes for timing safety.
            let provided_bytes = hex::decode(sig.trim()).map_err(|e| {
                anyhow!("X-Replication-Sig is not valid hex: {e}")
            })?;
            let expected_bytes = hex::decode(&expected).expect("we just hex-encoded it");
            if provided_bytes.len() != expected_bytes.len() {
                bail!("X-Replication-Sig length mismatch");
            }
            // constant-time compare via subtle would be ideal; we have hmac
            // crate which exposes mac.verify_slice. Reconstruct mac for
            // exact verification.
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(&secret).expect("any key length");
            mac.update(instance_id.as_bytes());
            mac.update(b"\n");
            mac.update(segment_name.as_bytes());
            mac.update(b"\n");
            mac.update(segment_hash.as_bytes());
            mac.update(b"\n");
            mac.update(previous_hash.as_bytes());
            mac.update(b"\n");
            mac.update(chain_index.to_string().as_bytes());
            mac.verify_slice(&provided_bytes)
                .map_err(|_| anyhow!("X-Replication-Sig HMAC mismatch"))?;
            Ok(())
        }
    }
}

use crate::config::Config;
use crate::db::{Database, ReplicaSegment, WalSegment};

/// Length of the ChaCha20-Poly1305 nonce in bytes.
const NONCE_LEN: usize = 12;

/// Maximum delivery attempts for a single shipment before it's marked failed.
const MAX_SHIPMENT_ATTEMPTS: i32 = 5;

/// `ReplicationManager` owns the Postgres-side WAL archival pipeline as well
/// as the replica-side ingest. A single struct serves both roles because every
/// node is symmetric: it may be primary for some instances and replica for
/// others, sometimes simultaneously.
pub struct ReplicationManager {
    config: Arc<Config>,
    db: Arc<Database>,
    http: reqwest::Client,
}

impl ReplicationManager {
    pub fn new(config: Arc<Config>, db: Arc<Database>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client must build");
        Self { config, db, http }
    }

    // ───────────────────────────────────────────────────────────────────────
    // Postgres configuration
    // ───────────────────────────────────────────────────────────────────────

    /// Configure WAL archiving on the primary's Postgres container.
    ///
    /// Idempotent: safe to call repeatedly. Returns `Ok(())` even if archive
    /// mode requires a Postgres restart to take effect — the next provision
    /// will pick it up.
    pub async fn configure_wal_archiving(&self, instance_id: &str) -> Result<()> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .context("instance not found")?;

        let container_name = format!("{}-db-1", instance.compose_project_name);

        // Create the archive directory inside the container.
        //
        // /var/lib/postgresql is owned by root in the supabase/postgres image
        // (only the postgres data subdirectory is postgres-owned), so we have
        // to mkdir as root (no -u flag), then chown to postgres so the
        // postgres process can write WAL segments via archive_command.
        let mkdir = Command::new("docker")
            .args([
                "exec",
                &container_name,
                "sh",
                "-c",
                "mkdir -p /var/lib/postgresql/wal-archive && chown postgres:postgres /var/lib/postgresql/wal-archive",
            ])
            .output()
            .await
            .context("docker exec mkdir failed")?;
        if !mkdir.status.success() {
            warn!(
                instance_id = %instance_id,
                stderr = %String::from_utf8_lossy(&mkdir.stderr),
                "wal-archive mkdir/chown non-zero (continuing)"
            );
        }

        // Configure Postgres. Each ALTER SYSTEM must run in its OWN
        // statement (psql wraps multiple `;`-delimited statements in an
        // implicit transaction, but ALTER SYSTEM is forbidden inside a
        // transaction). We pass each as a separate `-c` flag.
        //
        // Use `-U supabase_admin` because in the supabase/postgres image
        // the `postgres` role is restricted; `supabase_admin` is the actual
        // superuser that owns ALTER SYSTEM and pg_switch_wal.
        let psql = Command::new("docker")
            .args([
                "exec",
                "-u",
                "postgres",
                &container_name,
                "psql",
                "-U",
                "supabase_admin",
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "ALTER SYSTEM SET archive_mode = on",
                "-c",
                "ALTER SYSTEM SET archive_command = 'test ! -f /var/lib/postgresql/wal-archive/%f && cp %p /var/lib/postgresql/wal-archive/%f'",
                "-c",
                "ALTER SYSTEM SET wal_level = replica",
                "-c",
                "SELECT pg_reload_conf()",
            ])
            .output()
            .await
            .context("docker exec psql failed")?;
        if !psql.status.success() {
            warn!(
                instance_id = %instance_id,
                stderr = %String::from_utf8_lossy(&psql.stderr),
                "ALTER SYSTEM returned non-zero"
            );
        }

        // Make sure host-side archive/encrypted dirs exist.
        fs::create_dir_all(self.archive_dir(instance_id)).await?;
        fs::create_dir_all(self.encrypted_dir(instance_id)).await?;

        // Check whether archive_mode is already active. If yes (because the
        // container was started with archive_mode=on baked into the image's
        // postgresql.conf, or because we already restarted previously), we
        // can skip the costly restart. Otherwise force a restart so the
        // ALTER SYSTEM SET archive_mode = on takes effect.
        let needs_restart = match Command::new("docker")
            .args([
                "exec",
                "-u",
                "postgres",
                &container_name,
                "psql",
                "-U",
                "supabase_admin",
                "-d",
                "postgres",
                "-tAc",
                "SHOW archive_mode",
            ])
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                s.trim() != "on"
            }
            _ => true, // be safe — restart on any uncertainty
        };

        if needs_restart {
            info!(
                instance_id = %instance_id,
                "restarting db container to activate archive_mode"
            );
            let restart = Command::new("docker")
                .args(["restart", "-t", "30", &container_name])
                .output()
                .await
                .context("docker restart failed")?;
            if !restart.status.success() {
                warn!(
                    instance_id = %instance_id,
                    stderr = %String::from_utf8_lossy(&restart.stderr),
                    "db container restart failed"
                );
            } else {
                // Wait for Postgres to accept connections again. Poll up to
                // 30s with a simple SELECT 1.
                for attempt in 0..30 {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let probe = Command::new("docker")
                        .args([
                            "exec",
                            "-u",
                            "postgres",
                            &container_name,
                            "psql",
                            "-U",
                            "supabase_admin",
                            "-d",
                            "postgres",
                            "-tAc",
                            "SELECT 1",
                        ])
                        .output()
                        .await;
                    if matches!(probe, Ok(out) if out.status.success()) {
                        debug!(instance_id = %instance_id, attempt, "postgres back online");
                        break;
                    }
                }
            }

            // Verify archive_mode is now actually on.
            let verify = Command::new("docker")
                .args([
                    "exec",
                    "-u",
                    "postgres",
                    &container_name,
                    "psql",
                    "-U",
                    "supabase_admin",
                    "-d",
                    "postgres",
                    "-tAc",
                    "SHOW archive_mode",
                ])
                .output()
                .await;
            match verify {
                Ok(out) if out.status.success() => {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if s == "on" {
                        info!(instance_id = %instance_id, "archive_mode = on confirmed");
                    } else {
                        warn!(instance_id = %instance_id, archive_mode = %s, "archive_mode did not flip to on after restart");
                    }
                }
                _ => warn!(instance_id = %instance_id, "could not verify archive_mode after restart"),
            }
        } else {
            debug!(instance_id = %instance_id, "archive_mode already on, skipping restart");
        }

        info!(instance_id = %instance_id, "WAL archiving configured");
        Ok(())
    }

    /// Force Postgres to rotate its current WAL segment immediately. Useful
    /// for tests so we don't have to wait for `archive_timeout` or for the
    /// active segment to fill up.
    pub async fn switch_wal(&self, instance_id: &str) -> Result<String> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .context("instance not found")?;
        let container_name = format!("{}-db-1", instance.compose_project_name);

        let out = Command::new("docker")
            .args([
                "exec",
                "-u",
                "postgres",
                &container_name,
                "psql",
                "-U",
                "supabase_admin",
                "-d",
                "postgres",
                "-tAc",
                "SELECT pg_walfile_name(pg_switch_wal());",
            ])
            .output()
            .await
            .context("pg_switch_wal failed")?;
        if !out.status.success() {
            bail!(
                "pg_switch_wal stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        info!(instance_id = %instance_id, segment = %name, "forced WAL switch");
        Ok(name)
    }

    // ───────────────────────────────────────────────────────────────────────
    // Primary-side processing
    // ───────────────────────────────────────────────────────────────────────

    /// Process newly archived WAL segments for every running instance. Called
    /// from a background tokio task at fixed intervals.
    pub async fn process_new_segments(&self) -> Result<()> {
        let instances = self.db.list_running_instances()?;
        for instance in instances {
            if instance.wal_encryption_key.is_empty() {
                debug!(instance_id = %instance.id, "skipping: no wal_encryption_key (legacy instance)");
                continue;
            }
            if let Err(e) = self.process_instance_wal(&instance).await {
                error!(instance_id = %instance.id, error = %e, "WAL processing failed");
            }
        }
        Ok(())
    }

    async fn process_instance_wal(
        &self,
        instance: &crate::db::Instance,
    ) -> Result<()> {
        let instance_id = &instance.id;
        let container_name = format!("{}-db-1", instance.compose_project_name);

        // List archived WAL files inside the container.
        let ls_out = Command::new("docker")
            .args([
                "exec",
                &container_name,
                "ls",
                "-1",
                "/var/lib/postgresql/wal-archive/",
            ])
            .output()
            .await;
        let mut wal_files: Vec<String> = match ls_out {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.ends_with(".tmp"))
                .collect(),
            Ok(_) | Err(_) => return Ok(()), // Archive dir not yet created
        };
        wal_files.sort(); // Postgres WAL filenames sort lexicographically by chain order
        if wal_files.is_empty() {
            return Ok(());
        }

        // Audit F50: defence-in-depth WAL filename validation. The names
        // come from `ls -1` inside the db container, which is in theory
        // attacker-influenceable: an agent with Postgres superuser AND a
        // file-writing extension (plperlu, etc — not present in default
        // Supabase) could `COPY ... TO 'evil-name'` into the archive dir.
        // The name then flows into `docker cp <container>:/.../<wal_file>`
        // and `archive_dir.join(wal_file)` — both with path-traversal
        // potential.
        //
        // Real Postgres WAL filenames are:
        //   24-char hex segments:        000000010000000000000001
        //   ... with .partial suffix:    000000010000000000000001.partial
        //   8-char timeline history:     00000002.history
        //
        // We hand-validate to avoid pulling in the regex crate. Anything
        // that doesn't match is silently dropped with a warning so an
        // operator can investigate genuine breakage.
        fn is_valid_wal_name(name: &str) -> bool {
            // Length bounds first — cheap and avoids weird edge cases.
            if name.len() < 9 || name.len() > 32 {
                return false;
            }
            // 8-char hex prefix is required for ALL valid forms.
            let (head, tail) = name.split_at(8);
            if !head.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_uppercase())) {
                return false;
            }
            // Three valid tail shapes: ".history", "<16hex>", "<16hex>.partial".
            if tail == ".history" {
                return true;
            }
            let (mid, ext) = if let Some(stripped) = tail.strip_suffix(".partial") {
                (stripped, ".partial")
            } else {
                (tail, "")
            };
            if mid.len() != 16 {
                return false;
            }
            if !mid.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_uppercase())) {
                return false;
            }
            ext.is_empty() || ext == ".partial"
        }
        let original_len = wal_files.len();
        wal_files.retain(|f| is_valid_wal_name(f));
        let dropped = original_len - wal_files.len();
        if dropped > 0 {
            warn!(
                instance_id = %instance_id,
                dropped,
                "ignored WAL filenames outside the Postgres naming scheme (possible filesystem tampering — investigate)"
            );
        }

        // Drop already-processed segments.
        let processed = self.db.get_processed_wal_segments(instance_id)?;
        let processed_set: std::collections::HashSet<&str> =
            processed.iter().map(|s| s.as_str()).collect();

        // Recover the previous chain link.
        let prev_hash_hex = self.db.get_latest_wal_hash(instance_id)?;
        let mut prev_hash_bytes: Option<Vec<u8>> =
            prev_hash_hex.as_deref().and_then(|h| hex::decode(h).ok());
        let mut next_chain_index = self
            .db
            .get_latest_wal_chain_index(instance_id)?
            .map(|i| i + 1)
            .unwrap_or(0);

        let archive_dir = self.archive_dir(instance_id);
        let encrypted_dir = self.encrypted_dir(instance_id);
        fs::create_dir_all(&archive_dir).await?;
        fs::create_dir_all(&encrypted_dir).await?;

        // Look up replicas once per processing pass; the registry might
        // change between passes but is stable for the duration of one.
        let replicas = self.db.list_instance_replicas(instance_id)?;

        let key_bytes = hex::decode(&instance.wal_encryption_key)
            .context("wal_encryption_key is not valid hex")?;
        if key_bytes.len() != 32 {
            bail!("wal_encryption_key must be 32 bytes, got {}", key_bytes.len());
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

        for wal_file in &wal_files {
            if processed_set.contains(wal_file.as_str()) {
                continue;
            }

            // Copy plaintext segment out of the container.
            let local_plaintext = archive_dir.join(wal_file);
            let cp = Command::new("docker")
                .args([
                    "cp",
                    &format!(
                        "{}:/var/lib/postgresql/wal-archive/{}",
                        container_name, wal_file
                    ),
                    &local_plaintext.to_string_lossy(),
                ])
                .output()
                .await
                .context("docker cp failed")?;
            if !cp.status.success() {
                error!(wal_file = wal_file.as_str(), stderr = %String::from_utf8_lossy(&cp.stderr), "docker cp failed");
                continue;
            }

            let plaintext = fs::read(&local_plaintext).await?;

            // Encrypt: nonce || ciphertext || tag.
            let mut nonce_bytes = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Bind the ciphertext to the segment name + chain index via AEAD
            // associated data, so a malicious replica can't swap segments.
            let aad = format!("{}|{}|{}", instance_id, wal_file, next_chain_index);
            let ciphertext = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &plaintext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

            let mut on_disk = Vec::with_capacity(NONCE_LEN + ciphertext.len());
            on_disk.extend_from_slice(&nonce_bytes);
            on_disk.extend_from_slice(&ciphertext);

            // SHA-256 of the on-the-wire encrypted blob, chained to the
            // previous segment.
            let mut hasher = Sha256::new();
            if let Some(ref prev) = prev_hash_bytes {
                hasher.update(prev);
            }
            hasher.update(&on_disk);
            let hash: [u8; 32] = hasher.finalize().into();
            let hash_hex = hex::encode(hash);
            let prev_hex = prev_hash_bytes
                .as_deref()
                .map(hex::encode)
                .unwrap_or_default();

            // Persist the encrypted blob.
            let encrypted_path = encrypted_dir.join(format!("{}.enc", wal_file));
            fs::write(&encrypted_path, &on_disk).await?;

            // Record in DB. INSERT OR IGNORE makes this safe across crashes.
            let segment = WalSegment {
                id: None,
                instance_id: instance_id.clone(),
                segment_name: wal_file.clone(),
                hash: hash_hex.clone(),
                previous_hash: prev_hex.clone(),
                encrypted_path: encrypted_path.to_string_lossy().to_string(),
                size: on_disk.len() as i64,
                chain_index: next_chain_index,
                created_at: None,
            };
            self.db.insert_wal_segment(&segment)?;

            // Enqueue a shipment for every registered replica.
            let mut enqueued = 0usize;
            for replica in &replicas {
                if self
                    .db
                    .enqueue_replica_shipment(instance_id, replica, wal_file)?
                {
                    enqueued += 1;
                }
            }

            info!(
                instance_id = %instance_id,
                segment = %wal_file,
                chain_index = next_chain_index,
                size = on_disk.len(),
                hash = &hash_hex[..16],
                replicas = enqueued,
                "WAL segment encrypted + shipments enqueued"
            );

            // Advance chain state for the next segment in this pass.
            prev_hash_bytes = Some(hash.to_vec());
            next_chain_index += 1;

            // Clean up plaintext. We never persist plaintext WAL on the host
            // and we delete it from the container too once it's been archived.
            let _ = fs::remove_file(&local_plaintext).await;
            let _ = Command::new("docker")
                .args([
                    "exec",
                    &container_name,
                    "rm",
                    "-f",
                    &format!("/var/lib/postgresql/wal-archive/{}", wal_file),
                ])
                .output()
                .await;
        }

        Ok(())
    }

    /// Drain the `replica_shipments` queue, POSTing each ciphertext to its
    /// target replica. Marks rows shipped/failed and respects retry caps.
    pub async fn ship_pending_segments(&self) -> Result<()> {
        let pending = self.db.get_pending_shipments()?;
        if pending.is_empty() {
            return Ok(());
        }

        for shipment in pending {
            if shipment.attempts >= MAX_SHIPMENT_ATTEMPTS {
                self.db.mark_shipment_failed(shipment.id)?;
                warn!(
                    segment = %shipment.segment_name,
                    endpoint = %shipment.replica_node_endpoint,
                    "shipment exceeded retry cap, marked failed"
                );
                continue;
            }

            let segment = match self
                .db
                .get_wal_segment(&shipment.instance_id, &shipment.segment_name)?
            {
                Some(s) => s,
                None => {
                    error!(
                        segment = %shipment.segment_name,
                        "shipment references unknown WAL segment"
                    );
                    self.db.mark_shipment_failed(shipment.id)?;
                    continue;
                }
            };

            let body = match fs::read(&segment.encrypted_path).await {
                Ok(d) => d,
                Err(e) => {
                    error!(path = %segment.encrypted_path, error = %e, "encrypted WAL read failed");
                    self.db.increment_shipment_attempts(shipment.id)?;
                    continue;
                }
            };

            let url = format!(
                "{}/replication/receive",
                shipment.replica_node_endpoint.trim_end_matches('/')
            );

            // HMAC-sign the headers if a shared secret is configured.
            // Receivers without the secret accept anything (rollout phase);
            // once every node has the secret, set
            // SUPABA_REPLICATION_REQUIRE_HMAC=true on receivers to enforce.
            let mut req = self
                .http
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Instance-Id", &shipment.instance_id)
                .header("X-Segment-Name", &shipment.segment_name)
                .header("X-Segment-Hash", &segment.hash)
                .header("X-Previous-Hash", &segment.previous_hash)
                .header("X-Chain-Index", segment.chain_index.to_string());
            if let Some(secret) = replication_hmac_secret() {
                let sig = build_replication_sig(
                    &secret,
                    &shipment.instance_id,
                    &shipment.segment_name,
                    &segment.hash,
                    &segment.previous_hash,
                    segment.chain_index,
                );
                req = req.header("X-Replication-Sig", sig);
            }
            let resp = req.body(body).send().await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    self.db.mark_shipment_shipped(shipment.id)?;
                    info!(
                        segment = %shipment.segment_name,
                        endpoint = %shipment.replica_node_endpoint,
                        chain_index = segment.chain_index,
                        "WAL segment shipped"
                    );
                }
                Ok(r) => {
                    self.db.increment_shipment_attempts(shipment.id)?;
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    error!(
                        segment = %shipment.segment_name,
                        status = %status,
                        body = %body.chars().take(200).collect::<String>(),
                        "replica rejected segment"
                    );
                }
                Err(e) => {
                    self.db.increment_shipment_attempts(shipment.id)?;
                    error!(
                        segment = %shipment.segment_name,
                        endpoint = %shipment.replica_node_endpoint,
                        error = %e,
                        "shipment HTTP error"
                    );
                }
            }
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────────
    // Replica-side ingest
    // ───────────────────────────────────────────────────────────────────────

    /// Ingest an encrypted WAL segment received from a peer primary node.
    ///
    /// Validates:
    ///   - SHA-256 of the body matches the `X-Segment-Hash` header
    ///   - The hash chain links to the latest segment we already hold for
    ///     this instance (or empty if this is the first)
    ///   - The chain index is one greater than the latest stored
    ///
    /// Stores the ciphertext at `<data>/replicas/<instance>/<segment>.enc`
    /// and inserts a `replica_segments` row.
    pub async fn receive_segment(
        &self,
        instance_id: &str,
        segment_name: &str,
        provided_hash: &str,
        provided_previous_hash: &str,
        provided_chain_index: i64,
        provided_sig: Option<&str>,
        body: &[u8],
    ) -> Result<ReplicaSegment> {
        // Audit F62: validate path-bound identifiers BEFORE doing ANY
        // filesystem or DB work. Without these guards an attacker who
        // reaches /replication/receive (with a leaked or missing HMAC
        // secret) could supply traversal values in instance_id or
        // segment_name and write attacker bytes anywhere the node
        // process can write.
        crate::path_safety::validate_instance_id_component(instance_id)
            .map_err(|e| anyhow!("invalid instance_id: {e}"))?;
        crate::path_safety::validate_segment_name(segment_name)
            .map_err(|e| anyhow!("invalid segment_name: {e}"))?;

        // Authenticate the caller before doing ANY work. Without this gate,
        // an unauthenticated POST to /replication/receive could fill disk
        // or corrupt the hash chain.
        verify_replication_sig(
            provided_sig,
            instance_id,
            segment_name,
            provided_hash,
            provided_previous_hash,
            provided_chain_index,
        )?;
        if body.len() < NONCE_LEN + 16 {
            bail!("body too small to contain nonce + tag (got {} bytes)", body.len());
        }

        // Validate hash of received bytes.
        let computed = Sha256::digest(body);
        let computed_hex = hex::encode(computed);

        // The wire hash is hash(prev || body), so we recompute the same way.
        let mut chain_hasher = Sha256::new();
        if !provided_previous_hash.is_empty() {
            let prev_bytes = hex::decode(provided_previous_hash)
                .context("X-Previous-Hash is not valid hex")?;
            chain_hasher.update(&prev_bytes);
        }
        chain_hasher.update(body);
        let chain_hash = hex::encode(chain_hasher.finalize());
        if chain_hash != provided_hash {
            bail!(
                "hash mismatch: header={}, computed={} (body sha256={})",
                provided_hash,
                chain_hash,
                computed_hex
            );
        }

        // Validate the chain links to whatever we already have on this replica.
        match self.db.latest_replica_hash(instance_id)? {
            Some((latest_hash, latest_idx)) => {
                if provided_previous_hash != latest_hash {
                    bail!(
                        "chain break: expected previous_hash={}, got {}",
                        latest_hash,
                        provided_previous_hash
                    );
                }
                if provided_chain_index != latest_idx + 1 {
                    bail!(
                        "chain index gap: expected {}, got {}",
                        latest_idx + 1,
                        provided_chain_index
                    );
                }
            }
            None => {
                if !provided_previous_hash.is_empty() {
                    debug!(
                        "first segment for instance {} but X-Previous-Hash is non-empty (will accept)",
                        instance_id
                    );
                }
            }
        }

        // Persist. Belt-and-braces: validators above already restrict the
        // shape of instance_id and segment_name, but we *also* run the
        // final path through safe_join_under so any future widening of
        // those validators can never make the filesystem layer unsafe.
        let replica_dir = self.replica_dir(instance_id);
        fs::create_dir_all(&replica_dir).await?;
        let segment_file = format!("{}.enc", segment_name);
        let stored_path = crate::path_safety::safe_join_under(
            &replica_dir,
            &[segment_file.as_str()],
        )
        .map_err(|e| anyhow!("replica path escape: {e}"))?;
        fs::write(&stored_path, body).await?;

        let row = ReplicaSegment {
            id: None,
            instance_id: instance_id.to_string(),
            segment_name: segment_name.to_string(),
            hash: provided_hash.to_string(),
            previous_hash: provided_previous_hash.to_string(),
            stored_path: stored_path.to_string_lossy().to_string(),
            size: body.len() as i64,
            chain_index: provided_chain_index,
            received_at: None,
        };
        self.db.insert_replica_segment(&row)?;

        info!(
            instance_id = %instance_id,
            segment = %segment_name,
            chain_index = provided_chain_index,
            size = body.len(),
            "encrypted WAL segment received and stored"
        );

        Ok(row)
    }

    pub async fn list_replica_segments(&self, instance_id: &str) -> Result<Vec<ReplicaSegment>> {
        self.db.list_replica_segments_db(instance_id)
    }

    pub async fn get_replica_segment_bytes(
        &self,
        instance_id: &str,
        segment_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        // Audit F62: same defence as receive_segment — validate ids
        // before joining them into a filesystem path.
        crate::path_safety::validate_instance_id_component(instance_id)
            .map_err(|e| anyhow!("invalid instance_id: {e}"))?;
        crate::path_safety::validate_segment_name(segment_name)
            .map_err(|e| anyhow!("invalid segment_name: {e}"))?;
        let segment_file = format!("{}.enc", segment_name);
        let path = crate::path_safety::safe_join_under(
            &self.replica_dir(instance_id),
            &[segment_file.as_str()],
        )
        .map_err(|e| anyhow!("replica path escape: {e}"))?;
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read(&path).await?))
    }

    // ───────────────────────────────────────────────────────────────────────
    // Path helpers
    // ───────────────────────────────────────────────────────────────────────

    fn archive_dir(&self, instance_id: &str) -> PathBuf {
        Path::new(&self.config.data_dir)
            .join("wal-archive")
            .join(instance_id)
    }

    fn encrypted_dir(&self, instance_id: &str) -> PathBuf {
        Path::new(&self.config.data_dir)
            .join("wal-encrypted")
            .join(instance_id)
    }

    fn replica_dir(&self, instance_id: &str) -> PathBuf {
        Path::new(&self.config.data_dir)
            .join("replicas")
            .join(instance_id)
    }
}

/// Generate a fresh 32-byte ChaCha20-Poly1305 key, hex-encoded.
pub fn fresh_wal_key_hex() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    hex::encode(key)
}
