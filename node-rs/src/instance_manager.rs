use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bollard::Docker;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::Engine;

use crate::config::Config;
use crate::db::{Database, Instance};
use crate::warm_pool::{self, WarmInstance};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub wallet_pubkey: String,
    pub name: Option<String>,
    /// Optional data-encryption key (caller-provided, 32 bytes).
    pub dek: Option<Vec<u8>>,
    /// Auto-confirm signups without sending a confirmation email. `true`
    /// (default) is the right call for agent-built apps that want
    /// frictionless onboarding; `false` requires the user to click a
    /// magic-link / confirm email before the account is usable.
    /// When `false`, SMTP MUST be configured on the node, otherwise
    /// signups silently fail.
    #[serde(default)]
    pub email_autoconfirm: Option<bool>,
    /// Extra URLs the magic-link / OAuth callback may redirect to. The
    /// instance's own subdomain (`https://<id>.<public_host>/api/**`),
    /// the IPFS gateway (`https://ipfs.<public_host>/**`), and
    /// `http://localhost:*` are always added — these cover SPAs hosted on
    /// IPFS via kraph_pin_frontend / kraph_github_build_frontend, the
    /// instance API itself, and local dev. Pass extra URLs here when the
    /// agent serves the SPA at a custom domain (e.g. via kraph_buy_domain
    /// + a CNAME to ipfs.kraph.com).
    #[serde(default, rename = "redirectUrls")]
    pub redirect_urls: Option<Vec<String>>,
    /// Audit F69: replica endpoints that the gateway placed alongside
    /// this primary. The list flows in via the SAME signed body as
    /// provision, so a single owner signature authorises the primary
    /// AND its replica registrations — no unsigned follow-up call is
    /// needed. Empty / missing means no replicas (single-node mode).
    #[serde(default, rename = "replicaEndpoints")]
    pub replica_endpoints: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ProvisionResult {
    pub id: String,
    pub url: String,
    pub studio_url: String,
    pub anon_key: String,
    pub service_role_key: String,
    pub postgres_connection_string: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ContainerInfo {
    pub name: String,
    pub status: String,
    pub health: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InstanceHealth {
    pub id: String,
    pub status: String,
    pub containers: Vec<ContainerInfo>,
    pub uptime_seconds: i64,
}

#[derive(Debug, Default, Serialize)]
pub struct NodeStats {
    pub total_instances: usize,
    pub running_instances: usize,
    pub available_capacity: usize,
    pub allocated_ports: usize,
}

// ---------------------------------------------------------------------------
// Secret material — zeroized on drop
// ---------------------------------------------------------------------------

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct SupabaseKeys {
    jwt_secret: String,
    anon_key: String,
    service_role_key: String,
    postgres_password: String,
    dashboard_password: String,
}

/// Parameters for `.env` template rendering.
struct EnvParams {
    instance_id: String,
    hostname: String,
    kong_port: u16,
    postgres_port: u16,
    gotrue_port: u16,
    realtime_port: u16,
    storage_port: u16,
    studio_port: u16,
    analytics_port: u16,
    meta_port: u16,
    functions_port: u16,
    jwt_secret: String,
    anon_key: String,
    service_role_key: String,
    postgres_password: String,
    dashboard_password: String,
    cpuset_cpus: Option<String>,
    /// Per-instance autoconfirm toggle. Default `true` for frictionless
    /// agent-built apps; opt-out to require email click-through.
    mailer_autoconfirm: bool,
    /// Public site URL exposed in magic-link / verify / recovery emails.
    /// Includes the trailing scheme + host (no path). When config.public_host
    /// is set, this is `https://<id>.<public_host>/api`; otherwise legacy
    /// `http://<hostname>:<kong_port>`.
    site_url: String,
    api_external_url: String,
    /// Comma-separated `GOTRUE_URI_ALLOW_LIST` value. Built by
    /// `compose_redirect_allow_list` from a permissive default (instance
    /// subdomain glob, IPFS gateway glob, localhost wildcard) plus any
    /// extras the caller passed in `ProvisionRequest::redirect_urls`.
    redirect_allow_list: String,
}

impl Drop for EnvParams {
    fn drop(&mut self) {
        self.jwt_secret.zeroize();
        self.anon_key.zeroize();
        self.service_role_key.zeroize();
        self.postgres_password.zeroize();
        self.dashboard_password.zeroize();
    }
}

// ---------------------------------------------------------------------------
// InstanceManager
// ---------------------------------------------------------------------------

pub struct InstanceManager {
    config: Config,
    db: Arc<Database>,
    docker: Docker,
    /// Set of CPU core indices currently in use.
    allocated_cores: Mutex<HashSet<usize>>,
}

impl InstanceManager {
    pub fn new(config: &Config, db: Arc<Database>) -> Self {
        let docker = Docker::connect_with_local_defaults()
            .expect("failed to connect to Docker daemon");
        Self {
            config: config.clone(),
            db,
            docker,
            allocated_cores: Mutex::new(HashSet::new()),
        }
    }

    // ======================================================================
    // Public API
    // ======================================================================

    /// Full provision: prepare metadata + finalize (docker compose up + health
    /// check). Used by warm pool and tests where the caller expects the final
    /// running state. The HTTP handler uses `prepare_provision` +
    /// `finalize_provision` separately so it can return the credentials in
    /// <1s and run docker compose up in a background tokio task.
    pub async fn provision(&self, request: ProvisionRequest) -> Result<ProvisionResult> {
        let result = self.prepare_provision(request).await?;
        // Run finalize inline (sync caller). Errors here propagate so the
        // caller can react; the DB row is left at status='provisioning' or
        // updated to running/degraded by finalize itself.
        let _ = self.finalize_provision(&result.id).await;
        // Re-read status from DB to give the caller the final state.
        let final_status = self
            .db
            .get_instance_by_id(&result.id)?
            .map(|i| i.status.clone())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(ProvisionResult {
            status: final_status,
            ..result
        })
    }

    /// Phase 1: synchronous metadata prep. Allocates a port block, generates
    /// secrets, writes the .env / kong.yml, copies the docker-compose template,
    /// and inserts the `instances` row with `status='provisioning'`. Returns
    /// the credentials immediately so an HTTP handler can settle a payment
    /// inside the Solana blockhash window before docker compose up runs.
    pub async fn prepare_provision(&self, request: ProvisionRequest) -> Result<ProvisionResult> {
        // 1. Capacity check.
        let running = self.db.running_instance_count()?;
        if running >= self.config.max_instances {
            bail!(
                "node at capacity ({}/{})",
                running,
                self.config.max_instances
            );
        }

        // 2. Instance ID (lowercase only — Docker compose project names must be lowercase).
        let id = nanoid::nanoid!(12).to_lowercase();
        let compose_project = format!("supaba-{id}");
        info!(id = %id, wallet = %request.wallet_pubkey, "preparing new instance metadata");

        // 3. Allocate port block (binding happens after instance insert to satisfy FK).
        let base_port = self
            .db
            .allocate_port_block(self.config.port_range_start, self.config.port_range_end)?;

        let kong_port = base_port;
        let postgres_port = base_port + 1;
        let gotrue_port = base_port + 2;
        let realtime_port = base_port + 3;
        let storage_port = base_port + 4;
        let studio_port = base_port + 5;
        let analytics_port = base_port + 6;
        let meta_port = base_port + 7;
        let functions_port = base_port + 8;

        // 4. Generate secrets.
        let keys = self.generate_supabase_keys()?;

        // 5. CPU set.
        let cpuset = self.allocate_cpu_set();

        // 6. Instance directory.
        let instance_dir = self.config.data_dir.join("instances").join(&id);
        std::fs::create_dir_all(&instance_dir)
            .with_context(|| format!("creating instance dir {:?}", instance_dir))?;

        // Copy docker-compose template.
        self.copy_template(&instance_dir)?;

        // 7. Write .env file.
        let (site_url, api_external_url) = self.public_urls_for(&id, kong_port);
        let redirect_allow_list = self
            .compose_redirect_allow_list(&id, request.redirect_urls.as_deref());
        let env_params = EnvParams {
            instance_id: id.clone(),
            hostname: self.config.hostname.clone(),
            kong_port,
            postgres_port,
            gotrue_port,
            realtime_port,
            storage_port,
            studio_port,
            analytics_port,
            meta_port,
            functions_port,
            jwt_secret: keys.jwt_secret.clone(),
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            postgres_password: keys.postgres_password.clone(),
            dashboard_password: keys.dashboard_password.clone(),
            cpuset_cpus: cpuset.clone(),
            mailer_autoconfirm: request.email_autoconfirm.unwrap_or(true),
            site_url,
            api_external_url,
            redirect_allow_list,
        };
        let env_content = self.render_env_file(&env_params);
        std::fs::write(instance_dir.join(".env"), &env_content)
            .context("writing .env file")?;

        // 7a. Ensure the per-instance edge-function env file exists, even if
        // empty. The docker-compose template has `env_file: ./volumes/functions/.env`
        // for the functions service, and compose errors out if that file is
        // missing at container-create time. An empty file is valid.
        let functions_env_dir = instance_dir.join("volumes").join("functions");
        std::fs::create_dir_all(&functions_env_dir)
            .context("creating volumes/functions dir")?;
        let functions_env_path = functions_env_dir.join(".env");
        if !functions_env_path.exists() {
            std::fs::write(
                &functions_env_path,
                b"# Supaba edge-function env (managed by node).\n",
            )
            .context("writing empty functions .env placeholder")?;
        }

        // 7b. Write kong.yml with actual keys substituted (no template vars).
        let kong_path = instance_dir.join("volumes").join("api").join("kong.yml");
        if kong_path.exists() {
            let kong_template = std::fs::read_to_string(&kong_path)
                .context("reading kong.yml template")?;
            let kong_rendered = kong_template
                .replace("${ANON_KEY}", &keys.anon_key)
                .replace("${SERVICE_ROLE_KEY}", &keys.service_role_key);
            std::fs::write(&kong_path, kong_rendered)
                .context("writing rendered kong.yml")?;
        }

        // 8. Persist to DB at status='provisioning'. The actual docker
        // compose up runs in finalize_provision and updates this row to
        // 'running' or 'degraded' when health checks complete.
        let now = Utc::now().to_rfc3339();
        let url = format!("http://{}:{}", self.config.hostname, kong_port);
        let studio_url = format!("http://{}:{}", self.config.hostname, studio_port);

        let instance = Instance {
            id: id.clone(),
            wallet_pubkey: request.wallet_pubkey.clone(),
            name: request.name.clone(),
            status: "provisioning".into(),
            kong_port,
            postgres_port,
            gotrue_port,
            realtime_port,
            storage_port,
            studio_port,
            analytics_port,
            meta_port,
            functions_port,
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            jwt_secret: keys.jwt_secret.clone(),
            postgres_password: keys.postgres_password.clone(),
            dashboard_password: keys.dashboard_password.clone(),
            url: url.clone(),
            studio_url: studio_url.clone(),
            compose_project_name: compose_project,
            instance_dir: instance_dir.to_string_lossy().into(),
            cpuset_cpus: cpuset,
            wal_encryption_key: crate::replication::fresh_wal_key_hex(),
            created_at: now.clone(),
            expires_at: None,
            destroyed_at: None,
            lifecycle_state: "running".to_string(),
            last_seen_at: None,
            pinned_until: None,
        };
        self.db.insert_instance(&instance)?;
        self.db.bind_port_to_instance(base_port, &id)?;

        let pg_conn = format!(
            "postgresql://postgres:{}@{}:{}/postgres",
            keys.postgres_password, self.config.hostname, postgres_port
        );

        info!(id = %id, "instance metadata prepared (status=provisioning)");

        Ok(ProvisionResult {
            id,
            url,
            studio_url,
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            postgres_connection_string: pg_conn,
            status: "provisioning".into(),
            created_at: now,
        })
    }

    /// Phase 2: bring the prepared instance up. Reads the row inserted by
    /// prepare_provision, runs `docker compose up` with retries, waits for
    /// container health, and updates the row's status to 'running' or
    /// 'degraded'. Designed to run inside a tokio::spawn so the HTTP handler
    /// returns its response (and any x402 settlement) without blocking on
    /// Docker.
    pub async fn finalize_provision(&self, instance_id: &str) -> Result<()> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .with_context(|| format!("instance {instance_id} not found in DB"))?;

        let compose_project = instance.compose_project_name.clone();
        let instance_dir = std::path::PathBuf::from(&instance.instance_dir);

        // docker compose up — retry up to 3 times because services may
        // exit early before db is healthy on the first attempt.
        for attempt in 1..=3 {
            let up_output = Command::new("docker")
                .args(["compose", "-p", &compose_project, "up", "-d"])
                .current_dir(&instance_dir)
                .output()
                .await
                .context("running docker compose up")?;

            if up_output.status.success() {
                info!(id = %instance_id, attempt, "docker compose up succeeded");
                break;
            }

            let stderr = String::from_utf8_lossy(&up_output.stderr);
            if attempt < 3 {
                warn!(id = %instance_id, attempt, "docker compose up exited non-zero, retrying in 10s...");
                tokio::time::sleep(Duration::from_secs(10)).await;
            } else {
                warn!(id = %instance_id, %stderr, "docker compose up failed after 3 attempts, checking health...");
            }
        }

        // Wait for containers to report healthy.
        let healthy = self
            .wait_for_health(&compose_project, Duration::from_secs(180))
            .await;
        let final_status = if healthy { "running" } else { "degraded" };
        self.db.update_instance_status(instance_id, final_status)?;

        info!(id = %instance_id, status = %final_status, "instance finalize complete");
        Ok(())
    }

    /// Provision by reassigning a pre-warmed instance. This rewrites the .env
    /// with real credentials and restarts the compose stack under a new project
    /// name, reducing provisioning time from ~30s to <2s.
    pub async fn provision_from_warm(
        &self,
        request: ProvisionRequest,
        warm: WarmInstance,
    ) -> Result<ProvisionResult> {
        // 1. Capacity check.
        let running = self.db.running_instance_count()?;
        if running >= self.config.max_instances {
            bail!(
                "node at capacity ({}/{})",
                running,
                self.config.max_instances
            );
        }

        // 2. Instance ID and compose project name.
        let id = nanoid::nanoid!(12);
        let compose_project = format!("supaba-{id}");
        info!(id = %id, wallet = %request.wallet_pubkey, "provisioning from warm instance");

        // 3. Reuse the warm instance's port block.
        let base_port = warm.base_port;

        // Update the port allocation to the new instance id.
        self.db.free_port_block(&warm.compose_project_name)?;
        self.db.allocate_port_block_at(base_port)?;
        self.db.bind_port_to_instance(base_port, &id)?;

        let kong_port = base_port;
        let postgres_port = base_port + 1;
        let gotrue_port = base_port + 2;
        let realtime_port = base_port + 3;
        let storage_port = base_port + 4;
        let studio_port = base_port + 5;
        let analytics_port = base_port + 6;
        let meta_port = base_port + 7;
        let functions_port = base_port + 8;

        // 4. Generate real secrets.
        let keys = self.generate_supabase_keys()?;

        // 5. CPU set.
        let cpuset = self.allocate_cpu_set();

        // 6. Render real .env and reassign the warm instance.
        let (site_url, api_external_url) = self.public_urls_for(&id, kong_port);
        let redirect_allow_list = self
            .compose_redirect_allow_list(&id, request.redirect_urls.as_deref());
        let env_params = EnvParams {
            instance_id: id.clone(),
            hostname: self.config.hostname.clone(),
            kong_port,
            postgres_port,
            gotrue_port,
            realtime_port,
            storage_port,
            studio_port,
            analytics_port,
            meta_port,
            functions_port,
            jwt_secret: keys.jwt_secret.clone(),
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            postgres_password: keys.postgres_password.clone(),
            dashboard_password: keys.dashboard_password.clone(),
            cpuset_cpus: cpuset.clone(),
            mailer_autoconfirm: request.email_autoconfirm.unwrap_or(true),
            site_url,
            api_external_url,
            redirect_allow_list,
        };
        let env_content = self.render_env_file(&env_params);

        warm_pool::reassign_warm_instance(&warm, &env_content, &compose_project)
            .await
            .context("reassigning warm instance")?;

        // 7. Wait for containers to become healthy.
        let healthy = self
            .wait_for_health(&compose_project, Duration::from_secs(30))
            .await;
        let status = if healthy { "running" } else { "degraded" };

        let now = Utc::now().to_rfc3339();
        let url = format!("http://{}:{}", self.config.hostname, kong_port);
        let studio_url = format!("http://{}:{}", self.config.hostname, studio_port);

        // 8. Move the instance directory from warm/ to instances/.
        let final_dir = self.config.data_dir.join("instances").join(&id);
        if let Err(e) = std::fs::rename(&warm.instance_dir, &final_dir) {
            // If rename fails (cross-device), try copy + remove.
            warn!(error = %e, "rename failed, falling back to copy");
            copy_dir_recursive(&warm.instance_dir, &final_dir)?;
            let _ = std::fs::remove_dir_all(&warm.instance_dir);
        }

        // 9. Persist to DB.
        let instance = Instance {
            id: id.clone(),
            wallet_pubkey: request.wallet_pubkey.clone(),
            name: request.name.clone(),
            status: status.into(),
            kong_port,
            postgres_port,
            gotrue_port,
            realtime_port,
            storage_port,
            studio_port,
            analytics_port,
            meta_port,
            functions_port,
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            jwt_secret: keys.jwt_secret.clone(),
            postgres_password: keys.postgres_password.clone(),
            dashboard_password: keys.dashboard_password.clone(),
            url: url.clone(),
            studio_url: studio_url.clone(),
            compose_project_name: compose_project,
            instance_dir: final_dir.to_string_lossy().into(),
            cpuset_cpus: cpuset,
            wal_encryption_key: crate::replication::fresh_wal_key_hex(),
            created_at: now.clone(),
            expires_at: None,
            destroyed_at: None,
            lifecycle_state: "running".to_string(),
            last_seen_at: None,
            pinned_until: None,
        };
        self.db.insert_instance(&instance)?;

        let pg_conn = format!(
            "postgresql://postgres:{}@{}:{}/postgres",
            keys.postgres_password, self.config.hostname, postgres_port
        );

        info!(id = %id, %status, "instance provisioned from warm pool");

        Ok(ProvisionResult {
            id,
            url,
            studio_url,
            anon_key: keys.anon_key.clone(),
            service_role_key: keys.service_role_key.clone(),
            postgres_connection_string: pg_conn,
            status: status.into(),
            created_at: now,
        })
    }

    pub async fn destroy(&self, instance_id: &str, wallet: &str) -> Result<()> {
        // 1. Verify ownership.
        let instance = self
            .db
            .get_instance(instance_id, wallet)?
            .with_context(|| format!("instance {instance_id} not found"))?;

        info!(id = %instance_id, "destroying instance");

        // 2. docker compose down -v.
        let down_output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &instance.compose_project_name,
                "down",
                "-v",
                "--remove-orphans",
            ])
            .current_dir(&instance.instance_dir)
            .output()
            .await
            .context("running docker compose down")?;

        if !down_output.status.success() {
            let stderr = String::from_utf8_lossy(&down_output.stderr);
            warn!(%instance_id, %stderr, "docker compose down had errors");
        }

        // 3. Remove instance directory.
        if let Err(e) = std::fs::remove_dir_all(&instance.instance_dir) {
            warn!(%instance_id, error = %e, "failed to remove instance dir");
        }

        // 4. Release resources.
        if let Some(ref cpuset) = instance.cpuset_cpus {
            self.release_cpu_set(cpuset);
        }
        self.db.free_port_block(instance_id)?;

        // 4b. Clear user-supplied env vars. The schema has ON DELETE CASCADE
        // but destroy_instance only tombstones the `instances` row (it does
        // not hard-delete it), so the cascade does not fire. Explicit
        // cleanup keeps secrets out of the DB after destruction.
        if let Err(e) = self.db.delete_all_env(instance_id) {
            warn!(instance_id, error = %e, "failed to clear instance_env rows on destroy");
        }

        // 5. Mark destroyed.
        self.db.destroy_instance(instance_id)?;

        info!(id = %instance_id, "instance destroyed");
        Ok(())
    }

    /// Suspend an instance: docker compose STOP every container in its
    /// project. Volumes are preserved on disk; on the next request the
    /// resume path runs `docker compose start` and Postgres recovers
    /// from WAL in ~10-20 s.
    ///
    /// Does NOT change `instances.status` — that column tracks the
    /// long-term lifecycle (provisioning/active/destroyed). Suspend
    /// flips `lifecycle_state` only.
    pub async fn suspend(&self, instance_id: &str) -> Result<()> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .with_context(|| format!("instance {instance_id} not found"))?;

        if instance.destroyed_at.is_some() {
            return Err(anyhow::anyhow!(
                "cannot suspend destroyed instance {instance_id}"
            ));
        }

        info!(id = %instance_id, "suspending instance (docker compose stop)");

        let stop_output = Command::new("docker")
            .args(["compose", "-p", &instance.compose_project_name, "stop"])
            .current_dir(&instance.instance_dir)
            .output()
            .await
            .context("running docker compose stop")?;

        if !stop_output.status.success() {
            let stderr = String::from_utf8_lossy(&stop_output.stderr);
            return Err(anyhow::anyhow!(
                "docker compose stop failed for {instance_id}: {stderr}"
            ));
        }

        self.db.set_lifecycle_state(instance_id, "suspended")?;
        info!(id = %instance_id, "instance suspended");
        Ok(())
    }

    /// Bring a suspended instance back online. Sets state to `starting`,
    /// runs `docker compose start`, polls Postgres health for up to 30 s,
    /// then sets state to `running`. On failure the state is reset to
    /// `suspended` so the next request retries cleanly.
    ///
    /// **Caller responsible for serialization.** Concurrent resumes of
    /// the same instance race each other on the docker socket. Wrap
    /// the call in a per-instance mutex held by the HTTP handler.
    pub async fn resume(&self, instance_id: &str) -> Result<()> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .with_context(|| format!("instance {instance_id} not found"))?;

        if instance.destroyed_at.is_some() {
            return Err(anyhow::anyhow!(
                "cannot resume destroyed instance {instance_id}"
            ));
        }

        // Already running — nothing to do. Coalesces concurrent requests
        // that arrive after the mutex holder finished.
        if instance.lifecycle_state == "running" {
            return Ok(());
        }

        self.db.set_lifecycle_state(instance_id, "starting")?;
        info!(id = %instance_id, "resuming instance (docker compose start)");

        let start_output = Command::new("docker")
            .args(["compose", "-p", &instance.compose_project_name, "start"])
            .current_dir(&instance.instance_dir)
            .output()
            .await
            .context("running docker compose start")?;

        if !start_output.status.success() {
            let stderr = String::from_utf8_lossy(&start_output.stderr);
            // Reset state so the next request retries from a known place.
            let _ = self.db.set_lifecycle_state(instance_id, "suspended");
            return Err(anyhow::anyhow!(
                "docker compose start failed for {instance_id}: {stderr}"
            ));
        }

        // Wait for Postgres to recover from WAL and accept connections.
        // The pg port is exposed on the host, so we just dial TCP — full
        // SELECT 1 ping would need a client; TCP open is enough to know
        // the container is listening, and Kong won't proxy traffic until
        // the upstreams are healthy anyway.
        let pg_addr = format!("{}:{}", self.config.hostname, instance.postgres_port);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut last_err: Option<std::io::Error> = None;
        while std::time::Instant::now() < deadline {
            match tokio::net::TcpStream::connect(&pg_addr).await {
                Ok(_) => {
                    self.db.set_lifecycle_state(instance_id, "running")?;
                    info!(id = %instance_id, addr = %pg_addr, "instance resumed and Postgres is listening");
                    // Bump last_seen_at so we don't immediately re-suspend.
                    let _ = self.db.touch_instance(instance_id);
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        // Postgres never came up. Leave state as 'starting' so the next
        // request will try again — flipping back to suspended would lie
        // about the actual container state (they ARE started, just not
        // healthy yet) and would trigger a second `compose start` which
        // can fail when containers are already running.
        Err(anyhow::anyhow!(
            "instance {instance_id} did not become healthy within 30s: last_err={:?}",
            last_err
        ))
    }

    pub async fn get_health(&self, instance_id: &str) -> Result<Option<InstanceHealth>> {
        // Use bollard to list containers for the compose project.
        use bollard::container::ListContainersOptions;
        use std::collections::HashMap;

        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![format!("com.docker.compose.project=supaba-{instance_id}")],
        );
        let opts = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(opts)).await?;
        if containers.is_empty() {
            return Ok(None);
        }

        let mut infos = Vec::new();
        let mut oldest_created: i64 = Utc::now().timestamp();
        for c in &containers {
            let name = c
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_default();
            let status = c.status.clone().unwrap_or_default();
            let health = c.state.clone();
            if let Some(created) = c.created {
                if created < oldest_created {
                    oldest_created = created;
                }
            }
            infos.push(ContainerInfo {
                name,
                status,
                health,
            });
        }

        let all_running = containers
            .iter()
            .all(|c| c.state.as_deref() == Some("running"));
        let status = if all_running { "running" } else { "degraded" };
        let uptime = Utc::now().timestamp() - oldest_created;

        Ok(Some(InstanceHealth {
            id: instance_id.to_string(),
            status: status.into(),
            containers: infos,
            uptime_seconds: uptime,
        }))
    }

    pub fn list_instances(
        &self,
        wallet: &str,
        status: Option<&str>,
    ) -> Result<Vec<Instance>> {
        self.db.list_instances(wallet, status)
    }

    /// List all instances across all wallets (for admin / integrity endpoints).
    pub fn list_all_instances(&self) -> Result<Vec<Instance>> {
        self.db.list_all_instances()
    }

    /// Get a single instance by ID, verifying wallet ownership.
    /// If wallet is empty, ownership check is skipped.
    pub fn get_instance(&self, id: &str, wallet: &str) -> Result<Option<Instance>> {
        if wallet.is_empty() {
            return self.db.get_instance_by_id(id);
        }
        let instances = self.db.list_instances(wallet, None)?;
        Ok(instances.into_iter().find(|i| i.id == id))
    }

    pub fn extend_instance(
        &self,
        id: &str,
        wallet: &str,
        duration_secs: i64,
    ) -> Result<()> {
        self.db.extend_instance(id, wallet, duration_secs)
    }

    pub async fn cleanup_expired(&self) -> Result<Vec<String>> {
        let expired = self.db.expired_instance_ids()?;
        let mut cleaned = Vec::new();
        for (id, wallet) in expired {
            info!(id = %id, "cleaning up expired instance");
            if let Err(e) = self.destroy(&id, &wallet).await {
                error!(id = %id, error = %e, "failed to clean up expired instance");
            } else {
                cleaned.push(id);
            }
        }
        Ok(cleaned)
    }

    pub fn get_stats(&self) -> Result<NodeStats> {
        let running = self.db.running_instance_count()?;
        let allocated_ports = self.db.allocated_port_count()?;
        Ok(NodeStats {
            total_instances: running,
            running_instances: running,
            available_capacity: self.config.max_instances.saturating_sub(running),
            allocated_ports,
        })
    }

    // ======================================================================
    // Private helpers
    // ======================================================================

    /// Allocate 2 CPU cores for a new instance. Returns a cpuset string like
    /// "2,3".
    fn allocate_cpu_set(&self) -> Option<String> {
        let mut cores = self.allocated_cores.lock().expect("cpu lock poisoned");
        let total = self.config.available_cpu_cores;

        // Find two consecutive free cores.
        for start in (0..total).step_by(2) {
            if !cores.contains(&start) && start + 1 < total && !cores.contains(&(start + 1)) {
                cores.insert(start);
                cores.insert(start + 1);
                return Some(format!("{},{}", start, start + 1));
            }
        }
        // If we cannot find a pair, allow unconstrained.
        warn!("no free CPU pair available, running without cpuset constraint");
        None
    }

    fn release_cpu_set(&self, cpuset: &str) {
        let mut cores = self.allocated_cores.lock().expect("cpu lock poisoned");
        for part in cpuset.split(',') {
            if let Ok(n) = part.trim().parse::<usize>() {
                cores.remove(&n);
            }
        }
    }

    /// Generate Supabase JWT secret, anon key and service-role key.
    fn generate_supabase_keys(&self) -> Result<SupabaseKeys> {
        let mut rng = rand::thread_rng();

        // 64 random bytes -> hex for the JWT secret.
        let mut secret_bytes = [0u8; 64];
        rng.fill(&mut secret_bytes);
        let jwt_secret = hex::encode(secret_bytes);
        secret_bytes.zeroize();

        // Build the two Supabase API keys (anon, service_role).
        let anon_key = self.mint_supabase_jwt(&jwt_secret, "anon")?;
        let service_role_key = self.mint_supabase_jwt(&jwt_secret, "service_role")?;

        // Passwords.
        let postgres_password = generate_password(&mut rng, 32);
        let dashboard_password = generate_password(&mut rng, 24);

        Ok(SupabaseKeys {
            jwt_secret,
            anon_key,
            service_role_key,
            postgres_password,
            dashboard_password,
        })
    }

    /// Create a Supabase API-key JWT (`anon` or `service_role`).
    /// Uses HMAC-SHA256 directly to avoid the `ring` dependency.
    fn mint_supabase_jwt(&self, secret: &str, role: &str) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let iat = Utc::now().timestamp();
        let exp = iat + 10 * 365 * 24 * 3600; // ~10 years

        // JWT header: {"alg":"HS256","typ":"JWT"}
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);

        // JWT payload
        let payload_json = serde_json::json!({
            "role": role,
            "iss": "supabase",
            "iat": iat,
            "exp": exp,
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(payload_json.to_string());

        // Sign with HMAC-SHA256
        let signing_input = format!("{}.{}", header, payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
        mac.update(signing_input.as_bytes());
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(mac.finalize().into_bytes());

        Ok(format!("{}.{}.{}", header, payload, signature))
    }

    /// Compute the public URLs (SITE_URL + API_EXTERNAL_URL) GoTrue should
    /// embed in magic-link / verify / recovery emails. When `public_host` is
    /// set, this is the gateway-proxied subdomain
    /// (`https://<id>.<public_host>/api`). Otherwise legacy direct-to-node.
    pub fn public_urls_for(&self, instance_id: &str, kong_port: u16) -> (String, String) {
        let public = self.config.public_host.trim().trim_matches(|c| c == '.' || c == '/');
        if !public.is_empty() {
            let base = format!("https://{instance_id}.{public}/api");
            (base.clone(), base)
        } else {
            let base = format!("http://{}:{}", self.config.hostname, kong_port);
            (base.clone(), base)
        }
    }

    /// Build the `GOTRUE_URI_ALLOW_LIST` value from a permissive default plus
    /// any caller-supplied extras. Defaults cover everywhere a Kraph-hosted
    /// SPA can legitimately land:
    ///   - `https://<id>.<public_host>/**` — SPA served from instance subdomain
    ///   - `https://ipfs.<public_host>/**` — SPA pinned to IPFS via Kubo
    ///   - `http://localhost:*` + `http://127.0.0.1:*` — local dev
    /// Extras passed via the provision request let agents add custom domains
    /// bound through `kraph_buy_domain` + a CNAME to the IPFS gateway.
    fn compose_redirect_allow_list(
        &self,
        instance_id: &str,
        extras: Option<&[String]>,
    ) -> String {
        let public = self
            .config
            .public_host
            .trim()
            .trim_matches(|c| c == '.' || c == '/');
        let mut entries: Vec<String> = Vec::new();
        if !public.is_empty() {
            entries.push(format!("https://{instance_id}.{public}/**"));
        }
        // IPFS gateway is a single global service — same host regardless
        // of which node is running this instance.
        entries.push("https://ipfs.kraph.com/**".to_string());
        // Local dev — fixed wildcard ports so `vite` / `vite preview` /
        // `npm run dev` all work without the operator threading a port
        // through the agent every time.
        entries.push("http://localhost:**".to_string());
        entries.push("http://127.0.0.1:**".to_string());
        if let Some(extras) = extras {
            for u in extras {
                let trimmed = u.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // Reject anything that contains a comma (would corrupt the
                // CSV) or whitespace mid-string. Caller bug, refuse silently.
                if trimmed.contains(',') || trimmed.split_whitespace().count() > 1 {
                    continue;
                }
                // Audit F54: scheme allowlist. Without this, an agent
                // (or compromised gateway pre-F38) could add
                // `javascript:**` to the URI allow list. GoTrue then
                // permits magic-link redirects to that scheme, which
                // executes attacker JS in the victim user's browser
                // session with the JWT in the URL fragment — direct
                // credential theft. Restrict to http(s) and the
                // ipfs:// pseudo-scheme we add as a default. Reject
                // silently so the agent's "added 3 URLs" call doesn't
                // partially fail.
                let lower = trimmed.to_ascii_lowercase();
                if !(lower.starts_with("http://")
                    || lower.starts_with("https://"))
                {
                    tracing::warn!(
                        url = %trimmed,
                        "redirect-url scheme rejected (only http(s) allowed)"
                    );
                    continue;
                }
                if !entries.iter().any(|e| e == trimmed) {
                    entries.push(trimmed.to_string());
                }
            }
        }
        entries.join(",")
    }

    /// Render the `.env` file that docker-compose reads.
    fn render_env_file(&self, p: &EnvParams) -> String {
        let kong_https = p.kong_port + 100; // offset for HTTPS port
        let pg_external = p.postgres_port + 100; // external Postgres port
        let pgrst_internal = p.kong_port + 200; // PostgREST internal port
        let mailer_autoconfirm = if p.mailer_autoconfirm { "true" } else { "false" };
        format!(
            r#"# Supaba instance {id} — auto-generated

# Ports
KONG_HTTP_PORT={kong_port}
KONG_HTTPS_PORT={kong_https}
POSTGRES_PORT=5432
POSTGRES_EXTERNAL_PORT={pg_external}
PGRST_PORT={pgrst_internal}
GOTRUE_PORT={gotrue_port}
REALTIME_PORT={realtime_port}
STORAGE_PORT={storage_port}
STUDIO_PORT={studio_port}
ANALYTICS_PORT={analytics_port}
META_PORT={meta_port}
FUNCTIONS_PORT={functions_port}

# Database
POSTGRES_DB=postgres
POSTGRES_HOST=db
POSTGRES_PASSWORD={postgres_password}

# Auth
JWT_SECRET={jwt_secret}
ANON_KEY={anon_key}
SERVICE_ROLE_KEY={service_role_key}
GOTRUE_JWT_SECRET={jwt_secret}
GOTRUE_JWT_EXP=3600
GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated
GOTRUE_DISABLE_SIGNUP=false
GOTRUE_MAILER_AUTOCONFIRM={mailer_autoconfirm}
GOTRUE_SITE_URL={site_url}
GOTRUE_EXTERNAL_URL={api_external_url}/auth/v1
# GOTRUE_URI_ALLOW_LIST controls where signInWithOtp / OAuth callbacks may
# redirect to. Defaults cover the instance subdomain, ipfs.<public_host>,
# and localhost; extras come from ProvisionRequest::redirect_urls.
GOTRUE_URI_ALLOW_LIST={redirect_allow_list}

# Auth · SMTP relay (operator-shared; empty = autoconfirm-only fallback)
GOTRUE_SMTP_HOST={smtp_host}
GOTRUE_SMTP_PORT={smtp_port}
GOTRUE_SMTP_USER={smtp_user}
GOTRUE_SMTP_PASS={smtp_pass}
GOTRUE_SMTP_ADMIN_EMAIL={smtp_admin_email}
GOTRUE_SMTP_SENDER_NAME={smtp_sender_name}

# Dashboard
DASHBOARD_USERNAME=supabase
DASHBOARD_PASSWORD={dashboard_password}

# Networking — public URL is the gateway-proxied subdomain when configured;
# legacy direct-to-node when SUPABA_PUBLIC_HOST is unset.
SITE_URL={site_url}
API_EXTERNAL_URL={api_external_url}
SUPABASE_PUBLIC_URL={site_url}
SUPABASE_URL=http://kong:8000

# Realtime
REALTIME_DB=postgresql://supabase_admin:{postgres_password}@db:5432/postgres

# Storage
STORAGE_BACKEND=file
FILE_SIZE_LIMIT=52428800

# Analytics
LOGFLARE_API_KEY=supaba-logflare-{id}
LOGFLARE_URL=http://analytics:4000

# Studio
STUDIO_DEFAULT_ORGANIZATION=supaba
STUDIO_DEFAULT_PROJECT=default

# Performance
SHM_SIZE=256m
COMPOSE_PROJECT_NAME=supaba-{id}

# CPU pinning
CPUSET_CPUS={cpuset}
"#,
            id = p.instance_id,
            kong_port = p.kong_port,
            kong_https = kong_https,
            pg_external = pg_external,
            pgrst_internal = pgrst_internal,
            gotrue_port = p.gotrue_port,
            realtime_port = p.realtime_port,
            storage_port = p.storage_port,
            studio_port = p.studio_port,
            analytics_port = p.analytics_port,
            meta_port = p.meta_port,
            functions_port = p.functions_port,
            jwt_secret = p.jwt_secret,
            anon_key = p.anon_key,
            service_role_key = p.service_role_key,
            postgres_password = p.postgres_password,
            dashboard_password = p.dashboard_password,
            site_url = p.site_url,
            api_external_url = p.api_external_url,
            redirect_allow_list = p.redirect_allow_list,
            mailer_autoconfirm = mailer_autoconfirm,
            smtp_host = self.config.smtp_host,
            smtp_port = self.config.smtp_port,
            smtp_user = self.config.smtp_user,
            smtp_pass = self.config.smtp_pass,
            smtp_admin_email = self.config.smtp_admin_email,
            smtp_sender_name = self.config.smtp_sender_name,
            cpuset = p.cpuset_cpus.as_deref().unwrap_or(""),
        )
    }

    /// Append URLs to the running instance's `GOTRUE_URI_ALLOW_LIST`, then
    /// restart only the auth container so GoTrue picks up the change.
    ///
    /// The .env file is the source of truth (rendered once at provision
    /// time + edited in place here). We rewrite the single
    /// `GOTRUE_URI_ALLOW_LIST=` line, preserving the rest of the file
    /// byte-for-byte. Idempotent — duplicates are de-duped.
    ///
    /// Caller must validate `wallet_pubkey` ownership before calling.
    /// Returns the resulting allow-list as a CSV string for the agent to
    /// echo back.
    pub async fn append_redirect_urls(
        &self,
        instance_id: &str,
        wallet_pubkey: &str,
        extras: &[String],
    ) -> Result<String> {
        // Ownership check first — defence in depth (the HTTP handler also
        // checks).
        let inst = self
            .get_instance(instance_id, wallet_pubkey)?
            .ok_or_else(|| anyhow::anyhow!("instance not found or not owned"))?;

        let env_path = std::path::PathBuf::from(&inst.instance_dir).join(".env");
        let body = std::fs::read_to_string(&env_path)
            .with_context(|| format!("reading {:?}", env_path))?;

        let mut existing: Vec<String> = Vec::new();
        let mut found_line = false;
        let lines_out: Vec<String> = body
            .lines()
            .map(|line| {
                if let Some(rest) = line.strip_prefix("GOTRUE_URI_ALLOW_LIST=") {
                    found_line = true;
                    existing = rest
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    String::new() // placeholder; replaced after loop
                } else {
                    line.to_string()
                }
            })
            .collect();

        // Merge in extras (de-duped, validated).
        for u in extras {
            let trimmed = u.trim();
            if trimmed.is_empty() || trimmed.contains(',') {
                continue;
            }
            if trimmed.split_whitespace().count() > 1 {
                continue;
            }
            // Audit F54: same scheme allowlist as compose_redirect_allow_list.
            // Block javascript:/data:/file: URIs; only http(s) accepted.
            let lower = trimmed.to_ascii_lowercase();
            if !(lower.starts_with("http://")
                || lower.starts_with("https://"))
            {
                tracing::warn!(
                    url = %trimmed,
                    "redirect-url scheme rejected in append path"
                );
                continue;
            }
            if !existing.iter().any(|e| e == trimmed) {
                existing.push(trimmed.to_string());
            }
        }
        // Rebuild file, swapping the placeholder line back in. If the
        // original .env had no GOTRUE_URI_ALLOW_LIST line (older instance
        // pre-this-feature), append it at the end.
        let new_value = format!("GOTRUE_URI_ALLOW_LIST={}", existing.join(","));
        let mut rebuilt: Vec<String> = lines_out
            .into_iter()
            .map(|l| if l.is_empty() && found_line { new_value.clone() } else { l })
            .collect();
        if !found_line {
            rebuilt.push(new_value.clone());
        }
        let new_body = rebuilt.join("\n");
        std::fs::write(&env_path, &new_body)
            .with_context(|| format!("writing {:?}", env_path))?;

        // Restart only the auth container — cheaper than `docker compose
        // up -d` since GoTrue boot is ~1s and other services don't need to
        // know about this change.
        let project = inst.compose_project_name.clone();
        let auth_container = format!("supabase-auth-{}", instance_id);
        let docker = self.docker.clone();
        let _ = project; // compose_project_name kept for symmetry / future use
        // Use bollard restart; ignore "not found" errors (the auth service
        // sometimes restarts as `auth-<id>` depending on compose version).
        for candidate in [&auth_container, &format!("auth-{instance_id}")] {
            let opts = bollard::container::RestartContainerOptions { t: 5 };
            match docker.restart_container(candidate, Some(opts)).await {
                Ok(()) => break,
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 404,
                    ..
                }) => continue,
                Err(e) => return Err(anyhow::anyhow!("restart auth: {e}")),
            }
        }

        Ok(existing.join(","))
    }

    /// Render and write the per-instance edge-function env file, then
    /// force-recreate the `functions` container so the edge-runtime process
    /// picks up the new values.
    ///
    /// **Path A** was chosen (see the env-vars design doc): every mutation on
    /// `/instances/:id/env` writes the file and fires an async recreate. The
    /// DB is authoritative; the file is a cached projection of the DB state
    /// and is always overwritten in full to keep the two in sync.
    ///
    /// **Env-file location:** `{instance_dir}/volumes/functions/.env`.
    /// This directory is the one mounted into the edge-runtime container at
    /// `/home/deno/functions` (see docker-compose template). Docker-compose
    /// reads the `env_file:` directive **from the host side** at container
    /// start, so the path only needs to be readable on the host; the mount
    /// itself is incidental (but convenient because it lives inside the
    /// instance dir that `destroy()` cleans up).
    ///
    /// **Refresh mechanism:** `docker compose restart` does NOT re-read
    /// `env_file:` — it reuses the container's existing env. We therefore
    /// use `up -d --force-recreate --no-deps functions` which tears the
    /// container down and brings it back with the new env in ~1-2s. We do
    /// this in a spawned task so the HTTP handler returns immediately.
    pub async fn apply_env_to_functions(&self, instance_id: &str) -> Result<()> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .with_context(|| format!("instance {instance_id} not found"))?;

        let instance_dir = std::path::PathBuf::from(&instance.instance_dir);
        let functions_dir = instance_dir.join("volumes").join("functions");

        // Ensure the directory exists (the volumes/functions path is created
        // by the template copy at provision time, but guard against a caller
        // deploying env before the volume is present — e.g. in warm-pool
        // edge cases).
        std::fs::create_dir_all(&functions_dir)
            .with_context(|| format!("creating functions dir {:?}", functions_dir))?;

        // Render the .env file. Keys are already validated by the handler,
        // so we only need to escape the value. `.env` syntax is primitive:
        // a value containing a newline or a `"` must be double-quoted and
        // the embedded `"` / `\` / `$` escaped. Keep it simple and safe by
        // always double-quoting values and escaping the three danger chars.
        let entries = self.db.list_env(instance_id)?;
        let mut contents = String::with_capacity(entries.len() * 64 + 128);
        contents.push_str(
            "# Supaba edge-function env — auto-generated, do not edit by hand.\n\
             # Managed by the node from the instance_env table.\n",
        );
        for (k, v) in &entries {
            let escaped: String = v
                .chars()
                .flat_map(|c| match c {
                    '\\' => vec!['\\', '\\'],
                    '"' => vec!['\\', '"'],
                    '$' => vec!['\\', '$'],
                    '\n' => vec!['\\', 'n'],
                    '\r' => vec!['\\', 'r'],
                    other => vec![other],
                })
                .collect();
            contents.push_str(&format!("{k}=\"{escaped}\"\n"));
        }

        let env_path = functions_dir.join(".env");
        tokio::fs::write(&env_path, contents.as_bytes())
            .await
            .with_context(|| format!("writing {env_path:?}"))?;

        info!(
            instance_id,
            var_count = entries.len(),
            path = %env_path.display(),
            "edge-function env file written"
        );

        // Fire-and-forget container recreate. We clone only the strings we
        // need so the spawned task owns no reference to `self`.
        let compose_project = instance.compose_project_name.clone();
        let instance_dir_str = instance.instance_dir.clone();
        let instance_id_owned = instance_id.to_string();
        tokio::spawn(async move {
            let out = Command::new("docker")
                .args([
                    "compose",
                    "-p",
                    &compose_project,
                    "up",
                    "-d",
                    "--force-recreate",
                    "--no-deps",
                    "functions",
                ])
                .current_dir(&instance_dir_str)
                .output()
                .await;
            match out {
                Ok(o) if o.status.success() => {
                    info!(
                        instance_id = %instance_id_owned,
                        "functions container recreated with new env"
                    );
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!(
                        instance_id = %instance_id_owned,
                        %stderr,
                        "functions recreate exited non-zero"
                    );
                }
                Err(e) => {
                    error!(
                        instance_id = %instance_id_owned,
                        error = %e,
                        "functions recreate failed to spawn"
                    );
                }
            }
        });

        Ok(())
    }

    /// Copy the docker-compose template into the instance directory.
    fn copy_template(&self, instance_dir: &PathBuf) -> Result<()> {
        let src = &self.config.supabase_template_path;
        if !src.exists() {
            bail!("supabase template path does not exist: {:?}", src);
        }
        copy_dir_recursive(src, instance_dir)
            .with_context(|| format!("copying template {:?} -> {:?}", src, instance_dir))?;
        Ok(())
    }

    /// Poll Docker (via bollard) until every container in the compose project
    /// reports `running`, or the timeout elapses.
    async fn wait_for_health(&self, compose_project: &str, timeout: Duration) -> bool {
        use bollard::container::ListContainersOptions;
        use std::collections::HashMap;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                warn!(compose_project, "health check timed out");
                return false;
            }

            let mut filters = HashMap::new();
            filters.insert(
                "label".to_string(),
                vec![format!("com.docker.compose.project={compose_project}")],
            );
            let opts = ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            };

            match self.docker.list_containers(Some(opts)).await {
                Ok(containers) if !containers.is_empty() => {
                    let all_running = containers
                        .iter()
                        .all(|c| c.state.as_deref() == Some("running"));
                    if all_running {
                        debug!(compose_project, "all containers running");
                        return true;
                    }
                    // Check for any exited / dead containers — fail fast.
                    let any_dead = containers.iter().any(|c| {
                        matches!(c.state.as_deref(), Some("exited") | Some("dead"))
                    });
                    if any_dead {
                        warn!(compose_project, "container exited/dead during health wait");
                        return false;
                    }
                }
                Ok(_) => { /* no containers yet, keep waiting */ }
                Err(e) => {
                    warn!(compose_project, error = %e, "error listing containers");
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a random alphanumeric password of the given length.
fn generate_password(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Recursively copy a directory tree.  Existing files in `dst` are
/// overwritten; extra files already in `dst` are left alone.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        // Audit F57: use `symlink_metadata` (not `file_type` which follows
        // symlinks) so we can refuse them explicitly. Symlinks in the
        // template would otherwise expand to whatever the link target
        // points at — escaping the template directory's bounds during
        // copy. Template path is operator-controlled today
        // (SUPABA_SUPABASE_TEMPLATE_PATH), so this is defence-in-depth
        // against a misconfigured template, not a known exploit. Refuse
        // loudly so the operator can investigate rather than silently
        // copying outside the intended source tree.
        let meta = entry.path().symlink_metadata().with_context(|| {
            format!("symlink_metadata for {:?}", entry.path())
        })?;
        let ft = meta.file_type();
        let dest_path = dst.join(entry.file_name());
        if ft.is_symlink() {
            bail!(
                "refusing to copy symlink {:?} during template copy (audit F57). \
                 Remove or replace the symlink in the template tree.",
                entry.path()
            );
        }
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else if ft.is_file() {
            std::fs::copy(entry.path(), &dest_path)?;
        } else {
            // Special files (block devices, sockets, FIFOs) — refuse.
            bail!(
                "refusing to copy non-regular file {:?} during template copy",
                entry.path()
            );
        }
    }
    Ok(())
}
