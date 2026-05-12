use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::db::Database;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A pre-provisioned Supabase stack ready for immediate assignment.
pub struct WarmInstance {
    pub compose_project_name: String,
    pub instance_dir: PathBuf,
    pub base_port: u16,
    pub created_at: DateTime<Utc>,
}

/// Manages a pool of pre-provisioned Supabase stacks that can be instantly
/// assigned to new users, reducing provisioning time from ~30s to <2s.
pub struct WarmPool {
    config: Arc<Config>,
    db: Arc<Database>,
    pool: Mutex<Vec<WarmInstance>>,
}

impl WarmPool {
    pub fn new(config: Arc<Config>, db: Arc<Database>) -> Self {
        Self {
            config,
            db,
            pool: Mutex::new(Vec::new()),
        }
    }

    /// Periodic maintenance: replenish pool to target size and replace stale
    /// instances (older than 1 hour).
    pub async fn maintain(&self) -> Result<()> {
        let target = self.config.warm_pool_size;
        if target == 0 {
            return Ok(());
        }

        // Destroy stale instances (> 1 hour old).
        let stale_cutoff = Utc::now() - chrono::Duration::hours(1);
        let mut pool = self.pool.lock().await;
        let mut kept = Vec::new();
        for inst in pool.drain(..) {
            if inst.created_at < stale_cutoff {
                info!(
                    project = %inst.compose_project_name,
                    "destroying stale warm instance"
                );
                if let Err(e) = destroy_warm_instance(&inst).await {
                    error!(
                        project = %inst.compose_project_name,
                        error = %e,
                        "failed to destroy stale warm instance"
                    );
                }
                // Free the port block.
                if let Err(e) = self.db.free_port_block(&inst.compose_project_name) {
                    warn!(error = %e, "failed to free port block for stale warm instance");
                }
            } else {
                kept.push(inst);
            }
        }
        let current_size = kept.len();
        *pool = kept;
        drop(pool);

        // Replenish to target size.
        let needed = target.saturating_sub(current_size);
        for _ in 0..needed {
            match self.provision_warm_instance().await {
                Ok(inst) => {
                    info!(
                        project = %inst.compose_project_name,
                        port = inst.base_port,
                        "warm instance provisioned"
                    );
                    self.pool.lock().await.push(inst);
                }
                Err(e) => {
                    error!(error = %e, "failed to provision warm instance");
                    break;
                }
            }
        }

        let final_size = self.pool.lock().await.len();
        debug!(pool_size = final_size, target, "warm pool maintenance complete");

        Ok(())
    }

    /// Pop a pre-provisioned instance from the pool for immediate assignment.
    pub async fn take(&self) -> Option<WarmInstance> {
        self.pool.lock().await.pop()
    }

    /// Add a single new warm instance to the pool.
    pub async fn replenish(&self) -> Result<()> {
        let inst = self.provision_warm_instance().await?;
        info!(
            project = %inst.compose_project_name,
            port = inst.base_port,
            "warm instance replenished"
        );
        self.pool.lock().await.push(inst);
        Ok(())
    }

    // ======================================================================
    // Private helpers
    // ======================================================================

    /// Provision a new warm instance with placeholder credentials.
    async fn provision_warm_instance(&self) -> Result<WarmInstance> {
        // Allocate a port block.
        let base_port = self.db.allocate_port_block(
            self.config.port_range_start,
            self.config.port_range_end,
        )?;

        let warm_id = nanoid::nanoid!(12);
        let compose_project = format!("supaba-warm-{warm_id}");

        // Bind the port block to the warm project name so free_port_block works.
        self.db.bind_port_to_instance(base_port, &compose_project)?;

        // Create instance directory.
        let instance_dir = self.config.data_dir.join("warm").join(&warm_id);
        std::fs::create_dir_all(&instance_dir)
            .with_context(|| format!("creating warm instance dir {:?}", instance_dir))?;

        // Copy docker-compose template.
        copy_dir_recursive(&self.config.supabase_template_path, &instance_dir)
            .with_context(|| "copying template for warm instance")?;

        // Write placeholder .env (services will be restarted with real creds on assignment).
        let kong_port = base_port;
        let postgres_port = base_port + 1;
        let gotrue_port = base_port + 2;
        let realtime_port = base_port + 3;
        let storage_port = base_port + 4;
        let studio_port = base_port + 5;
        let analytics_port = base_port + 6;
        let meta_port = base_port + 7;
        let functions_port = base_port + 8;

        // Audit F53: previously these were CONSTANT strings —
        //   placeholder_secret = "warm-placeholder-jwt-secret-0...0"
        //   placeholder_password = "warm-placeholder-password"
        //
        // The warm Supabase stack runs on a public port between provision
        // and assignment (up to 1h before stale-cleanup kicks in). Anyone
        // who scans the node's port range and finds a warm instance
        // running could:
        //   - Connect to Postgres on POSTGRES_PORT (constant password)
        //   - Mint forged JWTs (constant JWT_SECRET)
        //   - Sign in to Studio (constant DASHBOARD_PASSWORD)
        //
        // The warm instance has no real user data yet, but the attacker
        // could plant data that survives into the assigned-instance state
        // if the .env rewrite doesn't drop the db (and AFAIK it doesn't
        // — only the env values get replaced; existing DB rows survive).
        //
        // Mitigated today by operator firewall rules (CF-only ingress on
        // public IPs limits which ports are reachable), but defence in
        // depth: use random per-warm placeholders so even a reachable
        // warm instance can't be authenticated to.
        //
        // 64 hex chars = 256 bits of entropy for the JWT secret, plenty
        // for the placeholder lifetime.
        let placeholder_secret_bytes: [u8; 32] = rand::random();
        let placeholder_secret = hex::encode(placeholder_secret_bytes);
        let placeholder_password_bytes: [u8; 24] = rand::random();
        let placeholder_password = hex::encode(placeholder_password_bytes);

        let env_content = format!(
            r#"# Supaba warm instance {id} — placeholder
INSTANCE_ID={id}

# Ports
KONG_HTTP_PORT={kong_port}
POSTGRES_PORT={postgres_port}
GOTRUE_PORT={gotrue_port}
REALTIME_PORT={realtime_port}
STORAGE_PORT={storage_port}
STUDIO_PORT={studio_port}
ANALYTICS_PORT={analytics_port}
META_PORT={meta_port}
FUNCTIONS_PORT={functions_port}

# Auth (placeholder — replaced on assignment)
JWT_SECRET={jwt_secret}
ANON_KEY=placeholder-anon-key
SERVICE_ROLE_KEY=placeholder-service-role-key

# Postgres
POSTGRES_PASSWORD={pg_pass}

# Dashboard
DASHBOARD_USERNAME=supabase
DASHBOARD_PASSWORD={dash_pass}

# Networking
SITE_URL=http://{hostname}:{kong_port}
API_EXTERNAL_URL=http://{hostname}:{kong_port}
SUPABASE_PUBLIC_URL=http://{hostname}:{kong_port}
STUDIO_DEFAULT_ORGANIZATION=supaba
STUDIO_DEFAULT_PROJECT=default

# CPU pinning
CPUSET_CPUS=
"#,
            id = warm_id,
            kong_port = kong_port,
            postgres_port = postgres_port,
            gotrue_port = gotrue_port,
            realtime_port = realtime_port,
            storage_port = storage_port,
            studio_port = studio_port,
            analytics_port = analytics_port,
            meta_port = meta_port,
            functions_port = functions_port,
            jwt_secret = placeholder_secret,
            pg_pass = placeholder_password,
            dash_pass = placeholder_password,
            hostname = self.config.hostname,
        );

        std::fs::write(instance_dir.join(".env"), &env_content)
            .context("writing warm instance .env")?;

        // The docker-compose template references ./volumes/functions/.env
        // via `env_file:` on the functions service. Docker compose errors
        // if that file is missing at `up` time, so ensure an empty one
        // exists before we bring the warm stack up.
        let functions_env_dir = instance_dir.join("volumes").join("functions");
        std::fs::create_dir_all(&functions_env_dir)
            .context("creating volumes/functions dir for warm instance")?;
        let functions_env_path = functions_env_dir.join(".env");
        if !functions_env_path.exists() {
            std::fs::write(
                &functions_env_path,
                b"# Supaba warm-pool placeholder - rewritten on assignment.\n",
            )
            .context("writing warm instance functions .env placeholder")?;
        }

        // Start the compose stack.
        let up_output = Command::new("docker")
            .args(["compose", "-p", &compose_project, "up", "-d"])
            .current_dir(&instance_dir)
            .output()
            .await
            .context("running docker compose up for warm instance")?;

        if !up_output.status.success() {
            let stderr = String::from_utf8_lossy(&up_output.stderr);
            // Clean up on failure.
            self.db.free_port_block(&compose_project)?;
            let _ = std::fs::remove_dir_all(&instance_dir);
            anyhow::bail!("docker compose up failed for warm instance: {stderr}");
        }

        // Wait briefly for containers to start (non-blocking best-effort).
        tokio::time::sleep(Duration::from_secs(5)).await;

        Ok(WarmInstance {
            compose_project_name: compose_project,
            instance_dir,
            base_port,
            created_at: Utc::now(),
        })
    }
}

/// Reassign a warm instance: rewrite its .env with real credentials and restart
/// services that read environment variables.
pub async fn reassign_warm_instance(
    inst: &WarmInstance,
    new_env_content: &str,
    new_compose_project: &str,
) -> Result<()> {
    // 1. Write the real .env file.
    std::fs::write(inst.instance_dir.join(".env"), new_env_content)
        .context("writing real .env over warm instance")?;

    // 2. Stop the old compose project.
    let down_output = Command::new("docker")
        .args([
            "compose",
            "-p",
            &inst.compose_project_name,
            "down",
        ])
        .current_dir(&inst.instance_dir)
        .output()
        .await
        .context("stopping warm compose project")?;

    if !down_output.status.success() {
        let stderr = String::from_utf8_lossy(&down_output.stderr);
        warn!(stderr = %stderr, "warm compose down had warnings");
    }

    // 3. Bring up with the new project name so containers get new env.
    let up_output = Command::new("docker")
        .args([
            "compose",
            "-p",
            new_compose_project,
            "up",
            "-d",
        ])
        .current_dir(&inst.instance_dir)
        .output()
        .await
        .context("restarting warm instance with real credentials")?;

    if !up_output.status.success() {
        let stderr = String::from_utf8_lossy(&up_output.stderr);
        anyhow::bail!("failed to restart warm instance: {stderr}");
    }

    Ok(())
}

/// Tear down a warm instance's docker compose stack and remove its directory.
async fn destroy_warm_instance(inst: &WarmInstance) -> Result<()> {
    let down_output = Command::new("docker")
        .args([
            "compose",
            "-p",
            &inst.compose_project_name,
            "down",
            "-v",
            "--remove-orphans",
        ])
        .current_dir(&inst.instance_dir)
        .output()
        .await
        .context("docker compose down for warm instance")?;

    if !down_output.status.success() {
        let stderr = String::from_utf8_lossy(&down_output.stderr);
        warn!(project = %inst.compose_project_name, %stderr, "warm compose down had errors");
    }

    if let Err(e) = std::fs::remove_dir_all(&inst.instance_dir) {
        warn!(error = %e, "failed to remove warm instance dir");
    }

    Ok(())
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    if !src.exists() {
        anyhow::bail!("template path does not exist: {:?}", src);
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}
