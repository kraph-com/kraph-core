//! Per-instance Next.js sidecar service.
//!
//! When a Forge-built app is Next.js with SSR (anything that isn't a pure
//! `output: "export"` static build), we can't pin it to IPFS — the app
//! needs a Node runtime. This module runs that runtime as a long-lived
//! container on the same node that hosts the instance's Supabase stack.
//!
//! The container:
//!   - image: `node:20-alpine`
//!   - mounts the instance's `nextjs/` directory at `/app` (read-only)
//!   - cwd: `/app`
//!   - cmd: `node server.js`  (Next.js standalone output convention)
//!   - joins the instance's `supaba-<id>_internal` network so server-side
//!     code can reach `http://kong:8000` for in-cluster Supabase calls
//!   - exposes container port 3000, host-mapped to a dynamically allocated
//!     port the gateway's subdomain proxy routes to
//!   - restart: `unless-stopped` so a crash doesn't take the site down
//!     forever
//!
//! Lifecycle is independent of the Supabase compose project (no nested
//! compose templates to keep in sync). Destroying the instance reaps the
//! container via the same docker compose down hook + an explicit remove
//! of the sidecar.
//!
//! The bundle layout we expect (from `next build` with
//! `output: "standalone"` set in next.config.*):
//!   /app/server.js              ← Next.js standalone entrypoint
//!   /app/.next/                 ← built routes + server files
//!   /app/.next/static/          ← static chunks (also served by the SPA)
//!   /app/public/                ← repo `public/` mirror
//!   /app/node_modules/          ← minimal subset Next.js bundled
//!
//! The deploy endpoint accepts a tarball, extracts it to a fresh dir,
//! atomically swaps the symlink so an in-flight request doesn't see a
//! half-deployed tree, then restarts the container.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use bollard::container::{
    Config as ContainerConfig, CreateContainerOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::errors::Error as BollardError;
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};
use bollard::Docker;
use flate2::read::GzDecoder;
use futures_util::TryStreamExt;
use tar::Archive;
use tracing::{info, warn};

use crate::db::Database;

/// Container image used to run Next.js. Matches the build-side default so
/// `next build` and `node server.js` see compatible Node majors.
const NEXTJS_IMAGE: &str = "node:20-alpine";

/// Container port the Next.js standalone server listens on inside the
/// container. We always set PORT=3000 + HOSTNAME=0.0.0.0 in the env so
/// this never has to vary per-instance.
const CONTAINER_PORT: u16 = 3000;

/// Hard cap on the uncompressed bundle size. Big enough for any real
/// Next.js app (the standalone output is typically 30-200 MB including
/// node_modules), small enough to refuse hostile fillers.
pub const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

/// Per-instance deploy state returned to the gateway. Mirrors what the
/// gateway needs to update its subdomain-proxy cache and confirm the
/// service is reachable.
#[derive(Debug, Clone)]
pub struct DeployResult {
    pub instance_id: String,
    pub host_port: u16,
    pub container_id: String,
    /// Public URL the user should hit (gateway's subdomain proxy routes
    /// `/` here when `nextjs_service_port` is set).
    pub url: String,
}

/// Service handle that owns the deploy + start + replace flow. Keeps the
/// docker handle + db reference + a base data dir; instantiated once at
/// node startup and shared.
pub struct NextjsService {
    docker: Docker,
    db: Database,
    /// Root of `<SUPABA_DATA_DIR>/instances/<id>/nextjs/` lives under here.
    data_root: PathBuf,
    /// `<id>.kraph.com` host the public URL is derived from. Falls back to
    /// the node's own hostname when the gateway doesn't proxy.
    public_host: String,
}

impl NextjsService {
    pub fn new(docker: Docker, db: Database, data_root: PathBuf, public_host: String) -> Self {
        Self { docker, db, data_root, public_host }
    }

    /// Top-level deploy: accept a tar.gz of the build output, extract +
    /// run. Idempotent — re-running with a new tarball replaces the
    /// running container in place (start the new one BEFORE killing the
    /// old one so we don't 502 in the seam, but since we reuse the same
    /// host port we have to stop first; ~3s of downtime per redeploy
    /// is acceptable for MVP and matches how `kraph_deploy_function`
    /// behaves on Deno function updates).
    ///
    /// `entry_argv` is the command invoked inside the container, relative
    /// to `/app`. Pass `["node", "server.js"]` for the Next.js standalone
    /// convention, `["node", "build/index.js"]` for SvelteKit
    /// adapter-node, `["node", ".output/server/index.mjs"]` for Nuxt,
    /// etc. The argv reaches docker verbatim — no shell layer.
    pub async fn deploy(
        &self,
        instance_id: &str,
        wallet: &str,
        tarball: &[u8],
        entry_argv: Vec<String>,
    ) -> Result<DeployResult> {
        // Ownership check is handled at the HTTP layer; this module
        // trusts its caller. We still verify the instance exists.
        let instance = self
            .db
            .get_instance(instance_id, wallet)?
            .ok_or_else(|| anyhow!("instance_not_found"))?;

        if (tarball.len() as u64) > MAX_BUNDLE_BYTES {
            return Err(anyhow!(
                "bundle too large: {} bytes > {} max",
                tarball.len(),
                MAX_BUNDLE_BYTES
            ));
        }

        // Pull image once. The `node:20-alpine` image is shared across
        // every instance on the node so we expect a cache hit after the
        // very first deploy.
        self.ensure_image().await?;

        // Stage the bundle into <data>/instances/<id>/nextjs-staging/<ts>/.
        // Swap into nextjs/ at the end. The staging path keeps a failed
        // extract from clobbering a working deploy.
        let instance_root = self.data_root.join("instances").join(&instance.id);
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let staging = instance_root.join(format!("nextjs-staging-{ts}"));
        let target = instance_root.join("nextjs");
        std::fs::create_dir_all(&staging).context("create nextjs staging dir")?;

        // Extract. We refuse absolute paths or any entry that escapes
        // staging via `..` to avoid a path-traversal attack from a
        // hostile build container.
        let mut archive = Archive::new(GzDecoder::new(tarball));
        archive.set_preserve_permissions(false);
        archive.set_preserve_mtime(false);
        for entry in archive.entries().context("read tar entries")? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            if path.is_absolute() {
                return Err(anyhow!("absolute path in bundle: {}", path.display()));
            }
            if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(anyhow!("parent-dir traversal in bundle: {}", path.display()));
            }
            entry.unpack_in(&staging)?;
        }

        // Determine the bundle root by locating the entry script. For
        // Next.js this is `server.js`; for SvelteKit it's
        // `build/index.js`; for Nuxt it's `.output/server/index.mjs`.
        // We derive the relative path from `entry_argv[1]` (the script
        // arg) — `entry_argv[0]` is always the binary like `node` and
        // doesn't help us locate the bundle. Some tarballs wrap
        // everything in a single directory (e.g. `tar -czf bundle.tgz
        // myapp/`); detect that and lift one level up. The build-side
        // tool emits the flat form so this is belt-and-braces.
        let entry_script_rel: &str = entry_argv
            .get(1)
            .map(|s| s.as_str())
            .unwrap_or("server.js");
        let bundle_root = if staging.join(entry_script_rel).exists() {
            staging.clone()
        } else {
            // Look for the single directory inside that contains the entry script.
            let entries: Vec<_> = std::fs::read_dir(&staging)?
                .filter_map(Result::ok)
                .collect();
            let candidate = entries
                .iter()
                .find(|e| e.path().is_dir() && e.path().join(entry_script_rel).exists())
                .ok_or_else(|| anyhow!("bundle missing entry script '{}'", entry_script_rel))?;
            candidate.path()
        };

        // Swap target → new bundle. We rename rather than copying for
        // atomicity within the same filesystem.
        let _ = std::fs::remove_dir_all(&target); // best-effort old cleanup
        std::fs::rename(&bundle_root, &target).context("swap nextjs dir into place")?;
        // If the bundle was wrapped, the staging shell is now empty; drop it.
        let _ = std::fs::remove_dir_all(&staging);

        // The Next.js sidecar reuses the LAST port in this instance's
        // 10-port block (kong = base_port + 0 … functions = base_port + 8,
        // nextjs = base_port + 9). That slot was previously unused, so no
        // new port allocation is needed and re-deploys land on the same
        // port — the gateway's subdomain-proxy cache stays valid.
        let host_port: u16 = instance
            .kong_port
            .checked_add(9)
            .ok_or_else(|| anyhow!("kong_port too high to derive nextjs port"))?;

        // Replace any prior running container before starting the new one.
        // We name it deterministically so re-deploys don't accumulate.
        let container_name = format!("supaba-{}-nextjs", instance.id);
        let _ = self.stop_and_remove(&container_name).await; // best-effort

        // Build runtime env: Supabase auto-injected envs (SUPABASE_URL =
        // in-cluster kong DNS, not the public subdomain) + the standard
        // PORT/HOSTNAME knobs Next.js standalone reads.
        //
        // NEXT_PUBLIC_SUPABASE_URL must already be baked at BUILD time by
        // the gateway's kraph_github_build_frontend tool — runtime env
        // vars don't affect client-bundled values.
        //
        // Service-role key is INTENTIONALLY NOT auto-injected here. A
        // hostile npm dependency in the agent's Next.js repo can read
        // any process.env key from any SSR handler, so handing
        // service_role to every sidecar by default would silently break
        // RLS for the agent's own data. The static IPFS-pin path has
        // never exposed service_role (the SPA only ever sees anon), and
        // the SSR path now matches: agents that genuinely need RLS
        // bypass on the server (server actions writing trusted data)
        // must opt in by calling kraph_set_env({ SUPABASE_SERVICE_ROLE_KEY:
        // ... }) — same path used for any third-party secret. The
        // user-supplied entries get merged below so an explicit
        // SUPABASE_SERVICE_ROLE_KEY in instance_env still flows through.
        let mut env = vec![
            format!("PORT={CONTAINER_PORT}"),
            "HOSTNAME=0.0.0.0".to_string(),
            "NODE_ENV=production".to_string(),
            format!("SUPABASE_URL=http://kong:8000"),
            format!("SUPABASE_ANON_KEY={}", instance.anon_key),
        ];
        // Merge user-managed env (kraph_set_env). list_env returns
        // plaintext per the instance DEK; values flow only inside the
        // node process and into the container env — never to the wire.
        // User entries can override the defaults above (e.g. NODE_ENV)
        // because they appear later; PORT/HOSTNAME left first by
        // convention but the agent overriding them is their prerogative.
        match self.db.list_env(instance_id) {
            Ok(user_env) => {
                for (k, v) in user_env {
                    // Drop empty keys defensively; everything else passes
                    // through verbatim.
                    if !k.is_empty() {
                        env.push(format!("{}={}", k, v));
                    }
                }
            }
            Err(e) => {
                warn!(
                    instance_id,
                    error = %e,
                    "failed to load instance_env for nextjs sidecar; \
                     continuing with built-in env only"
                );
            }
        }

        // Host port → container 3000.
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        port_bindings.insert(
            format!("{CONTAINER_PORT}/tcp"),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(host_port.to_string()),
            }]),
        );

        // Join the instance's docker network so server-side fetch() can
        // resolve `kong` etc. without going through the public proxy.
        let network = format!("{}_internal", instance.compose_project_name);

        let host_cfg = HostConfig {
            binds: Some(vec![format!(
                "{}:/app:ro",
                target.to_string_lossy()
            )]),
            port_bindings: Some(port_bindings),
            network_mode: Some(network.clone()),
            // Bounded resource ceiling. A misbehaving SPA must not be
            // able to thrash the node's other tenants.
            memory: Some(1024 * 1024 * 1024), // 1 GB
            nano_cpus: Some(2_000_000_000),   // 2 CPUs
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            ..Default::default()
        };

        let mut exposed_ports = HashMap::new();
        exposed_ports.insert(format!("{CONTAINER_PORT}/tcp"), HashMap::<(), ()>::new());

        let create_opts = CreateContainerOptions {
            name: container_name.clone(),
            platform: None,
        };
        let config: ContainerConfig<String> = ContainerConfig {
            image: Some(NEXTJS_IMAGE.to_string()),
            cmd: Some(entry_argv.clone()),
            working_dir: Some("/app".to_string()),
            env: Some(env),
            exposed_ports: Some(exposed_ports),
            host_config: Some(host_cfg),
            ..Default::default()
        };

        let created = self
            .docker
            .create_container(Some(create_opts), config)
            .await
            .with_context(|| format!("create container {container_name}"))?;
        self.docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
            .with_context(|| format!("start container {container_name}"))?;

        // Persist port + status. The gateway reads the row on every
        // subdomain-proxy hit so this DB write must happen BEFORE we
        // return success.
        self.db
            .set_nextjs_service(&instance.id, Some(host_port), "running")?;

        info!(id = %instance.id, host_port, "nextjs service deployed");

        Ok(DeployResult {
            instance_id: instance.id.clone(),
            host_port,
            container_id: created.id,
            url: format!("https://{}.{}/", instance.id, self.public_host),
        })
    }

    async fn ensure_image(&self) -> Result<()> {
        // CreateImage is idempotent and short-circuits when the image is
        // already local. The stream returns one chunk per layer; we
        // drain it but ignore the contents.
        let opts = CreateImageOptions {
            from_image: NEXTJS_IMAGE,
            ..Default::default()
        };
        let mut stream = self.docker.create_image(Some(opts), None, None);
        while let Some(item) = stream.try_next().await.map_err(|e| anyhow!("pull image: {e}"))? {
            let _ = item;
        }
        Ok(())
    }

    async fn stop_and_remove(&self, name: &str) -> Result<()> {
        match self
            .docker
            .stop_container(name, Some(StopContainerOptions { t: 5 }))
            .await
        {
            Ok(_) | Err(BollardError::DockerResponseServerError { status_code: 404, .. }) => {}
            Err(e) => warn!("stop_container {name} failed: {e}"),
        }
        match self
            .docker
            .remove_container(
                name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(_) | Err(BollardError::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
            Err(e) => Err(anyhow!("remove_container {name}: {e}")),
        }
    }

    /// Tear down the sidecar when the instance is destroyed. Best-effort;
    /// the caller has already removed the supabase compose project, so
    /// even if this leaks the container, it's a stale sidecar with no
    /// network peers to talk to.
    pub async fn teardown(&self, instance_id: &str) -> Result<()> {
        let container_name = format!("supaba-{instance_id}-nextjs");
        self.stop_and_remove(&container_name).await
    }
}

/// Helper used by tests + paths that don't have a NextjsService handle:
/// derive the canonical service container name.
pub fn container_name_for(instance_id: &str) -> String {
    format!("supaba-{instance_id}-nextjs")
}

/// Re-export so the HTTP handler doesn't need to know about anyhow's
/// internals when building the deploy URL.
pub fn root_path(data_root: &Path, instance_id: &str) -> PathBuf {
    data_root.join("instances").join(instance_id).join("nextjs")
}
