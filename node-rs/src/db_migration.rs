//! Database migration engine — pg_dump | pg_restore inside a sandboxed
//! `postgres:16-alpine` container.
//!
//! v1 mode: `bulk` — one-shot dump + restore via piped stdio (no temp file
//! on disk, so a 100GB dump streams through without filling /var/lib/docker).
//! v2 will add `live_sync` (logical replication) sharing this module's
//! container-lifecycle code.
//!
//! Ports follow the same pattern as `frontend_build.rs`: bollard creates an
//! ephemeral container, attaches stdout/stderr, kills on cancel/timeout,
//! removes on drop. Resource limits: 4GB RAM, 1 CPU, 30-min timeout.
//!
//! Concurrency: one migration per instance at a time. The HTTP handler
//! enforces this by checking the instance's existing in-flight job rows
//! against the gateway store; node-rs trusts the gateway here.

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
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const MAX_LOG_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 30 * 60; // 30 min
/// Audit F66: server-clamped maximum wall-clock timeout. Even though
/// the gateway's tool parameter advertises a sane default, an attacker
/// who reaches the node directly (or a tampered gateway) could pass an
/// arbitrarily large `timeoutSecs` and tie up Docker capacity. 2 hours
/// is generous for a real production migration and refuses anything
/// larger.
const MAX_TIMEOUT_SECS: u64 = 2 * 60 * 60;

/// Clamp a caller-supplied timeout to MAX_TIMEOUT_SECS. None → default.
pub(crate) fn clamp_timeout_secs(supplied: Option<u64>) -> u64 {
    supplied
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .min(MAX_TIMEOUT_SECS)
}

#[derive(Debug, Deserialize)]
pub struct MigrationStartRequest {
    #[serde(rename = "walletPubkey")]
    pub wallet_pubkey: String,
    /// Source `postgres://...` URL with credentials. Either this OR
    /// `source_url_env` must be set; the handler in main.rs resolves
    /// `source_url_env` (name of an env var in the instance's encrypted
    /// env store) and overwrites `source_url` with the plaintext value
    /// before passing this struct to `run_bulk_migration` / `run_live_sync_setup`,
    /// so the inner pipeline always sees a resolved plaintext URL.
    #[serde(default, rename = "sourceUrl")]
    pub source_url: String,
    /// Name of an env var on this instance (kraph_set_env) holding the
    /// source URL. The wire-side caller (agent) passes this instead of
    /// `source_url` so the credential never appears in chat / transcript /
    /// SSE / Anthropic history. Resolved server-side by the HTTP handler.
    #[serde(default, rename = "sourceUrlEnv")]
    pub source_url_env: Option<String>,
    /// Target instance's local Postgres URL. Constructed by the HTTP handler
    /// from the instance row (host.docker.internal + external port +
    /// stored postgres_password). Don't accept from the request body —
    /// that would let an authed wallet redirect dumps elsewhere.
    #[serde(skip)]
    pub target_url: String,
    /// Mode — only "bulk" honored in v1.
    #[serde(default)]
    pub mode: Option<String>,
    /// Skip data, dump schema only.
    #[serde(default, rename = "schemaOnly")]
    pub schema_only: bool,
    /// Skip schema, dump data only.
    #[serde(default, rename = "dataOnly")]
    pub data_only: bool,
    /// Schemas to exclude. Defaults to Supabase's system schemas (auth,
    /// storage, realtime, etc.) if not provided — those are already wired
    /// on the target.
    #[serde(default, rename = "excludeSchemas")]
    pub exclude_schemas: Option<Vec<String>>,
    /// `schema.table` patterns to exclude (passed verbatim to pg_dump's
    /// `--exclude-table=`).
    #[serde(default, rename = "excludeTables")]
    pub exclude_tables: Option<Vec<String>>,
    /// `schema.table` patterns to include — when set, ONLY these tables
    /// move (passed as repeated `--table=` to pg_dump).
    #[serde(default, rename = "includeTables")]
    pub include_tables: Option<Vec<String>>,
    /// Wall-clock timeout. Defaults to 30 minutes.
    #[serde(default, rename = "timeoutSecs")]
    pub timeout_secs: Option<u64>,
    /// Number of restore parallel jobs. Defaults to 4. Higher → faster
    /// for large multi-table imports but contends with the target's
    /// connection limit.
    #[serde(default, rename = "parallelJobs")]
    pub parallel_jobs: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct MigrationResult {
    pub state: String, // "done" | "failed"
    pub duration_ms: u128,
    pub log_tail: String,
    pub exit_code_dump: i64,
    pub exit_code_restore: i64,
    pub rows_migrated: u64,
    pub tables_done: u64,
    /// Empty on success, populated on failure.
    pub error: String,
}

/// Default exclude list: every Supabase-managed schema that lives in our
/// own Kraph instances pre-wired. Importing on top of these would clobber
/// JWT secrets, role grants, GoTrue migrations, etc.
const DEFAULT_EXCLUDE_SCHEMAS: &[&str] = &[
    "auth",
    "storage",
    "realtime",
    "supabase_functions",
    "extensions",
    "graphql",
    "graphql_public",
    "net",
    "pgsodium",
    "pgsodium_masks",
    "vault",
    "_realtime",
    "_analytics",
    "pg_catalog",
    "information_schema",
];

pub async fn run_bulk_migration(
    docker: Arc<Docker>,
    container_name: &str,
    req: MigrationStartRequest,
) -> Result<MigrationResult> {
    let started = Instant::now();
    let mode = req.mode.as_deref().unwrap_or("bulk");
    if mode != "bulk" {
        return Err(anyhow!(
            "run_bulk_migration: mode='{mode}' not supported here; use run_live_sync_setup for live_sync"
        ));
    }
    if req.schema_only && req.data_only {
        return Err(anyhow!("schemaOnly and dataOnly are mutually exclusive"));
    }

    // Build pg_dump argv. We always use custom format (`-Fc`) for piped
    // restore — directory format would need shared filesystem.
    let mut dump_args: Vec<String> = vec![
        "-Fc".into(),
        "--no-owner".into(),
        "--no-privileges".into(),
        "--no-comments".into(),
        "--verbose".into(),
        "--quote-all-identifiers".into(),
    ];
    if req.schema_only {
        dump_args.push("--schema-only".into());
    }
    if req.data_only {
        dump_args.push("--data-only".into());
    }
    let exclude_schemas = req
        .exclude_schemas
        .clone()
        .unwrap_or_else(|| DEFAULT_EXCLUDE_SCHEMAS.iter().map(|s| s.to_string()).collect());
    for schema in &exclude_schemas {
        // Sanitise — schema names are normally alnum/underscore. Reject
        // anything weirder to keep injection out of the shell args.
        if !is_pg_identifier_safe(schema) {
            return Err(anyhow!("excludeSchemas contains unsafe value: {schema:?}"));
        }
        dump_args.push(format!("--exclude-schema={schema}"));
    }
    if let Some(excludes) = &req.exclude_tables {
        for t in excludes {
            if !is_pg_table_pattern_safe(t) {
                return Err(anyhow!("excludeTables contains unsafe value: {t:?}"));
            }
            dump_args.push(format!("--exclude-table={t}"));
        }
    }
    if let Some(includes) = &req.include_tables {
        for t in includes {
            if !is_pg_table_pattern_safe(t) {
                return Err(anyhow!("includeTables contains unsafe value: {t:?}"));
            }
            dump_args.push(format!("--table={t}"));
        }
    }
    // Source URL goes last, as the `dbname` positional arg.
    dump_args.push("$KRAPH_SOURCE_URL".into());

    let parallel = req.parallel_jobs.unwrap_or(4).clamp(1, 16);
    let restore_args: Vec<String> = vec![
        "--no-owner".into(),
        "--no-privileges".into(),
        "--no-comments".into(),
        "--verbose".into(),
        "--single-transaction".into(),
        format!("--jobs={parallel}"),
        "--dbname=$KRAPH_TARGET_URL".into(),
    ];

    // The shell script. pg_dump streams to stdout; pg_restore reads from
    // stdin. Two-process pipeline inside one container = no intermediate
    // disk for the dump file. We capture exit codes from BOTH processes
    // via PIPESTATUS so the agent can tell whether the dump or the
    // restore failed.
    let script = format!(
        r#"set -o pipefail
echo "[kraph-migrate] starting bulk pg_dump | pg_restore"
echo "[kraph-migrate] exclude_schemas: {exclude_count}"
pg_dump {dump_args} | pg_restore {restore_args}
DUMP_RC=${{PIPESTATUS[0]}}
RESTORE_RC=${{PIPESTATUS[1]}}
echo "[kraph-migrate] pg_dump rc=$DUMP_RC"
echo "[kraph-migrate] pg_restore rc=$RESTORE_RC"
# Surface a structured tail so the gateway can parse it cleanly.
echo "::kraph-migrate-result:: dump=$DUMP_RC restore=$RESTORE_RC"
[ $DUMP_RC -eq 0 ] && [ $RESTORE_RC -eq 0 ]
"#,
        dump_args = dump_args.join(" "),
        restore_args = restore_args.join(" "),
        exclude_count = exclude_schemas.len(),
    );

    // postgres:17-alpine ships pg_dump 17. pg_dump 17 can dump v13–v17
    // sources; pg_dump 16 REFUSED v17 sources with the version-mismatch
    // error (Supabase moved free-tier projects to PG17), exited
    // immediately, and the empty container surfaced only as the generic
    // "wait_container: Docker container wait error" on the agent side.
    let image = "postgres:17-alpine".to_string();
    pull_image_if_missing(&docker, &image).await?;

    let env: Vec<String> = vec![
        format!("KRAPH_SOURCE_URL={}", req.source_url),
        format!("KRAPH_TARGET_URL={}", req.target_url),
        // Don't promiscuously echo PGPASSWORD into env — the URL form
        // carries credentials inline and pg_dump parses them out.
    ];

    let host_config = HostConfig {
        memory: Some(4 * 1024 * 1024 * 1024), // 4 GB
        cpu_quota: Some(100_000),
        cpu_period: Some(100_000),
        // network_mode bridge default; outbound to source + inbound on
        // host.docker.internal for target.
        extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
        auto_remove: Some(false),
        pids_limit: Some(2048),
        ..Default::default()
    };

    let create_opts = CreateContainerOptions {
        name: container_name.to_string(),
        platform: None,
    };
    let cfg = ContainerConfig {
        image: Some(image.clone()),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), script]),
        env: Some(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create = docker
        .create_container(Some(create_opts), cfg)
        .await
        .with_context(|| format!("docker create_container ({image})"))?;
    let container_id = create.id;
    let cleanup = ContainerCleanup {
        docker: docker.clone(),
        container_id: container_id.clone(),
    };

    docker
        .start_container(&container_id, None::<StartContainerOptions<String>>)
        .await
        .context("start migration container")?;

    // Stream logs into a capped buffer. We grep for ::kraph-migrate-result::
    // lines to extract dump/restore exit codes.
    let logs_handle = {
        let docker = docker.clone();
        let cid = container_id.clone();
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
                        if buf.len() >= MAX_LOG_BYTES {
                            // Drop head, keep tail.
                            let drop = buf.len() - (MAX_LOG_BYTES * 3 / 4);
                            buf.drain(0..drop);
                        }
                        buf.extend_from_slice(&message);
                    }
                    Err(e) => {
                        warn!(error = %e, "migration log stream errored");
                        break;
                    }
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };

    let timeout = clamp_timeout_secs(req.timeout_secs);
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
                    Err(BollardError::DockerResponseServerError {
                        status_code: 404, ..
                    }) => return Ok::<i64, anyhow::Error>(137),
                    // DockerContainerWaitError's Display is literally
                    // "Docker container wait error" — the actual daemon
                    // error string is in the `error` field which Display
                    // drops. Extract it explicitly so callers see the
                    // real cause (e.g. "OCI runtime exec failed: ...",
                    // "container ... not found", etc.) instead of the
                    // useless generic.
                    Err(BollardError::DockerContainerWaitError { error, code }) => {
                        // bollard fires this for ANY non-zero container
                        // exit. `error` is the Docker daemon's message
                        // (usually empty if the container exited cleanly
                        // with a non-zero rc), `code` is the exit code.
                        // Empty error + exit code = "container ran, pg_dump
                        // or pg_restore returned non-zero" — caller needs
                        // the log_tail to know which step failed and why.
                        return Ok::<i64, anyhow::Error>(code);
                    }
                    Err(e) => return Err(anyhow!("wait_container: {e}")),
                }
            }
            Ok(last.map(|r| r.status_code).unwrap_or(0))
        };
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(timeout),
            wait_fut,
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                warn!(container_id = %container_id, "migration timed out, killing");
                let _ = docker
                    .kill_container(&container_id, None::<KillContainerOptions<String>>)
                    .await;
                return Err(anyhow!(
                    "migration exceeded {timeout}s timeout — killed"
                ));
            }
        }
    };

    let log_tail = logs_handle.await.unwrap_or_default();
    drop(cleanup);

    // Parse structured marker for exit codes. If the marker isn't present
    // (script crashed before printing it), fall back to inferring from the
    // outer exit code: 0 = both succeeded, anything else = at least one
    // failed.
    let (dump_rc, restore_rc) = parse_result_marker(&log_tail).unwrap_or_else(|| {
        if exit_code == 0 {
            (0, 0)
        } else {
            (-1, -1)
        }
    });

    // Best-effort row count + tables-done — pg_restore prints lines like
    // "pg_restore: processing data for table "public.posts"" so we count
    // those. Imperfect but useful as a heartbeat.
    let tables_done = log_tail
        .lines()
        .filter(|l| l.contains("processing data for table"))
        .count() as u64;
    let rows_migrated = 0u64; // pg_restore doesn't emit row counts; left for v2 progress hook

    let duration_ms = started.elapsed().as_millis();

    if exit_code != 0 || dump_rc != 0 || restore_rc != 0 {
        let err = format!(
            "migration failed (container exit={exit_code}, dump={dump_rc}, restore={restore_rc}). last log:\n{}",
            tail_log(&log_tail, 4096)
        );
        return Ok(MigrationResult {
            state: "failed".into(),
            duration_ms,
            log_tail,
            exit_code_dump: dump_rc,
            exit_code_restore: restore_rc,
            rows_migrated,
            tables_done,
            error: err,
        });
    }

    info!(
        container = %container_name,
        duration_ms,
        tables_done,
        wallet = %req.wallet_pubkey,
        "bulk migration completed"
    );
    Ok(MigrationResult {
        state: "done".into(),
        duration_ms,
        log_tail,
        exit_code_dump: 0,
        exit_code_restore: 0,
        rows_migrated,
        tables_done,
        error: String::new(),
    })
}

/// Live-sync (logical replication) phase 1: schema-only bulk + create
/// publication on source + create subscription on target. Returns once
/// the subscription is set up; rows then flow continuously inside the
/// target's Postgres instance until `cutover_live_sync` runs.
///
/// Workflow inside the container:
///   1. pg_dump --schema-only source | pg_restore target
///   2. psql source: DROP PUBLICATION IF EXISTS kraph_<id> ; CREATE PUBLICATION kraph_<id> FOR ALL TABLES
///   3. psql target: DROP SUBSCRIPTION IF EXISTS kraph_<id> ; CREATE SUBSCRIPTION kraph_<id> CONNECTION '...' PUBLICATION kraph_<id>
///   4. report initial pg_stat_subscription state and exit
///
/// Postgres handles initial table copy + ongoing CDC natively after this.
/// We name the publication/subscription `kraph_<id>` (12-char nanoid) so
/// multiple concurrent migrations don't clash.
pub async fn run_live_sync_setup(
    docker: Arc<Docker>,
    container_name: &str,
    pubsub_name: &str,
    req: &MigrationStartRequest,
) -> Result<MigrationResult> {
    let started = Instant::now();

    // Build the schema-dump portion identically to bulk mode (always
    // --schema-only; live_sync doesn't bulk-dump rows, replication does).
    let exclude_schemas = req
        .exclude_schemas
        .clone()
        .unwrap_or_else(|| DEFAULT_EXCLUDE_SCHEMAS.iter().map(|s| s.to_string()).collect());
    for s in &exclude_schemas {
        if !is_pg_identifier_safe(s) {
            return Err(anyhow!("excludeSchemas contains unsafe value: {s:?}"));
        }
    }
    if !is_pg_identifier_safe(pubsub_name) {
        return Err(anyhow!("pubsub_name unsafe: {pubsub_name:?}"));
    }

    let mut dump_args: Vec<String> = vec![
        "-Fc".into(),
        "--no-owner".into(),
        "--no-privileges".into(),
        "--no-comments".into(),
        "--schema-only".into(),
        "--verbose".into(),
        "--quote-all-identifiers".into(),
    ];
    for schema in &exclude_schemas {
        dump_args.push(format!("--exclude-schema={schema}"));
    }
    dump_args.push("$KRAPH_SOURCE_URL".into());

    let restore_args: Vec<String> = vec![
        "--no-owner".into(),
        "--no-privileges".into(),
        "--no-comments".into(),
        "--single-transaction".into(),
        "--dbname=$KRAPH_TARGET_URL".into(),
    ];

    // Build the SQL that creates publication + subscription. We DROP IF
    // EXISTS first so re-running a failed live_sync setup is idempotent.
    // FOR ALL TABLES is the broadest possible publication; if the user
    // wanted table-level filtering they'd use bulk mode.
    let pub_sql = format!(
        "DROP PUBLICATION IF EXISTS {p}; CREATE PUBLICATION {p} FOR ALL TABLES;",
        p = pubsub_name,
    );
    let sub_sql = format!(
        "DROP SUBSCRIPTION IF EXISTS {p}; CREATE SUBSCRIPTION {p} CONNECTION :'src' PUBLICATION {p};",
        p = pubsub_name,
    );

    let script = format!(
        r#"set -o pipefail
echo "[kraph-migrate] live_sync setup phase 1: schema dump + restore"
pg_dump {dump_args} | pg_restore {restore_args}
DUMP_RC=${{PIPESTATUS[0]}}
RESTORE_RC=${{PIPESTATUS[1]}}
echo "[kraph-migrate] schema phase rc=dump:$DUMP_RC restore:$RESTORE_RC"
[ $DUMP_RC -eq 0 ] && [ $RESTORE_RC -eq 0 ] || {{
  echo "::kraph-migrate-result:: dump=$DUMP_RC restore=$RESTORE_RC sub=skipped"
  exit 1
}}

echo "[kraph-migrate] live_sync setup phase 2: create publication on source"
psql "$KRAPH_SOURCE_URL" -v ON_ERROR_STOP=1 -c "{pub_sql}"
PUB_RC=$?
[ $PUB_RC -eq 0 ] || {{
  echo "::kraph-migrate-result:: dump=$DUMP_RC restore=$RESTORE_RC pub=$PUB_RC sub=skipped"
  exit 1
}}

echo "[kraph-migrate] live_sync setup phase 3: create subscription on target"
# pass the source URL via psql variable so it's not splatted into shell
# logs (still ends up in pg_subscription though — that's how Postgres
# stores it).
psql "$KRAPH_TARGET_URL" -v ON_ERROR_STOP=1 -v "src=$KRAPH_SOURCE_URL" -c "{sub_sql}"
SUB_RC=$?
echo "::kraph-migrate-result:: dump=$DUMP_RC restore=$RESTORE_RC pub=$PUB_RC sub=$SUB_RC"
[ $SUB_RC -eq 0 ]
"#,
        dump_args = dump_args.join(" "),
        restore_args = restore_args.join(" "),
    );

    // postgres:17-alpine ships pg_dump 17. pg_dump 17 can dump v13–v17
    // sources; pg_dump 16 REFUSED v17 sources with the version-mismatch
    // error (Supabase moved free-tier projects to PG17), exited
    // immediately, and the empty container surfaced only as the generic
    // "wait_container: Docker container wait error" on the agent side.
    let image = "postgres:17-alpine".to_string();
    pull_image_if_missing(&docker, &image).await?;
    let env: Vec<String> = vec![
        format!("KRAPH_SOURCE_URL={}", req.source_url),
        format!("KRAPH_TARGET_URL={}", req.target_url),
    ];
    let host_config = HostConfig {
        memory: Some(2 * 1024 * 1024 * 1024),
        cpu_quota: Some(100_000),
        cpu_period: Some(100_000),
        extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
        auto_remove: Some(false),
        pids_limit: Some(2048),
        ..Default::default()
    };
    let create_opts = CreateContainerOptions {
        name: container_name.to_string(),
        platform: None,
    };
    let cfg = ContainerConfig {
        image: Some(image.clone()),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), script]),
        env: Some(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        host_config: Some(host_config),
        ..Default::default()
    };
    let created = docker
        .create_container(Some(create_opts), cfg)
        .await
        .with_context(|| format!("docker create_container ({image})"))?;
    let cid = created.id;
    let cleanup = ContainerCleanup {
        docker: docker.clone(),
        container_id: cid.clone(),
    };
    docker
        .start_container(&cid, None::<StartContainerOptions<String>>)
        .await
        .context("start live_sync container")?;
    let logs_handle = drain_logs(docker.clone(), cid.clone());
    let timeout = clamp_timeout_secs(req.timeout_secs);
    let exit_code = match tokio::time::timeout(
        tokio::time::Duration::from_secs(timeout),
        async {
            let mut s = docker.wait_container(&cid, None::<WaitContainerOptions<String>>);
            let mut last: Option<ContainerWaitResponse> = None;
            while let Some(item) = s.try_next().await.transpose() {
                if let Ok(resp) = item {
                    last = Some(resp);
                }
            }
            anyhow::Ok(last.map(|r| r.status_code).unwrap_or(0))
        },
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            let _ = docker
                .kill_container(&cid, None::<KillContainerOptions<String>>)
                .await;
            return Err(anyhow!("live_sync setup exceeded {timeout}s timeout"));
        }
    };
    let log_tail = logs_handle.await.unwrap_or_default();
    drop(cleanup);
    let (dump_rc, restore_rc) =
        parse_result_marker(&log_tail).unwrap_or((if exit_code == 0 { 0 } else { -1 }, 0));
    let duration_ms = started.elapsed().as_millis();
    if exit_code != 0 {
        return Ok(MigrationResult {
            state: "failed".into(),
            duration_ms,
            log_tail: log_tail.clone(),
            exit_code_dump: dump_rc,
            exit_code_restore: restore_rc,
            rows_migrated: 0,
            tables_done: 0,
            error: format!(
                "live_sync setup failed (container exit={exit_code}). last log:\n{}",
                tail_log(&log_tail, 4096)
            ),
        });
    }
    info!(
        container = %container_name,
        duration_ms,
        pubsub = %pubsub_name,
        "live_sync subscription set up; replication now running inside target's Postgres"
    );
    Ok(MigrationResult {
        state: "cdc_streaming".into(),
        duration_ms,
        log_tail,
        exit_code_dump: dump_rc,
        exit_code_restore: restore_rc,
        rows_migrated: 0,
        tables_done: 0,
        error: String::new(),
    })
}

/// Cutover: wait for the target subscription to catch up to the source's
/// current LSN, then drop the subscription + publication. Container exits
/// once cutover is complete — the user can then redirect their app to the
/// Kraph instance.
pub async fn run_live_sync_cutover(
    docker: Arc<Docker>,
    container_name: &str,
    pubsub_name: &str,
    source_url: &str,
    target_url: &str,
    max_wait_secs: u64,
) -> Result<MigrationResult> {
    let started = Instant::now();
    if !is_pg_identifier_safe(pubsub_name) {
        return Err(anyhow!("pubsub_name unsafe: {pubsub_name:?}"));
    }
    let script = format!(
        r#"set -e
echo "[kraph-migrate] cutover: snapshotting source LSN"
SOURCE_LSN=$(psql "$KRAPH_SOURCE_URL" -t -A -c "SELECT pg_current_wal_lsn()")
echo "[kraph-migrate] source LSN: $SOURCE_LSN"
DEADLINE=$(( $(date +%s) + {max_wait_secs} ))
while true; do
  RECEIVED=$(psql "$KRAPH_TARGET_URL" -t -A -c "SELECT received_lsn FROM pg_stat_subscription WHERE subname = '{pubsub}' LIMIT 1")
  echo "[kraph-migrate] received: ${{RECEIVED:-<null>}} target_pos vs source $SOURCE_LSN"
  if [ -n "$RECEIVED" ] && [ "$RECEIVED" \!= "" ]; then
    CMP=$(psql "$KRAPH_TARGET_URL" -t -A -c "SELECT pg_lsn_cmp('$RECEIVED','$SOURCE_LSN') >= 0")
    if [ "$CMP" = "t" ]; then
      echo "[kraph-migrate] caught up"
      break
    fi
  fi
  if [ $(date +%s) -ge $DEADLINE ]; then
    echo "::kraph-migrate-result:: caught_up=false reason=timeout"
    exit 2
  fi
  sleep 3
done

echo "[kraph-migrate] dropping subscription on target"
psql "$KRAPH_TARGET_URL" -v ON_ERROR_STOP=1 -c "DROP SUBSCRIPTION IF EXISTS {pubsub}"

echo "[kraph-migrate] dropping publication on source"
psql "$KRAPH_SOURCE_URL" -v ON_ERROR_STOP=1 -c "DROP PUBLICATION IF EXISTS {pubsub}"
echo "::kraph-migrate-result:: caught_up=true"
"#,
        pubsub = pubsub_name,
        max_wait_secs = max_wait_secs,
    );
    // postgres:17-alpine ships pg_dump 17. pg_dump 17 can dump v13–v17
    // sources; pg_dump 16 REFUSED v17 sources with the version-mismatch
    // error (Supabase moved free-tier projects to PG17), exited
    // immediately, and the empty container surfaced only as the generic
    // "wait_container: Docker container wait error" on the agent side.
    let image = "postgres:17-alpine".to_string();
    pull_image_if_missing(&docker, &image).await?;
    let env = vec![
        format!("KRAPH_SOURCE_URL={}", source_url),
        format!("KRAPH_TARGET_URL={}", target_url),
    ];
    let host_config = HostConfig {
        memory: Some(256 * 1024 * 1024),
        extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
        auto_remove: Some(false),
        ..Default::default()
    };
    let cfg = ContainerConfig {
        image: Some(image),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), script]),
        env: Some(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        host_config: Some(host_config),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name: container_name.to_string(),
                platform: None,
            }),
            cfg,
        )
        .await
        .context("create cutover container")?;
    let cid = created.id;
    let cleanup = ContainerCleanup {
        docker: docker.clone(),
        container_id: cid.clone(),
    };
    docker
        .start_container(&cid, None::<StartContainerOptions<String>>)
        .await?;
    let logs_handle = drain_logs(docker.clone(), cid.clone());
    let timeout = max_wait_secs + 60;
    let exit_code = match tokio::time::timeout(
        tokio::time::Duration::from_secs(timeout),
        async {
            let mut s = docker.wait_container(&cid, None::<WaitContainerOptions<String>>);
            let mut last: Option<ContainerWaitResponse> = None;
            while let Some(item) = s.try_next().await.transpose() {
                if let Ok(resp) = item {
                    last = Some(resp);
                }
            }
            anyhow::Ok(last.map(|r| r.status_code).unwrap_or(0))
        },
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            let _ = docker
                .kill_container(&cid, None::<KillContainerOptions<String>>)
                .await;
            return Err(anyhow!("cutover exceeded {timeout}s timeout"));
        }
    };
    let log_tail = logs_handle.await.unwrap_or_default();
    drop(cleanup);
    let duration_ms = started.elapsed().as_millis();
    if exit_code != 0 {
        return Ok(MigrationResult {
            state: "failed".into(),
            duration_ms,
            log_tail: log_tail.clone(),
            exit_code_dump: 0,
            exit_code_restore: 0,
            rows_migrated: 0,
            tables_done: 0,
            error: format!(
                "cutover failed (exit={exit_code}). last log:\n{}",
                tail_log(&log_tail, 4096)
            ),
        });
    }
    info!(
        container = %container_name,
        duration_ms,
        pubsub = %pubsub_name,
        "live_sync cutover complete; subscription + publication dropped"
    );
    Ok(MigrationResult {
        state: "done".into(),
        duration_ms,
        log_tail,
        exit_code_dump: 0,
        exit_code_restore: 0,
        rows_migrated: 0,
        tables_done: 0,
        error: String::new(),
    })
}

/// Helper: drain a container's stdout/stderr into a capped String.
fn drain_logs(docker: Arc<Docker>, cid: String) -> tokio::task::JoinHandle<String> {
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
                    if buf.len() >= MAX_LOG_BYTES {
                        let drop = buf.len() - (MAX_LOG_BYTES * 3 / 4);
                        buf.drain(0..drop);
                    }
                    buf.extend_from_slice(&message);
                }
                Err(e) => {
                    warn!(error = %e, "log stream errored");
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Cancel a running migration by killing its container. Idempotent — if
/// the container is already gone we return Ok.
pub async fn cancel_migration(docker: Arc<Docker>, container_name: &str) -> Result<()> {
    match docker
        .kill_container(container_name, None::<KillContainerOptions<String>>)
        .await
    {
        Ok(()) => Ok(()),
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(()),
        Err(BollardError::DockerResponseServerError {
            status_code: 409, ..
        }) => Ok(()), // already stopped
        Err(e) => Err(anyhow!("kill_container({container_name}): {e}")),
    }
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

fn tail_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s[s.len() - max..].to_string()
    }
}

fn parse_result_marker(log: &str) -> Option<(i64, i64)> {
    for line in log.lines().rev().take(50) {
        if let Some(rest) = line.find("::kraph-migrate-result::") {
            let after = &line[rest + "::kraph-migrate-result::".len()..];
            // Format: " dump=N restore=M"
            let mut dump: Option<i64> = None;
            let mut restore: Option<i64> = None;
            for tok in after.split_whitespace() {
                if let Some(v) = tok.strip_prefix("dump=") {
                    dump = v.parse().ok();
                } else if let Some(v) = tok.strip_prefix("restore=") {
                    restore = v.parse().ok();
                }
            }
            if let (Some(d), Some(r)) = (dump, restore) {
                return Some((d, r));
            }
        }
    }
    None
}

fn is_pg_identifier_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `schema.table` or just `table` — allow alnum/underscore/dot/wildcard `*`.
fn is_pg_table_pattern_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '*'
        })
}

async fn pull_image_if_missing(docker: &Docker, image: &str) -> Result<()> {
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

/// Quick capability probe — runs from inside a `postgres:16-alpine` container.
/// Returns `(server_version, wal_level, max_replication_slots)` so the gateway
/// can pre-flight a migration: warn if `wal_level != logical` for live_sync,
/// reject obviously-incompatible source versions, etc.
pub async fn probe_source(
    docker: Arc<Docker>,
    source_url: &str,
) -> Result<SourceProbe> {
    // postgres:17-alpine ships pg_dump 17. pg_dump 17 can dump v13–v17
    // sources; pg_dump 16 REFUSED v17 sources with the version-mismatch
    // error (Supabase moved free-tier projects to PG17), exited
    // immediately, and the empty container surfaced only as the generic
    // "wait_container: Docker container wait error" on the agent side.
    let image = "postgres:17-alpine".to_string();
    pull_image_if_missing(&docker, &image).await?;

    let script = r#"set -e
psql "$KRAPH_SOURCE_URL" -t -A -c "SELECT current_setting('server_version'), current_setting('server_version_num'), current_setting('wal_level'), COALESCE(current_setting('max_replication_slots','t'), '0')"
"#;
    let env = vec![format!("KRAPH_SOURCE_URL={}", source_url)];
    let container_name = format!("kraph-migrate-probe-{}", nanoid::nanoid!(8).to_lowercase());
    let create_opts = CreateContainerOptions {
        name: container_name.clone(),
        platform: None,
    };
    let cfg = ContainerConfig {
        image: Some(image),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), script.to_string()]),
        env: Some(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        host_config: Some(HostConfig {
            memory: Some(256 * 1024 * 1024),
            auto_remove: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };
    let created = docker
        .create_container(Some(create_opts), cfg)
        .await
        .context("create probe container")?;
    let cid = created.id;
    let cleanup = ContainerCleanup {
        docker: docker.clone(),
        container_id: cid.clone(),
    };
    docker
        .start_container(&cid, None::<StartContainerOptions<String>>)
        .await?;
    // Capture combined stdout+stderr.
    let logs_handle = {
        let docker = docker.clone();
        let cid = cid.clone();
        tokio::spawn(async move {
            let opts = LogsOptions::<String> {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            };
            let mut buf: Vec<u8> = Vec::new();
            let mut stream = docker.logs(&cid, Some(opts));
            while let Some(item) = stream.next().await {
                if let Ok(LogOutput::StdOut { message })
                | Ok(LogOutput::StdErr { message }) = item
                {
                    buf.extend_from_slice(&message);
                    if buf.len() > 16 * 1024 {
                        break;
                    }
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    // 30s probe timeout — generous for a `psql -c "SELECT ..."`.
    let exit = tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        async {
            let mut s = docker.wait_container(&cid, None::<WaitContainerOptions<String>>);
            let mut last: Option<ContainerWaitResponse> = None;
            while let Some(item) = s.try_next().await.transpose() {
                if let Ok(resp) = item {
                    last = Some(resp);
                }
            }
            last.map(|r| r.status_code).unwrap_or(0)
        },
    )
    .await
    .map_err(|_| anyhow!("source probe timed out (30s)"))?;
    let log = logs_handle.await.unwrap_or_default();
    drop(cleanup);
    if exit != 0 {
        return Err(anyhow!(
            "source probe failed (exit={exit}). last log:\n{}",
            tail_log(&log, 2048)
        ));
    }
    // psql -t -A returns one row, pipe-separated.
    let last_line = log
        .lines()
        .rev()
        .find(|l| l.contains('|'))
        .ok_or_else(|| anyhow!("probe output missing pipe-separated row:\n{log}"))?;
    let mut parts = last_line.split('|');
    let server_version = parts.next().unwrap_or("").trim().to_string();
    let server_version_num = parts.next().unwrap_or("0").trim().parse::<i64>().unwrap_or(0);
    let wal_level = parts.next().unwrap_or("").trim().to_string();
    let max_replication_slots = parts.next().unwrap_or("0").trim().parse::<i64>().unwrap_or(0);
    Ok(SourceProbe {
        server_version,
        server_version_num,
        wal_level,
        max_replication_slots,
    })
}

#[derive(Debug, Serialize)]
pub struct SourceProbe {
    pub server_version: String,
    pub server_version_num: i64,
    pub wal_level: String,
    pub max_replication_slots: i64,
}
