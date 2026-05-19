//! In-memory tracking of in-flight builds so callers can poll for status
//! instead of holding open a multi-minute HTTP response.
//!
//! Today, `/instances/:id/build-and-pin` synchronously awaits the build
//! container + post-build deploy step — sometimes 5 minutes. Anything
//! between the client and the node (especially Cloudflare's 100s default
//! response cap) terminates the response mid-build. Work continues on
//! the node, but the response never arrives, so the client sees "stuck"
//! and any restart-of-the-gateway loses the connection entirely. The
//! fix is to make builds async: validate the request, spawn the build,
//! return a `build_id` immediately, expose a polling endpoint that
//! returns current status + log tail.
//!
//! State is in-memory + per-process. A node-rs restart loses in-flight
//! builds (their docker containers also die with the process if they
//! were still running) — that's the right behaviour. Finished builds
//! linger for `KEEP_FINISHED_FOR_SECS` so a slow client can still
//! retrieve the result on a poll after the build finished.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// How long a finished build's row is kept in memory after `finished_at`
/// so a slow poller can still retrieve `url` / `error`. After this, the
/// row gets GC'd and a poll returns 404.
const KEEP_FINISHED_FOR_SECS: i64 = 3600; // 1h

/// Max bytes of build_log we keep per build. The build container's stdout
/// stream is captured into this buffer (capped at the source); we mirror
/// the same cap here so a very chatty build can't OOM node-rs through the
/// log path. The build's own log buffer is the authoritative copy until
/// the build finishes; on completion the final tail is written into
/// `BuildState.log` for the polling endpoint to surface.
pub const MAX_LOG_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStatus {
    Running,
    Succeeded,
    Failed,
}

impl BuildStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            BuildStatus::Running => "running",
            BuildStatus::Succeeded => "succeeded",
            BuildStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuildState {
    pub build_id: String,
    pub instance_id: String,
    pub wallet_pubkey: String,
    pub status: BuildStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// "ipfs_pin" | "nextjs_service" | "node_service". Reported back as the
    /// final target on completion so the gateway can shape its MCP response
    /// without re-parsing the original request.
    pub target: Option<String>,
    /// Container `sh -c` exit code, if known. Present for builds that
    /// reached the wait step; absent for failures BEFORE the build
    /// container started (image pull failure, validation errors).
    pub exit_code: Option<i64>,
    /// Tail of the build container's stdout+stderr stream. While
    /// status=Running this is empty (the live stream lives in
    /// frontend_build's logs_handle); after terminal status it carries
    /// the final tail (up to MAX_LOG_BYTES).
    pub log_tail: String,
    pub duration_ms: Option<u128>,
    // ─── success fields (target=ipfs_pin) ───────────────────────────────
    pub cid: Option<String>,
    pub size_bytes: Option<u64>,
    pub file_count: Option<usize>,
    // ─── success fields (target=nextjs_service / node_service) ──────────
    pub host_port: Option<u16>,
    pub container_id: Option<String>,
    // ─── success: live URL (both target families set this) ──────────────
    pub url: Option<String>,
    // ─── failure ────────────────────────────────────────────────────────
    pub error: Option<String>,
}

/// Cloneable handle to the shared store. Stash one in AppState and
/// clone into each spawned build task.
#[derive(Clone, Default)]
pub struct BuildStore {
    inner: Arc<RwLock<HashMap<String, BuildState>>>,
}

impl BuildStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a freshly-started build. Returns the build_id for the caller
    /// to surface to the client.
    pub async fn start(
        &self,
        build_id: String,
        instance_id: String,
        wallet_pubkey: String,
        target: Option<String>,
    ) {
        let now = Utc::now();
        let state = BuildState {
            build_id: build_id.clone(),
            instance_id,
            wallet_pubkey,
            status: BuildStatus::Running,
            started_at: now,
            finished_at: None,
            target,
            exit_code: None,
            log_tail: String::new(),
            duration_ms: None,
            cid: None,
            size_bytes: None,
            file_count: None,
            host_port: None,
            container_id: None,
            url: None,
            error: None,
        };
        let mut guard = self.inner.write().await;
        guard.insert(build_id, state);
        // Best-effort GC of stale finished rows so the store stays bounded.
        let now_secs = now.timestamp();
        guard.retain(|_, b| match b.finished_at {
            None => true,
            Some(t) => now_secs - t.timestamp() <= KEEP_FINISHED_FOR_SECS,
        });
    }

    /// Mark a build successful with target-specific result fields.
    pub async fn complete_success(&self, build_id: &str, patch: impl FnOnce(&mut BuildState)) {
        let mut guard = self.inner.write().await;
        if let Some(b) = guard.get_mut(build_id) {
            b.status = BuildStatus::Succeeded;
            b.finished_at = Some(Utc::now());
            patch(b);
        }
    }

    /// Mark a build failed. `error` is stored verbatim; clients fetch it
    /// via the polling endpoint. `log_tail` is the captured container
    /// stdout/stderr (may be empty if failure happened before the
    /// container started — e.g. invalid output_dir).
    pub async fn complete_failure(
        &self,
        build_id: &str,
        error: String,
        log_tail: String,
        exit_code: Option<i64>,
    ) {
        let mut guard = self.inner.write().await;
        if let Some(b) = guard.get_mut(build_id) {
            b.status = BuildStatus::Failed;
            b.finished_at = Some(Utc::now());
            b.error = Some(error);
            // Trim defensively even though frontend_build also caps.
            b.log_tail = if log_tail.len() > MAX_LOG_BYTES {
                log_tail[log_tail.len() - MAX_LOG_BYTES..].to_string()
            } else {
                log_tail
            };
            b.exit_code = exit_code;
        }
    }

    /// Snapshot the state for read-only access. Cloning the inner struct
    /// is cheap (small fields, short strings) — the alternative is
    /// holding the RwLock across the response serialization, which would
    /// block other polls.
    pub async fn get(&self, build_id: &str) -> Option<BuildState> {
        let guard = self.inner.read().await;
        guard.get(build_id).cloned()
    }

    /// Total number of tracked builds (running + finished-but-not-GC'd).
    /// Exposed for the /health endpoint.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}
