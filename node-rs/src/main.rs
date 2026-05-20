mod build_store;
mod config;
mod db;
mod db_migration;
mod frontend_build;
mod health;
mod instance_manager;
mod integrity;
mod job_admission;
mod nextjs_service;
mod path_safety;
mod replication;
mod sigauth;
mod studio_proxy;
mod tee;
mod warm_pool;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::Digest as _;
use tokio::signal;
use tracing::{error, info, warn};

use config::Config;
use db::Database;
use instance_manager::{InstanceManager, ProvisionRequest};
use replication::ReplicationManager;
use warm_pool::WarmPool;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

struct AppState {
    config: Config,
    manager: InstanceManager,
    warm_pool: WarmPool,
    replication: Arc<ReplicationManager>,
    db: Arc<Database>,
    /// Per-instance mutex serializing resume / suspend operations on the
    /// docker socket. Concurrent first-hit requests on a suspended
    /// instance all `lock().await` the same mutex; only one runs
    /// `compose start`, the others observe state=running on retry.
    /// Lazily populated; entries are never removed (cheap — one Arc<Mutex>
    /// per ever-touched instance, ~50 bytes).
    resume_locks: tokio::sync::Mutex<
        std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    >,
    /// In-flight + recently-finished build registry. build_and_pin_handler
    /// returns the build_id immediately and spawns the actual build into
    /// a tokio task that updates this store on completion. Clients poll
    /// via GET /instances/:id/builds/:build_id. See build_store.rs.
    build_store: build_store::BuildStore,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "supaba_node=info,tower_http=info".into()),
        )
        .init();

    // Configuration.
    let config = Config::from_env()?;

    // Startup banner.
    print_banner(&config);

    // Database.
    let db = Arc::new(Database::new(&config.data_dir)?);

    // Instance manager + warm pool + replication.
    let config_arc = Arc::new(config.clone());
    let manager = InstanceManager::new(&config, db.clone());
    let warm_pool = WarmPool::new(config_arc.clone(), db.clone());
    let replication = Arc::new(ReplicationManager::new(config_arc.clone(), db.clone()));

    let state = Arc::new(AppState {
        config: config.clone(),
        manager,
        warm_pool,
        replication,
        db: db.clone(),
        resume_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        build_store: build_store::BuildStore::new(),
    });

    // Background tasks.
    spawn_background_tasks(state.clone(), &config);

    // Axum router.
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/instances", post(provision_handler))
        .route("/instances", get(list_instances_handler))
        .route("/instances/:id", get(get_instance_handler))
        .route("/instances/:id", delete(destroy_handler))
        .route(
            "/instances/:id/credentials",
            get(get_instance_credentials_handler),
        )
        .route("/instances/:id/health", get(instance_health_handler))
        .route("/instances/:id/extend", post(extend_handler))
        // Idle-suspend lifecycle. /touch is hit by every proxy hop to
        // bump last_seen_at; /resume cold-starts a suspended stack
        // (compose start + pg health poll, coalesced via resume_locks);
        // /pin is the gateway hook after a kraph_pin_instance x402
        // settlement, extending pinned_until.
        .route("/instances/:id/touch", post(touch_handler))
        .route("/instances/:id/resume", post(resume_handler))
        .route("/instances/:id/pin", post(pin_handler))
        // IPFS pinning. Default axum body limit is 2MB, which silently
        // rejects most frontend bundles. 50MB matches the gateway's
        // express.json() ceiling so an agent-supplied SPA flows end to end.
        .route(
            "/ipfs/pin",
            post(ipfs_pin_handler).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        .route("/ipfs/:cid", get(ipfs_get_handler))
        // Sandboxed frontend builder — agent-driven via kraph_github_build_frontend.
        // Body is small (just URLs + commands), the heavy work happens inside
        // an ephemeral container against a tarball downloaded from GitHub.
        .route("/instances/:id/build-and-pin", post(build_and_pin_handler))
        // Poll a previously-spawned build by build_id. Returns current
        // status (running | succeeded | failed), the last MAX_LOG_BYTES
        // of build container stdout/stderr, and result fields on
        // completion (cid+url for ipfs_pin, host_port+url for service
        // targets). Mirrors build_and_pin_handler's auth: wallet must
        // own the instance the build is bound to. See build_store.rs.
        .route(
            "/instances/:id/builds/:build_id",
            get(get_build_status_handler),
        )
        // Per-instance Next.js service deploy. Body is a tar.gz of the
        // Next.js standalone build output; the handler extracts, runs
        // node:20-alpine as a sidecar on the instance's docker network,
        // exposes the service at base_port+9. 512 MB body limit matches
        // MAX_BUNDLE_BYTES in nextjs_service.rs.
        .route(
            "/instances/:id/services/nextjs/deploy",
            post(deploy_nextjs_service_handler)
                .layer(DefaultBodyLimit::max(512 * 1024 * 1024)),
        )
        // Read the per-instance Next.js sidecar's container logs. Cheap
        // diagnostic endpoint — returns interleaved stdout+stderr from
        // the running (or last-stopped) sidecar container so users can
        // see why their app crashed on boot, what env vars it logged
        // they were missing, etc.
        .route(
            "/instances/:id/services/nextjs/logs",
            get(get_nextjs_service_logs_handler),
        )
        // Append URLs to GOTRUE_URI_ALLOW_LIST + restart the auth container.
        // Used by kraph_auth_set_redirect_urls so the magic-link allow list
        // can grow after the IPFS CID is known (or after kraph_buy_domain).
        .route(
            "/instances/:id/auth/redirect-urls",
            post(append_redirect_urls_handler),
        )
        // Database migration — Supabase / generic Postgres → Kraph instance.
        // Source-probe is fast (one psql query); start kicks off a docker job
        // that pipes pg_dump | pg_restore. Cancel kills the container.
        .route("/instances/:id/migrate/probe", post(migrate_probe_handler))
        .route("/instances/:id/migrate", post(migrate_start_handler))
        .route(
            "/instances/:id/migrate/cutover/:pubsub",
            post(migrate_cutover_handler),
        )
        .route(
            "/instances/:id/migrate/:container",
            delete(migrate_cancel_handler),
        )
        // Integrity (Layer 2: Merkle state commitments)
        .route("/instances/:id/integrity/root", get(integrity_root_handler))
        // TEE attestation
        .route("/instances/:id/attest", post(attest_handler))
        // Edge Functions
        .route("/instances/:id/functions/deploy", post(deploy_function_handler))
        .route("/instances/:id/functions", get(list_functions_handler))
        .route("/instances/:id/functions/:name/source", get(get_function_source_handler))
        // Per-instance edge-function env vars (scoped to the functions container,
        // not the whole Supabase stack). Mutations live-reload by recreating
        // only the `functions` service; no Postgres restart involved.
        .route("/instances/:id/env", post(set_env_handler))
        .route("/instances/:id/env", get(list_env_handler))
        .route("/instances/:id/env/keys", get(list_env_keys_handler))
        .route("/instances/:id/env/apply", post(apply_env_handler))
        .route("/instances/:id/env/:key", delete(delete_env_handler))
        // Replication
        .route("/instances/:id/replicas", post(add_replica_handler))
        .route("/instances/:id/replicas", get(list_replicas_handler))
        .route("/instances/:id/replicas/force-switch-wal", post(force_switch_wal_handler))
        .route(
            "/replication/receive",
            // Postgres WAL segments are 16 MB by default. Allow up to 64 MB
            // per request to leave headroom for non-default WAL sizes and the
            // ChaCha20-Poly1305 nonce + tag overhead.
            post(receive_replication_handler).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
        )
        .route("/replication/:instance_id/segments", get(list_replica_segments_handler))
        // Studio auth gate (Phase 3, subdomain mode). The exchange endpoint
        // verifies the gateway-minted HMAC token and drops a wildcard-Domain
        // cookie. forward-auth is what Caddy hits on every Studio request
        // to validate that cookie before forwarding to 127.0.0.1:<studio_port>.
        .route("/__kraph/studio/exchange", get(studio_exchange_handler))
        .route("/__kraph/studio/forward-auth", get(studio_forward_auth_handler))
        // CORS: allow the landing page (and any other browser-based agent)
        // to fetch /health, /stats, /replication/*/segments. The node API has
        // no authenticated state that a cross-origin GET could exfiltrate —
        // everything sensitive (wallet ops, provision) requires POST body
        // auth — so permissive CORS is safe here.
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.api_port));
    info!(%addr, "HTTP server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server shut down cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn stats_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let stats = state.manager.get_stats()?;
    Ok(Json(stats))
}

async fn provision_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: ProvisionRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F43: sigauth on provision. The request's `wallet_pubkey`
    // field IS the wallet that will own the new instance — a forged
    // gateway claim there means the wrong wallet gets billed (x402
    // delegation drains the claimed wallet's USDC) and ends up as the
    // owner. Verify the signature is from that wallet before any
    // docker/db work.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        "/instances",
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    // Audit F69: replica endpoints arrive in the SAME signed body so we
    // can register them now without an unsigned follow-up. Snapshot the
    // list before `req` is moved into the manager.
    let replica_endpoints: Vec<String> = req
        .replica_endpoints
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.trim().trim_end_matches('/').to_string())
        .filter(|e| {
            !e.is_empty() && (e.starts_with("http://") || e.starts_with("https://"))
        })
        .collect();
    // Try the warm pool first if anything is in it. provision_from_warm is
    // also async-friendly because it does down+up in <2s when the warm
    // instance is healthy.
    let result = if let Some(warm_inst) = state.warm_pool.take().await {
        info!(
            warm_project = %warm_inst.compose_project_name,
            "using warm instance for fast provisioning"
        );
        match state
            .manager
            .provision_from_warm(req.clone(), warm_inst)
            .await
        {
            Ok(result) => {
                let replenish_state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = replenish_state.warm_pool.replenish().await {
                        warn!(error = %e, "warm pool replenish after take failed");
                    }
                });
                result
            }
            Err(e) => {
                warn!(error = %e, "warm instance assignment failed, falling back to async cold provision");
                state.manager.prepare_provision(req).await?
            }
        }
    } else {
        // Cold path: prepare metadata synchronously (returns the
        // credentials in <1s) and run docker compose up in the background.
        // This keeps the HTTP response well within the Solana blockhash
        // window so x402 settlement on a paid /instances call succeeds
        // even when the underlying Supabase stack takes a minute to come
        // up. The agent can poll GET /instances/:id/health for the
        // running/degraded transition.
        state.manager.prepare_provision(req).await?
    };

    // Audit F69: register the signed replica endpoints now, in the same
    // logical operation as provision. No unsigned follow-up call needed
    // — strict sigauth on /instances/:id/replicas can't break the
    // provision flow because the gateway no longer needs to call it.
    for ep in &replica_endpoints {
        match state.db.add_instance_replica(&result.id, ep) {
            Ok(added) => {
                info!(
                    instance_id = %result.id,
                    endpoint = %ep,
                    added,
                    "replica registered from signed provision body"
                );
            }
            Err(e) => {
                warn!(
                    instance_id = %result.id,
                    endpoint = %ep,
                    error = %e,
                    "replica registration failed (continuing)"
                );
            }
        }
    }

    // If the result came back as 'provisioning' it means we took the cold
    // path (or warm fast path is somehow still in flight). Spawn the docker
    // work in the background. For 'running' (warm pool succeeded) the work
    // is already done.
    if result.status == "provisioning" {
        let bg_state = state.clone();
        let instance_id = result.id.clone();
        tokio::spawn(async move {
            if let Err(e) = bg_state.manager.finalize_provision(&instance_id).await {
                error!(instance_id = %instance_id, error = %e, "background finalize_provision failed");
            }
            // Configure WAL archiving once Postgres is up. The 5s grace
            // period inside finalize_provision's wait_for_health is usually
            // enough, but we add a small extra wait to be safe.
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Err(e) = bg_state
                .replication
                .configure_wal_archiving(&instance_id)
                .await
            {
                warn!(instance_id = %instance_id, error = %e, "WAL archiving configuration failed");
            }
        });
    } else {
        // Already running (warm path) — still configure archiving.
        let configure_state = state.clone();
        let instance_id = result.id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = configure_state
                .replication
                .configure_wal_archiving(&instance_id)
                .await
            {
                warn!(instance_id = %instance_id, error = %e, "WAL archiving configuration failed");
            }
        });
    }

    // 202 Accepted communicates "I'm working on it" semantics for the cold
    // path. The body still includes everything the agent needs to start
    // using the instance once provisioning completes.
    let status_code = if result.status == "provisioning" {
        StatusCode::ACCEPTED
    } else {
        StatusCode::CREATED
    };
    Ok((status_code, Json(result)).into_response())
}

#[derive(Deserialize)]
struct ListQuery {
    wallet: String,
    status: Option<String>,
}

async fn list_instances_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let instances =
        state
            .manager
            .list_instances(&q.wallet, q.status.as_deref())?;
    Ok(Json(instances))
}

#[derive(Deserialize)]
struct InstanceQuery {
    wallet: String,
}

/// Query for the direct nextjs/node-service deploy endpoint. `entry` is
/// an optional JSON-encoded string array (URL-encoded) that overrides
/// the default `["node", "server.js"]` start argv — used by the gateway
/// when the agent uploads a generic Node bundle (SvelteKit, Nuxt, Remix,
/// etc.) instead of a Next.js standalone build.
#[derive(Deserialize)]
struct DeployServiceQuery {
    wallet: String,
    entry: Option<String>,
}

/// Query for the nextjs/node-service logs endpoint.
#[derive(Deserialize)]
struct NextjsLogsQuery {
    wallet: String,
    /// Max bytes of log output to return. Clamped to [1024, 262144].
    tail: Option<usize>,
}

async fn get_instance_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<InstanceQuery>,
) -> Result<impl IntoResponse, AppError> {
    let instance = state
        .manager
        .list_instances(&q.wallet, None)?
        .into_iter()
        .find(|i| i.id == id);
    match instance {
        Some(i) => Ok(Json(serde_json::to_value(i)?)),
        None => Ok(Json(
            serde_json::json!({ "error": "not found" }),
        )),
    }
}

/// Reveal anon_key / service_role_key / jwt_secret / postgres_password for an
/// owned instance. Same `?wallet=` gate as get_instance_handler — the wallet
/// pubkey + instance_id pair is the implicit owner credential everywhere in
/// node-rs today. Used by the Forge dashboard's Connect panel so a wallet
/// owner can recover the keys kraph_provision returned at creation time
/// without re-provisioning the whole stack.
///
/// Threat note: this is a "owner-equivalent" disclosure path. Long-term the
/// audit-2026-05-11 sigauth (mitigation #1) should be required here; today
/// the same posture as the rest of /instances/:id applies — the wallet is
/// the secret.
async fn get_instance_credentials_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<InstanceQuery>,
) -> Result<impl IntoResponse, AppError> {
    let instance = state
        .manager
        .list_instances(&q.wallet, None)?
        .into_iter()
        .find(|i| i.id == id);
    match instance {
        Some(i) => Ok(Json(serde_json::json!({
            "id": i.id,
            "wallet_pubkey": i.wallet_pubkey,
            "url": i.url,
            "kong_port": i.kong_port,
            "postgres_port": i.postgres_port,
            "anon_key": i.anon_key,
            "service_role_key": i.service_role_key,
            "jwt_secret": i.jwt_secret,
            "postgres_password": i.postgres_password,
        }))),
        None => Ok(Json(serde_json::json!({ "error": "not found" }))),
    }
}

async fn destroy_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<InstanceQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Audit F38: sigauth on destroy. Of all state changes this is the
    // most consequential — destroy is irreversible. A compromised gateway
    // could otherwise wipe arbitrary instances by claiming any wallet in
    // the query string. Permissive rollout still in effect: missing
    // sigauth warns + accepts; present-but-bad rejects 401.
    //
    // The canonical path matches what the gateway forwarder signs (path
    // without query string), and the body is empty since DELETE carries
    // no payload.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "DELETE",
        &format!("/instances/{id}"),
        &[],
        &q.wallet,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    state.manager.destroy(&id, &q.wallet).await?;
    Ok(Json(serde_json::json!({ "status": "destroyed", "id": id })).into_response())
}

async fn instance_health_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    match state.manager.get_health(&id).await? {
        Some(h) => Ok(Json(serde_json::to_value(h)?)),
        None => Ok(Json(
            serde_json::json!({ "error": "not found" }),
        )),
    }
}

#[derive(Deserialize)]
struct ExtendRequest {
    wallet: String,
    duration_secs: i64,
}

async fn extend_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: ExtendRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F38: sigauth on extend. The wallet bound to the instance
    // ALSO pays the x402 — so without sigauth a compromised gateway
    // could repeatedly extend a victim's instance, draining their USDC
    // 0.05 at a time. Verify the signature is from the instance's
    // bound wallet before mutating expiry.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/extend"),
        &body_bytes,
        &req.wallet,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    state
        .manager
        .extend_instance(&id, &req.wallet, req.duration_secs)?;
    Ok(Json(serde_json::json!({ "status": "extended", "id": id })).into_response())
}

// ---------------------------------------------------------------------------
// Idle-suspend lifecycle handlers
// ---------------------------------------------------------------------------
//
// All three endpoints (/touch, /resume, /pin) are gateway-only. Agents
// never reach node-rs directly — traffic flows kraph.com → gateway →
// node-rs. So the trust anchor is the operator pubkey, not the agent's
// wallet, consistent with the audit-2026-05-11 hardening (sigauth
// required, no soft-accept) and side-stepping the "Privy denies
// signMessage" problem that prevents the gateway from signing as an
// OAuth-authed agent.
//
// /touch: cheap bump of last_seen_at on every forwarded proxy request.
// /resume: cold-start a suspended stack, coalesced per instance via
//   AppState::resume_locks.
// /pin: extend instances.pinned_until after a successful x402
//   settlement on kraph_pin_instance.

/// Body shared by `/touch` and `/resume`. The `operator` field's
/// pubkey must match SUPABA_OPERATOR_ADDRESS on the node, AND the
/// request must be sigauth-signed by the matching keypair.
#[derive(Deserialize)]
struct OperatorOnlyRequest {
    operator: String,
}

/// Reusable operator-sigauth gate. Returns Err with a ready-to-send
/// (StatusCode, Json) on any failure; Ok(()) when the request can
/// proceed. Used by `/touch`, `/resume`, `/pin`.
fn verify_operator_signed(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body_bytes: &axum::body::Bytes,
    operator: &str,
) -> std::result::Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(expected) = state.config.operator_address.as_deref() {
        if expected != operator {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "operator pubkey does not match SUPABA_OPERATOR_ADDRESS"
                })),
            ));
        }
    }
    if let Err(e) = sigauth::verify_request_sig(headers, method, path, body_bytes, operator) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": format!("operator sigauth: {e}") })),
        ));
    }
    Ok(())
}

async fn touch_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: OperatorOnlyRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;

    if let Err((code, body)) = verify_operator_signed(
        &state,
        &headers,
        "POST",
        &format!("/instances/{id}/touch"),
        &body_bytes,
        &req.operator,
    ) {
        return Ok((code, body).into_response());
    }

    state.db.touch_instance(&id)?;
    Ok(Json(serde_json::json!({ "status": "touched", "id": id })).into_response())
}

async fn resume_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: OperatorOnlyRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;

    if let Err((code, body)) = verify_operator_signed(
        &state,
        &headers,
        "POST",
        &format!("/instances/{id}/resume"),
        &body_bytes,
        &req.operator,
    ) {
        return Ok((code, body).into_response());
    }

    let instance = state
        .db
        .get_instance_by_id(&id)?
        .ok_or_else(|| AppError(anyhow::anyhow!("instance {id} not found")))?;

    // Fast-path: already running. Skip the lock + bump last_seen.
    if instance.lifecycle_state == "running" {
        state.db.touch_instance(&id)?;
        return Ok(Json(serde_json::json!({
            "status": "running",
            "id": id,
            "already_running": true
        }))
        .into_response());
    }

    // Acquire the per-instance lock, then re-check state inside the lock
    // (another caller may have resumed while we were waiting).
    let lock = {
        let mut map = state.resume_locks.lock().await;
        map.entry(id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = lock.lock().await;

    let refreshed = state
        .db
        .get_instance_by_id(&id)?
        .ok_or_else(|| AppError(anyhow::anyhow!("instance {id} disappeared during resume")))?;
    if refreshed.lifecycle_state == "running" {
        state.db.touch_instance(&id)?;
        return Ok(Json(serde_json::json!({
            "status": "running",
            "id": id,
            "already_running": true
        }))
        .into_response());
    }

    state.manager.resume(&id).await?;
    Ok(Json(serde_json::json!({
        "status": "running",
        "id": id,
        "already_running": false
    }))
    .into_response())
}

#[derive(Deserialize)]
struct PinRequest {
    /// Gateway's operator pubkey — same gate as `/touch` and `/resume`.
    operator: String,
    /// Unix epoch seconds the pin should run through. Idempotent against
    /// the current value: server takes max(existing, until_ts).
    until_ts: i64,
}

async fn pin_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: PinRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;

    if let Err((code, body)) = verify_operator_signed(
        &state,
        &headers,
        "POST",
        &format!("/instances/{id}/pin"),
        &body_bytes,
        &req.operator,
    ) {
        return Ok((code, body).into_response());
    }

    let resolved = state.db.set_pinned_until(&id, req.until_ts)?;
    Ok(Json(serde_json::json!({
        "status": "pinned",
        "id": id,
        "pinned_until": resolved
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// IPFS pinning — real Kubo (go-ipfs)
// ---------------------------------------------------------------------------
//
// Each node runs a sidecar Kubo daemon (typically `ipfs/kubo` in docker)
// with the API bound to 127.0.0.1:5001 and the gateway on 127.0.0.1:8080.
// Pin handler POSTs the content as multipart to /api/v0/add?pin=true and
// returns the real CID; get handler streams from Kubo's gateway.
//
// Sidecar metadata: we keep `<data_dir>/ipfs-meta/<cid>.json` (filename +
// content-type + wallet pubkey) so we can serve content back with the
// right Content-Type and so an operator can audit who pinned what without
// querying Kubo.

#[derive(Deserialize)]
struct IpfsPinRequest {
    /// Single-file mode: literal content as a string. Required when `files`
    /// is absent. Use this for inlined SPAs (one HTML file with everything).
    #[serde(default)]
    content: Option<String>,
    /// Multi-file mode: full SPA bundle. Each entry becomes a file under a
    /// UnixFS directory whose root CID is returned. Required when
    /// `content` is absent. Use this for SPAs split across index.html +
    /// assets/* etc. — Kubo's `wrap-with-directory=true` builds the
    /// directory in one round-trip.
    #[serde(default)]
    files: Option<Vec<IpfsPinFile>>,
    /// Single-file mode only: filename for the upload (defaults to
    /// "index.html"). Ignored in multi-file mode.
    #[serde(default)]
    filename: String,
    /// Single-file mode only: MIME type. Ignored in multi-file mode (each
    /// file carries its own).
    #[serde(rename = "contentType", default)]
    content_type: String,
    #[serde(rename = "walletPubkey")]
    wallet_pubkey: String,
}

#[derive(Deserialize)]
struct IpfsPinFile {
    /// Path inside the UnixFS dir, e.g. "index.html" or "assets/main.js".
    /// Forward slashes create nested dirs server-side.
    path: String,
    /// File contents. Plain UTF-8 by default; set encoding="base64" for
    /// binary assets (images, fonts, wasm).
    content: String,
    /// Optional MIME type. Defaults to "application/octet-stream"; Kubo's
    /// gateway will sniff from the path extension if absent.
    #[serde(rename = "contentType", default)]
    content_type: String,
    /// "utf8" (default) or "base64". When base64, content is decoded
    /// before passing to Kubo so the on-IPFS bytes match the original
    /// binary, not the base64 string.
    #[serde(default)]
    encoding: String,
}

#[derive(serde::Deserialize)]
struct KuboAddResponse {
    #[serde(rename = "Hash")]
    hash: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Size")]
    #[allow(dead_code)]
    size: String,
}

/// Sanitise a single filename component — used for the single-file path's
/// `filename` field, which doesn't carry directory structure. Multi-file
/// paths go through `sanitise_path` below which also allows slashes.
fn sanitise_filename(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Sanitise a multi-file path. Allows ASCII alnum + dot/dash/underscore +
/// forward slashes. Strips leading slashes and `..` segments to make path
/// traversal impossible. Empty result => caller rejects.
fn sanitise_path(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == '/')
        .collect();
    cleaned
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect::<Vec<_>>()
        .join("/")
}

/// Per-wallet daily byte quota for /ipfs/pin (audit F65). Default 100 MiB
/// per day. Operators can override via `SUPABA_IPFS_DAILY_BYTES_PER_WALLET`.
/// State is in-memory: (wallet, utc_day_bucket) → bytes_pinned_today. Day
/// rolls over implicitly because (wallet, new_day) is a fresh key; old
/// buckets are pruned opportunistically on every call.
fn ipfs_daily_quota_bytes() -> u64 {
    std::env::var("SUPABA_IPFS_DAILY_BYTES_PER_WALLET")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(100 * 1024 * 1024)
}

fn ipfs_quota_state() -> &'static std::sync::Mutex<std::collections::HashMap<(String, i64), u64>>
{
    static STATE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(String, i64), u64>>,
    > = std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Returns Ok(()) if the wallet is under quota after adding `add_bytes`,
/// or Err(remaining_bytes_today) describing how much was left at refusal.
fn ipfs_check_and_charge(wallet: &str, add_bytes: u64) -> Result<(), u64> {
    let cap = ipfs_daily_quota_bytes();
    let today = chrono::Utc::now().timestamp() / 86_400;
    let mut map = ipfs_quota_state()
        .lock()
        .expect("ipfs quota mutex poisoned");
    // Opportunistic prune of stale buckets to bound memory growth.
    map.retain(|(_, day), _| *day >= today - 1);
    let entry = map.entry((wallet.to_string(), today)).or_insert(0);
    let next = entry.saturating_add(add_bytes);
    if next > cap {
        let remaining = cap.saturating_sub(*entry);
        return Err(remaining);
    }
    *entry = next;
    Ok(())
}

async fn ipfs_pin_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Audit F65: parse the body manually so we can hand it to sigauth.
    // The pre-rewrite handler trusted walletPubkey from the request body,
    // which made /ipfs/pin a free-for-all for anyone who could reach the
    // node directly. Now wallet identity is bound by ed25519 signature
    // and pin bytes are rate-limited per wallet per day.
    let req: IpfsPinRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    if req.wallet_pubkey.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "walletPubkey is required" })),
        ));
    }
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        "/ipfs/pin",
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        ));
    }

    let multi_mode = matches!(&req.files, Some(f) if !f.is_empty());
    if !multi_mode && req.content.as_deref().unwrap_or("").is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "either `content` (single-file) or `files` (multi-file SPA) is required",
            })),
        ));
    }

    // Audit F65: per-wallet daily byte quota. body length is a safe
    // upper bound on the bytes Kubo will accept (multipart adds a few
    // hundred bytes of framing, never less than the raw content).
    let pin_bytes = body_bytes.len() as u64;
    if let Err(remaining) = ipfs_check_and_charge(&req.wallet_pubkey, pin_bytes) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "ipfs daily pin quota exceeded",
                "remaining_bytes_today": remaining,
                "daily_limit_bytes": ipfs_daily_quota_bytes(),
            })),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| AppError(anyhow::anyhow!("reqwest client build: {e}")))?;

    // ── Multi-file SPA path ────────────────────────────────────────────────
    // Build one multipart Part per file with `wrap-with-directory=true`
    // so Kubo assembles the UnixFS dir in a single API call. The response
    // is NDJSON: one line per file plus one for the wrapping dir (with
    // empty Name). The dir CID is what the agent gets back.
    if multi_mode {
        let files = req.files.unwrap();
        let mut form = reqwest::multipart::Form::new();
        let mut total_size: usize = 0;
        let mut manifest: Vec<serde_json::Value> = Vec::with_capacity(files.len());
        for f in &files {
            let safe_path = sanitise_path(&f.path);
            if safe_path.is_empty() {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("invalid path '{}': must contain alphanumerics + . - _ / only", f.path),
                    })),
                ));
            }
            let bytes: Vec<u8> = match f.encoding.as_str() {
                "" | "utf8" | "utf-8" => f.content.clone().into_bytes(),
                "base64" => match {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.decode(f.content.trim())
                }
                {
                    Ok(b) => b,
                    Err(e) => {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": format!("base64 decode of '{}' failed: {e}", safe_path),
                            })),
                        ));
                    }
                },
                other => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("unknown encoding '{other}' for path '{}': use 'utf8' or 'base64'", safe_path),
                        })),
                    ));
                }
            };
            total_size += bytes.len();
            let mime = if f.content_type.is_empty() {
                "application/octet-stream"
            } else {
                f.content_type.as_str()
            };
            let part = reqwest::multipart::Part::bytes(bytes)
                .file_name(safe_path.clone())
                .mime_str(mime)
                .map_err(|e| AppError(anyhow::anyhow!("invalid Content-Type for '{safe_path}': {e}")))?;
            form = form.part("file", part);
            manifest.push(serde_json::json!({
                "path": safe_path,
                "contentType": f.content_type,
            }));
        }

        let api_url = format!(
            "{}/api/v0/add?cid-version=1&pin=true&wrap-with-directory=true&progress=false",
            state.config.kubo_api_url.trim_end_matches('/')
        );

        let resp = match client.post(&api_url).multipart(form).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, api_url = %api_url, "kubo /api/v0/add (multi) failed");
                return Ok((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("kubo unreachable: {e}"),
                    })),
                ));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            warn!(status, body = %body, "kubo /api/v0/add (multi) returned non-2xx");
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("kubo add failed (HTTP {status})"),
                    "kuboBody": body,
                })),
            ));
        }

        // Parse NDJSON. The wrapping directory is the entry whose Name
        // matches the empty string OR the longest leading-empty path
        // (Kubo emits it last). Take the last non-empty line as a
        // sturdy fallback — older Kubo versions sometimes use Name="."
        // or the last `/`-prefixed entry to mark the dir.
        let body_text = resp
            .text()
            .await
            .map_err(|e| AppError(anyhow::anyhow!("reading kubo response: {e}")))?;
        let entries: Vec<KuboAddResponse> = body_text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if entries.is_empty() {
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "kubo returned no entries for multi-file pin",
                    "kuboBody": body_text,
                })),
            ));
        }
        // Prefer the entry with empty/blank Name (the wrap-with-dir root).
        // Fall through to the last entry, which is what Kubo emits when
        // the wrapping dir is unnamed in newer versions.
        let dir_entry = entries
            .iter()
            .find(|e| e.name.trim().is_empty())
            .unwrap_or_else(|| entries.last().unwrap());
        let cid = dir_entry.hash.clone();

        let meta_dir = state.config.data_dir.join("ipfs-meta");
        tokio::fs::create_dir_all(&meta_dir).await?;
        let meta = serde_json::json!({
            "cid": &cid,
            "kind": "directory",
            "files": manifest,
            "walletPubkey": req.wallet_pubkey,
            "size": total_size,
        });
        tokio::fs::write(
            meta_dir.join(format!("{cid}.json")),
            serde_json::to_string_pretty(&meta)?,
        )
        .await?;

        let gateway_url = format!(
            "http://{}:{}/ipfs/{}/",
            state.config.hostname, state.config.api_port, cid
        );

        info!(
            cid = %cid,
            files = files.len(),
            size = total_size,
            wallet = %req.wallet_pubkey,
            "multi-file SPA pinned via kubo"
        );

        return Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({
                "cid": cid,
                "gatewayUrl": gateway_url,
                "publicGatewayUrl": format!("https://ipfs.io/ipfs/{cid}/"),
                "size": total_size,
                "fileCount": files.len(),
            })),
        ));
    }

    // ── Single-file path (legacy) ─────────────────────────────────────────
    let content = req.content.unwrap_or_default();
    let raw_filename = if req.filename.is_empty() {
        "index.html".to_string()
    } else {
        req.filename.clone()
    };
    let safe_filename = sanitise_filename(&raw_filename);
    if safe_filename.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "filename contains only invalid characters" })),
        ));
    }

    // Build a multipart request. Kubo's /api/v0/add expects a "file" part
    // with the raw bytes. We pass cid-version=1 so we get a modern
    // self-describing CID (bafy…) instead of legacy QmHash format.
    let body_bytes = content.into_bytes();
    let size = body_bytes.len();
    let part = reqwest::multipart::Part::bytes(body_bytes)
        .file_name(safe_filename.clone())
        .mime_str(if req.content_type.is_empty() {
            "application/octet-stream"
        } else {
            req.content_type.as_str()
        })
        .map_err(|e| AppError(anyhow::anyhow!("invalid Content-Type: {e}")))?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let api_url = format!(
        "{}/api/v0/add?cid-version=1&pin=true&progress=false",
        state.config.kubo_api_url.trim_end_matches('/')
    );

    let resp = client.post(&api_url).multipart(form).send().await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, api_url = %api_url, "kubo /api/v0/add failed");
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("kubo unreachable: {e}"),
                    "hint": "check that the Kubo daemon is running and SUPABA_KUBO_API_URL is correct",
                })),
            ));
        }
    };

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        warn!(status, body = %body, "kubo /api/v0/add returned non-2xx");
        return Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": format!("kubo add failed (HTTP {status})"),
                "kuboBody": body,
            })),
        ));
    }

    // Kubo's /api/v0/add returns one JSON object per added file (we sent
    // one). When `progress=false` we still get a single `{Name,Hash,Size}`
    // line. Some Kubo versions still emit ND-JSON, so take the last
    // non-empty line.
    let body_text = resp
        .text()
        .await
        .map_err(|e| AppError(anyhow::anyhow!("reading kubo response: {e}")))?;
    let last_line = body_text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let added: KuboAddResponse = serde_json::from_str(last_line).map_err(|e| {
        AppError(anyhow::anyhow!(
            "parsing kubo response (line='{last_line}'): {e}"
        ))
    })?;

    let cid = added.hash;

    // Sidecar metadata so /ipfs/:cid can return the right Content-Type.
    let meta_dir = state.config.data_dir.join("ipfs-meta");
    tokio::fs::create_dir_all(&meta_dir).await?;
    let meta = serde_json::json!({
        "cid": &cid,
        "filename": &safe_filename,
        "contentType": req.content_type,
        "walletPubkey": req.wallet_pubkey,
        "size": size,
    });
    tokio::fs::write(
        meta_dir.join(format!("{cid}.json")),
        serde_json::to_string_pretty(&meta)?,
    )
    .await?;

    let gateway_url = format!(
        "http://{}:{}/ipfs/{}",
        state.config.hostname, state.config.api_port, cid
    );

    info!(
        cid = %cid,
        filename = %safe_filename,
        size,
        wallet = %req.wallet_pubkey,
        "content pinned via kubo"
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "cid": cid,
            "gatewayUrl": gateway_url,
            "publicGatewayUrl": format!("https://ipfs.io/ipfs/{cid}"),
            "size": size,
        })),
    ))
}

async fn build_and_pin_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: frontend_build::BuildAndPinRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F47: sigauth on build_and_pin. A forged build_and_pin lets a
    // compromised gateway pin ATTACKER's frontend to the victim's
    // instance — the resulting CID gets added to the redirect allow-list
    // (via the same path F38 protects) and victim's magic-link emails
    // redirect into attacker-controlled JS. Indirect credential theft +
    // arbitrary code execution in the victim's browser session.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/build-and-pin"),
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    // Wallet ownership check before doing any docker work — this is a paid
    // tool on the gateway, but the node still needs to refuse cross-wallet
    // calls. Mirrors deploy_function_handler / get_function_source_handler.
    let _instance = match state.manager.get_instance(&id, &req.wallet_pubkey)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "instance not found or not owned by this wallet",
                })),
            )
                .into_response());
        }
    };

    // Audit F66: cap concurrent builds at 1 per wallet AND 1 per
    // instance. The guard is moved into the spawned task below so it
    // lives for the full build duration, not just the HTTP response.
    let admit_guard = match job_admission::try_acquire(
        job_admission::JobKind::Build,
        &req.wallet_pubkey,
        &id,
    ) {
        Ok(g) => g,
        Err(e) => {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "build_already_in_progress",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };

    // Branch decision is part of validation — fail fast on bad target
    // before we hand off to a background task.
    let build_target = match frontend_build::BuildTarget::from_request(&req) {
        Ok(t) => t,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_target",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };
    let reported_target = match &build_target {
        frontend_build::BuildTarget::IpfsPin => "ipfs_pin",
        frontend_build::BuildTarget::NodeService { .. } => match req.target.as_deref() {
            Some("nextjs_service") => "nextjs_service",
            _ => "node_service",
        },
    };

    // Spawn the actual build into a tokio task and return immediately.
    // The previous flow blocked the response for 5+ minutes while docker
    // ran the build; anything between client and node (Cloudflare's 100s
    // response cap, a gateway restart, a flaky link) cut the response
    // mid-build and the client saw "stuck" while work continued on the
    // node. Now: validate → mint build_id → spawn → 202. Clients poll
    // GET /instances/:id/builds/:build_id for status + log_tail.
    let build_id = nanoid::nanoid!(16).to_lowercase();
    state
        .build_store
        .start(
            build_id.clone(),
            id.clone(),
            req.wallet_pubkey.clone(),
            Some(reported_target.to_string()),
        )
        .await;

    let task_state = state.clone();
    let task_id = id.clone();
    let task_build_id = build_id.clone();
    let task_target = reported_target.to_string();
    tokio::spawn(async move {
        // admit_guard drops when this task exits — that's the only place
        // the wallet/instance slot is released. Survives the original
        // HTTP connection being cut, so a CF-killed POST no longer leaks
        // an admission slot.
        let _admit = admit_guard;
        run_build_task(task_state, task_id, task_build_id, task_target, build_target, req).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "buildId": build_id,
            "status": "running",
            "target": reported_target,
        })),
    )
        .into_response())
}

/// GET /instances/:id/builds/:build_id — poll a previously-spawned
/// build. Returns the BuildStore row as JSON. 404 if the build_id
/// is unknown OR the row's stored wallet doesn't match the caller.
///
/// Auth: caller passes their wallet pubkey via the `wallet` query
/// parameter (same shape as get_function_source / deploy_function's
/// GET endpoints). We then verify ownership of the build by comparing
/// against the wallet stored in the BuildState — set when
/// build_and_pin_handler validated wallet ownership before spawning
/// the build. So any caller who passes a wallet that doesn't match
/// the build's owning wallet gets a 404 (not 403 — same response so
/// an attacker can't probe whether a build_id exists for another
/// wallet's instance).
async fn get_build_status_handler(
    State(state): State<Arc<AppState>>,
    Path((id, build_id)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let row = match state.build_store.get(&build_id).await {
        Some(r) => r,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "build_id_unknown" })),
            )
                .into_response());
        }
    };
    if row.instance_id != id {
        // Path id mismatch (typo or cross-instance probe). 404 to keep
        // the response shape indistinguishable from a real unknown id.
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "build_id_unknown" })),
        )
            .into_response());
    }
    let caller_wallet = q.get("wallet").map(|s| s.as_str()).unwrap_or("");
    if caller_wallet != row.wallet_pubkey {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "build_id_unknown" })),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "buildId": row.build_id,
            "instanceId": row.instance_id,
            "status": row.status.as_str(),
            "target": row.target,
            "startedAt": row.started_at.to_rfc3339(),
            "finishedAt": row.finished_at.map(|t| t.to_rfc3339()),
            "exitCode": row.exit_code,
            "logTail": row.log_tail,
            "durationMs": row.duration_ms,
            "cid": row.cid,
            "url": row.url,
            "sizeBytes": row.size_bytes,
            "fileCount": row.file_count,
            "hostPort": row.host_port,
            "containerId": row.container_id,
            "error": row.error,
        })),
    )
        .into_response())
}

/// Actual build work, run in a tokio task spawned by build_and_pin_handler.
/// Owns the AdmissionGuard for the build's lifetime; on return (success
/// or failure), the guard drops and the wallet/instance slot is freed.
/// Result fields are written into BuildStore; clients poll for them.
async fn run_build_task(
    state: Arc<AppState>,
    id: String,
    build_id: String,
    reported_target: String,
    build_target: frontend_build::BuildTarget,
    req: frontend_build::BuildAndPinRequest,
) {
    let docker = match bollard::Docker::connect_with_local_defaults() {
        Ok(d) => std::sync::Arc::new(d),
        Err(e) => {
            state
                .build_store
                .complete_failure(
                    &build_id,
                    format!("connect docker: {e}"),
                    String::new(),
                    None,
                )
                .await;
            return;
        }
    };
    // Build-store-backed log sink. Every container stdout/stderr chunk
    // is appended to BuildState.log_tail in real time so a polling
    // status fetch sees the same `npm install` / `next build` output
    // that the build container is producing live. Without this, the
    // status endpoint returns log_tail="" for the entire 5min build,
    // the orchestrator's build_log_delta emit gate never fires (its
    // `tail.length > lastLogLen` condition compares 0>0), and the
    // dashboard shows a static "running…" with no progress.
    let log_sink = frontend_build::LogSink::new(state.build_store.clone(), build_id.clone());
    match build_target {
        frontend_build::BuildTarget::IpfsPin => {
            match frontend_build::build_and_pin(
                docker,
                &state.config.kubo_api_url,
                &state.config.public_host,
                state.config.api_port,
                req,
                log_sink,
            )
            .await
            {
                Ok(r) => {
                    let exit_code = r.exit_code;
                    let log_tail = r.build_log.clone();
                    state
                        .build_store
                        .complete_success(&build_id, move |b| {
                            b.cid = Some(r.cid);
                            b.url = Some(r.url);
                            b.size_bytes = Some(r.size_bytes);
                            b.file_count = Some(r.file_count);
                            b.duration_ms = Some(r.duration_ms);
                            b.exit_code = Some(exit_code);
                            b.log_tail = log_tail;
                        })
                        .await;
                }
                Err(e) => {
                    state
                        .build_store
                        .complete_failure(&build_id, e.to_string(), String::new(), None)
                        .await;
                }
            }
        }
        frontend_build::BuildTarget::NodeService { entry } => {
            let wallet = req.wallet_pubkey.clone();
            let artifacts =
                match frontend_build::build_to_artifacts((*docker).clone().into(), &req, log_sink).await {
                    Ok(a) => a,
                    Err(e) => {
                        state
                            .build_store
                            .complete_failure(&build_id, e.to_string(), String::new(), None)
                            .await;
                        return;
                    }
                };
            let tarball = match frontend_build::tarball_from_dir(&artifacts.output_root) {
                Ok(b) => b,
                Err(e) => {
                    state
                        .build_store
                        .complete_failure(
                            &build_id,
                            format!("pack_failed: {e}"),
                            artifacts.build_log.clone(),
                            Some(artifacts.exit_code),
                        )
                        .await;
                    return;
                }
            };
            let svc = nextjs_service::NextjsService::new(
                (*docker).clone(),
                (*state.db).clone(),
                state.config.data_dir.clone(),
                state.config.public_host.clone(),
            );
            match svc.deploy(&id, &wallet, &tarball, entry).await {
                Ok(r) => {
                    let log_tail = artifacts.build_log.clone();
                    let exit_code = artifacts.exit_code;
                    let duration_ms = artifacts.duration_ms;
                    let size = tarball.len() as u64;
                    state
                        .build_store
                        .complete_success(&build_id, move |b| {
                            b.host_port = Some(r.host_port);
                            b.container_id = Some(r.container_id);
                            b.url = Some(r.url);
                            b.size_bytes = Some(size);
                            b.duration_ms = Some(duration_ms);
                            b.exit_code = Some(exit_code);
                            b.log_tail = log_tail;
                            b.target = Some(reported_target.clone());
                        })
                        .await;
                }
                Err(e) => {
                    state
                        .build_store
                        .complete_failure(
                            &build_id,
                            format!("node_service_deploy_failed: {e}"),
                            artifacts.build_log.clone(),
                            Some(artifacts.exit_code),
                        )
                        .await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Next.js sidecar service handler
// ---------------------------------------------------------------------------

/// Deploy or replace the Next.js sidecar service for an instance. Body is
/// the raw tar.gz of the standalone build output (not JSON) — keeps the
/// transfer small + avoids the base64 50% blow-up. Auth-shape mirrors
/// build_and_pin: sigauth over the path + body SHA256.
///
/// Query params:
///   wallet=<pubkey>   (required; wallet ownership check)
async fn deploy_nextjs_service_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<DeployServiceQuery>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Sigauth on the full body bytes so a hostile intermediary can't
    // replay a previous deploy bundle into a different instance.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/services/nextjs/deploy"),
        &body_bytes,
        &q.wallet,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }

    // Wallet ownership check.
    if state.manager.get_instance(&id, &q.wallet)?.is_none() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "instance not found or not owned by this wallet",
            })),
        )
            .into_response());
    }

    // Single deploy at a time per instance — the swap-rename path is
    // racy if two POSTs land at once.
    let _admit = match job_admission::try_acquire(
        job_admission::JobKind::Build,
        &q.wallet,
        &id,
    ) {
        Ok(g) => g,
        Err(e) => {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "nextjs_deploy_already_in_progress",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };

    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?;
    let svc = nextjs_service::NextjsService::new(
        docker,
        (*state.db).clone(),
        state.config.data_dir.clone(),
        state.config.public_host.clone(),
    );
    // Resolve entry argv. When the gateway uploads a generic Node
    // bundle (SvelteKit, Nuxt, Remix, custom Express server, etc.) it
    // sends entry as a URL-encoded JSON string array. Default to the
    // Next.js standalone convention when absent so existing callers
    // keep working unchanged.
    let entry: Vec<String> = match q.entry.as_deref() {
        Some(s) => match serde_json::from_str::<Vec<String>>(s) {
            Ok(v) if !v.is_empty() && v.iter().all(|x| !x.is_empty()) => v,
            _ => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "bad_entry",
                        "message":
                            "?entry must be URL-encoded JSON of a non-empty string array, e.g. [\"node\",\"build/index.js\"]",
                    })),
                )
                    .into_response());
            }
        },
        None => vec!["node".to_string(), "server.js".to_string()],
    };
    // Reject shell metas in argv — same defence the build-and-pin path
    // applies. Docker takes argv raw (no shell layer), so these
    // characters would land as literal filename chars and fail
    // confusingly; bailing early gives a clearer error.
    for a in &entry {
        if a.contains(';')
            || a.contains('|')
            || a.contains('&')
            || a.contains('`')
            || a.contains('\n')
        {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "bad_entry",
                    "message": format!(
                        "entry arg '{}' contains a shell metacharacter; argv is passed straight to docker (no shell).",
                        a
                    ),
                })),
            )
                .into_response());
        }
    }

    match svc.deploy(&id, &q.wallet, &body_bytes, entry).await {
        Ok(r) => Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({
                "instance_id": r.instance_id,
                "host_port": r.host_port,
                "container_id": r.container_id,
                "url": r.url,
            })),
        )
            .into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "node_service_deploy_failed",
                "message": e.to_string(),
            })),
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// Database migration handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MigrateProbeRequest {
    #[serde(rename = "walletPubkey")]
    wallet_pubkey: String,
    /// Either source_url OR source_url_env must be present, not both.
    /// source_url is the legacy plaintext form (URL with credentials).
    /// source_url_env names a key in the instance's encrypted env store
    /// (instance_env table) — the node resolves it locally so the URL
    /// never appears on the wire, in the agent chat history, or in the
    /// transcript.
    #[serde(default, rename = "sourceUrl")]
    source_url: Option<String>,
    #[serde(default, rename = "sourceUrlEnv")]
    source_url_env: Option<String>,
}

/// Resolve `(source_url, source_url_env)` to a plaintext URL. Exactly
/// one of the two must be set. When source_url_env is used, the value
/// comes from this instance's encrypted env store (instance_env table,
/// XChaCha20 under the per-instance DEK). That way the agent only ever
/// sees / passes the env-var NAME, not the URL — credentials don't
/// land in the chat transcript, the Anthropic message history, or the
/// SSE event stream.
fn resolve_source_url(
    db: &Database,
    instance_id: &str,
    source_url: Option<&str>,
    source_url_env: Option<&str>,
) -> Result<String, anyhow::Error> {
    match (source_url, source_url_env) {
        (Some(u), None) if !u.is_empty() => Ok(u.to_string()),
        (None, Some(name)) | (Some(""), Some(name)) if !name.is_empty() => {
            let entries = db.list_env(instance_id)?;
            entries
                .into_iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "sourceUrlEnv: env var '{}' not set on instance {}. \
                         Set it via kraph_set_env first.",
                        name,
                        instance_id
                    )
                })
        }
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "pass exactly ONE of sourceUrl or sourceUrlEnv, not both"
        )),
        _ => Err(anyhow::anyhow!(
            "must pass either sourceUrl (plaintext) or sourceUrlEnv (env var name on the instance)"
        )),
    }
}

/// Return the last N bytes of stdout+stderr from the per-instance Next.js
/// sidecar container. Read-only diagnostic — answers "why did my app
/// crash on boot?" Returns 404 with `error: "no_sidecar"` when the
/// instance has no sidecar container (instance is IPFS-pinned or was
/// never deployed as a node service).
///
/// Query params:
///   wallet=<pubkey>   (required; wallet ownership check)
///   tail=<int>        (optional; max bytes of log output, default 64K,
///                      hard cap 256K)
async fn get_nextjs_service_logs_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<NextjsLogsQuery>,
) -> Result<impl IntoResponse, AppError> {
    use bollard::container::LogsOptions;
    use bollard::container::LogOutput;
    use futures_util::StreamExt;

    // Wallet ownership — same gate as every other instance-scoped read.
    if state.manager.get_instance(&id, &q.wallet)?.is_none() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "instance not found or not owned by this wallet",
            })),
        )
            .into_response());
    }

    let cap_bytes = q
        .tail
        .map(|t| t.clamp(1024, 256 * 1024))
        .unwrap_or(64 * 1024) as usize;
    let container_name = nextjs_service::container_name_for(&id);

    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?;

    // Probe the container; absence is a clean 404, not a 5xx.
    let inspect = docker.inspect_container(&container_name, None).await;
    match inspect {
        Ok(_) => {}
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "no_sidecar",
                    "message": format!(
                        "No Next.js sidecar container for instance {id}. Either the instance was IPFS-pinned (kraph_pin_frontend / kraph_github_build_frontend target=ipfs_pin), or no deploy has run yet."
                    ),
                })),
            )
                .into_response());
        }
        Err(e) => return Err(AppError(anyhow::anyhow!("inspect failed: {e}"))),
    }

    let opts = LogsOptions::<String> {
        follow: false,
        stdout: true,
        stderr: true,
        // The tail option is a count, not bytes — we ask for "all" and
        // truncate by bytes ourselves below. That way we get the most
        // recent N bytes regardless of how chatty individual lines are.
        tail: "all".to_string(),
        timestamps: true,
        ..Default::default()
    };
    let mut stream = docker.logs(&container_name, Some(opts));
    let mut buf: Vec<u8> = Vec::with_capacity(cap_bytes);
    while let Some(item) = stream.next().await {
        match item {
            Ok(LogOutput::StdOut { message })
            | Ok(LogOutput::StdErr { message })
            | Ok(LogOutput::Console { message })
            | Ok(LogOutput::StdIn { message }) => {
                buf.extend_from_slice(&message);
                // Trim from the front when we exceed the cap so the tail
                // is always the most recent bytes.
                if buf.len() > cap_bytes {
                    let drop = buf.len() - cap_bytes;
                    buf.drain(0..drop);
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "instance_id": id,
            "container": container_name,
            "bytes": buf.len(),
            "logs": text,
        })),
    )
        .into_response())
}

async fn migrate_probe_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: MigrateProbeRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F46: sigauth on migrate_probe. Even though probe is
    // read-only, the source_url carries credentials and a forged probe
    // could be used to test which internal hosts are reachable from
    // the migration container (same SSRF probe concern as F5 — though
    // F5 closed that at the gateway, sigauth here defends the node-
    // side path too).
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/migrate/probe"),
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    if state.manager.get_instance(&id, &req.wallet_pubkey)?.is_none() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "instance not found or not owned by this wallet"
            })),
        )
            .into_response());
    }
    let docker = std::sync::Arc::new(
        bollard::Docker::connect_with_local_defaults()
            .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?,
    );
    let resolved_source_url = match resolve_source_url(
        &state.db,
        &id,
        req.source_url.as_deref(),
        req.source_url_env.as_deref(),
    ) {
        Ok(u) => u,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "source_url_unresolved",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };
    match db_migration::probe_source(docker, &resolved_source_url).await {
        Ok(probe) => Ok((StatusCode::OK, Json(serde_json::to_value(probe)?)).into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "source_probe_failed",
                "message": e.to_string(),
            })),
        )
            .into_response()),
    }
}

async fn migrate_start_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let mut req: db_migration::MigrationStartRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F46: sigauth on migrate_start. A migration container runs
    // pg_dump | pg_restore from an attacker-controlled source into the
    // victim's instance — that means a forged migrate_start could
    // OVERWRITE the victim's tables with arbitrary data sourced from
    // the attacker's chosen URL. Data-integrity attack via gateway
    // compromise. Verify the sig is from the instance owner's wallet
    // before doing any docker work.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/migrate"),
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let inst = match state.manager.get_instance(&id, &req.wallet_pubkey)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "instance not found or not owned by this wallet"
                })),
            )
                .into_response());
        }
    };
    // Audit F66: 1 active migration per instance, node-side enforced.
    // The gateway already debounces this on its own state but a forged
    // gateway call could fire concurrent pg_restores into the same
    // instance — partial-state recovery is a nightmare.
    let _admit = match job_admission::try_acquire(
        job_admission::JobKind::Migration,
        &req.wallet_pubkey,
        &id,
    ) {
        Ok(g) => g,
        Err(e) => {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "migration_already_in_progress",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };
    // Build the target URL server-side. External Postgres port is
    // postgres_port + 100 (matches render_env_file's pg_external offset).
    // We use host.docker.internal so the migration container reaches the
    // host-bound port.
    let pg_external_port = inst.postgres_port + 100;
    req.target_url = format!(
        "postgresql://postgres:{}@host.docker.internal:{}/postgres",
        urlencoding::encode(&inst.postgres_password),
        pg_external_port
    );
    // Resolve sourceUrlEnv → plaintext source_url server-side, so the
    // inner pipeline (which passes source_url into env KRAPH_SOURCE_URL
    // for the migration container) sees a real URL. The wire-side
    // caller / agent only sees the env var NAME — the credential never
    // touches the chat transcript, the SSE stream, or the Anthropic
    // message history.
    let source_url_for_log = if req.source_url_env.is_some() {
        format!("<env:{}>", req.source_url_env.as_deref().unwrap_or(""))
    } else {
        "<inline>".to_string()
    };
    let resolved_source_url = match resolve_source_url(
        &state.db,
        &id,
        if req.source_url.is_empty() {
            None
        } else {
            Some(req.source_url.as_str())
        },
        req.source_url_env.as_deref(),
    ) {
        Ok(u) => u,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "source_url_unresolved",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };
    req.source_url = resolved_source_url;
    tracing::info!(
        instance_id = %id,
        source = %source_url_for_log,
        "migrate_start: resolved source URL"
    );
    let docker = std::sync::Arc::new(
        bollard::Docker::connect_with_local_defaults()
            .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?,
    );
    let mode = req.mode.as_deref().unwrap_or("bulk").to_string();
    let container_name = format!("kraph-migrate-{}", nanoid::nanoid!(12).to_lowercase());
    let result = if mode == "live_sync" {
        // Pubsub name lives for the lifetime of the replication — cutover
        // tool needs the same name. Encode it into the container name so
        // the gateway can reconstruct it.
        let pubsub = format!(
            "kraph_{}",
            container_name.trim_start_matches("kraph-migrate-")
        );
        db_migration::run_live_sync_setup(docker, &container_name, &pubsub, &req).await
    } else {
        db_migration::run_bulk_migration(docker, &container_name, req).await
    };
    match result {
        Ok(r) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "container_name": container_name,
                "state": r.state,
                "duration_ms": r.duration_ms,
                "exit_code_dump": r.exit_code_dump,
                "exit_code_restore": r.exit_code_restore,
                "rows_migrated": r.rows_migrated,
                "tables_done": r.tables_done,
                "log_tail": r.log_tail,
                "error": r.error,
            })),
        )
            .into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "migration_failed",
                "message": e.to_string(),
                "container_name": container_name,
            })),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
struct MigrateCutoverRequest {
    #[serde(rename = "walletPubkey")]
    wallet_pubkey: String,
    #[serde(default, rename = "sourceUrl")]
    source_url: Option<String>,
    /// Name of an env var on this instance holding the source URL.
    /// See MigrateProbeRequest::source_url_env for the rationale.
    #[serde(default, rename = "sourceUrlEnv")]
    source_url_env: Option<String>,
    #[serde(default, rename = "maxWaitSecs")]
    max_wait_secs: Option<u64>,
}

async fn migrate_cutover_handler(
    State(state): State<Arc<AppState>>,
    Path((id, pubsub)): Path<(String, String)>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: MigrateCutoverRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F55: sigauth on cutover. Wallet ownership is also checked
    // below via get_instance, but a forged gateway request could still
    // race other operations. Cutover drops a PUBLICATION on the source
    // and SUBSCRIPTION on the target — partially-cut state is hard to
    // recover from; require the wallet sig.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/migrate/cutover/{pubsub}"),
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let inst = match state.manager.get_instance(&id, &req.wallet_pubkey)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "instance not found or not owned by this wallet"
                })),
            )
                .into_response());
        }
    };
    let target_url = format!(
        "postgresql://postgres:{}@host.docker.internal:{}/postgres",
        urlencoding::encode(&inst.postgres_password),
        inst.postgres_port + 100
    );
    let docker = std::sync::Arc::new(
        bollard::Docker::connect_with_local_defaults()
            .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?,
    );
    let cutover_container = format!("kraph-cutover-{}", nanoid::nanoid!(8).to_lowercase());
    let resolved_source_url = match resolve_source_url(
        &state.db,
        &id,
        req.source_url.as_deref(),
        req.source_url_env.as_deref(),
    ) {
        Ok(u) => u,
        Err(e) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "source_url_unresolved",
                    "message": e.to_string(),
                })),
            )
                .into_response());
        }
    };
    match db_migration::run_live_sync_cutover(
        docker,
        &cutover_container,
        &pubsub,
        &resolved_source_url,
        &target_url,
        req.max_wait_secs.unwrap_or(15 * 60),
    )
    .await
    {
        Ok(r) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "state": r.state,
                "duration_ms": r.duration_ms,
                "log_tail": r.log_tail,
                "error": r.error,
            })),
        )
            .into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "cutover_failed",
                "message": e.to_string(),
            })),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
struct MigrateCancelQuery {
    wallet: String,
}

async fn migrate_cancel_handler(
    State(state): State<Arc<AppState>>,
    Path((id, container)): Path<(String, String)>,
    Query(q): Query<MigrateCancelQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Audit F55: previously this handler had NO wallet check AND NO
    // restriction on `container` — the comment said "wallet-scoped at the
    // gateway layer" which is exactly the trust-the-gateway pattern the
    // F37+ sigauth rollout is designed to defeat. A compromised gateway
    // (or anyone reaching :3401 directly) could kill ANY docker container
    // on the node by passing its name through this route — including
    // victims' postgres/storage/auth containers ('supabase-db-<id>',
    // 'supabase-auth-<id>', etc.) → cross-instance DoS.
    //
    // Two guards now:
    //   1. The `container` path segment MUST start with `kraph-migrate-`.
    //      This is the format the migration engine generates; refusing
    //      anything else prevents the killer from being repurposed to
    //      stop unrelated containers.
    //   2. Verify ed25519 sigauth against the wallet that owns the
    //      instance at this URL's :id. The gateway looks up the
    //      migration's wallet before sending; we re-check here.
    if !container.starts_with("kraph-migrate-") {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "container_name_not_migration",
                "hint": "this endpoint only kills containers in the `kraph-migrate-*` namespace",
            })),
        )
            .into_response());
    }
    let inst = match state.db.get_instance_by_id(&id)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found on this node" })),
            )
                .into_response());
        }
    };
    // Also check wallet match — the query carries `wallet=<pubkey>` from
    // the gateway. Defense-in-depth alongside the sigauth verify below.
    if q.wallet != inst.wallet_pubkey {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "wallet does not own this instance" })),
        )
            .into_response());
    }
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "DELETE",
        &format!("/instances/{id}/migrate/{container}"),
        &[],
        &inst.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let docker = std::sync::Arc::new(
        bollard::Docker::connect_with_local_defaults()
            .map_err(|e| AppError(anyhow::anyhow!("connect docker: {e}")))?,
    );
    match db_migration::cancel_migration(docker, &container).await {
        Ok(()) => Ok((StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "migration_cancel_failed",
                "message": e.to_string(),
            })),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
struct AppendRedirectUrlsRequest {
    #[serde(rename = "walletPubkey")]
    wallet_pubkey: String,
    /// Extra URL patterns to allow in the GoTrue redirect allow-list.
    /// May include `**` glob wildcards (GoTrue supports them in path
    /// segments). Idempotent — duplicates with the existing list are
    /// dropped server-side.
    #[serde(default)]
    urls: Vec<String>,
    /// Optional: also update GOTRUE_SITE_URL / API_EXTERNAL_URL /
    /// SITE_URL / SUPABASE_PUBLIC_URL on the instance to this value.
    /// Use after pinning an SPA so magic-link clicks land on the
    /// SPA (which can read the access_token from the URL fragment)
    /// instead of the bare API root (which Kong has no route for
    /// and returns "no Route matched"). Must be http:// or https://.
    #[serde(default, rename = "siteUrl")]
    site_url: Option<String>,
}

async fn append_redirect_urls_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: AppendRedirectUrlsRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    // Audit F38: sigauth on redirect-urls append. A compromised gateway
    // could otherwise add `https://attacker.com/**` to a victim's
    // GOTRUE_URI_ALLOW_LIST, then trigger magic-link sends whose
    // emailRedirectTo points at attacker.com — capturing JWT tokens via
    // the OAuth-style fragment. Sigauth pins the request to the wallet.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/auth/redirect-urls"),
        &body_bytes,
        &req.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    match state
        .manager
        .append_redirect_urls(
            &id,
            &req.wallet_pubkey,
            &req.urls,
            req.site_url.as_deref(),
        )
        .await
    {
        Ok(allow_list) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "redirect_allow_list": allow_list,
            })),
        )
            .into_response()),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("not found") || msg.contains("not owned") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok((
                status,
                Json(serde_json::json!({
                    "error": "redirect_url_update_failed",
                    "message": msg,
                })),
            )
                .into_response())
        }
    }
}

async fn ipfs_get_handler(
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Sanitize CID. Real CIDs are alphanumeric (b58 / b32) — strip
    // anything else as a defence against path injection into the URL we
    // build for Kubo's gateway.
    let safe_cid: String = cid
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if safe_cid.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid CID" })),
        )
            .into_response());
    }

    // Look up sidecar metadata for content-type. If missing, we still
    // serve the content but fall back to octet-stream — Kubo's gateway
    // typically figures it out via UnixFS metadata, but this lets us
    // override and matches what the pin handler recorded.
    let meta_path = state
        .config
        .data_dir
        .join("ipfs-meta")
        .join(format!("{safe_cid}.json"));
    let content_type = if meta_path.exists() {
        let meta_bytes = tokio::fs::read(&meta_path).await.unwrap_or_default();
        serde_json::from_slice::<serde_json::Value>(&meta_bytes)
            .ok()
            .and_then(|v| v.get("contentType").and_then(|c| c.as_str()).map(String::from))
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    // Stream from the local Kubo gateway. We could 302 redirect to a
    // public gateway instead, but proxying keeps the URL stable for
    // agents and lets us inject the recorded Content-Type.
    let gateway = state.config.kubo_gateway_url.trim_end_matches('/');
    let upstream = format!("{gateway}/ipfs/{safe_cid}");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| AppError(anyhow::anyhow!("reqwest build: {e}")))?;

    let resp = match client.get(&upstream).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, upstream = %upstream, "kubo gateway unreachable");
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("kubo gateway unreachable: {e}"),
                    "publicGatewayUrl": format!("https://ipfs.io/ipfs/{safe_cid}"),
                })),
            )
                .into_response());
        }
    };

    let status = resp.status();
    let upstream_ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError(anyhow::anyhow!("kubo gateway body read: {e}")))?;

    if !status.is_success() {
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(serde_json::json!({
                "error": "content not available from local kubo",
                "publicGatewayUrl": format!("https://ipfs.io/ipfs/{safe_cid}"),
            })),
        )
            .into_response());
    }

    // Sidecar Content-Type wins; fall back to upstream's; finally octet.
    let final_ct = content_type
        .or(upstream_ct)
        .unwrap_or_else(|| "application/octet-stream".into());

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, final_ct)],
        bytes.to_vec(),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Integrity / Merkle root
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct IntegrityQuery {
    wallet: Option<String>,
}

async fn integrity_root_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(_q): Query<IntegrityQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Find the instance
    let instances = state.manager.list_all_instances()?;
    let instance = instances.into_iter().find(|i| i.id == id);
    let instance = match instance {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found" })),
            )
                .into_response());
        }
    };

    // Audit F52 fix: previously the query operated on `(SELECT 1 AS _) t`
    // — a literal one-row table — so the "Merkle root" was always the
    // same constant regardless of actual DB state. Agents got false
    // "verified: true" responses from kraph_verify_integrity.
    //
    // Now: walk every public-schema table, hash each row via md5, sort
    // and aggregate within a table, then aggregate across tables. The
    // %I format token is Postgres's identifier-safe quoting (handles
    // tables with reserved words / unusual names) — there is no SQL
    // injection surface even though tablename comes from pg_tables.
    //
    // The function-level SHA-256 hash of the aggregate gives us a
    // deterministic 32-byte root. Empty schema returns sha256("").
    //
    // Limitations of this still-simple digest:
    //   - It's a flat hash over sorted-row md5s, not a real Merkle tree
    //     (no inclusion proofs possible). Adding real Merkle proofs
    //     requires the dead IntegrityManager path to be revived
    //     (F51) with parameterised queries.
    //   - System-column ordering of `t.*::text` is stable within a
    //     postgres version but could shift across major upgrades. The
    //     hash will change after an upgrade even if logical state is
    //     unchanged. Acceptable for v1 attestation; document for v2.
    let container = format!("{}-db-1", instance.compose_project_name);
    let query = r#"
        DO $$
        DECLARE tbl RECORD;
        BEGIN
            CREATE TEMP TABLE IF NOT EXISTS _kraph_row_hashes (h TEXT) ON COMMIT DROP;
            FOR tbl IN
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
            LOOP
                EXECUTE format(
                    'INSERT INTO _kraph_row_hashes SELECT md5(t::text) FROM %I t',
                    tbl.tablename
                );
            END LOOP;
        END $$;
        SELECT coalesce(string_agg(h, '' ORDER BY h), '') FROM _kraph_row_hashes;
    "#;

    let out = tokio::process::Command::new("docker")
        .args(["exec", &container, "psql", "-U", "postgres", "-t", "-A", "-c", query])
        .output()
        .await;

    // Audit F71: previously docker/SQL failure returned sha256("")
    // — a real-looking 32-byte hash that callers could mistake for a
    // valid commitment to an empty schema. Now: failure surfaces as a
    // 502 with valid:false so verify_integrity callers can distinguish
    // "schema is empty" from "we have no idea what's in this DB."
    let (root, valid, error_msg) = match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let h = if s.is_empty() {
                hex::encode(sha2::Sha256::digest(b""))
            } else {
                hex::encode(sha2::Sha256::digest(s.as_bytes()))
            };
            (Some(h), true, None)
        }
        Ok(o) => {
            let stderr_tail = String::from_utf8_lossy(&o.stderr).to_string();
            tracing::error!(
                instance_id = %id,
                status = %o.status,
                stderr = %stderr_tail.chars().take(400).collect::<String>(),
                "merkle root query failed"
            );
            (
                None,
                false,
                Some(format!(
                    "psql exited {}: {}",
                    o.status,
                    stderr_tail.chars().take(200).collect::<String>()
                )),
            )
        }
        Err(e) => {
            tracing::error!(instance_id = %id, error = %e, "merkle root docker exec failed");
            (None, false, Some(format!("docker exec failed: {e}")))
        }
    };

    if !valid {
        return Ok((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "instance_id": id,
                "valid": false,
                "error": error_msg.unwrap_or_else(|| "unknown integrity failure".into()),
                "computed_at": chrono::Utc::now().to_rfc3339(),
            })),
        )
            .into_response());
    }

    Ok(Json(serde_json::json!({
        "instance_id": id,
        "valid": true,
        "merkle_root": root,
        "computed_at": chrono::Utc::now().to_rfc3339(),
    }))
        .into_response())
}

// ---------------------------------------------------------------------------
// TEE attestation
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct AttestRequest {
    nonce: String,
    #[serde(default)]
    report_data: Option<String>,
}

async fn attest_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AttestRequest>,
) -> Result<impl IntoResponse, AppError> {
    use crate::tee::{TeeManager, TeeBackend};

    let tee = TeeManager::new(&state.config);
    let report_data_str = req.report_data.as_deref().or(Some(id.as_str()));

    let report = match tee.generate_report(&req.nonce, report_data_str).await {
        Ok(r) => r,
        Err(e) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "valid": false,
                    "error": format!("attestation failed: {e}"),
                })),
            )
                .into_response());
        }
    };

    let verification = tee.verify_report(&report, &req.nonce).await;

    let platform_str = match report.platform {
        TeeBackend::SevSnp => "sev-snp",
        TeeBackend::Tdx => "tdx",
        TeeBackend::Mock => "mock",
        TeeBackend::None => "none",
    };

    Ok(Json(serde_json::json!({
        "valid": verification.valid,
        "platform": platform_str,
        "measurement": verification.measurement,
        "measurement_match": verification.measurement_match,
        "certificate_chain_valid": verification.certificate_chain_valid,
        "nonce_match": verification.nonce_match,
        "error": verification.error,
        "raw_report": base64_encode(&report.raw_report),
        "certificate_chain": report.certificate_chain,
    }))
        .into_response())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Edge Functions
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct DeployFunctionRequest {
    #[serde(alias = "walletPubkey")]
    wallet_pubkey: String,
    #[serde(alias = "functionName")]
    function_name: String,
    code: String,
    #[serde(default, alias = "codeHash")]
    code_hash: Option<String>,
}

async fn deploy_function_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Parse the body manually so we can also hand it to verify_request_sig.
    let req: DeployFunctionRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;

    let instance = match state.manager.get_instance(&id, &req.wallet_pubkey)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found" })),
            )
                .into_response());
        }
    };

    // Mitigation #1 (audit F37 — was F34 in dead code at api/mod.rs).
    // Verify per-call ed25519 signature from the instance owner's wallet
    // over the canonical request message. Rollout mode: missing sigauth
    // is accepted with a warning log; present-but-bad is rejected 401.
    // Nonce uniqueness (F34) closes the ±5-min replay window.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/functions/deploy"),
        &body_bytes,
        &instance.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }

    // Verify code hash
    use sha2::Digest;
    let computed_hash = hex::encode(sha2::Sha256::digest(req.code.as_bytes()));
    if let Some(expected) = &req.code_hash {
        if *expected != computed_hash {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "code hash mismatch" })),
            )
                .into_response());
        }
    }

    // Sanitize function name
    let fname: String = req
        .function_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if fname.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid function name" })),
        )
            .into_response());
    }

    // Write function code to the instance's functions volume
    let instance_dir = std::path::PathBuf::from(&instance.instance_dir);
    let func_dir = instance_dir.join("volumes").join("functions").join(&fname);
    tokio::fs::create_dir_all(&func_dir).await?;
    tokio::fs::write(func_dir.join("index.ts"), &req.code).await?;

    let invoke_url = format!("{}/functions/v1/{}", instance.url, fname);

    Ok(Json(serde_json::json!({
        "status": "deployed",
        "function_name": fname,
        "code_hash": computed_hash,
        "invoke_url": invoke_url,
    }))
        .into_response())
}

async fn list_functions_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<IntegrityQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Audit F61: empty wallet must NEVER bypass ownership on a public
    // route. `InstanceManager::get_instance(id, "")` skips ownership
    // (admin-style lookup intended for internal callers only), so reject
    // the query before it ever reaches that path.
    let wallet = match q.wallet.as_deref() {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "wallet query param required" })),
            )
                .into_response());
        }
    };
    // Audit F61: function inventory is sensitive; require sigauth so
    // X-Wallet-Pubkey cannot be spoofed when the node is reachable
    // directly.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "GET",
        &format!("/instances/{id}/functions"),
        &[],
        &wallet,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let instance = match state.manager.get_instance(&id, &wallet)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found" })),
            )
                .into_response());
        }
    };

    let instance_dir = std::path::PathBuf::from(&instance.instance_dir);
    let func_dir = instance_dir.join("volumes").join("functions");

    let mut functions = Vec::new();
    if func_dir.exists() {
        let mut entries = tokio::fs::read_dir(&func_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "main" || name.starts_with('.') {
                continue;
            }
            let code_path = func_dir.join(&name).join("index.ts");
            let code_hash = if code_path.exists() {
                let code = tokio::fs::read(&code_path).await.unwrap_or_default();
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(&code))
            } else {
                "unknown".to_string()
            };
            functions.push(serde_json::json!({
                "name": name,
                "code_hash": code_hash,
            }));
        }
    }

    Ok(Json(serde_json::json!({ "functions": functions })).into_response())
}

/// `GET /instances/:id/functions/:name/source` — return the deployed
/// function's source code verbatim.
///
/// Reads from `<instance_dir>/volumes/functions/<name>/index.{ts,js}` —
/// the same on-host path the deploy handler writes to. The file IS the
/// agent's source as-typed (Deno compiles TS→JS JIT at request time
/// inside the container; we don't run a build step).
async fn get_function_source_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((id, name)): Path<(String, String)>,
    Query(q): Query<IntegrityQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Audit F61: empty wallet must NEVER bypass ownership on a public
    // route. Refuse before reaching get_instance's admin path.
    let wallet = match q.wallet.as_deref() {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "wallet query param required" })),
            )
                .into_response());
        }
    };
    // Audit F61: function source is high-value (business logic, baked
    // tokens). Require sigauth so direct node access cannot exfiltrate
    // source by spoofing a wallet identity.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "GET",
        &format!("/instances/{id}/functions/{name}/source"),
        &[],
        &wallet,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let instance = match state.manager.get_instance(&id, &wallet)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found" })),
            )
                .into_response());
        }
    };

    // Sanitise name the same way deploy_function does — alphanumerics,
    // dash, underscore. Path traversal is impossible because we never
    // join arbitrary input into the path; the regex enforces it.
    let safe_name: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_name.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid function name" })),
        )
            .into_response());
    }

    let func_dir = std::path::PathBuf::from(&instance.instance_dir)
        .join("volumes")
        .join("functions")
        .join(&safe_name);
    if !func_dir.exists() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("function '{}' not found", safe_name),
            })),
        )
            .into_response());
    }

    // Probe .ts first then .js (deploy_function picks based on `language`).
    let ts_path = func_dir.join("index.ts");
    let js_path = func_dir.join("index.js");
    let (path, language) = if ts_path.exists() {
        (ts_path, "typescript")
    } else if js_path.exists() {
        (js_path, "javascript")
    } else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("function '{}' has no index.ts or index.js", safe_name),
            })),
        )
            .into_response());
    };

    let code = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(e) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("failed to read source: {e}"),
                })),
            )
                .into_response());
        }
    };

    use sha2::Digest;
    let code_hash = hex::encode(sha2::Sha256::digest(code.as_bytes()));
    let updated_at = match tokio::fs::metadata(&path).await {
        Ok(meta) => meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64),
        Err(_) => None,
    };

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "name": safe_name,
            "language": language,
            "code": code,
            "code_hash": code_hash,
            "size_bytes": code.len(),
            "updated_at_unix": updated_at,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Per-instance edge-function env vars
// ---------------------------------------------------------------------------
//
// Design notes (Path A from the env-vars spec): we persist `(instance_id,
// key, value)` tuples in SQLite, and on every mutation we rewrite
// `{instance_dir}/volumes/functions/.env` and force-recreate ONLY the
// functions container (`docker compose up -d --force-recreate --no-deps
// functions`). Postgres and the rest of the stack are untouched. The
// rewrite + recreate is fired off in a tokio task so the HTTP handler
// returns in <10ms; the agent can poll `GET /env` to confirm.

/// Extract the `X-Wallet-Pubkey` header or return a 401.
fn extract_wallet_header(
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get("X-Wallet-Pubkey")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "missing or invalid X-Wallet-Pubkey header"
                })),
            )
        })
}

/// Fetch the instance and verify the caller owns it. Returns the `Instance`
/// on success, or a ready-to-return HTTP error tuple on failure.
fn require_owned_instance(
    state: &AppState,
    id: &str,
    wallet: &str,
) -> Result<db::Instance, (StatusCode, Json<serde_json::Value>)> {
    let instance = match state.db.get_instance_by_id(id) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found" })),
            ));
        }
        Err(e) => {
            error!(error = %e, instance_id = %id, "db error looking up instance");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal error" })),
            ));
        }
    };

    if instance.wallet_pubkey != wallet {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "wallet does not own this instance"
            })),
        ));
    }
    Ok(instance)
}

/// Validate that the env-var key is a sane shell identifier. We're writing
/// it into a `.env` file that docker-compose parses, so keep the rules
/// narrow: `[A-Za-z_][A-Za-z0-9_]*`, 1..=128 chars.
fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key is empty".into());
    }
    if key.len() > 128 {
        return Err("key exceeds 128 chars".into());
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err("key must start with a letter or underscore".into());
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("key contains invalid character '{c}'"));
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct SetEnvRequest {
    key: String,
    value: String,
    /// When `true`, the value is hidden from `GET /env` responses (only
    /// keys + protected flag are returned). Used for user-paste-in
    /// secrets that the agent must not be able to read back. Defaults
    /// to `false` for backward compat with the agent-set path.
    #[serde(default)]
    protected: bool,
}

/// `POST /instances/:id/env` — upsert a single env var.
///
/// Body: `{ "key": "OPENAI_API_KEY", "value": "sk-..." }`.
/// Requires `X-Wallet-Pubkey` header; caller must own the instance.
/// Returns `200 {"ok": true, "key": "...", "applied": true}` and kicks off
/// an async functions-container recreate.
async fn set_env_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    body_bytes: axum::body::Bytes,
) -> impl IntoResponse {
    let wallet = match extract_wallet_header(&headers) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owned_instance(&state, &id, &wallet) {
        return e.into_response();
    }

    // Mitigation #1 (audit F37): verify per-call sigauth from the instance
    // owner's wallet. set_env writes potentially-sensitive values (API
    // keys etc.) to the functions container — sigauth ensures the request
    // really came from the wallet, not a forged gateway claim.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/env"),
        &body_bytes,
        &wallet,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let req: SetEnvRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid JSON body: {e}") })),
            )
                .into_response();
        }
    };

    if let Err(msg) = validate_env_key(&req.key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid key: {msg}") })),
        )
            .into_response();
    }
    // Reasonable upper bound so an agent cannot exhaust disk with a single
    // multi-MB value. 1 MiB is far above any sane API key / config blob.
    if req.value.len() > 1_048_576 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "value exceeds 1 MiB" })),
        )
            .into_response();
    }

    if let Err(e) = state
        .db
        .upsert_env_with_protection(&id, &req.key, &req.value, req.protected)
    {
        let msg = format!("{e}");
        // The "key reserved as user-set secret" guard is a precise 409
        // (conflict), not a 500 — the gateway maps this to a friendly
        // error the agent can act on by picking a different name.
        if msg.contains("reserved as a user-set secret") {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": msg,
                    "error_code": "key_reserved_protected",
                })),
            )
                .into_response();
        }
        error!(error = %e, instance_id = %id, "upsert_env failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to persist env var" })),
        )
            .into_response();
    }

    // Rewrite .env + recreate the functions container. apply_env_to_functions
    // spawns the docker work itself; the file rewrite is sync.
    //
    // Audit F70: ONE in-line retry before giving up so a transient
    // docker hiccup doesn't strand the caller with applied:false (and
    // the user staring at a UI saying "secret set" while functions
    // still run the old value). Two attempts max: ~3–5 s per recreate
    // plus a single 500 ms backoff ≈ 7 s worst case, comfortably under
    // the gateway-side 10 s timeout on /env. After both attempts:
    //   * Plain (agent-set) env: ok:true, applied:false, surface the
    //     warning prominently so the client knows to call /env/apply.
    //   * Protected (user-paste-in) env: FAIL CLOSED — return 503 with
    //     applied:false. Protected secrets are typically credentials
    //     the app needs RIGHT NOW; silently succeeding here lets
    //     downstream code run against the OLD secret and produces the
    //     intermittent failures the audit flagged.
    let mut apply_err: Option<String> = None;
    for attempt in 0..2 {
        match state.manager.apply_env_to_functions(&id).await {
            Ok(()) => {
                apply_err = None;
                break;
            }
            Err(e) => {
                let msg = format!("{e}");
                warn!(
                    error = %msg,
                    instance_id = %id,
                    attempt,
                    "apply_env_to_functions failed; will retry"
                );
                apply_err = Some(msg);
                // Only sleep if another attempt is coming. Single 500 ms
                // backoff between the two attempts.
                if attempt == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
    }
    if let Some(err) = apply_err {
        let status_code = if req.protected {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };
        error!(
            instance_id = %id,
            key = %req.key,
            protected = req.protected,
            error = %err,
            "apply_env_to_functions failed after 2 attempts"
        );
        return (
            status_code,
            Json(serde_json::json!({
                "ok": !req.protected,
                "key": req.key,
                "applied": false,
                "error": format!("functions container recreate failed after 2 attempts: {err}"),
                "hint": if req.protected {
                    "Protected secrets must reach the functions container before this call returns success. Retry kraph_set_env or call /env/apply once the node recovers."
                } else {
                    "DB row is updated but the functions container did NOT pick it up. Call /env/apply (or kraph_set_env again) once node load eases."
                },
            })),
        )
            .into_response();
    }

    info!(instance_id = %id, key = %req.key, "env var set");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "key": req.key,
            "applied": true,
        })),
    )
        .into_response()
}

/// `GET /instances/:id/env` — list env vars.
///
/// Authority: requires sigauth (audit F60). The X-Wallet-Pubkey header is
/// only an identity hint; the actual authority is the per-call ed25519
/// signature from that wallet. Without sigauth, anyone who can reach this
/// route directly could spoof X-Wallet-Pubkey and read another wallet's
/// env values.
///
/// Protected rows ALWAYS come back with `value=null` from this public
/// route. The `include_protected=true` plaintext path was removed (audit
/// F60). Operator/dashboard tooling that needs protected plaintext must
/// use a separate internal credential path, not this public route.
async fn list_env_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(_q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let wallet = match extract_wallet_header(&headers) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owned_instance(&state, &id, &wallet) {
        return e.into_response();
    }

    // Audit F60: require per-call signature on env reads. GET has no body
    // so sign against sha256("").
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "GET",
        &format!("/instances/{id}/env"),
        &[],
        &wallet,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    match state.db.list_env_full_with_protection(&id) {
        Ok(rows) => {
            let env: Vec<_> = rows
                .into_iter()
                .map(|(k, v, prot, ts)| {
                    if prot {
                        // Hide the value; surface that it exists and is
                        // protected so the agent can REFERENCE the key
                        // by name in code without ever seeing plaintext.
                        serde_json::json!({
                            "key": k,
                            "value": serde_json::Value::Null,
                            "protected": true,
                            "updated_at": ts,
                        })
                    } else {
                        serde_json::json!({
                            "key": k,
                            "value": v,
                            "protected": prot,
                            "updated_at": ts,
                        })
                    }
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({ "env": env }))).into_response()
        }
        Err(e) => {
            error!(error = %e, instance_id = %id, "list_env_full failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to list env" })),
            )
                .into_response()
        }
    }
}

/// `GET /instances/:id/env/keys` — list just the env-var keys.
///
/// Audit F60: requires sigauth. Key enumeration is sensitive (it exposes
/// which secrets exist) so the X-Wallet-Pubkey header alone is not enough
/// authority — the caller must produce a per-call signature.
async fn list_env_keys_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wallet = match extract_wallet_header(&headers) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owned_instance(&state, &id, &wallet) {
        return e.into_response();
    }

    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "GET",
        &format!("/instances/{id}/env/keys"),
        &[],
        &wallet,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    match state.db.get_env_keys(&id) {
        Ok(keys) => (
            StatusCode::OK,
            Json(serde_json::json!({ "keys": keys })),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, instance_id = %id, "get_env_keys failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to list env keys" })),
            )
                .into_response()
        }
    }
}

/// `DELETE /instances/:id/env/:key` — delete one env var.
async fn delete_env_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let wallet = match extract_wallet_header(&headers) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owned_instance(&state, &id, &wallet) {
        return e.into_response();
    }

    // Audit F39 (sigauth rollout continued): verify per-call signature
    // on env deletes too. DELETE has no body so we sign against
    // sha256("") = e3b0c4... Same permissive-rollout semantics.
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "DELETE",
        &format!("/instances/{id}/env/{key}"),
        &[],
        &wallet,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    if let Err(msg) = validate_env_key(&key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid key: {msg}") })),
        )
            .into_response();
    }

    let deleted = match state.db.delete_env(&id, &key) {
        Ok(d) => d,
        Err(e) => {
            error!(error = %e, instance_id = %id, %key, "delete_env failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to delete env var" })),
            )
                .into_response();
        }
    };

    if !deleted {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "key not found" })),
        )
            .into_response();
    }

    // Rewrite and recreate.
    if let Err(e) = state.manager.apply_env_to_functions(&id).await {
        warn!(
            error = %e,
            instance_id = %id,
            "apply_env_to_functions failed after delete; DB is authoritative"
        );
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "key": key,
                "applied": false,
                "warning": format!("deleted but apply failed: {e}"),
            })),
        )
            .into_response();
    }

    info!(instance_id = %id, %key, "env var deleted");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "key": key,
            "applied": true,
        })),
    )
        .into_response()
}

/// `POST /instances/:id/env/apply` — force a rewrite of the functions
/// `.env` file and recreate the functions container. Useful after an
/// out-of-band DB edit or to retry a failed apply.
///
/// Audit F60: requires sigauth — apply triggers a container recreate
/// (mild DoS surface) so X-Wallet-Pubkey header alone is not authority.
async fn apply_env_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wallet = match extract_wallet_header(&headers) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owned_instance(&state, &id, &wallet) {
        return e.into_response();
    }

    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{id}/env/apply"),
        &[],
        &wallet,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    match state.manager.apply_env_to_functions(&id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "applied": true,
            })),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, instance_id = %id, "apply_env_to_functions failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("apply failed: {e}"),
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Studio auth gate (Phase 3, subdomain mode)
// ---------------------------------------------------------------------------
//
// Two HTTP routes, both mounted on the wildcard subdomain `*.studio.<apex>`
// behind Caddy:
//
//   GET /__kraph/studio/exchange?token=<minted-by-gateway>
//     - Verifies the gateway-minted HMAC token.
//     - Sets a Domain=.studio.<apex> cookie (HttpOnly, Secure, SameSite=Lax).
//     - 302s the browser to `/` of the same subdomain (Studio's home).
//
//   GET /__kraph/studio/forward-auth   (called by Caddy's `forward_auth`)
//     - Reads the cookie, verifies HMAC, checks claims.i == <id> from Host.
//     - On success: 200 + X-Kraph-Studio-Port: <port>  (Caddy proxies there).
//     - On the *exchange URL itself* (which carries a fresh `token` query
//       param but no cookie yet): also 200, so Caddy hands the request to
//       the exchange handler which sets the cookie.

#[derive(serde::Deserialize)]
struct StudioExchangeQuery {
    token: String,
}

async fn studio_exchange_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StudioExchangeQuery>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let secret = &state.config.studio_proxy_secret;
    if secret.is_empty() {
        warn!("/__kraph/studio/exchange called but SUPABA_STUDIO_PROXY_SECRET is unset");
        return (
            StatusCode::FORBIDDEN,
            "studio proxy not configured on this node",
        )
            .into_response();
    }
    let apex = state.config.studio_apex.trim_start_matches('.');
    if apex.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            "studio proxy apex not configured (SUPABA_STUDIO_APEX)",
        )
            .into_response();
    }

    let claims = match studio_proxy::verify_token(secret, &q.token) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "studio token rejected at exchange");
            return (
                StatusCode::FORBIDDEN,
                format!("invalid studio token: {e}"),
            )
                .into_response();
        }
    };

    // Confirm the instance still exists on this node before handing out a
    // cookie. Avoids minting a session that 404s on the very next click.
    match state.db.get_instance_by_id(&claims.i) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, "instance not found on this node")
                .into_response();
        }
        Err(e) => {
            error!(error = %e, "db lookup failed during studio exchange");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    // The Host the browser used (Caddy passes it through). We need it to
    // confirm the URL the user actually loaded matches the token's instance
    // — otherwise a wallet that owns instance A could craft a link that
    // sets the cookie on subdomain B. Defence-in-depth: claims.i is also
    // the basis for the forward-auth host check below.
    //
    // Audit F49: previously this check was nested `if let Some(...)` which
    // fell through (no error) when the Host header was missing or had no
    // dot. Cookie would still get set in that case. Fail-CLOSED instead:
    // a missing/malformed host on the exchange path is itself a 403.
    // forward_auth_handler already fails closed (cookie won't validate on
    // any later request), so this is mostly defence in depth + clearer
    // user-visible error rather than confusing silent cookie-set.
    let host = match headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => {
            return (StatusCode::FORBIDDEN, "Host header required").into_response();
        }
    };
    let host_id = match studio_proxy::instance_id_from_host(host) {
        Some(id) => id,
        None => {
            return (StatusCode::FORBIDDEN, "malformed Host header").into_response();
        }
    };
    if host_id != claims.i {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "exchange URL host ({host}) does not match token instance ({})",
                claims.i
            ),
        )
            .into_response();
    }

    let cookie = studio_proxy::build_cookie(&q.token, apex, studio_proxy::DEFAULT_TTL_SECS);

    info!(
        instance_id = %claims.i,
        wallet = %claims.w,
        "studio exchange ok — minting cookie",
    );

    axum::response::Response::builder()
        .status(StatusCode::FOUND)
        .header(axum::http::header::LOCATION, "/")
        .header(axum::http::header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .expect("static response builds")
}

/// `GET /__kraph/studio/forward-auth` — invoked by Caddy on every Studio
/// request before forwarding upstream. Returns:
///   - 200 + X-Kraph-Studio-Port: <port>   when cookie is valid for this host
///   - 200 (unauthenticated, but allowed)  when the request is to the
///     `/__kraph/studio/exchange` URL itself (carries a token query string;
///     the exchange handler will validate the token and set the cookie)
///   - 401                                 otherwise
async fn studio_forward_auth_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Caddy passes the original request URI in X-Forwarded-Uri so we can
    // detect the "user is mid-exchange, no cookie yet" case.
    let forwarded_uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if forwarded_uri.starts_with("/__kraph/studio/exchange") {
        // Let the request through; the exchange handler authenticates via
        // the token query string.
        return (StatusCode::OK, "").into_response();
    }

    let secret = &state.config.studio_proxy_secret;
    if secret.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "studio proxy not configured")
            .into_response();
    }

    let cookie = match studio_proxy::read_studio_cookie(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "missing cookie").into_response(),
    };
    let claims = match studio_proxy::verify_token(secret, &cookie) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, format!("invalid cookie: {e}"))
                .into_response();
        }
    };

    // Bind the cookie to the host the browser used. Without this, a cookie
    // for instance A is good for instance B's subdomain too (since Domain
    // is wildcard).
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let host_id = studio_proxy::instance_id_from_host(host).unwrap_or("");
    if host_id != claims.i {
        return (
            StatusCode::UNAUTHORIZED,
            format!("cookie issued for {}, host says {host_id}", claims.i),
        )
            .into_response();
    }

    let instance = match state.db.get_instance_by_id(&claims.i) {
        Ok(Some(i)) => i,
        Ok(None) => return (StatusCode::NOT_FOUND, "instance not found").into_response(),
        Err(e) => {
            error!(error = %e, "db lookup failed in forward-auth");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    // Tell Caddy where to proxy. It picks this up via `copy_headers` in
    // the forward_auth block, then plugs it into reverse_proxy.
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("X-Kraph-Studio-Port", instance.studio_port.to_string())
        .body(axum::body::Body::empty())
        .expect("static response builds")
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!(error = %self.0, "request error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// ---------------------------------------------------------------------------
// Replication handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddReplicaRequest {
    /// Full URL of the replica node, e.g. "http://10.0.0.5:3401".
    /// Trailing slash is tolerated.
    endpoint: String,
}

async fn add_replica_handler(
    State(state): State<Arc<AppState>>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let req: AddReplicaRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError(anyhow::anyhow!("invalid JSON body: {e}")))?;
    let endpoint = req.endpoint.trim().trim_end_matches('/').to_string();
    if endpoint.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "endpoint is required" })),
        )
            .into_response());
    }
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "endpoint must start with http(s)://" })),
        )
            .into_response());
    }

    // Audit F47: previously this endpoint accepted ANY caller with no
    // wallet or signature check at all — the node would happily add a
    // replica to any existing instance for anyone who could reach
    // :3401/instances/:id/replicas. A network attacker could add
    // arbitrary replica endpoints (the primary ships encrypted WAL to
    // each — opaque ciphertext, but a DoS via bandwidth AND a future
    // exfil path if the DEK envelope is ever weakened). Now: look up
    // the instance's bound wallet and require a sig from that wallet.
    let inst = match state.db.get_instance_by_id(&instance_id)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found on this node" })),
            )
                .into_response());
        }
    };
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{instance_id}/replicas"),
        &body_bytes,
        &inst.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }

    let added = state.db.add_instance_replica(&instance_id, &endpoint)?;
    info!(instance_id = %instance_id, endpoint = %endpoint, added, "replica registered");

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "instance_id": instance_id,
            "endpoint": endpoint,
            "added": added,
        })),
    )
        .into_response())
}

async fn list_replicas_handler(
    State(state): State<Arc<AppState>>,
    Path(instance_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let replicas = state.db.list_instance_replicas(&instance_id)?;
    Ok(Json(serde_json::json!({
        "instance_id": instance_id,
        "replicas": replicas,
    })))
}

async fn force_switch_wal_handler(
    State(state): State<Arc<AppState>>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Audit F48: prior version had NO wallet check at all — anyone reaching
    // :3401/instances/:id/replicas/force-switch-wal could repeatedly
    // trigger pg_switch_wal() and spawn fresh WAL segments. Each new
    // segment ships to all replicas (bandwidth + disk DoS).
    //
    // Look up the instance's bound wallet, then verify the signature is
    // from that wallet. Same pattern as add_replica_handler.
    let inst = match state.db.get_instance_by_id(&instance_id)? {
        Some(i) => i,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "instance not found on this node" })),
            )
                .into_response());
        }
    };
    if let Err(e) = sigauth::verify_request_sig(
        &headers,
        "POST",
        &format!("/instances/{instance_id}/replicas/force-switch-wal"),
        &body_bytes,
        &inst.wallet_pubkey,
    ) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response());
    }
    let segment = state.replication.switch_wal(&instance_id).await?;
    Ok(Json(serde_json::json!({
        "instance_id": instance_id,
        "rotated_segment": segment,
    }))
    .into_response())
}

/// `POST /replication/receive` — replica-side ingest endpoint.
///
/// Body: raw bytes of the encrypted segment (nonce || ciphertext || tag).
/// Headers:
///   - X-Instance-Id
///   - X-Segment-Name
///   - X-Segment-Hash       (sha256(prev_hash || body), hex)
///   - X-Previous-Hash      (hex, may be empty for the first segment)
///   - X-Chain-Index        (decimal i64)
async fn receive_replication_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    fn h<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Result<&'a str, AppError> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError(anyhow::anyhow!("missing or invalid header {name}"))
            })
    }

    let instance_id = h(&headers, "X-Instance-Id")?.to_string();
    let segment_name = h(&headers, "X-Segment-Name")?.to_string();
    let segment_hash = h(&headers, "X-Segment-Hash")?.to_string();
    let previous_hash = headers
        .get("X-Previous-Hash")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let chain_index: i64 = h(&headers, "X-Chain-Index")?
        .parse()
        .map_err(|e| AppError(anyhow::anyhow!("invalid X-Chain-Index: {e}")))?;
    let replication_sig = headers
        .get("X-Replication-Sig")
        .and_then(|v| v.to_str().ok());

    let row = state
        .replication
        .receive_segment(
            &instance_id,
            &segment_name,
            &segment_hash,
            &previous_hash,
            chain_index,
            replication_sig,
            &body,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "received",
            "instance_id": row.instance_id,
            "segment_name": row.segment_name,
            "chain_index": row.chain_index,
            "size": row.size,
            "stored_path": row.stored_path,
        })),
    ))
}

async fn list_replica_segments_handler(
    State(state): State<Arc<AppState>>,
    Path(instance_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let segments = state.replication.list_replica_segments(&instance_id).await?;
    Ok(Json(serde_json::json!({
        "instance_id": instance_id,
        "segment_count": segments.len(),
        "segments": segments,
    })))
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

fn spawn_background_tasks(state: Arc<AppState>, config: &Config) {
    let cleanup_interval = Duration::from_secs(config.cleanup_interval_secs);
    let heartbeat_interval = Duration::from_secs(config.heartbeat_interval_secs);
    let wal_replication_interval =
        Duration::from_secs(config.wal_replication_interval_secs.max(1));

    // WAL processing + replica shipping. Runs both phases in sequence so a
    // segment encrypted on this tick can be shipped on the same tick.
    let wal_state = state.clone();
    tokio::spawn(async move {
        // Brief startup delay so the first call doesn't race with router
        // bind / database open.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut interval = tokio::time::interval(wal_replication_interval);
        // The first tick fires immediately, then on each interval.
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = wal_state.replication.process_new_segments().await {
                warn!(error = %e, "WAL processing pass failed");
            }
            if let Err(e) = wal_state.replication.ship_pending_segments().await {
                warn!(error = %e, "WAL shipment pass failed");
            }
        }
    });

    // Cleanup expired instances.
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            match cleanup_state.manager.cleanup_expired().await {
                Ok(ids) if !ids.is_empty() => {
                    info!(count = ids.len(), "cleaned up expired instances");
                }
                Err(e) => {
                    warn!(error = %e, "cleanup sweep failed");
                }
                _ => {}
            }
        }
    });

    // Idle-suspend sweeper. Off by default (SUPABA_IDLE_SUSPEND_SECS=0
    // skips the sweep entirely) so deploying a new node-rs binary
    // before the gateway resume-on-demand path is wired doesn't strand
    // suspended instances behind a gateway that doesn't know how to wake
    // them. When the gateway has both /resume + the proxy detection,
    // bump SUPABA_IDLE_SUSPEND_SECS to a positive value (e.g. 900).
    if config.idle_suspend_secs > 0 {
        let idle_state = state.clone();
        let idle_secs = config.idle_suspend_secs;
        let sweep_interval = Duration::from_secs(config.idle_sweep_interval_secs.max(10));
        tokio::spawn(async move {
            // Stagger startup so we don't race provision + suspend on cold start.
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(sweep_interval);
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let candidates = match idle_state.db.list_idle_running_instances(idle_secs as i64) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "idle-sweep: list query failed");
                        continue;
                    }
                };
                for instance in candidates {
                    // Skip if a concurrent resume is in flight (we'd race
                    // the docker socket and end up with a half-started
                    // stack). The resume_locks map in AppState serializes
                    // resume on the HTTP side; we mirror that here.
                    let lock = {
                        let mut map = idle_state.resume_locks.lock().await;
                        map.entry(instance.id.clone())
                            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                            .clone()
                    };
                    let _guard = match lock.try_lock() {
                        Ok(g) => g,
                        Err(_) => {
                            // Resume in progress for this id — skip this tick.
                            continue;
                        }
                    };
                    if let Err(e) = idle_state.manager.suspend(&instance.id).await {
                        warn!(id = %instance.id, error = %e, "idle-sweep: suspend failed");
                    } else {
                        info!(
                            id = %instance.id,
                            idle_secs,
                            "idle-sweep: instance suspended"
                        );
                    }
                }
            }
        });
    } else {
        info!("idle-suspend is DISABLED (SUPABA_IDLE_SUSPEND_SECS=0)");
    }

    // Warm pool maintenance.
    let warm_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = warm_state.warm_pool.maintain().await {
                warn!(error = %e, "warm pool maintenance failed");
            }
        }
    });

    // Heartbeat (placeholder — logs for now).
    let region = config.region.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        loop {
            interval.tick().await;
            match state.manager.get_stats() {
                Ok(stats) => {
                    info!(
                        region = %region,
                        running = stats.running_instances,
                        capacity = stats.available_capacity,
                        "heartbeat"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "heartbeat stats failed");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

fn print_banner(config: &Config) {
    let tee_status = match config.tee_backend.as_str() {
        "sev-snp" => "AMD SEV-SNP (active)",
        "tdx" => "Intel TDX (active)",
        _ => "none (WARNING: not running in a TEE)",
    };

    info!("==========================================================");
    info!("  Supaba Node v{}", env!("CARGO_PKG_VERSION"));
    info!("==========================================================");
    info!("  TEE backend   : {}", tee_status);
    info!("  Region         : {}", config.region);
    info!("  Max instances  : {}", config.max_instances);
    info!("  Port range     : {}-{}", config.port_range_start, config.port_range_end);
    info!("  CPU cores      : {}", config.available_cpu_cores);
    info!("  Data dir       : {:?}", config.data_dir);
    info!("  Attestation    : {}", if config.require_attestation { "required" } else { "disabled" });
    info!("==========================================================");
}
