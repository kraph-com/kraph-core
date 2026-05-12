/// Per-call ed25519 signature verification (mitigation #1).
///
/// State-changing endpoints used to trust the X-Wallet-Pubkey header
/// verbatim, which means a compromised gateway could deploy hostile code
/// to any instance by claiming any wallet pubkey. With this helper we
/// verify an ed25519 signature from the instance owner's Solana key on
/// each such request.
///
/// Wire format (gateway sets these headers when the agent provided sigauth):
///   X-Kraph-Auth-Sig    : base58(ed25519 signature)
///   X-Kraph-Auth-Nonce  : random nonce (32 chars or so)
///   X-Kraph-Auth-Ts     : unix seconds at signing time
///   X-Kraph-Auth-Hash   : sha256 hex of the request body (so the body can't
///                         be tampered with after signing)
///
/// Canonical message signed:
///   "kraph-auth:v1:<METHOD>:<PATH>:<BODY_SHA256>:<NONCE>:<TS>"
///
/// Replay protection: two layers.
///   1. Timestamp window — Ts must be within ±5 minutes (SIG_TIMESTAMP_SKEW_SECS).
///   2. Nonce uniqueness (audit F34) — in-memory seen-set rejects any
///      nonce the node has already observed within NONCE_RETENTION.
///
/// Behaviour:
///   - if no signature headers present:    log warning, allow (rollout phase)
///   - if signature headers present + ok:  log success, record nonce, allow
///   - if signature headers present + bad: REJECT 401
///   - if nonce already seen within window: REJECT 401 (replay)
///
/// Audit F37: this module replaces the orphaned `api/mod.rs::verify_request_sig`
/// — that file was never declared as a module by `main.rs`, so its sigauth
/// path (and F34's nonce store) was not compiled into the live binary.
/// Live deploy_function_handler in main.rs now calls into this module.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::http::HeaderMap;
use sha2::Digest as _;

pub const SIG_TIMESTAMP_SKEW_SECS: i64 = 5 * 60;

/// Retention window for the seen-nonce set. Slightly longer than
/// SIG_TIMESTAMP_SKEW_SECS (5 min) so a nonce that's about to fall out of
/// the timestamp window is still caught at the boundary.
const NONCE_RETENTION: Duration = Duration::from_secs(10 * 60);

/// Soft cap on the seen-nonce map size. Amortised cleanup at this threshold.
/// At ~100 bytes per entry, 100k entries ≈ 10 MB max footprint.
const NONCE_CLEANUP_THRESHOLD: usize = 100_000;

/// Max length of a nonce we'll record. Real nonces are ≤64 chars; this
/// bound keeps pathological-spam memory at ~12.8 MB worst case.
const MAX_NONCE_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVerifyOutcome {
    /// No signature headers at all — backwards-compat allow path.
    Missing,
    /// Signature present and valid.
    Verified,
}

#[derive(Debug, thiserror::Error)]
pub enum SigVerifyError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

fn seen_nonces() -> &'static Mutex<HashMap<String, Instant>> {
    static SEEN_NONCES: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    SEEN_NONCES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Atomically check-and-record a nonce. Returns true if fresh, false if
/// already seen within `NONCE_RETENTION`.
fn check_and_record_nonce(nonce: &str) -> bool {
    let mut map = seen_nonces().lock().expect("seen_nonces mutex poisoned");
    let now = Instant::now();
    if map.len() > NONCE_CLEANUP_THRESHOLD {
        map.retain(|_, expires| *expires > now);
    }
    let expires = now + NONCE_RETENTION;
    use std::collections::hash_map::Entry;
    match map.entry(nonce.to_string()) {
        Entry::Occupied(mut e) => {
            if *e.get() > now {
                false
            } else {
                e.insert(expires);
                true
            }
        }
        Entry::Vacant(e) => {
            e.insert(expires);
            true
        }
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Verify the per-call request signature. Body bytes are SHA-256'd here so
/// the caller can't tamper with the body after signing.
pub fn verify_request_sig(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body_bytes: &[u8],
    expected_signer_pubkey: &str,
) -> Result<SigVerifyOutcome, SigVerifyError> {
    let sig_b58 = header_str(headers, "X-Kraph-Auth-Sig");
    let nonce = header_str(headers, "X-Kraph-Auth-Nonce");
    let ts_str = header_str(headers, "X-Kraph-Auth-Ts");

    if sig_b58.is_none() && nonce.is_none() && ts_str.is_none() {
        tracing::warn!(
            target: "supaba_node::sigauth",
            wallet = %expected_signer_pubkey,
            path = %path,
            "request without per-call signature — accepted during rollout. Once all clients sign, this will become a 401."
        );
        return Ok(SigVerifyOutcome::Missing);
    }

    let (sig_b58, nonce, ts_str) = match (sig_b58, nonce, ts_str) {
        (Some(s), Some(n), Some(t)) => (s, n, t),
        _ => {
            return Err(SigVerifyError::Unauthorized(
                "X-Kraph-Auth-Sig, X-Kraph-Auth-Nonce, and X-Kraph-Auth-Ts must all be present together".into(),
            ));
        }
    };

    let ts: i64 = ts_str.parse().map_err(|_| {
        SigVerifyError::Unauthorized("X-Kraph-Auth-Ts not an integer".into())
    })?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > SIG_TIMESTAMP_SKEW_SECS {
        return Err(SigVerifyError::Unauthorized(format!(
            "X-Kraph-Auth-Ts skew too large ({}s); expected within ±{}s of server time",
            (now - ts).abs(),
            SIG_TIMESTAMP_SKEW_SECS
        )));
    }

    if nonce.len() > MAX_NONCE_LEN {
        return Err(SigVerifyError::Unauthorized(
            "X-Kraph-Auth-Nonce too long (max 128 chars)".into(),
        ));
    }

    // Nonce-uniqueness check (audit F34) BEFORE ed25519 verify so replays
    // bail without burning ~30µs of crypto per call.
    if !check_and_record_nonce(nonce) {
        return Err(SigVerifyError::Unauthorized(
            "X-Kraph-Auth-Nonce already used (replay)".into(),
        ));
    }

    let body_hash_hex = hex::encode(sha2::Sha256::digest(body_bytes));
    if let Some(claimed) = header_str(headers, "X-Kraph-Auth-Hash") {
        if claimed != body_hash_hex {
            return Err(SigVerifyError::Unauthorized(
                "X-Kraph-Auth-Hash does not match SHA-256 of body".into(),
            ));
        }
    }

    let canonical = format!(
        "kraph-auth:v1:{method}:{path}:{body_hash_hex}:{nonce}:{ts}",
        method = method,
        path = path,
        body_hash_hex = body_hash_hex,
        nonce = nonce,
        ts = ts,
    );

    let sig_bytes = bs58::decode(sig_b58).into_vec().map_err(|_| {
        SigVerifyError::Unauthorized("X-Kraph-Auth-Sig not valid base58".into())
    })?;
    if sig_bytes.len() != 64 {
        return Err(SigVerifyError::Unauthorized(
            "X-Kraph-Auth-Sig must be 64 bytes after base58 decode".into(),
        ));
    }
    let pubkey_bytes = bs58::decode(expected_signer_pubkey).into_vec().map_err(|_| {
        SigVerifyError::Unauthorized("expected signer pubkey not base58".into())
    })?;
    if pubkey_bytes.len() != 32 {
        return Err(SigVerifyError::Unauthorized(
            "expected signer pubkey not 32 bytes after base58 decode".into(),
        ));
    }

    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .expect("checked length above");
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .expect("checked length above");

    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| {
        SigVerifyError::Unauthorized(format!("invalid ed25519 pubkey: {e}"))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    pubkey.verify(canonical.as_bytes(), &signature).map_err(|_| {
        SigVerifyError::Unauthorized(
            "signature does not verify against canonical request message".into(),
        )
    })?;

    tracing::info!(
        target: "supaba_node::sigauth",
        wallet = %expected_signer_pubkey,
        path = %path,
        ts = ts,
        "request signature verified"
    );
    Ok(SigVerifyOutcome::Verified)
}
