//! Auth gate for the per-instance Supabase Studio dashboard.
//!
//! Phase 3 of the security model. Each provisioned Supabase stack ships with
//! Studio, which has **zero built-in auth** and bakes the `SERVICE_ROLE_KEY`
//! into the rendered HTML. Studio is bound to `127.0.0.1` on the node; the
//! only path in is the wildcard subdomain:
//!
//! ```text
//!   gateway (kraph_studio_url) ──HMAC──> https://<id>.studio.<apex>/__kraph/studio/exchange?token=…
//!                                            │
//!                                            ├─ Caddy: forward_auth → /__kraph/studio/forward-auth
//!                                            │     (which 200s on first hit because the URL itself
//!                                            │      carries the token; we set the cookie below)
//!                                            ├─ exchange handler verifies HMAC + ttl
//!                                            ├─ Set-Cookie: kraph_studio=…  (Domain=.studio.<apex>)
//!                                            └─ 302 → /
//!
//!   browser ──cookie──> https://<id>.studio.<apex>/<any_studio_path>
//!                                            │
//!                                            ├─ Caddy: forward_auth → /__kraph/studio/forward-auth
//!                                            │     (validates cookie, returns 200 + X-Kraph-Studio-Port)
//!                                            └─ Caddy: reverse_proxy 127.0.0.1:{X-Kraph-Studio-Port}
//! ```
//!
//! Why subdomain instead of path-prefix: Supabase Studio is a Next.js app
//! whose `basePath` is set at *build time*, not runtime. Path-prefix proxying
//! breaks every absolute `/_next/...` asset URL. Subdomain proxying needs no
//! Studio change.
//!
//! Token format (compact, URL-safe — same shape gateway and node both encode):
//!
//! ```text
//!   <base64url(payload_json)>.<base64url(hmac_sha256(payload_b64, secret))>
//! ```
//!
//! Payload is `{w: wallet, i: instance_id, e: expiry_unix_seconds}`. The
//! field names are short because every byte ends up in the URL. We
//! intentionally avoid the JWT header dance — exactly one algorithm and one
//! secret on each side, the extra ceremony buys us nothing.
//!
//! The axum handlers themselves live in `main.rs` so they can see `AppState`;
//! this module exports the building blocks they assemble.

use axum::http::{header, HeaderMap};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Cookie name set by the exchange handler and read on every proxied
/// request. The cookie's Domain attribute is the wildcard apex
/// (`.studio.<apex>`), so the same cookie covers every `<id>.studio.<apex>`
/// — Caddy's forward_auth on the wildcard host needs only one validation
/// path. Per-instance ownership is checked inside the cookie itself
/// (`claims.i` must match the request's host's `<id>` segment).
pub const COOKIE_NAME: &str = "kraph_studio";

/// Default token / cookie lifetime. 15 minutes is enough for the gateway
/// hand-off and a typical Studio click-through; a returning user can mint
/// a fresh URL via `kraph_studio_url`.
pub const DEFAULT_TTL_SECS: i64 = 15 * 60;

/// Serialized form is whatever `mint_token` produces. Field names are
/// short because every byte ends up in the URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudioClaims {
    /// Wallet pubkey (base58) — the agent the gateway authenticated.
    pub w: String,
    /// Instance id this token grants access to. Must match the
    /// `<id>` segment of the request host on every subsequent request.
    pub i: String,
    /// Expiry, unix seconds.
    pub e: i64,
}

fn b64u() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::URL_SAFE_NO_PAD
}

// ---------------------------------------------------------------------------
// Token mint / verify
// ---------------------------------------------------------------------------

/// Mint a `<payload>.<hmac>` token. Mirror of the gateway's TS implementation
/// in `packages/gateway/src/tools/studio.ts`.
pub fn mint_token(secret: &str, wallet: &str, instance_id: &str, ttl_secs: i64) -> String {
    let claims = StudioClaims {
        w: wallet.to_string(),
        i: instance_id.to_string(),
        e: chrono::Utc::now().timestamp() + ttl_secs,
    };
    let payload = serde_json::to_vec(&claims).expect("StudioClaims always serializes");
    let payload_b64 = b64u().encode(&payload);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any-length keys");
    mac.update(payload_b64.as_bytes());
    let tag = mac.finalize().into_bytes();
    let tag_b64 = b64u().encode(tag);

    format!("{payload_b64}.{tag_b64}")
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is malformed")]
    Malformed,
    #[error("signature does not verify")]
    BadSignature,
    #[error("token expired")]
    Expired,
}

pub fn verify_token(secret: &str, token: &str) -> Result<StudioClaims, TokenError> {
    if secret.is_empty() {
        return Err(TokenError::BadSignature);
    }

    let (payload_b64, tag_b64) = token.split_once('.').ok_or(TokenError::Malformed)?;

    let tag = b64u()
        .decode(tag_b64)
        .map_err(|_| TokenError::Malformed)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any-length keys");
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&tag).map_err(|_| TokenError::BadSignature)?;

    let payload_bytes = b64u()
        .decode(payload_b64)
        .map_err(|_| TokenError::Malformed)?;
    let claims: StudioClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::Malformed)?;

    if chrono::Utc::now().timestamp() > claims.e {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Cookie parsing + minting
// ---------------------------------------------------------------------------

/// Pull the `kraph_studio` cookie out of a Cookie: header. Browsers send
/// the whole jar in one header, ; -separated.
pub fn read_studio_cookie(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    for kv in header.split(';') {
        let kv = kv.trim();
        if let Some(rest) = kv.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Build a Set-Cookie value scoped to `.studio.<apex>` so the cookie is
/// valid across every `<id>.studio.<apex>` host. `Secure` is on by default
/// because the subdomain mode runs behind TLS (Caddy).
pub fn build_cookie(token: &str, apex: &str, max_age_secs: i64) -> String {
    let dot_apex = if apex.starts_with('.') {
        apex.to_string()
    } else {
        format!(".{apex}")
    };
    format!(
        "{name}={value}; Path=/; Domain={domain}; HttpOnly; SameSite=Lax; Secure; Max-Age={max_age}",
        name = COOKIE_NAME,
        value = token,
        domain = dot_apex,
        max_age = max_age_secs,
    )
}

/// Pull the `<id>` from `<id>.studio.<apex>` (or any prefix.suffix split).
/// Returns None if the host is malformed or has no leading subdomain.
pub fn instance_id_from_host(host: &str) -> Option<&str> {
    let host = host.split(':').next().unwrap_or(host); // drop port if present
    host.split_once('.').map(|(id, _rest)| id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn round_trip_token() {
        let secret = "spongebob-squarepants";
        let token = mint_token(secret, "wallet1", "instX", 60);
        let claims = verify_token(secret, &token).expect("should verify");
        assert_eq!(claims.w, "wallet1");
        assert_eq!(claims.i, "instX");
    }

    #[test]
    fn rejects_bad_secret() {
        let token = mint_token("real-secret", "w", "i", 60);
        let err = verify_token("attacker-guess", &token).unwrap_err();
        assert!(matches!(err, TokenError::BadSignature));
    }

    #[test]
    fn rejects_expired_token() {
        let token = mint_token("s", "w", "i", -1);
        let err = verify_token("s", &token).unwrap_err();
        assert!(matches!(err, TokenError::Expired));
    }

    #[test]
    fn rejects_malformed() {
        assert!(matches!(
            verify_token("s", "not-a-token").unwrap_err(),
            TokenError::Malformed
        ));
    }

    #[test]
    fn rejects_empty_secret() {
        let err = verify_token("", "anything.anything").unwrap_err();
        assert!(matches!(err, TokenError::BadSignature));
    }

    #[test]
    fn cookie_domain_scoped() {
        let c = build_cookie("tok", "studio.kraph.com", 600);
        assert!(c.contains("Domain=.studio.kraph.com"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Secure"));
        // Apex with leading dot also normalizes:
        assert!(build_cookie("t", ".studio.kraph.com", 60).contains("Domain=.studio.kraph.com"));
    }

    #[test]
    fn read_cookie_picks_kraph_studio() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; kraph_studio=mytoken; baz=qux"),
        );
        assert_eq!(read_studio_cookie(&h), Some("mytoken".to_string()));
    }

    #[test]
    fn host_to_instance_id() {
        assert_eq!(
            instance_id_from_host("zy54a9llirpw.studio.kraph.com"),
            Some("zy54a9llirpw")
        );
        assert_eq!(
            instance_id_from_host("zy54a9llirpw.studio.kraph.com:8443"),
            Some("zy54a9llirpw")
        );
        assert_eq!(instance_id_from_host("noprefix"), None);
    }
}
