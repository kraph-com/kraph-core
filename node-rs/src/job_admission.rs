//! Per-wallet / per-instance admission control for expensive jobs.
//!
//! Audit F66 (2026-05-11): build, migration, and IPFS pin are all
//! Docker-heavy and individually capped, but had no aggregate limits.
//! A compromised gateway (or anyone who reaches the node directly with
//! sigauth) could fire dozens of concurrent builds or migrations and
//! starve the Docker daemon for everyone else on the host.
//!
//! This module is a small RAII gate: each handler calls
//! `JobAdmission::try_acquire(kind, wallet, instance)` and gets back
//! either a guard (drops the slot when the job finishes) or an error
//! describing the cap that was hit.
//!
//! Limits:
//!   * 1 active build per wallet, 1 per instance
//!   * 1 active migration per instance (any wallet)
//!
//! State is in-memory and per-process. Restart-on-crash clears it,
//! which is the right behaviour — jobs that were in flight are no
//! longer running because their containers died with the process.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// `POST /instances/:id/build-and-pin`
    Build,
    /// `POST /instances/:id/migrate` and `/migrate/cutover/...`
    Migration,
}

impl JobKind {
    fn as_str(self) -> &'static str {
        match self {
            JobKind::Build => "build",
            JobKind::Migration => "migration",
        }
    }
}

#[derive(Default)]
struct State {
    /// `kind | wallet` keys currently in flight.
    by_wallet: HashSet<String>,
    /// `kind | instance` keys currently in flight.
    by_instance: HashSet<String>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::default()))
}

/// RAII guard. Dropping it frees the wallet/instance slot.
pub struct AdmissionGuard {
    kind: JobKind,
    wallet_key: String,
    instance_key: String,
    // Use Arc<()> as a "release the lock once" semaphore — the mutex is
    // re-acquired in Drop. Arc is here purely so the type is non-Copy.
    _marker: Arc<()>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = state().lock() {
            s.by_wallet.remove(&self.wallet_key);
            s.by_instance.remove(&self.instance_key);
        }
        tracing::debug!(
            kind = self.kind.as_str(),
            wallet_key = %self.wallet_key,
            instance_key = %self.instance_key,
            "job admission released"
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("wallet already has a {0} in flight; wait for it to finish")]
    WalletBusy(&'static str),
    #[error("instance already has a {0} in flight; wait for it to finish")]
    InstanceBusy(&'static str),
}

/// Try to admit a job. Returns a guard on success, AdmissionError on
/// refusal. The caller MUST keep the guard alive for the duration of
/// the job — dropping it before the job finishes will let another
/// caller in, which is the wrong behaviour.
pub fn try_acquire(
    kind: JobKind,
    wallet: &str,
    instance: &str,
) -> Result<AdmissionGuard, AdmissionError> {
    let wallet_key = format!("{}|{wallet}", kind.as_str());
    let instance_key = format!("{}|{instance}", kind.as_str());
    let mut s = state().lock().expect("admission mutex poisoned");
    if matches!(kind, JobKind::Build) && s.by_wallet.contains(&wallet_key) {
        return Err(AdmissionError::WalletBusy(kind.as_str()));
    }
    if s.by_instance.contains(&instance_key) {
        return Err(AdmissionError::InstanceBusy(kind.as_str()));
    }
    s.by_wallet.insert(wallet_key.clone());
    s.by_instance.insert(instance_key.clone());
    tracing::debug!(
        kind = kind.as_str(),
        wallet_key = %wallet_key,
        instance_key = %instance_key,
        "job admission acquired"
    );
    Ok(AdmissionGuard {
        kind,
        wallet_key,
        instance_key,
        _marker: Arc::new(()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_concurrency_capped_per_wallet() {
        let g1 = try_acquire(JobKind::Build, "wallet-a", "inst-1").unwrap();
        // Same wallet, different instance: refused (1 active build per wallet).
        let err = try_acquire(JobKind::Build, "wallet-a", "inst-2");
        assert!(matches!(err, Err(AdmissionError::WalletBusy(_))));
        drop(g1);
        // After drop, it's allowed.
        let _g2 = try_acquire(JobKind::Build, "wallet-a", "inst-2").unwrap();
    }

    #[test]
    fn migration_capped_per_instance_across_wallets() {
        let g1 = try_acquire(JobKind::Migration, "wallet-a", "inst-mig").unwrap();
        let err = try_acquire(JobKind::Migration, "wallet-b", "inst-mig");
        assert!(matches!(err, Err(AdmissionError::InstanceBusy(_))));
        drop(g1);
        let _g2 = try_acquire(JobKind::Migration, "wallet-b", "inst-mig").unwrap();
    }
}
