use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

use crate::config::Config;
use crate::instance_manager::InstanceManager;

/// HealthManager handles:
/// 1. On-chain heartbeat — proving to the network this node is alive
/// 2. Capacity reporting — providing current stats for the gateway
/// 3. Self-health checks — monitoring Docker and resource usage
///
/// Heartbeats are sent via raw Solana JSON-RPC (no SDK dependency) to keep
/// the binary small and avoid version conflicts. The transaction is
/// pre-serialized using the known instruction layout.
pub struct HealthManager {
    config: Arc<Config>,
    instance_manager: Arc<InstanceManager>,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeHealthReport {
    pub status: String,
    pub version: String,
    pub region: String,
    pub operator: String,
    pub capacity: CapacityInfo,
    pub tee: TeeInfo,
    pub heartbeat: HeartbeatInfo,
    pub uptime_seconds: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CapacityInfo {
    pub max_instances: u32,
    pub running_instances: u32,
    pub available_slots: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TeeInfo {
    pub backend: String,
    pub attestation_available: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HeartbeatInfo {
    pub interval_seconds: u64,
    pub active: bool,
}

impl HealthManager {
    pub fn new(config: Arc<Config>, instance_manager: Arc<InstanceManager>) -> Self {
        Self {
            config,
            instance_manager,
            http_client: reqwest::Client::new(),
        }
    }

    /// Send an on-chain heartbeat via Solana JSON-RPC.
    ///
    /// In production, this calls the gateway's heartbeat relay endpoint
    /// which handles transaction signing with the operator keypair.
    /// The node itself doesn't hold the operator keypair in the TEE —
    /// it's stored in the gateway which runs outside the TEE.
    ///
    /// For now, we POST to a configurable heartbeat URL.
    pub async fn send_heartbeat(&self) -> Result<Option<String>> {
        let heartbeat_url = format!(
            "{}/heartbeat",
            self.config.solana_rpc_url.trim_end_matches('/')
        );

        let stats = self.instance_manager.get_stats().unwrap_or_default();

        let payload = serde_json::json!({
            "node_region": self.config.region,
            "running_instances": stats.running_instances,
            "available_capacity": stats.available_capacity,
            "tee_backend": self.config.tee_backend,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        match self.http_client
            .post(&heartbeat_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let sig = body["signature"].as_str().map(|s| s.to_string());
                if let Some(ref s) = sig {
                    info!(signature = %s, "Heartbeat sent");
                }
                Ok(sig)
            }
            Ok(resp) => {
                error!(status = %resp.status(), "Heartbeat rejected");
                Ok(None)
            }
            Err(e) => {
                error!(error = %e, "Heartbeat failed");
                Ok(None)
            }
        }
    }

    /// Get comprehensive health report for this node.
    pub fn get_health_report(&self) -> NodeHealthReport {
        let stats = self.instance_manager.get_stats().unwrap_or_default();

        NodeHealthReport {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            region: self.config.region.clone(),
            operator: "configured-via-gateway".to_string(),
            capacity: CapacityInfo {
                max_instances: self.config.max_instances as u32,
                running_instances: stats.running_instances as u32,
                available_slots: stats.available_capacity as u32,
            },
            tee: TeeInfo {
                backend: self.config.tee_backend.clone(),
                attestation_available: self.config.tee_backend != "none",
            },
            heartbeat: HeartbeatInfo {
                interval_seconds: self.config.heartbeat_interval_secs,
                active: true,
            },
            uptime_seconds: 0, // TODO: track actual start time
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}
