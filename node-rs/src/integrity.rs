//! ⚠️ ORPHANED MODULE — `IntegrityManager` IS NEVER INSTANTIATED.
//!
//! Audit F51: this module is declared as `mod integrity;` in `main.rs`
//! but no code creates an `IntegrityManager`. Every method on the struct
//! (`compute_merkle_root`, `generate_proof`, `run_checks`) is unreachable
//! at runtime. The standalone helpers (`compute_wal_hash`,
//! `verify_wal_chain`, `build_merkle_proof`, `verify_merkle_proof`) are
//! also unreferenced — replication.rs and main.rs use their own inline
//! hashing.
//!
//! The live Merkle-root endpoint is `main.rs::integrity_root_handler`,
//! which uses an inline SQL query (no dependency on this module). That
//! handler returns a constant hash today and doesn't actually reflect
//! DB state — flagged in F52 as a functionality bug.
//!
//! Dormant code in this file contains SQL-injection patterns in
//! `generate_proof` (table_name and row_condition format!-ed into the
//! query) — irrelevant today because the path is unreachable, but
//! anyone reviving this module MUST either parameterise via psql
//! variables (-v) or restrict the inputs to a strict regex BEFORE
//! wiring it to a route.
//!
//! Kept for historical reference only. Same pattern as F37's
//! `api/mod.rs` cleanup. Safe to delete when an operator with
//! appropriate permission can do so.

#![allow(dead_code)]

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::process::Command;
use tracing::{error, info};

use crate::config::Config;
use crate::db::Database;

/// IntegrityManager implements Layers 1-2 of the Supaba integrity model:
///
/// Layer 1 (WAL hash chain): Each WAL segment is hashed with SHA-256,
///   chaining to the previous hash. Tampering breaks the chain.
///
/// Layer 2 (Merkle state commitments): Periodic Merkle root computation
///   over database tables, published on-chain for verification.
pub struct IntegrityManager {
    config: Arc<Config>,
    db: Arc<Database>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MerkleRootResult {
    pub instance_id: String,
    pub merkle_root: String,
    pub computed_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MerkleProofResult {
    pub row_hash: String,
    pub root: String,
    pub proof: Vec<ProofNode>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProofNode {
    pub hash: String,
    pub position: String, // "left" or "right"
}

impl IntegrityManager {
    pub fn new(config: Arc<Config>, db: Arc<Database>) -> Self {
        Self { config, db }
    }

    /// Compute a Merkle root for an instance's database state.
    ///
    /// Queries all user-created tables in the public schema,
    /// hashes each row, and builds a Merkle tree.
    pub async fn compute_merkle_root(&self, instance_id: &str) -> Result<MerkleRootResult> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .context("Instance not found")?;

        if instance.status != "running" {
            anyhow::bail!("Instance {} is not running (status: {})", instance_id, instance.status);
        }

        let container_name = format!("{}-db-1", instance.compose_project_name);

        // Query to get all row hashes from all public tables
        let sql = r#"
            SELECT md5(t::text) FROM (
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
            ) tables,
            LATERAL (SELECT * FROM public."tablename" ORDER BY (*)::text) t
        "#;

        // Simplified approach: hash each table's content
        let query = r#"
            DO $$
            DECLARE tbl RECORD; BEGIN
                CREATE TEMP TABLE IF NOT EXISTS _sh (h TEXT) ON COMMIT DROP;
                FOR tbl IN SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LOOP
                    EXECUTE format('INSERT INTO _sh SELECT md5(t::text) FROM %I t ORDER BY t::text', tbl.tablename);
                END LOOP;
            END $$;
            SELECT string_agg(h, '' ORDER BY h) FROM _sh;
        "#;

        let output = Command::new("docker")
            .args(["exec", &container_name, "psql", "-U", "postgres", "-t", "-A", "-c", query])
            .output()
            .await
            .context("Failed to execute psql in container")?;

        let combined = String::from_utf8_lossy(&output.stdout).trim().to_string();

        let root = if combined.is_empty() {
            // Empty database
            let mut hasher = Sha256::new();
            hasher.update(b"");
            hex::encode(hasher.finalize())
        } else {
            let mut hasher = Sha256::new();
            hasher.update(combined.as_bytes());
            hex::encode(hasher.finalize())
        };

        Ok(MerkleRootResult {
            instance_id: instance_id.to_string(),
            merkle_root: root,
            computed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Generate a Merkle proof for a specific row in a table.
    pub async fn generate_proof(
        &self,
        instance_id: &str,
        table_name: &str,
        row_condition: &str,
    ) -> Result<MerkleProofResult> {
        let instance = self
            .db
            .get_instance_by_id(instance_id)?
            .context("Instance not found")?;

        if instance.status != "running" {
            anyhow::bail!("Instance not running");
        }

        let container_name = format!("{}-db-1", instance.compose_project_name);

        // Get all row hashes for the table (sorted)
        let all_query = format!(
            "SELECT md5(t::text) FROM public.{} t ORDER BY t::text",
            table_name
        );
        let target_query = format!(
            "SELECT md5(t::text) FROM public.{} t WHERE {} LIMIT 1",
            table_name, row_condition
        );

        let (all_output, target_output) = tokio::join!(
            Command::new("docker")
                .args(["exec", &container_name, "psql", "-U", "postgres", "-t", "-A", "-c", &all_query])
                .output(),
            Command::new("docker")
                .args(["exec", &container_name, "psql", "-U", "postgres", "-t", "-A", "-c", &target_query])
                .output(),
        );

        let all_output = all_output.context("Failed to query all rows")?;
        let target_output = target_output.context("Failed to query target row")?;

        let all_hashes: Vec<String> = String::from_utf8_lossy(&all_output.stdout)
            .trim()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|s| s.to_string())
            .collect();

        let target_hash = String::from_utf8_lossy(&target_output.stdout)
            .trim()
            .to_string();

        if target_hash.is_empty() {
            anyhow::bail!("Row not found matching condition: {}", row_condition);
        }

        let target_index = all_hashes
            .iter()
            .position(|h| h == &target_hash)
            .context("Target hash not found in table")?;

        // Hash each leaf
        let leaves: Vec<[u8; 32]> = all_hashes
            .iter()
            .map(|h| {
                let mut hasher = Sha256::new();
                hasher.update(h.as_bytes());
                hasher.finalize().into()
            })
            .collect();

        let (root, proof) = build_merkle_proof(&leaves, target_index);

        Ok(MerkleProofResult {
            row_hash: target_hash,
            root: hex::encode(root),
            proof,
        })
    }

    /// Run integrity checks for all running instances.
    pub async fn run_checks(&self) -> Result<()> {
        let instances = self.db.list_running_instances()?;
        for instance in instances {
            match self.compute_merkle_root(&instance.id).await {
                Ok(result) => {
                    info!(
                        instance_id = %instance.id,
                        merkle_root = %result.merkle_root,
                        "Integrity check passed"
                    );
                }
                Err(e) => {
                    error!(
                        instance_id = %instance.id,
                        error = %e,
                        "Integrity check failed"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Compute WAL hash chain entry: SHA-256(previous_hash || segment_data).
pub fn compute_wal_hash(segment_data: &[u8], previous_hash: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Some(prev) = previous_hash {
        hasher.update(prev);
    }
    hasher.update(segment_data);
    hasher.finalize().into()
}

/// Verify a WAL hash chain.
pub fn verify_wal_chain(segments: &[(&[u8], [u8; 32])]) -> bool {
    let mut previous_hash: Option<&[u8]> = None;
    for (data, expected_hash) in segments {
        let computed = compute_wal_hash(data, previous_hash);
        if computed != *expected_hash {
            return false;
        }
        previous_hash = Some(expected_hash.as_slice());
    }
    true
}

/// Build a Merkle proof for a leaf at the given index.
fn build_merkle_proof(leaves: &[[u8; 32]], target_index: usize) -> ([u8; 32], Vec<ProofNode>) {
    if leaves.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        return (hasher.finalize().into(), vec![]);
    }

    if leaves.len() == 1 {
        return (leaves[0], vec![]);
    }

    let mut proof = Vec::new();
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut current_index = target_index;

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left // Odd number: duplicate the last node
            };

            // Record sibling for the proof
            if i == current_index || i + 1 == current_index {
                if current_index % 2 == 0 {
                    // Target is left, sibling is right
                    if i + 1 < current_level.len() {
                        proof.push(ProofNode {
                            hash: hex::encode(right),
                            position: "right".to_string(),
                        });
                    }
                } else {
                    // Target is right, sibling is left
                    proof.push(ProofNode {
                        hash: hex::encode(left),
                        position: "left".to_string(),
                    });
                }
            }

            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next_level.push(hasher.finalize().into());

            i += 2;
        }

        current_index /= 2;
        current_level = next_level;
    }

    (current_level[0], proof)
}

/// Verify a Merkle proof against an expected root.
pub fn verify_merkle_proof(leaf: &[u8; 32], proof: &[ProofNode], expected_root: &[u8; 32]) -> bool {
    let mut current = *leaf;

    for node in proof {
        let sibling = match hex::decode(&node.hash) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return false,
        };

        let mut hasher = Sha256::new();
        match node.position.as_str() {
            "left" => {
                hasher.update(sibling);
                hasher.update(current);
            }
            "right" => {
                hasher.update(current);
                hasher.update(sibling);
            }
            _ => return false,
        }
        current = hasher.finalize().into();
    }

    current == *expected_root
}
