pub mod attestation;
pub mod mock;

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use zeroize::Zeroize;

use crate::config::Config;
use attestation::{parse_snp_report, parse_tdx_quote};

/// Shorthand for the standard base64 engine.
fn b64() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which confidential-computing backend is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeBackend {
    SevSnp,
    Tdx,
    Mock,
    None,
}

impl std::fmt::Display for TeeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeBackend::SevSnp => write!(f, "sev-snp"),
            TeeBackend::Tdx => write!(f, "tdx"),
            TeeBackend::Mock => write!(f, "mock"),
            TeeBackend::None => write!(f, "none"),
        }
    }
}

/// Result of probing the host for TEE device nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeCapabilities {
    pub sev_snp: bool,
    pub tdx: bool,
    pub detected: TeeBackend,
}

/// An attestation report ready for transmission or verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Raw binary report, base64-encoded for JSON transport.
    pub raw_report: Vec<u8>,
    pub platform: TeeBackend,
    /// SHA-384 launch measurement / MR_TD, hex-encoded.
    pub measurement: String,
    /// Caller-supplied nonce that was embedded in report_data.
    pub nonce: String,
    /// Full report_data field, hex-encoded.
    pub report_data: String,
    /// PEM-encoded certificate chain (VCEK -> ASK -> ARK for SNP, PCK chain for TDX).
    pub certificate_chain: Vec<String>,
    /// Unix epoch seconds when the report was generated.
    pub timestamp: i64,
}

/// Outcome of verifying an attestation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerification {
    pub valid: bool,
    pub platform: TeeBackend,
    pub measurement: String,
    pub measurement_match: bool,
    pub certificate_chain_valid: bool,
    pub nonce_match: bool,
    pub error: Option<String>,
}

/// Result returned by the Key Broker Service after a successful attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyReleaseResult {
    /// The decrypted DEK bytes (caller must zeroize after use).
    pub dek: Vec<u8>,
    /// Whether the KBS accepted our attestation.
    pub attestation_accepted: bool,
    /// Human-readable message from the KBS.
    pub message: String,
}

impl Drop for KeyReleaseResult {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

// ---------------------------------------------------------------------------
// TeeManager
// ---------------------------------------------------------------------------

/// Manages TEE attestation operations for the node.
pub struct TeeManager {
    backend: TeeBackend,
    kbs_url: String,
    expected_measurement: Option<String>,
    require_attestation: bool,
}

impl TeeManager {
    /// Create a new `TeeManager` from the node configuration.
    pub fn new(config: &Config) -> Self {
        let backend = match config.tee_backend.as_str() {
            "sev-snp" => TeeBackend::SevSnp,
            "tdx" => TeeBackend::Tdx,
            "mock" => {
                tracing::warn!("TEE backend set to MOCK — no real security! Development only.");
                TeeBackend::Mock
            }
            _ => TeeBackend::None,
        };

        let expected_measurement = if config.expected_measurement_path.as_os_str().is_empty() {
            None
        } else {
            match std::fs::read_to_string(&config.expected_measurement_path) {
                Ok(content) => {
                    let trimmed = content.trim().to_lowercase();
                    if trimmed.is_empty() {
                        None
                    } else {
                        tracing::info!(
                            measurement = %trimmed,
                            "loaded expected TEE measurement"
                        );
                        Some(trimmed)
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = %config.expected_measurement_path.display(),
                        error = %e,
                        "could not read expected measurement file"
                    );
                    None
                }
            }
        };

        tracing::info!(
            backend = %backend,
            require_attestation = config.require_attestation,
            has_expected_measurement = expected_measurement.is_some(),
            "TEE manager initialized"
        );

        Self {
            backend,
            kbs_url: config.kbs_url.clone(),
            expected_measurement,
            require_attestation: config.require_attestation,
        }
    }

    /// Return the configured TEE backend.
    pub fn backend(&self) -> TeeBackend {
        self.backend
    }

    /// Whether the node requires attestation for provisioning.
    pub fn require_attestation(&self) -> bool {
        self.require_attestation
    }

    /// Probe the host for available TEE hardware device nodes.
    pub async fn detect_capabilities() -> TeeCapabilities {
        let sev_snp = Path::new("/dev/sev-guest").exists();
        let tdx = Path::new("/dev/tdx-guest").exists();

        let detected = if sev_snp {
            TeeBackend::SevSnp
        } else if tdx {
            TeeBackend::Tdx
        } else {
            TeeBackend::None
        };

        tracing::info!(
            sev_snp = sev_snp,
            tdx = tdx,
            detected = %detected,
            "TEE capability detection complete"
        );

        TeeCapabilities {
            sev_snp,
            tdx,
            detected,
        }
    }

    /// Generate a fresh attestation report embedding the supplied nonce.
    ///
    /// The nonce (and optional extra `report_data`) are SHA-256-hashed and
    /// placed into the 64-byte report_data field of the hardware report.
    pub async fn generate_report(
        &self,
        nonce: &str,
        report_data: Option<&str>,
    ) -> Result<AttestationReport> {
        // Build the 64-byte report_data payload: SHA-256(nonce || extra).
        let mut hasher = Sha256::new();
        hasher.update(nonce.as_bytes());
        if let Some(extra) = report_data {
            hasher.update(extra.as_bytes());
        }
        let digest = hasher.finalize();
        // Pad to 64 bytes (SHA-256 output is 32, zero-pad the rest).
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&digest);

        let report_data_hex = hex::encode(rd);
        let timestamp = chrono::Utc::now().timestamp();

        match self.backend {
            TeeBackend::SevSnp => {
                self.generate_snp_report(&rd, nonce, &report_data_hex, timestamp)
                    .await
            }
            TeeBackend::Tdx => {
                self.generate_tdx_report(&rd, nonce, &report_data_hex, timestamp)
                    .await
            }
            TeeBackend::Mock => {
                // Mock TEE — generates fake reports for local testing.
                // WARNING: Provides zero actual security.
                let raw = mock::generate_mock_snp_report(nonce, report_data)?;
                let measurement = mock::mock_measurement_hex();
                Ok(AttestationReport {
                    raw_report: raw,
                    platform: TeeBackend::Mock,
                    measurement,
                    nonce: nonce.to_string(),
                    report_data: report_data_hex,
                    certificate_chain: mock::mock_certificate_chain(),
                    timestamp,
                })
            }
            TeeBackend::None => {
                if self.require_attestation {
                    bail!("attestation required but no TEE backend configured");
                }
                Ok(AttestationReport {
                    raw_report: Vec::new(),
                    platform: TeeBackend::None,
                    measurement: String::new(),
                    nonce: nonce.to_string(),
                    report_data: report_data_hex,
                    certificate_chain: Vec::new(),
                    timestamp,
                })
            }
        }
    }

    /// Verify a previously generated attestation report.
    pub async fn verify_report(
        &self,
        report: &AttestationReport,
        expected_nonce: &str,
    ) -> AttestationVerification {
        let nonce_match = report.nonce == expected_nonce;

        // Audit F14 (2026-05-11): the previous default was
        // `measurement_match = true` when `expected_measurement` was
        // unset. That silently passed any forged measurement on operators
        // who hadn't yet pinned SUPABA_EXPECTED_MEASUREMENT_PATH — i.e.
        // exactly when verification matters most. Now fail-closed unless:
        //   - We're on a Mock/None backend (devnet) — they're not real
        //     attestations to begin with; measurement check is moot.
        //   - Operator opts out via SUPABA_ALLOW_UNVERIFIED_MEASUREMENT=true
        //     (must be explicit; logs a WARN at every verify).
        let measurement_match = match &self.expected_measurement {
            Some(expected) => report.measurement.to_lowercase() == *expected,
            None => {
                let is_devnet_backend = matches!(
                    report.platform,
                    TeeBackend::Mock | TeeBackend::None
                );
                let opt_out = matches!(
                    std::env::var("SUPABA_ALLOW_UNVERIFIED_MEASUREMENT").as_deref(),
                    Ok("true" | "1" | "yes")
                );
                if is_devnet_backend {
                    true
                } else if opt_out {
                    tracing::warn!(
                        platform = ?report.platform,
                        measurement = %report.measurement,
                        "SUPABA_ALLOW_UNVERIFIED_MEASUREMENT=true — accepting attestation without measurement check. DO NOT use this in production."
                    );
                    true
                } else {
                    tracing::warn!(
                        platform = ?report.platform,
                        measurement = %report.measurement,
                        "no expected_measurement configured on a real TEE backend — refusing attestation. Set SUPABA_EXPECTED_MEASUREMENT_PATH to pin the launch measurement."
                    );
                    false
                }
            }
        };

        // Attempt certificate chain verification via external tooling.
        let certificate_chain_valid = match report.platform {
            TeeBackend::SevSnp => self.verify_snp_certs(report).await,
            TeeBackend::Tdx => self.verify_tdx_certs(report).await,
            TeeBackend::Mock => true, // Mock certs are always "valid"
            TeeBackend::None => true,
        };

        let valid = nonce_match && measurement_match && certificate_chain_valid;

        let error = if !valid {
            let mut reasons = Vec::new();
            if !nonce_match {
                reasons.push("nonce mismatch".to_string());
            }
            if !measurement_match {
                reasons.push(format!(
                    "measurement mismatch: got {}, expected {}",
                    report.measurement,
                    self.expected_measurement.as_deref().unwrap_or("(none)")
                ));
            }
            if !certificate_chain_valid {
                reasons.push("certificate chain validation failed".to_string());
            }
            Some(reasons.join("; "))
        } else {
            None
        };

        AttestationVerification {
            valid,
            platform: report.platform,
            measurement: report.measurement.clone(),
            measurement_match,
            certificate_chain_valid,
            nonce_match,
            error,
        }
    }

    /// Request key release from the Key Broker Service.
    ///
    /// Flow:
    /// 1. Generate a fresh attestation report with a random nonce.
    /// 2. POST the report + encrypted DEK to the KBS.
    /// 3. KBS verifies attestation and, if valid, returns the unwrapped DEK.
    pub async fn request_key_release(
        &self,
        instance_id: &str,
        encrypted_dek: &[u8],
        nonce: &str,
    ) -> Result<KeyReleaseResult> {
        if self.kbs_url.is_empty() {
            bail!("KBS URL not configured — cannot request key release");
        }

        // Generate attestation report that proves we are running in a genuine enclave.
        let report = self
            .generate_report(nonce, Some(instance_id))
            .await
            .context("failed to generate attestation report for key release")?;

        // Build the KBS request payload.
        let payload = serde_json::json!({
            "instance_id": instance_id,
            "nonce": nonce,
            "encrypted_dek": b64().encode(encrypted_dek),
            "attestation_report": b64().encode(&report.raw_report),
            "platform": report.platform,
            "measurement": report.measurement,
            "certificate_chain": report.certificate_chain,
        });

        let url = format!("{}/v1/keys/release", self.kbs_url.trim_end_matches('/'));

        tracing::info!(
            url = %url,
            instance_id = %instance_id,
            platform = %report.platform,
            "requesting key release from KBS"
        );

        let output = Command::new("curl")
            .args([
                "-s",
                "-S",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &serde_json::to_string(&payload)?,
                "--max-time",
                "30",
                &url,
            ])
            .output()
            .await
            .context("failed to execute curl for KBS request")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("KBS request failed: {stderr}");
        }

        let body: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse KBS response JSON")?;

        let accepted = body
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !accepted {
            let msg = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("attestation rejected by KBS");
            bail!("KBS rejected attestation: {msg}");
        }

        let dek_b64 = body
            .get("dek")
            .and_then(|v| v.as_str())
            .context("KBS response missing 'dek' field")?;

        let dek = b64()
            .decode(dek_b64)
            .context("invalid base64 in KBS dek response")?;

        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("key released")
            .to_string();

        tracing::info!(
            instance_id = %instance_id,
            "key release successful"
        );

        Ok(KeyReleaseResult {
            dek,
            attestation_accepted: true,
            message,
        })
    }

    // -----------------------------------------------------------------------
    // Private — SEV-SNP
    // -----------------------------------------------------------------------

    async fn generate_snp_report(
        &self,
        report_data: &[u8; 64],
        nonce: &str,
        report_data_hex: &str,
        timestamp: i64,
    ) -> Result<AttestationReport> {
        // Write report_data to a temp file for snpguest.
        let tmp_dir = std::env::temp_dir();
        let rd_path = tmp_dir.join(format!("supaba_snp_rd_{}.bin", nanoid::nanoid!(8)));
        let report_path = tmp_dir.join(format!("supaba_snp_report_{}.bin", nanoid::nanoid!(8)));

        tokio::fs::write(&rd_path, report_data)
            .await
            .context("failed to write report_data temp file")?;

        // Use snpguest to request an attestation report from the AMD PSP.
        let output = Command::new("snpguest")
            .args([
                "report",
                report_path.to_str().unwrap_or_default(),
                rd_path.to_str().unwrap_or_default(),
            ])
            .output()
            .await
            .context("failed to execute snpguest report")?;

        // Clean up the request-data temp file (best-effort).
        let _ = tokio::fs::remove_file(&rd_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = tokio::fs::remove_file(&report_path).await;
            bail!("snpguest report failed: {stderr}");
        }

        let raw_report = tokio::fs::read(&report_path)
            .await
            .context("failed to read SNP report file")?;

        let _ = tokio::fs::remove_file(&report_path).await;

        let fields = parse_snp_report(&raw_report)
            .context("failed to parse generated SNP report")?;

        // Fetch the certificate chain (VCEK, ASK, ARK).
        let certs = self.fetch_snp_cert_chain().await.unwrap_or_default();

        Ok(AttestationReport {
            raw_report,
            platform: TeeBackend::SevSnp,
            measurement: fields.measurement,
            nonce: nonce.to_string(),
            report_data: report_data_hex.to_string(),
            certificate_chain: certs,
            timestamp,
        })
    }

    /// Fetch the AMD certificate chain (VCEK -> ASK -> ARK) using snpguest.
    async fn fetch_snp_cert_chain(&self) -> Result<Vec<String>> {
        let tmp_dir = std::env::temp_dir();
        let certs_dir = tmp_dir.join(format!("supaba_snp_certs_{}", nanoid::nanoid!(8)));
        tokio::fs::create_dir_all(&certs_dir).await?;

        let output = Command::new("snpguest")
            .args([
                "fetch",
                "ca",
                "pem",
                certs_dir.to_str().unwrap_or_default(),
            ])
            .output()
            .await
            .context("failed to fetch SNP CA certs")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(stderr = %stderr, "snpguest fetch ca failed");
            let _ = tokio::fs::remove_dir_all(&certs_dir).await;
            return Ok(Vec::new());
        }

        // Also fetch the VCEK.
        let _ = Command::new("snpguest")
            .args([
                "fetch",
                "vcek",
                "pem",
                certs_dir.to_str().unwrap_or_default(),
            ])
            .output()
            .await;

        let mut certs = Vec::new();
        let mut entries = tokio::fs::read_dir(&certs_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "pem") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    certs.push(content);
                }
            }
        }

        let _ = tokio::fs::remove_dir_all(&certs_dir).await;
        Ok(certs)
    }

    /// Verify SNP certificate chain using snpguest verify.
    async fn verify_snp_certs(&self, report: &AttestationReport) -> bool {
        if report.raw_report.is_empty() || report.certificate_chain.is_empty() {
            return false;
        }

        let tmp_dir = std::env::temp_dir();
        let work_dir = tmp_dir.join(format!("supaba_snp_verify_{}", nanoid::nanoid!(8)));
        if tokio::fs::create_dir_all(&work_dir).await.is_err() {
            return false;
        }

        let report_path = work_dir.join("report.bin");
        let certs_dir = work_dir.join("certs");
        if tokio::fs::create_dir_all(&certs_dir).await.is_err() {
            let _ = tokio::fs::remove_dir_all(&work_dir).await;
            return false;
        }

        // Write report and certs to disk.
        if tokio::fs::write(&report_path, &report.raw_report)
            .await
            .is_err()
        {
            let _ = tokio::fs::remove_dir_all(&work_dir).await;
            return false;
        }

        for (i, pem) in report.certificate_chain.iter().enumerate() {
            let cert_path = certs_dir.join(format!("cert_{i}.pem"));
            if tokio::fs::write(&cert_path, pem).await.is_err() {
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
                return false;
            }
        }

        let result = Command::new("snpguest")
            .args([
                "verify",
                "attestation",
                certs_dir.to_str().unwrap_or_default(),
                report_path.to_str().unwrap_or_default(),
            ])
            .output()
            .await;

        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        match result {
            Ok(output) => {
                if output.status.success() {
                    tracing::info!("SNP certificate chain verification passed");
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(stderr = %stderr, "SNP certificate chain verification failed");
                    false
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to execute snpguest verify");
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private — TDX
    // -----------------------------------------------------------------------

    async fn generate_tdx_report(
        &self,
        report_data: &[u8; 64],
        nonce: &str,
        report_data_hex: &str,
        timestamp: i64,
    ) -> Result<AttestationReport> {
        let tmp_dir = std::env::temp_dir();
        let rd_path = tmp_dir.join(format!("supaba_tdx_rd_{}.bin", nanoid::nanoid!(8)));
        let quote_path = tmp_dir.join(format!("supaba_tdx_quote_{}.bin", nanoid::nanoid!(8)));

        tokio::fs::write(&rd_path, report_data)
            .await
            .context("failed to write TDX report_data temp file")?;

        // Use the tdx_attest tool to generate a quote.
        let output = Command::new("tdx_attest")
            .args([
                "-r",
                rd_path.to_str().unwrap_or_default(),
                "-o",
                quote_path.to_str().unwrap_or_default(),
            ])
            .output()
            .await
            .context("failed to execute tdx_attest")?;

        let _ = tokio::fs::remove_file(&rd_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = tokio::fs::remove_file(&quote_path).await;
            bail!("tdx_attest failed: {stderr}");
        }

        let raw_quote = tokio::fs::read(&quote_path)
            .await
            .context("failed to read TDX quote file")?;

        let _ = tokio::fs::remove_file(&quote_path).await;

        let fields =
            parse_tdx_quote(&raw_quote).context("failed to parse generated TDX quote")?;

        // Attempt to fetch the PCK certificate chain.
        let certs = self.fetch_tdx_cert_chain().await.unwrap_or_default();

        Ok(AttestationReport {
            raw_report: raw_quote,
            platform: TeeBackend::Tdx,
            measurement: fields.mr_td,
            nonce: nonce.to_string(),
            report_data: report_data_hex.to_string(),
            certificate_chain: certs,
            timestamp,
        })
    }

    /// Fetch the TDX/DCAP PCK certificate chain via the PCCS or local cache.
    async fn fetch_tdx_cert_chain(&self) -> Result<Vec<String>> {
        // Look for certificates in the standard DCAP paths.
        let pck_cert_path = Path::new("/var/opt/aesmd/data/pck_cert_chain.pem");
        if pck_cert_path.exists() {
            let content = tokio::fs::read_to_string(pck_cert_path).await?;
            // Split PEM chain into individual certificates.
            let certs: Vec<String> = content
                .split("-----END CERTIFICATE-----")
                .filter_map(|chunk| {
                    let trimmed = chunk.trim();
                    if trimmed.contains("-----BEGIN CERTIFICATE-----") {
                        Some(format!("{trimmed}\n-----END CERTIFICATE-----\n"))
                    } else {
                        None
                    }
                })
                .collect();
            return Ok(certs);
        }

        // Fallback: try to get via the quote verification library tool.
        let output = Command::new("pck_id_retrieval_tool")
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                // Re-check for the cert file.
                if pck_cert_path.exists() {
                    let content = tokio::fs::read_to_string(pck_cert_path).await?;
                    let certs: Vec<String> = content
                        .split("-----END CERTIFICATE-----")
                        .filter_map(|chunk| {
                            let trimmed = chunk.trim();
                            if trimmed.contains("-----BEGIN CERTIFICATE-----") {
                                Some(format!("{trimmed}\n-----END CERTIFICATE-----\n"))
                            } else {
                                None
                            }
                        })
                        .collect();
                    Ok(certs)
                } else {
                    Ok(Vec::new())
                }
            }
            _ => {
                tracing::warn!("could not retrieve TDX PCK certificate chain");
                Ok(Vec::new())
            }
        }
    }

    /// Verify TDX certificate chain.
    async fn verify_tdx_certs(&self, report: &AttestationReport) -> bool {
        if report.raw_report.is_empty() || report.certificate_chain.is_empty() {
            return false;
        }

        // Use the DCAP quote verification tool if available.
        let tmp_dir = std::env::temp_dir();
        let quote_path = tmp_dir.join(format!("supaba_tdx_verify_{}.bin", nanoid::nanoid!(8)));

        if tokio::fs::write(&quote_path, &report.raw_report)
            .await
            .is_err()
        {
            return false;
        }

        let result = Command::new("tdx_quote_verify")
            .arg(quote_path.to_str().unwrap_or_default())
            .output()
            .await;

        let _ = tokio::fs::remove_file(&quote_path).await;

        match result {
            Ok(output) => {
                if output.status.success() {
                    tracing::info!("TDX quote verification passed");
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(stderr = %stderr, "TDX quote verification failed");
                    false
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to execute tdx_quote_verify");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_backend_display() {
        assert_eq!(TeeBackend::SevSnp.to_string(), "sev-snp");
        assert_eq!(TeeBackend::Tdx.to_string(), "tdx");
        assert_eq!(TeeBackend::None.to_string(), "none");
    }

    #[test]
    fn tee_manager_from_default_config() {
        let config = Config::default();
        let mgr = TeeManager::new(&config);
        assert_eq!(mgr.backend(), TeeBackend::None);
        assert!(!mgr.require_attestation());
    }

    #[tokio::test]
    async fn generate_report_none_backend_no_require() {
        let config = Config::default();
        let mgr = TeeManager::new(&config);
        let report = mgr.generate_report("test-nonce", None).await.unwrap();
        assert_eq!(report.platform, TeeBackend::None);
        assert_eq!(report.nonce, "test-nonce");
        assert!(report.raw_report.is_empty());
    }

    #[tokio::test]
    async fn generate_report_none_backend_require_fails() {
        let mut config = Config::default();
        config.require_attestation = true;
        let mgr = TeeManager::new(&config);
        let result = mgr.generate_report("test-nonce", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn detect_capabilities_runs() {
        let caps = TeeManager::detect_capabilities().await;
        // In a non-TEE test environment both should be false.
        assert_eq!(caps.detected, TeeBackend::None);
    }
}
