use anyhow::Result;
use sha2::{Digest, Sha256};
use rand::Rng;
use tracing::warn;

/// Mock TEE backend for local development and testing.
///
/// SECURITY: This provides ZERO actual security. It simulates the attestation
/// flow (challenge → report → verify) so the full product can be tested
/// without SEV-SNP/TDX hardware. The "attestation reports" are self-signed
/// and the "measurement" is computed locally, not by hardware.
///
/// A real attacker could forge these reports trivially. Only use for development.

const MOCK_MEASUREMENT: &str = "mock_measurement_not_real_do_not_trust_in_production";

/// Generate a mock SEV-SNP attestation report.
///
/// Produces a 672-byte binary matching the real SEV-SNP report layout:
/// - 0x000-0x003: version (2)
/// - 0x004-0x007: guest_svn (0)
/// - 0x008-0x00F: policy (0x30000)
/// - 0x020-0x05F: report_data (64 bytes — our nonce hash)
/// - 0x090-0x0BF: measurement (48 bytes — fake SHA-384)
/// - 0x1A0-0x39F: signature (512 bytes — random, not a real ECDSA sig)
///
/// Total size: 0x2A0 = 672 bytes
pub fn generate_mock_snp_report(nonce: &str, report_data: Option<&str>) -> Result<Vec<u8>> {
    warn!("MOCK TEE: Generating fake SEV-SNP attestation report. NOT SECURE.");

    // Real SNP report is 0x4A0 = 1184 bytes (header + body + signature)
    let mut report = vec![0u8; 1184];

    // Version = 2 (SEV-SNP report version)
    report[0..4].copy_from_slice(&2u32.to_le_bytes());

    // Guest SVN = 0
    report[4..8].copy_from_slice(&0u32.to_le_bytes());

    // Policy = 0x30000 (SNP required)
    report[8..16].copy_from_slice(&0x30000u64.to_le_bytes());

    // Report data (offset 0x020, 64 bytes): SHA-256 of nonce + report_data
    let rd_input = match report_data {
        Some(rd) => format!("{}:{}", nonce, rd),
        None => nonce.to_string(),
    };
    let rd_hash = Sha256::digest(rd_input.as_bytes());
    report[0x020..0x020 + 32].copy_from_slice(&rd_hash);
    // Pad remaining 32 bytes with zeros (already zeroed)

    // Measurement (offset 0x090, 48 bytes): SHA-384 of mock measurement string
    // In real hardware, this is the launch digest computed by the AMD PSP
    let mut measurement_hasher = sha2::Sha384::new();
    measurement_hasher.update(MOCK_MEASUREMENT.as_bytes());
    let measurement = measurement_hasher.finalize();
    report[0x090..0x090 + 48].copy_from_slice(&measurement);

    // Host data (offset 0x060, 32 bytes): zeros (unused in our protocol)

    // ID key digest (offset 0x0C0, 48 bytes): zeros

    // Author key digest (offset 0x0F0, 48 bytes): zeros

    // Report ID (offset 0x140, 32 bytes): random
    let mut rng = rand::thread_rng();
    let mut report_id = [0u8; 32];
    rng.fill(&mut report_id);
    report[0x140..0x140 + 32].copy_from_slice(&report_id);

    // Chip ID (offset 0x170, 64 bytes): random (would be real chip ID)
    let mut chip_id = [0u8; 64];
    rng.fill(&mut chip_id[..32]);
    rng.fill(&mut chip_id[32..]);
    report[0x170..0x170 + 64].copy_from_slice(&chip_id);

    // Signature (offset 0x1A0, 512 bytes): random bytes (not a real ECDSA-P384 sig)
    for i in (0x1A0..0x1A0 + 512).step_by(32) {
        let end = std::cmp::min(i + 32, 0x1A0 + 512);
        let mut chunk = vec![0u8; end - i];
        rng.fill(&mut chunk[..]);
        report[i..end].copy_from_slice(&chunk);
    }

    Ok(report)
}

/// Generate a mock TDX attestation quote.
///
/// Produces a binary matching the TDX DCAP Quote v4 layout (simplified).
pub fn generate_mock_tdx_quote(nonce: &str, report_data: Option<&str>) -> Result<Vec<u8>> {
    warn!("MOCK TEE: Generating fake TDX attestation quote. NOT SECURE.");

    // TDX quote is variable length. We'll produce a minimal ~700 byte quote.
    let mut quote = vec![0u8; 700];

    // Header (48 bytes)
    // Version = 4
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    // Attestation key type = ECDSA-256
    quote[2..4].copy_from_slice(&2u16.to_le_bytes());
    // TEE type = TDX (0x81)
    quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());

    // Report body starts at offset 48
    // report_data at body + 0x000 (64 bytes)
    let rd_input = match report_data {
        Some(rd) => format!("{}:{}", nonce, rd),
        None => nonce.to_string(),
    };
    let rd_hash = Sha256::digest(rd_input.as_bytes());
    quote[48..48 + 32].copy_from_slice(&rd_hash);

    // MR_TD (measurement) at body + 0x088 (48 bytes)
    let mut measurement_hasher = sha2::Sha384::new();
    measurement_hasher.update(MOCK_MEASUREMENT.as_bytes());
    let measurement = measurement_hasher.finalize();
    let mr_td_offset = 48 + 0x088;
    quote[mr_td_offset..mr_td_offset + 48].copy_from_slice(&measurement);

    Ok(quote)
}

/// Verify a mock attestation report.
///
/// Always returns valid for mock reports (it's our own fake data).
/// Checks nonce freshness and measurement match.
pub fn verify_mock_report(
    report: &[u8],
    expected_nonce: &str,
    expected_measurement: Option<&str>,
) -> MockVerification {
    // Extract the report_data and check nonce
    let nonce_match = if report.len() >= 0x040 {
        let rd_hash = Sha256::digest(expected_nonce.as_bytes());
        report[0x020..0x020 + 32] == rd_hash[..]
    } else {
        false
    };

    // Extract measurement and check
    let measurement_hex = if report.len() >= 0x0C0 {
        hex::encode(&report[0x090..0x090 + 48])
    } else {
        String::new()
    };

    let measurement_match = match expected_measurement {
        Some(expected) => measurement_hex == expected,
        None => true, // No expected measurement configured — accept any
    };

    // Mock cert chain "valid" — it's all fake anyway
    let certificate_chain_valid = true;

    MockVerification {
        valid: nonce_match && measurement_match && certificate_chain_valid,
        platform: "mock".to_string(),
        measurement: measurement_hex,
        measurement_match,
        certificate_chain_valid,
        nonce_match,
        error: if !nonce_match {
            Some("nonce mismatch".to_string())
        } else if !measurement_match {
            Some("measurement mismatch".to_string())
        } else {
            None
        },
    }
}

/// Get the mock measurement string (for configuring expected measurement).
pub fn mock_measurement_hex() -> String {
    let mut hasher = sha2::Sha384::new();
    hasher.update(MOCK_MEASUREMENT.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MockVerification {
    pub valid: bool,
    pub platform: String,
    pub measurement: String,
    pub measurement_match: bool,
    pub certificate_chain_valid: bool,
    pub nonce_match: bool,
    pub error: Option<String>,
}

/// Generate fake PEM certificates for the mock chain.
pub fn mock_certificate_chain() -> Vec<String> {
    vec![
        "-----BEGIN CERTIFICATE-----\nMOCK-VCEK-NOT-REAL-DO-NOT-TRUST\n-----END CERTIFICATE-----".to_string(),
        "-----BEGIN CERTIFICATE-----\nMOCK-ASK-NOT-REAL-DO-NOT-TRUST\n-----END CERTIFICATE-----".to_string(),
        "-----BEGIN CERTIFICATE-----\nMOCK-ARK-NOT-REAL-DO-NOT-TRUST\n-----END CERTIFICATE-----".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_snp_report_size() {
        let report = generate_mock_snp_report("test-nonce", None).unwrap();
        assert_eq!(report.len(), 1184); // 0x4A0 = real SNP report size
    }

    #[test]
    fn test_mock_snp_report_version() {
        let report = generate_mock_snp_report("test-nonce", None).unwrap();
        let version = u32::from_le_bytes(report[0..4].try_into().unwrap());
        assert_eq!(version, 2);
    }

    #[test]
    fn test_mock_verification_valid() {
        let report = generate_mock_snp_report("my-nonce", None).unwrap();
        let result = verify_mock_report(&report, "my-nonce", None);
        assert!(result.valid);
        assert!(result.nonce_match);
    }

    #[test]
    fn test_mock_verification_bad_nonce() {
        let report = generate_mock_snp_report("my-nonce", None).unwrap();
        let result = verify_mock_report(&report, "wrong-nonce", None);
        assert!(!result.valid);
        assert!(!result.nonce_match);
    }

    #[test]
    fn test_mock_tdx_quote() {
        let quote = generate_mock_tdx_quote("nonce", None).unwrap();
        assert!(quote.len() >= 700);
        let version = u16::from_le_bytes(quote[0..2].try_into().unwrap());
        assert_eq!(version, 4);
    }

    #[test]
    fn test_mock_measurement_consistent() {
        let m1 = mock_measurement_hex();
        let m2 = mock_measurement_hex();
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 96); // SHA-384 = 48 bytes = 96 hex chars
    }
}
