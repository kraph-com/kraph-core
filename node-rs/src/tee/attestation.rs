//! Low-level binary parsers for AMD SEV-SNP attestation reports and Intel TDX
//! quotes.  Every parser performs strict bounds checking so that malformed input
//! returns an error instead of panicking.

use anyhow::{bail, ensure, Context, Result};

// ---------------------------------------------------------------------------
// AMD SEV-SNP report (see AMD SEV-SNP ABI Specification, Table 23)
// ---------------------------------------------------------------------------

/// Minimum size of a well-formed SEV-SNP attestation report binary.
/// Version(4) + guest_svn(4) + policy(8) + family_id(16) + image_id(16) +
/// vmpl(4) + sig_algo(4) + platform_version(8) + author_key_en(4) + reserved(4)
/// + report_data(64) + measurement(48) + host_data(32) + id_key_digest(48) +
/// author_key_digest(48) + report_id(32) + report_id_ma(32) + reported_tcb(8) +
/// reserved2(24) + chip_id(64) + committed_tcb(8) + current_build(1) +
/// current_minor(1) + current_major(1) + committed_build(1) + committed_minor(1)
/// + committed_major(1) + launch_tcb(8) + reserved3(168) + signature(512)
/// Total = 1184 bytes.
const SNP_REPORT_MIN_SIZE: usize = 1184;

const SNP_OFFSET_VERSION: usize = 0x000;
const SNP_OFFSET_GUEST_SVN: usize = 0x004;
const SNP_OFFSET_POLICY: usize = 0x008;
const SNP_OFFSET_FAMILY_ID: usize = 0x010;
const SNP_OFFSET_IMAGE_ID: usize = 0x020;
const SNP_OFFSET_VMPL: usize = 0x030;
const SNP_OFFSET_SIG_ALGO: usize = 0x034;
const SNP_OFFSET_PLATFORM_VERSION: usize = 0x038;
const SNP_OFFSET_REPORT_DATA: usize = 0x050;
const SNP_OFFSET_MEASUREMENT: usize = 0x090;
const SNP_OFFSET_HOST_DATA: usize = 0x0C0;
const SNP_OFFSET_ID_KEY_DIGEST: usize = 0x0E0;
const SNP_OFFSET_AUTHOR_KEY_DIGEST: usize = 0x110;
const SNP_OFFSET_REPORT_ID: usize = 0x140;
const SNP_OFFSET_REPORT_ID_MA: usize = 0x160;
const SNP_OFFSET_REPORTED_TCB: usize = 0x180;
const SNP_OFFSET_CHIP_ID: usize = 0x1A0;
const SNP_OFFSET_COMMITTED_TCB: usize = 0x1E0;
const SNP_OFFSET_LAUNCH_TCB: usize = 0x1F0;
const SNP_OFFSET_SIGNATURE: usize = 0x2A0;
const SNP_SIGNATURE_LEN: usize = 512;

/// Parsed fields from an AMD SEV-SNP attestation report.
#[derive(Debug, Clone)]
pub struct SnpReportFields {
    /// Report format version (expected: 2 for current ABI).
    pub version: u32,
    /// Guest Security Version Number.
    pub guest_svn: u32,
    /// Guest policy bit-field.
    pub policy: u64,
    /// Family ID (16 bytes, hex-encoded).
    pub family_id: String,
    /// Image ID (16 bytes, hex-encoded).
    pub image_id: String,
    /// Virtual Machine Privilege Level under which the report was generated.
    pub vmpl: u32,
    /// Signature algorithm (0 = invalid, 1 = ECDSA-P384-SHA384).
    pub signature_algo: u32,
    /// Platform version (microcode, SNP firmware, TEE, etc.).
    pub platform_version: u64,
    /// 64 bytes of caller-supplied data (our nonce lives here), hex-encoded.
    pub report_data: String,
    /// SHA-384 launch measurement (48 bytes), hex-encoded.
    pub measurement: String,
    /// Host-supplied data (32 bytes), hex-encoded.
    pub host_data: String,
    /// SHA-384 digest of the ID signing key, hex-encoded.
    pub id_key_digest: String,
    /// SHA-384 digest of the author signing key, hex-encoded.
    pub author_key_digest: String,
    /// Report ID (32 bytes), hex-encoded.
    pub report_id: String,
    /// Report ID MA (migration agent), hex-encoded.
    pub report_id_ma: String,
    /// Reported TCB version.
    pub reported_tcb: u64,
    /// Chip unique ID (64 bytes), hex-encoded.
    pub chip_id: String,
    /// Committed TCB version.
    pub committed_tcb: u64,
    /// Launch TCB version.
    pub launch_tcb: u64,
    /// ECDSA-P384 signature over the report (512 bytes), hex-encoded.
    pub signature: String,
}

/// Parse a raw AMD SEV-SNP attestation report binary blob.
pub fn parse_snp_report(data: &[u8]) -> Result<SnpReportFields> {
    ensure!(
        data.len() >= SNP_REPORT_MIN_SIZE,
        "SNP report too short: got {} bytes, need at least {}",
        data.len(),
        SNP_REPORT_MIN_SIZE
    );

    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
    };
    let read_u64 = |off: usize| -> u64 {
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
    };

    let version = read_u32(SNP_OFFSET_VERSION);
    if version < 2 {
        bail!("unexpected SNP report version {version}, expected >= 2");
    }

    let sig_end = SNP_OFFSET_SIGNATURE + SNP_SIGNATURE_LEN;
    ensure!(
        data.len() >= sig_end,
        "SNP report truncated before signature end"
    );

    Ok(SnpReportFields {
        version,
        guest_svn: read_u32(SNP_OFFSET_GUEST_SVN),
        policy: read_u64(SNP_OFFSET_POLICY),
        family_id: hex::encode(&data[SNP_OFFSET_FAMILY_ID..SNP_OFFSET_FAMILY_ID + 16]),
        image_id: hex::encode(&data[SNP_OFFSET_IMAGE_ID..SNP_OFFSET_IMAGE_ID + 16]),
        vmpl: read_u32(SNP_OFFSET_VMPL),
        signature_algo: read_u32(SNP_OFFSET_SIG_ALGO),
        platform_version: read_u64(SNP_OFFSET_PLATFORM_VERSION),
        report_data: hex::encode(&data[SNP_OFFSET_REPORT_DATA..SNP_OFFSET_REPORT_DATA + 64]),
        measurement: hex::encode(&data[SNP_OFFSET_MEASUREMENT..SNP_OFFSET_MEASUREMENT + 48]),
        host_data: hex::encode(&data[SNP_OFFSET_HOST_DATA..SNP_OFFSET_HOST_DATA + 32]),
        id_key_digest: hex::encode(&data[SNP_OFFSET_ID_KEY_DIGEST..SNP_OFFSET_ID_KEY_DIGEST + 48]),
        author_key_digest: hex::encode(
            &data[SNP_OFFSET_AUTHOR_KEY_DIGEST..SNP_OFFSET_AUTHOR_KEY_DIGEST + 48],
        ),
        report_id: hex::encode(&data[SNP_OFFSET_REPORT_ID..SNP_OFFSET_REPORT_ID + 32]),
        report_id_ma: hex::encode(&data[SNP_OFFSET_REPORT_ID_MA..SNP_OFFSET_REPORT_ID_MA + 32]),
        reported_tcb: read_u64(SNP_OFFSET_REPORTED_TCB),
        chip_id: hex::encode(&data[SNP_OFFSET_CHIP_ID..SNP_OFFSET_CHIP_ID + 64]),
        committed_tcb: read_u64(SNP_OFFSET_COMMITTED_TCB),
        launch_tcb: read_u64(SNP_OFFSET_LAUNCH_TCB),
        signature: hex::encode(&data[SNP_OFFSET_SIGNATURE..sig_end]),
    })
}

// ---------------------------------------------------------------------------
// Intel TDX Quote (DCAP Quote v4 format)
// ---------------------------------------------------------------------------

/// Minimum size of a TDX DCAP v4 quote.
/// Header (48) + TD Report Body (584) = 632 bytes minimum before signature data.
const TDX_QUOTE_MIN_SIZE: usize = 632;

// Header offsets (48-byte header)
const TDX_OFFSET_HEADER_VERSION: usize = 0x000; // 2 bytes
const TDX_OFFSET_HEADER_ATT_KEY_TYPE: usize = 0x002; // 2 bytes
const TDX_OFFSET_HEADER_TEE_TYPE: usize = 0x004; // 4 bytes
const TDX_OFFSET_HEADER_QE_SVN: usize = 0x008; // 2 bytes
const TDX_OFFSET_HEADER_PCE_SVN: usize = 0x00A; // 2 bytes
const TDX_OFFSET_HEADER_QE_VENDOR_ID: usize = 0x00C; // 16 bytes
const TDX_OFFSET_HEADER_USER_DATA: usize = 0x01C; // 20 bytes

// TD Report Body offsets (relative to start of report body at 0x030)
const TDX_BODY_BASE: usize = 0x030;
const TDX_OFFSET_TEE_TCB_SVN: usize = TDX_BODY_BASE; // 16 bytes
const TDX_OFFSET_MR_SEAM: usize = TDX_BODY_BASE + 0x010; // 48 bytes
const TDX_OFFSET_MR_SIGNER_SEAM: usize = TDX_BODY_BASE + 0x040; // 48 bytes
const TDX_OFFSET_SEAM_ATTRIBUTES: usize = TDX_BODY_BASE + 0x070; // 8 bytes
const TDX_OFFSET_TD_ATTRIBUTES: usize = TDX_BODY_BASE + 0x078; // 8 bytes
const TDX_OFFSET_XFAM: usize = TDX_BODY_BASE + 0x080; // 8 bytes
const TDX_OFFSET_MR_TD: usize = TDX_BODY_BASE + 0x088; // 48 bytes
const TDX_OFFSET_MR_CONFIG_ID: usize = TDX_BODY_BASE + 0x0B8; // 48 bytes
const TDX_OFFSET_MR_OWNER: usize = TDX_BODY_BASE + 0x0E8; // 48 bytes
const TDX_OFFSET_MR_OWNER_CONFIG: usize = TDX_BODY_BASE + 0x118; // 48 bytes
const TDX_OFFSET_RT_MR0: usize = TDX_BODY_BASE + 0x148; // 48 bytes
const TDX_OFFSET_RT_MR1: usize = TDX_BODY_BASE + 0x178; // 48 bytes
const TDX_OFFSET_RT_MR2: usize = TDX_BODY_BASE + 0x1A8; // 48 bytes
const TDX_OFFSET_RT_MR3: usize = TDX_BODY_BASE + 0x1D8; // 48 bytes
const TDX_OFFSET_REPORT_DATA: usize = TDX_BODY_BASE + 0x208; // 64 bytes

/// Parsed fields from an Intel TDX DCAP Quote v4.
#[derive(Debug, Clone)]
pub struct TdxQuoteFields {
    // -- Header --
    /// Quote format version (expected: 4).
    pub version: u16,
    /// Attestation key type (2 = ECDSA-256-with-P-256, 3 = ECDSA-384-with-P-384).
    pub att_key_type: u16,
    /// TEE type (0x00000081 = TDX).
    pub tee_type: u32,
    /// Quoting Enclave security version number.
    pub qe_svn: u16,
    /// Provisioning Certification Enclave security version number.
    pub pce_svn: u16,
    /// QE vendor ID (16 bytes), hex-encoded.
    pub qe_vendor_id: String,
    /// User data embedded in header (20 bytes), hex-encoded.
    pub user_data: String,

    // -- TD Report Body --
    /// TEE TCB SVN (16 bytes), hex-encoded.
    pub tee_tcb_svn: String,
    /// Measurement of the Intel TDX module (SEAM), hex-encoded (48 bytes).
    pub mr_seam: String,
    /// Measurement of the SEAM module signer, hex-encoded (48 bytes).
    pub mr_signer_seam: String,
    /// SEAM attributes (8 bytes), hex-encoded.
    pub seam_attributes: String,
    /// TD attributes (8 bytes), hex-encoded.
    pub td_attributes: String,
    /// XFAM — extended feature access mask (8 bytes), hex-encoded.
    pub xfam: String,
    /// MR_TD — SHA-384 measurement of the TD (the "launch digest"), hex-encoded.
    pub mr_td: String,
    /// MR_CONFIG_ID (48 bytes), hex-encoded.
    pub mr_config_id: String,
    /// MR_OWNER (48 bytes), hex-encoded.
    pub mr_owner: String,
    /// MR_OWNER_CONFIG (48 bytes), hex-encoded.
    pub mr_owner_config: String,
    /// Runtime measurement registers 0-3, hex-encoded (48 bytes each).
    pub rt_mr0: String,
    pub rt_mr1: String,
    pub rt_mr2: String,
    pub rt_mr3: String,
    /// Report data (64 bytes, nonce lives here), hex-encoded.
    pub report_data: String,
}

/// Parse a raw Intel TDX DCAP v4 quote binary.
pub fn parse_tdx_quote(data: &[u8]) -> Result<TdxQuoteFields> {
    ensure!(
        data.len() >= TDX_QUOTE_MIN_SIZE,
        "TDX quote too short: got {} bytes, need at least {}",
        data.len(),
        TDX_QUOTE_MIN_SIZE
    );

    let read_u16 = |off: usize| -> u16 {
        u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
    };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
    };
    let slice_hex = |off: usize, len: usize| -> Result<String> {
        ensure!(
            off + len <= data.len(),
            "TDX quote truncated at offset {off:#x} + {len}"
        );
        Ok(hex::encode(&data[off..off + len]))
    };

    let version = read_u16(TDX_OFFSET_HEADER_VERSION);
    if version != 4 {
        bail!("unexpected TDX quote version {version}, expected 4");
    }

    let tee_type = read_u32(TDX_OFFSET_HEADER_TEE_TYPE);
    if tee_type != 0x0000_0081 {
        bail!("unexpected TEE type {tee_type:#010x}, expected 0x00000081 (TDX)");
    }

    // Make sure report_data region is in-bounds.
    let report_data_end = TDX_OFFSET_REPORT_DATA + 64;
    ensure!(
        data.len() >= report_data_end,
        "TDX quote truncated before report_data end"
    );

    Ok(TdxQuoteFields {
        version,
        att_key_type: read_u16(TDX_OFFSET_HEADER_ATT_KEY_TYPE),
        tee_type,
        qe_svn: read_u16(TDX_OFFSET_HEADER_QE_SVN),
        pce_svn: read_u16(TDX_OFFSET_HEADER_PCE_SVN),
        qe_vendor_id: slice_hex(TDX_OFFSET_HEADER_QE_VENDOR_ID, 16)?,
        user_data: slice_hex(TDX_OFFSET_HEADER_USER_DATA, 20)?,
        tee_tcb_svn: slice_hex(TDX_OFFSET_TEE_TCB_SVN, 16)?,
        mr_seam: slice_hex(TDX_OFFSET_MR_SEAM, 48)?,
        mr_signer_seam: slice_hex(TDX_OFFSET_MR_SIGNER_SEAM, 48)?,
        seam_attributes: slice_hex(TDX_OFFSET_SEAM_ATTRIBUTES, 8)?,
        td_attributes: slice_hex(TDX_OFFSET_TD_ATTRIBUTES, 8)?,
        xfam: slice_hex(TDX_OFFSET_XFAM, 8)?,
        mr_td: slice_hex(TDX_OFFSET_MR_TD, 48)?,
        mr_config_id: slice_hex(TDX_OFFSET_MR_CONFIG_ID, 48)?,
        mr_owner: slice_hex(TDX_OFFSET_MR_OWNER, 48)?,
        mr_owner_config: slice_hex(TDX_OFFSET_MR_OWNER_CONFIG, 48)?,
        rt_mr0: slice_hex(TDX_OFFSET_RT_MR0, 48)?,
        rt_mr1: slice_hex(TDX_OFFSET_RT_MR1, 48)?,
        rt_mr2: slice_hex(TDX_OFFSET_RT_MR2, 48)?,
        rt_mr3: slice_hex(TDX_OFFSET_RT_MR3, 48)?,
        report_data: slice_hex(TDX_OFFSET_REPORT_DATA, 64)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_snp_report() {
        let data = vec![0u8; 100];
        assert!(parse_snp_report(&data).is_err());
    }

    #[test]
    fn rejects_short_tdx_quote() {
        let data = vec![0u8; 100];
        assert!(parse_tdx_quote(&data).is_err());
    }

    #[test]
    fn parses_valid_snp_report() {
        let mut data = vec![0u8; SNP_REPORT_MIN_SIZE];
        // Set version = 2 (little-endian).
        data[0] = 2;
        // Set sig_algo = 1.
        data[SNP_OFFSET_SIG_ALGO] = 1;
        // Write known bytes into measurement field so we can verify parsing.
        for (i, b) in data[SNP_OFFSET_MEASUREMENT..SNP_OFFSET_MEASUREMENT + 48]
            .iter_mut()
            .enumerate()
        {
            *b = (i & 0xFF) as u8;
        }

        let fields = parse_snp_report(&data).unwrap();
        assert_eq!(fields.version, 2);
        assert_eq!(fields.signature_algo, 1);
        assert_eq!(fields.measurement.len(), 96); // 48 bytes -> 96 hex chars
    }

    #[test]
    fn parses_valid_tdx_quote() {
        let mut data = vec![0u8; TDX_QUOTE_MIN_SIZE];
        // version = 4
        data[0] = 4;
        data[1] = 0;
        // tee_type = 0x81 at offset 4
        data[4] = 0x81;

        let fields = parse_tdx_quote(&data).unwrap();
        assert_eq!(fields.version, 4);
        assert_eq!(fields.tee_type, 0x81);
        assert_eq!(fields.mr_td.len(), 96);
    }
}
