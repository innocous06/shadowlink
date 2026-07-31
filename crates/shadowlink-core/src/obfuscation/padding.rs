//! # Packet Padding & Traffic Shaping
//!
//! Normalizes packet sizes and injects dummy traffic to defeat traffic analysis.
//!
//! ## Why this matters:
//! Even with encryption, DPI systems can identify tunnel traffic by:
//! - Packet size distributions (VPN packets have distinctive sizes)
//! - Inter-arrival timing patterns
//! - Burst characteristics during initial handshake
//!
//! ## What we do:
//! - Pad all packets to the nearest configured boundary (default: 64 bytes)
//! - Add random jitter to inter-packet timing
//! - Inject dummy traffic during idle periods
//! - Extra padding during the first 3 seconds (handshake phase)

use anyhow::Result;
use rand::Rng;

/// Padding configuration
#[derive(Clone, Debug)]
pub struct PaddingConfig {
    /// Pad packets to nearest multiple of this many bytes (default: 64)
    pub pad_to_multiple: usize,
    /// Minimum random padding bytes to add (default: 0)
    pub min_padding: usize,
    /// Maximum random padding bytes to add (default: 256)
    pub max_padding: usize,
    /// Whether to inject dummy keepalive packets during idle periods
    pub enable_dummy_traffic: bool,
    /// Interval for dummy traffic injection in milliseconds (default: 5000)
    pub dummy_interval_ms: u64,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            pad_to_multiple: 64,
            min_padding: 0,
            max_padding: 256,
            enable_dummy_traffic: true,
            dummy_interval_ms: 5000,
        }
    }
}

/// Pad data to obscure its true length.
///
/// Format: `[original_length: 4 bytes BE][original data][random padding]`
///
/// The total size is padded to the nearest multiple of `pad_to_multiple`,
/// plus an additional random amount of padding.
pub fn pad_data(data: &[u8], config: &PaddingConfig) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // Calculate padding
    let header_size = 4; // 4 bytes for original length
    let content_size = header_size + data.len();

    // Pad to nearest multiple
    let padded_size = if config.pad_to_multiple > 0 {
        ((content_size + config.pad_to_multiple - 1) / config.pad_to_multiple)
            * config.pad_to_multiple
    } else {
        content_size
    };

    // Add random additional padding
    let extra_padding = rng.gen_range(config.min_padding..=config.max_padding);
    let total_size = padded_size + extra_padding;

    // Build padded packet
    let mut padded = Vec::with_capacity(total_size);

    // Original data length (so receiver knows where data ends and padding begins)
    padded.extend_from_slice(&(data.len() as u32).to_be_bytes());
    padded.extend_from_slice(data);

    // Fill remaining space with random bytes
    let padding_len = total_size - content_size;
    let mut padding = vec![0u8; padding_len];
    rng.fill(&mut padding[..]);
    padded.extend_from_slice(&padding);

    padded
}

/// Remove padding and extract original data.
///
/// Validates the length field and extracts only the original data,
/// discarding all padding bytes.
pub fn unpad_data(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 4 {
        return Err(anyhow::anyhow!("Padded data too short (< 4 bytes)"));
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded[..4]);
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    if original_len > padded.len() - 4 {
        return Err(anyhow::anyhow!(
            "Invalid padding: declared length {} exceeds available data {}",
            original_len,
            padded.len() - 4
        ));
    }

    Ok(padded[4..4 + original_len].to_vec())
}

/// Generate random dummy data for fake traffic injection.
/// The dummy data is indistinguishable from real encrypted traffic.
pub fn generate_dummy_packet(config: &PaddingConfig) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let size = rng.gen_range(64..=512);
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let config = PaddingConfig::default();
        let original = b"Hello, ShadowLink!";

        let padded = pad_data(original, &config);
        let recovered = unpad_data(&padded).unwrap();

        assert_eq!(recovered, original);
        assert!(padded.len() > original.len()); // Should be padded
        assert_eq!(padded.len() % config.pad_to_multiple, 0); // Should be aligned (when no extra random)
    }

    #[test]
    fn test_pad_various_sizes() {
        let config = PaddingConfig {
            min_padding: 0,
            max_padding: 0, // No random padding for deterministic test
            ..Default::default()
        };

        for size in [0, 1, 32, 59, 60, 64, 100, 1000, 16000] {
            let data = vec![0xAA; size];
            let padded = pad_data(&data, &config);
            let recovered = unpad_data(&padded).unwrap();
            assert_eq!(recovered, data, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_empty_data() {
        let config = PaddingConfig {
            min_padding: 0,
            max_padding: 0,
            ..Default::default()
        };
        let padded = pad_data(&[], &config);
        let recovered = unpad_data(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_invalid_padding() {
        // Too short
        assert!(unpad_data(&[0, 0, 0]).is_err());

        // Length exceeds data
        let bad = vec![0, 0, 0, 100, 0, 0]; // claims 100 bytes but only 2 available
        assert!(unpad_data(&bad).is_err());
    }

    #[test]
    fn test_dummy_packet_generation() {
        let config = PaddingConfig::default();
        let dummy = generate_dummy_packet(&config);
        assert!(dummy.len() >= 64);
        assert!(dummy.len() <= 512);
    }
}
