//! # DNS over Tunnel
//!
//! Prevents DNS leaks by routing all DNS queries through the encrypted tunnel.
//! Your ISP/university will never see what domains you're resolving.
//!
//! ## How it works:
//! - Client intercepts DNS queries from applications
//! - Queries are sent through the tunnel to the server
//! - Server resolves using public DNS (1.1.1.1, 8.8.8.8)
//! - Response is sent back through the tunnel
//! - At no point does your local network see your DNS queries

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// DNS configuration for the server-side resolver
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers (resolved on the server side)
    pub upstream_servers: Vec<SocketAddr>,
    /// Whether to cache DNS responses (reduces latency)
    pub enable_cache: bool,
    /// DNS cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_servers: vec![
                // Cloudflare DNS
                "1.1.1.1:53".parse().unwrap(),
                "1.0.0.1:53".parse().unwrap(),
                // Google DNS
                "8.8.8.8:53".parse().unwrap(),
                "8.8.4.4:53".parse().unwrap(),
            ],
            enable_cache: true,
            cache_ttl_secs: 300, // 5 minutes
        }
    }
}

/// DNS tunnel command types
const DNS_CMD_QUERY: u8 = 0x10;
const DNS_CMD_RESPONSE: u8 = 0x11;

/// A DNS query to be resolved through the tunnel
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// Query ID for matching responses
    pub query_id: u16,
    /// Domain name to resolve
    pub domain: String,
    /// Query type (A=1, AAAA=28, etc.)
    pub query_type: u16,
}

impl DnsQuery {
    /// Serialize for tunnel transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let domain_bytes = self.domain.as_bytes();
        let mut buf = Vec::with_capacity(6 + domain_bytes.len());
        buf.push(DNS_CMD_QUERY);
        buf.extend_from_slice(&self.query_id.to_be_bytes());
        buf.extend_from_slice(&self.query_type.to_be_bytes());
        buf.push(domain_bytes.len() as u8);
        buf.extend_from_slice(domain_bytes);
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(anyhow!("DNS query too short"));
        }
        if data[0] != DNS_CMD_QUERY {
            return Err(anyhow!("Not a DNS query"));
        }

        let query_id = u16::from_be_bytes([data[1], data[2]]);
        let query_type = u16::from_be_bytes([data[3], data[4]]);
        let domain_len = data[5] as usize;

        if data.len() < 6 + domain_len {
            return Err(anyhow!("DNS query domain truncated"));
        }

        let domain = String::from_utf8(data[6..6 + domain_len].to_vec())
            .context("Invalid domain encoding")?;

        Ok(Self {
            query_id,
            domain,
            query_type,
        })
    }
}

/// A DNS response received through the tunnel
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Matching query ID
    pub query_id: u16,
    /// Resolved IPv4 addresses
    pub ipv4_addrs: Vec<Ipv4Addr>,
    /// Resolved IPv6 addresses
    pub ipv6_addrs: Vec<Ipv6Addr>,
    /// TTL in seconds
    pub ttl: u32,
    /// Whether resolution was successful
    pub success: bool,
}

impl DnsResponse {
    /// Serialize for tunnel transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(DNS_CMD_RESPONSE);
        buf.extend_from_slice(&self.query_id.to_be_bytes());
        buf.push(if self.success { 0x00 } else { 0x01 });
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        // IPv4 addresses
        buf.push(self.ipv4_addrs.len() as u8);
        for addr in &self.ipv4_addrs {
            buf.extend_from_slice(&addr.octets());
        }

        // IPv6 addresses
        buf.push(self.ipv6_addrs.len() as u8);
        for addr in &self.ipv6_addrs {
            buf.extend_from_slice(&addr.octets());
        }

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(anyhow!("DNS response too short"));
        }
        if data[0] != DNS_CMD_RESPONSE {
            return Err(anyhow!("Not a DNS response"));
        }

        let query_id = u16::from_be_bytes([data[1], data[2]]);
        let success = data[3] == 0x00;
        let ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let mut pos = 8;

        // IPv4 addresses
        if pos >= data.len() {
            return Err(anyhow!("DNS response truncated at IPv4 count"));
        }
        let ipv4_count = data[pos] as usize;
        pos += 1;

        let mut ipv4_addrs = Vec::with_capacity(ipv4_count);
        for _ in 0..ipv4_count {
            if pos + 4 > data.len() {
                return Err(anyhow!("DNS response truncated at IPv4 addr"));
            }
            ipv4_addrs.push(Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]));
            pos += 4;
        }

        // IPv6 addresses
        if pos >= data.len() {
            return Err(anyhow!("DNS response truncated at IPv6 count"));
        }
        let ipv6_count = data[pos] as usize;
        pos += 1;

        let mut ipv6_addrs = Vec::with_capacity(ipv6_count);
        for _ in 0..ipv6_count {
            if pos + 16 > data.len() {
                return Err(anyhow!("DNS response truncated at IPv6 addr"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            ipv6_addrs.push(Ipv6Addr::from(octets));
            pos += 16;
        }

        Ok(Self {
            query_id,
            ipv4_addrs,
            ipv6_addrs,
            ttl,
            success,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_roundtrip() {
        let query = DnsQuery {
            query_id: 1234,
            domain: "www.google.com".to_string(),
            query_type: 1, // A record
        };

        let bytes = query.to_bytes();
        let parsed = DnsQuery::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.query_id, 1234);
        assert_eq!(parsed.domain, "www.google.com");
        assert_eq!(parsed.query_type, 1);
    }

    #[test]
    fn test_dns_response_roundtrip() {
        let response = DnsResponse {
            query_id: 1234,
            ipv4_addrs: vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(1, 0, 0, 1),
            ],
            ipv6_addrs: vec![Ipv6Addr::LOCALHOST],
            ttl: 300,
            success: true,
        };

        let bytes = response.to_bytes();
        let parsed = DnsResponse::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.query_id, 1234);
        assert!(parsed.success);
        assert_eq!(parsed.ipv4_addrs.len(), 2);
        assert_eq!(parsed.ipv6_addrs.len(), 1);
        assert_eq!(parsed.ttl, 300);
    }

    #[test]
    fn test_default_dns_config() {
        let config = DnsConfig::default();
        assert_eq!(config.upstream_servers.len(), 4);
        assert!(config.enable_cache);
    }
}
