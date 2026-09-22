//! # SOCKS5 Proxy Server
//!
//! Local SOCKS5 proxy that captures application traffic and routes it through
//! the ShadowLink encrypted tunnel.
//!
//! ## SOCKS5 Protocol Support:
//! - CONNECT (TCP tunneling) — for web browsing, etc.
//! - UDP ASSOCIATE — for gaming, VoIP, etc.
//! - NO AUTH — since it only listens on localhost
//!
//! ## How it fits in:
//! ```text
//! Browser/Game → SOCKS5 (127.0.0.1:1080) → ShadowLink Tunnel → Server → Internet
//! ```

use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
pub const SOCKS5_REPLY_SUCCESS: u8 = 0x00;
// SOCKS5 reply codes (RFC 1928) — kept for protocol completeness and future error paths
#[allow(dead_code)] const SOCKS5_REPLY_FAILURE: u8 = 0x01;
#[allow(dead_code)] const SOCKS5_REPLY_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;

/// The target address parsed from a SOCKS5 request
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// IPv4 address and port
    Ipv4(Ipv4Addr, u16),
    /// IPv6 address and port
    Ipv6(Ipv6Addr, u16),
    /// Domain name and port (DNS resolution happens on the server side)
    Domain(String, u16),
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => TargetAddr::Ipv4(*a.ip(), a.port()),
            SocketAddr::V6(a) => TargetAddr::Ipv6(*a.ip(), a.port()),
        }
    }
}

impl TargetAddr {
    /// Convert to a string representation for display
    pub fn to_string_repr(&self) -> String {
        match self {
            TargetAddr::Ipv4(ip, port) => format!("{}:{}", ip, port),
            TargetAddr::Ipv6(ip, port) => format!("[{}]:{}", ip, port),
            TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }

    /// Serialize the target address for transmission through the tunnel
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            TargetAddr::Ipv4(ip, port) => {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Ipv6(ip, port) => {
                buf.push(SOCKS5_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                // SOCKS5 encodes domain length as a single byte — max 255
                if domain_bytes.len() > 255 {
                    // This should never happen for real hostnames, but guard defensively
                    panic!("Domain name too long for SOCKS5 encoding (> 255 bytes): {}", domain);
                }
                buf.push(SOCKS5_ATYP_DOMAIN);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }

    /// Deserialize a target address from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(anyhow!("Empty address data"));
        }

        match data[0] {
            SOCKS5_ATYP_IPV4 => {
                if data.len() < 7 {
                    return Err(anyhow!("IPv4 address too short"));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((TargetAddr::Ipv4(ip, port), 7))
            }
            SOCKS5_ATYP_IPV6 => {
                if data.len() < 19 {
                    return Err(anyhow!("IPv6 address too short"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((TargetAddr::Ipv6(ip, port), 19))
            }
            SOCKS5_ATYP_DOMAIN => {
                if data.len() < 2 {
                    return Err(anyhow!("Domain address too short"));
                }
                let domain_len = data[1] as usize;
                if data.len() < 2 + domain_len + 2 {
                    return Err(anyhow!("Domain address incomplete"));
                }
                let domain =
                    String::from_utf8(data[2..2 + domain_len].to_vec())
                        .context("Invalid domain encoding")?;
                let port =
                    u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
                Ok((TargetAddr::Domain(domain, port), 4 + domain_len))
            }
            other => Err(anyhow!("Unknown address type: 0x{:02x}", other)),
        }
    }
}

/// SOCKS5 server configuration
#[derive(Clone, Debug)]
pub struct Socks5Config {
    /// Address to listen on (default: 127.0.0.1:1080)
    pub listen_addr: SocketAddr,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".parse().unwrap(),
        }
    }
}

/// Handle the SOCKS5 authentication negotiation.
///
/// We only support NO AUTH since the proxy is localhost-only.
async fn handle_auth(stream: &mut TcpStream) -> Result<()> {
    // Read client greeting: [version, n_methods, methods...]
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("Failed to read SOCKS5 greeting")?;

    if header[0] != SOCKS5_VERSION {
        return Err(anyhow!(
            "Invalid SOCKS version: {} (expected 5)",
            header[0]
        ));
    }

    let n_methods = header[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream
        .read_exact(&mut methods)
        .await
        .context("Failed to read auth methods")?;

    // Check if NO AUTH is offered
    if !methods.contains(&SOCKS5_NO_AUTH) {
        // Reject — we only support NO AUTH (localhost only)
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        return Err(anyhow!("Client doesn't support NO AUTH method"));
    }

    // Accept NO AUTH
    stream
        .write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH])
        .await
        .context("Failed to send auth response")?;

    Ok(())
}

/// Parse the SOCKS5 connection request and extract the target address.
///
/// Returns the command type and target address.
pub async fn handle_request(stream: &mut TcpStream) -> Result<(u8, TargetAddr)> {
    // Read request header: [version, cmd, rsv, atyp]
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("Failed to read SOCKS5 request")?;

    if header[0] != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS version in request"));
    }

    let cmd = header[1];
    let atyp = header[3];

    // Parse target address based on address type
    let target = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            TargetAddr::Ipv4(Ipv4Addr::from(addr), port)
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            TargetAddr::Ipv6(Ipv6Addr::from(addr), port)
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut domain_len = [0u8; 1];
            stream.read_exact(&mut domain_len).await?;
            let mut domain = vec![0u8; domain_len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let domain_str = String::from_utf8(domain)
                .context("Invalid domain name encoding")?;
            TargetAddr::Domain(domain_str, port)
        }
        _ => {
            return Err(anyhow!("Unsupported address type: 0x{:02x}", atyp));
        }
    };

    Ok((cmd, target))
}

/// Send a SOCKS5 reply to the client.
pub async fn send_reply(
    stream: &mut TcpStream,
    reply_code: u8,
    bind_addr: SocketAddr,
) -> Result<()> {
    let mut reply = vec![SOCKS5_VERSION, reply_code, 0x00]; // version, reply, reserved

    match bind_addr {
        SocketAddr::V4(addr) => {
            reply.push(SOCKS5_ATYP_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply.push(SOCKS5_ATYP_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream
        .write_all(&reply)
        .await
        .context("Failed to send SOCKS5 reply")?;
    stream.flush().await?;

    Ok(())
}

/// RFC 1928 SOCKS5 UDP request/response packet header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub frag: u8,
    pub target: TargetAddr,
}

impl UdpHeader {
    /// Parse an RFC 1928 UDP header from datagram bytes.
    /// Returns the parsed header and the byte index where the payload data begins.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(anyhow!("UDP datagram too short for RFC 1928 header"));
        }
        let frag = data[2];
        let (target, consumed) = TargetAddr::from_bytes(&data[3..])?;
        let payload_offset = 3 + consumed;
        if data.len() < payload_offset {
            return Err(anyhow!("UDP datagram shorter than RFC 1928 header"));
        }
        Ok((Self { frag, target }, payload_offset))
    }

    /// Serialize this UDP header into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let target_bytes = self.target.to_bytes();
        let mut buf = Vec::with_capacity(3 + target_bytes.len());
        buf.push(0x00); // RSV
        buf.push(0x00); // RSV
        buf.push(self.frag);
        buf.extend_from_slice(&target_bytes);
        buf
    }

    /// Helper to encapsulate data into a full RFC 1928 UDP packet
    pub fn wrap_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut buf = self.to_bytes();
        buf.extend_from_slice(payload);
        buf
    }
}

/// Result of processing a SOCKS5 client connection request.
pub enum Socks5Request {
    Connect {
        stream: TcpStream,
        target: TargetAddr,
    },
    UdpAssociate {
        stream: TcpStream,
        client_expected_addr: TargetAddr,
    },
}

/// Process a single SOCKS5 client connection.
///
/// This handles the SOCKS5 protocol and returns the parsed request:
/// either a `Connect` request or a `UdpAssociate` request.
pub async fn process_socks5_connection(
    mut stream: TcpStream,
) -> Result<Socks5Request> {
    // Step 1: Authentication
    handle_auth(&mut stream)
        .await
        .context("SOCKS5 auth failed")?;

    // Step 2: Parse request
    let (cmd, target) = handle_request(&mut stream)
        .await
        .context("SOCKS5 request failed")?;

    match cmd {
        SOCKS5_CMD_CONNECT => {
            debug!("SOCKS5 CONNECT to {}", target.to_string_repr());
            // Reply with success (bind address is placeholder — tunnel handles the actual connection)
            send_reply(
                &mut stream,
                SOCKS5_REPLY_SUCCESS,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await?;
            Ok(Socks5Request::Connect { stream, target })
        }
        SOCKS5_CMD_UDP_ASSOCIATE => {
            debug!("SOCKS5 UDP ASSOCIATE from client {}", target.to_string_repr());
            // Note: caller binds the local UDP socket and calls send_reply with the bound port.
            Ok(Socks5Request::UdpAssociate {
                stream,
                client_expected_addr: target,
            })
        }
        _ => {
            warn!("Unsupported SOCKS5 command: 0x{:02x}", cmd);
            send_reply(
                &mut stream,
                SOCKS5_REPLY_CMD_NOT_SUPPORTED,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await?;
            Err(anyhow!("Unsupported SOCKS5 command: 0x{:02x}", cmd))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_addr_ipv4_roundtrip() {
        let addr = TargetAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080);
        let bytes = addr.to_bytes();
        let (parsed, _) = TargetAddr::from_bytes(&bytes).unwrap();
        assert_eq!(addr.to_string_repr(), parsed.to_string_repr());
    }

    #[test]
    fn test_target_addr_domain_roundtrip() {
        let addr = TargetAddr::Domain("www.google.com".to_string(), 443);
        let bytes = addr.to_bytes();
        let (parsed, _) = TargetAddr::from_bytes(&bytes).unwrap();
        assert_eq!(addr.to_string_repr(), parsed.to_string_repr());
    }

    #[test]
    fn test_target_addr_ipv6_roundtrip() {
        let addr = TargetAddr::Ipv6(Ipv6Addr::LOCALHOST, 443);
        let bytes = addr.to_bytes();
        let (parsed, _) = TargetAddr::from_bytes(&bytes).unwrap();
        assert_eq!(addr.to_string_repr(), parsed.to_string_repr());
    }

    #[test]
    fn test_udp_header_roundtrip() {
        let header = UdpHeader {
            frag: 0,
            target: TargetAddr::Ipv4(Ipv4Addr::new(8, 8, 4, 4), 53),
        };
        let payload = b"DNS query payload";
        let packet = header.wrap_packet(payload);

        let (parsed_header, offset) = UdpHeader::parse(&packet).unwrap();
        assert_eq!(parsed_header.frag, 0);
        assert_eq!(parsed_header.target.to_string_repr(), "8.8.4.4:53");
        assert_eq!(&packet[offset..], payload);
    }
}
