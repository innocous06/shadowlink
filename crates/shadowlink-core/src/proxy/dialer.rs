//! # Tunnel Dialer
//!
//! Routes outbound connections through the ShadowLink encrypted tunnel.
//! This is the bridge between the local SOCKS5 proxy and the remote server.

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::socks5::TargetAddr;

/// Tunnel command types sent through the encrypted session
const CMD_CONNECT: u8 = 0x01;
const CMD_CONNECT_REPLY: u8 = 0x02;
const CMD_DATA: u8 = 0x03;
const CMD_CLOSE: u8 = 0x04;
const CMD_RAW_PACKET: u8 = 0x05;

/// A request to open a new connection through the tunnel
#[derive(Debug)]
pub struct ConnectRequest {
    /// Unique stream ID for multiplexing
    pub stream_id: u32,
    /// Target address to connect to
    pub target: TargetAddr,
}

impl ConnectRequest {
    /// Serialize the connect request for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let target_bytes = self.target.to_bytes();
        let mut buf = Vec::with_capacity(5 + target_bytes.len());
        buf.push(CMD_CONNECT);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&target_bytes);
        buf
    }

    /// Deserialize a connect request
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(anyhow!("ConnectRequest too short"));
        }

        if data[0] != CMD_CONNECT {
            return Err(anyhow!("Not a ConnectRequest: 0x{:02x}", data[0]));
        }

        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let (target, _) = TargetAddr::from_bytes(&data[5..])?;

        Ok(Self { stream_id, target })
    }
}

/// A reply to a connect request
#[derive(Debug)]
pub struct ConnectReply {
    /// Stream ID matching the request
    pub stream_id: u32,
    /// Whether the connection was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl ConnectReply {
    /// Serialize the reply
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(CMD_CONNECT_REPLY);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(if self.success { 0x00 } else { 0x01 });

        if let Some(ref err) = self.error {
            let err_bytes = err.as_bytes();
            buf.extend_from_slice(&(err_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(err_bytes);
        } else {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        buf
    }

    /// Deserialize a reply
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(anyhow!("ConnectReply too short"));
        }

        if data[0] != CMD_CONNECT_REPLY {
            return Err(anyhow!("Not a ConnectReply"));
        }

        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let success = data[5] == 0x00;
        let err_len = u16::from_be_bytes([data[6], data[7]]) as usize;

        let error = if err_len > 0 && data.len() >= 8 + err_len {
            Some(String::from_utf8_lossy(&data[8..8 + err_len]).to_string())
        } else {
            None
        };

        Ok(Self {
            stream_id,
            success,
            error,
        })
    }
}

/// A data packet for a specific stream
#[derive(Debug)]
pub struct DataPacket {
    /// Stream ID this data belongs to
    pub stream_id: u32,
    /// The actual data
    pub data: Vec<u8>,
}

impl DataPacket {
    /// Serialize for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.data.len());
        buf.push(CMD_DATA);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize a data packet
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(anyhow!("DataPacket too short"));
        }

        if data[0] != CMD_DATA {
            return Err(anyhow!("Not a DataPacket"));
        }

        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        Ok(Self {
            stream_id,
            data: data[5..].to_vec(),
        })
    }
}

/// A close notification for a stream
#[derive(Debug)]
pub struct ClosePacket {
    /// Stream ID to close
    pub stream_id: u32,
}

impl ClosePacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5);
        buf.push(CMD_CLOSE);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(anyhow!("ClosePacket too short"));
        }

        if data[0] != CMD_CLOSE {
            return Err(anyhow!("Not a ClosePacket"));
        }

        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok(Self { stream_id })
    }
}

/// Parse a tunnel message and determine its type
pub enum TunnelMessage {
    Connect(ConnectRequest),
    ConnectReply(ConnectReply),
    Data(DataPacket),
    Close(ClosePacket),
    RawPacket(RawPacket),
}

/// A raw IP packet (Layer 3)
#[derive(Debug)]
pub struct RawPacket {
    pub data: Vec<u8>,
}

impl RawPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.data.len());
        buf.push(CMD_RAW_PACKET);
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data[0] != CMD_RAW_PACKET {
            return Err(anyhow!("Not a RawPacket"));
        }
        Ok(Self {
            data: data[1..].to_vec(),
        })
    }
}

impl TunnelMessage {
    /// Parse raw bytes into a tunnel message
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow!("Empty tunnel message"));
        }

        match data[0] {
            CMD_CONNECT => Ok(TunnelMessage::Connect(ConnectRequest::from_bytes(data)?)),
            CMD_CONNECT_REPLY => Ok(TunnelMessage::ConnectReply(ConnectReply::from_bytes(data)?)),
            CMD_DATA => Ok(TunnelMessage::Data(DataPacket::from_bytes(data)?)),
            CMD_CLOSE => Ok(TunnelMessage::Close(ClosePacket::from_bytes(data)?)),
            CMD_RAW_PACKET => Ok(TunnelMessage::RawPacket(RawPacket::from_bytes(data)?)),
            other => Err(anyhow!("Unknown tunnel message type: 0x{:02x}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connect_request_roundtrip() {
        let req = ConnectRequest {
            stream_id: 42,
            target: TargetAddr::Domain("www.google.com".to_string(), 443),
        };

        let bytes = req.to_bytes();
        let parsed = ConnectRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.stream_id, 42);
        assert_eq!(
            parsed.target.to_string_repr(),
            "www.google.com:443"
        );
    }

    #[test]
    fn test_connect_reply_roundtrip() {
        let reply = ConnectReply {
            stream_id: 42,
            success: true,
            error: None,
        };

        let bytes = reply.to_bytes();
        let parsed = ConnectReply::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.stream_id, 42);
        assert!(parsed.success);
    }

    #[test]
    fn test_connect_reply_error_roundtrip() {
        let reply = ConnectReply {
            stream_id: 1,
            success: false,
            error: Some("Connection refused".to_string()),
        };

        let bytes = reply.to_bytes();
        let parsed = ConnectReply::from_bytes(&bytes).unwrap();

        assert!(!parsed.success);
        assert_eq!(parsed.error.unwrap(), "Connection refused");
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let pkt = DataPacket {
            stream_id: 100,
            data: b"Hello World".to_vec(),
        };

        let bytes = pkt.to_bytes();
        let parsed = DataPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.stream_id, 100);
        assert_eq!(parsed.data, b"Hello World");
    }

    #[test]
    fn test_tunnel_message_parsing() {
        let req = ConnectRequest {
            stream_id: 1,
            target: TargetAddr::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53),
        };

        let bytes = req.to_bytes();
        match TunnelMessage::parse(&bytes).unwrap() {
            TunnelMessage::Connect(r) => {
                assert_eq!(r.stream_id, 1);
            }
            _ => panic!("Expected Connect message"),
        }
    }
}
