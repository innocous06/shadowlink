//! # ShadowLink Encrypted Session
//!
//! Manages an encrypted bidirectional communication channel after handshake.
//!
//! ## Features:
//! - ChaCha20-Poly1305 AEAD encryption per-frame
//! - Auto-incrementing nonce (replay protection)
//! - Keepalive and session timeout
//! - Graceful shutdown
//!
//! ## Data Flow:
//! ```text
//! Application Data  →  Encrypt (ChaCha20-Poly1305)  →  Frame  →  TCP Stream
//! TCP Stream  →  Unframe  →  Decrypt  →  Application Data
//! ```

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroize;

use super::frame::{self, FrameReader, FrameWriter, MAX_FRAME_PAYLOAD};
use super::handshake::HandshakeResult;

/// AEAD tag overhead (16 bytes for Poly1305)
const AEAD_TAG_SIZE: usize = 16;
/// Nonce size for ChaCha20-Poly1305
const NONCE_SIZE: usize = 12;
/// Maximum plaintext per frame (accounting for nonce + tag)
pub const MAX_PLAINTEXT_PER_FRAME: usize = MAX_FRAME_PAYLOAD - NONCE_SIZE - AEAD_TAG_SIZE;

/// Special frame types for control messages
const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_KEEPALIVE: u8 = 0x01;
const FRAME_TYPE_CLOSE: u8 = 0x02;

/// An encrypted session over a framed TCP stream.
///
/// Provides `send()` and `recv()` methods for encrypted communication.
/// All data is automatically encrypted/decrypted using the session keys
/// established during the handshake.
pub struct EncryptedSession<S: AsyncRead + AsyncWrite + Unpin> {
    reader: FrameReader<tokio::io::ReadHalf<S>>,
    writer: FrameWriter<tokio::io::WriteHalf<S>>,
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_nonce_counter: u64,
    recv_nonce_counter: u64,
    closed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedSession<S> {
    /// Create a new encrypted session from a handshake result and a stream.
    ///
    /// The stream should be the same stream used for the handshake.
    pub fn new(stream: S, mut handshake: HandshakeResult) -> Result<Self> {
        let send_cipher = ChaCha20Poly1305::new_from_slice(&handshake.send_key)
            .map_err(|e| anyhow!("Failed to init send cipher: {}", e))?;
        let recv_cipher = ChaCha20Poly1305::new_from_slice(&handshake.recv_key)
            .map_err(|e| anyhow!("Failed to init recv cipher: {}", e))?;

        // Zeroize the keys now that ciphers are initialized
        handshake.send_key.zeroize();
        handshake.recv_key.zeroize();

        let (read_half, write_half) = tokio::io::split(stream);

        Ok(Self {
            reader: FrameReader::new(read_half),
            writer: FrameWriter::new(write_half),
            send_cipher,
            recv_cipher,
            send_nonce_counter: 0,
            recv_nonce_counter: 0,
            closed: false,
        })
    }

    /// Build a nonce from a counter value.
    /// Format: 4 zero bytes || 8-byte big-endian counter
    fn build_nonce(counter: u64) -> [u8; NONCE_SIZE] {
        build_nonce(counter)
    }

    pub fn into_split(
        self,
    ) -> (
        EncryptedSessionReadHalf<tokio::io::ReadHalf<S>>,
        EncryptedSessionWriteHalf<tokio::io::WriteHalf<S>>,
    ) {
        (
            EncryptedSessionReadHalf {
                reader: self.reader,
                recv_cipher: self.recv_cipher,
                recv_nonce_counter: self.recv_nonce_counter,
                closed: self.closed,
            },
            EncryptedSessionWriteHalf {
                writer: self.writer,
                send_cipher: self.send_cipher,
                send_nonce_counter: self.send_nonce_counter,
                closed: self.closed,
            },
        )
    }

    /// Send encrypted data to the peer.
    ///
    /// Data is automatically chunked if it exceeds the maximum frame size.
    /// Each chunk is individually encrypted with a unique nonce.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }

        if data.is_empty() {
            return Ok(());
        }

        // Chunk the data if necessary
        for chunk in data.chunks(MAX_PLAINTEXT_PER_FRAME - 1) {
            // 1 byte for frame type
            let mut plaintext = Vec::with_capacity(1 + chunk.len());
            plaintext.push(FRAME_TYPE_DATA);
            plaintext.extend_from_slice(chunk);

            let encrypted = self.encrypt_frame(&plaintext)?;
            self.writer
                .write_frame(&encrypted)
                .await
                .context("Failed to send encrypted frame")?;
        }

        Ok(())
    }

    /// Receive decrypted data from the peer.
    ///
    /// Returns `Ok(None)` if the session was cleanly closed.
    /// Blocks until data is available.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.closed {
            return Ok(None);
        }

        loop {
            let frame = match self.reader.read_frame().await? {
                Some(f) => f,
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            };

            let plaintext = self.decrypt_frame(&frame)?;

            if plaintext.is_empty() {
                return Err(anyhow!("Received empty decrypted frame"));
            }

            let frame_type = plaintext[0];
            let payload = &plaintext[1..];

            match frame_type {
                FRAME_TYPE_DATA => {
                    return Ok(Some(payload.to_vec()));
                }
                FRAME_TYPE_KEEPALIVE => {
                    // Silently consume keepalive frames
                    continue;
                }
                FRAME_TYPE_CLOSE => {
                    self.closed = true;
                    return Ok(None);
                }
                _ => {
                    return Err(anyhow!("Unknown frame type: 0x{:02x}", frame_type));
                }
            }
        }
    }

    /// Send a keepalive frame to keep the connection alive.
    pub async fn send_keepalive(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }

        let plaintext = vec![FRAME_TYPE_KEEPALIVE];
        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send keepalive")
    }

    /// Gracefully close the session.
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }

        let plaintext = vec![FRAME_TYPE_CLOSE];
        let encrypted = self.encrypt_frame(&plaintext)?;
        let _ = self.writer.write_frame(&encrypted).await;
        self.closed = true;
        Ok(())
    }

    /// Encrypt a plaintext frame using the send cipher and incrementing nonce.
    fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::build_nonce(self.send_nonce_counter);
        self.send_nonce_counter += 1;

        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .send_cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut frame_data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        frame_data.extend_from_slice(&nonce_bytes);
        frame_data.extend_from_slice(&ciphertext);

        Ok(frame_data)
    }

    /// Decrypt a received frame using the recv cipher and expected nonce counter.
    fn decrypt_frame(&mut self, frame_data: &[u8]) -> Result<Vec<u8>> {
        if frame_data.len() < NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(anyhow!("Encrypted frame too short"));
        }

        let received_nonce = &frame_data[..NONCE_SIZE];
        let ciphertext = &frame_data[NONCE_SIZE..];

        // Verify nonce matches expected counter (replay protection)
        let expected_nonce = Self::build_nonce(self.recv_nonce_counter);
        if received_nonce != expected_nonce {
            return Err(anyhow!(
                "Nonce mismatch — possible replay or reorder attack (expected {}, got {:?})",
                self.recv_nonce_counter,
                &received_nonce[4..12]
            ));
        }

        self.recv_nonce_counter += 1;

        let nonce = chacha20poly1305::Nonce::from_slice(received_nonce);

        self.recv_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed — data corrupted or tampered"))
    }

    /// Check if the session is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the current send nonce counter (useful for diagnostics).
    pub fn send_counter(&self) -> u64 {
        self.send_nonce_counter
    }

    /// Get the current receive nonce counter.
    pub fn recv_counter(&self) -> u64 {
        self.recv_nonce_counter
    }
}

pub struct EncryptedSessionReadHalf<R: AsyncRead + Unpin> {
    reader: FrameReader<R>,
    recv_cipher: ChaCha20Poly1305,
    recv_nonce_counter: u64,
    pub closed: bool,
}

impl<R: AsyncRead + Unpin> EncryptedSessionReadHalf<R> {
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.closed {
            return Ok(None);
        }

        loop {
            let frame = match self.reader.read_frame().await? {
                Some(f) => f,
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            };

            let plaintext = self.decrypt_frame(&frame)?;

            if plaintext.is_empty() {
                return Err(anyhow!("Received empty decrypted frame"));
            }

            let frame_type = plaintext[0];
            let payload = &plaintext[1..];

            match frame_type {
                FRAME_TYPE_DATA => {
                    return Ok(Some(payload.to_vec()));
                }
                FRAME_TYPE_KEEPALIVE => {
                    continue;
                }
                FRAME_TYPE_CLOSE => {
                    self.closed = true;
                    return Ok(None);
                }
                _ => {
                    return Err(anyhow!("Unknown frame type: 0x{:02x}", frame_type));
                }
            }
        }
    }

    fn decrypt_frame(&mut self, frame_data: &[u8]) -> Result<Vec<u8>> {
        if frame_data.len() < NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(anyhow!("Encrypted frame too short"));
        }

        let received_nonce = &frame_data[..NONCE_SIZE];
        let ciphertext = &frame_data[NONCE_SIZE..];

        let expected_nonce = build_nonce(self.recv_nonce_counter);
        if received_nonce != expected_nonce {
            return Err(anyhow!(
                "Nonce mismatch — possible replay or reorder attack (expected {}, got {:?})",
                self.recv_nonce_counter,
                &received_nonce[4..12]
            ));
        }

        self.recv_nonce_counter += 1;

        let nonce = chacha20poly1305::Nonce::from_slice(received_nonce);

        self.recv_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed — data corrupted or tampered"))
    }
}

pub struct EncryptedSessionWriteHalf<W: AsyncWrite + Unpin> {
    writer: FrameWriter<W>,
    send_cipher: ChaCha20Poly1305,
    send_nonce_counter: u64,
    pub closed: bool,
}

impl<W: AsyncWrite + Unpin> EncryptedSessionWriteHalf<W> {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }

        if data.is_empty() {
            return Ok(());
        }

        for chunk in data.chunks(MAX_PLAINTEXT_PER_FRAME - 1) {
            let mut plaintext = Vec::with_capacity(1 + chunk.len());
            plaintext.push(FRAME_TYPE_DATA);
            plaintext.extend_from_slice(chunk);

            let encrypted = self.encrypt_frame(&plaintext)?;
            self.writer
                .write_frame(&encrypted)
                .await
                .context("Failed to send encrypted frame")?;
        }

        Ok(())
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }

        let plaintext = vec![FRAME_TYPE_KEEPALIVE];
        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send keepalive")
    }

    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }

        let plaintext = vec![FRAME_TYPE_CLOSE];
        let encrypted = self.encrypt_frame(&plaintext)?;
        let _ = self.writer.write_frame(&encrypted).await;
        self.closed = true;
        Ok(())
    }

    fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = build_nonce(self.send_nonce_counter);
        self.send_nonce_counter += 1;

        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .send_cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut frame_data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        frame_data.extend_from_slice(&nonce_bytes);
        frame_data.extend_from_slice(&ciphertext);

        Ok(frame_data)
    }
}

/// Build a nonce from a counter value.
fn build_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::protocol::handshake;
    use tokio::io::duplex;

    /// Helper: perform handshake and return encrypted sessions for both sides
    async fn setup_session() -> (
        EncryptedSession<tokio::io::DuplexStream>,
        EncryptedSession<tokio::io::DuplexStream>,
    ) {
        let server_kp = KeyPair::generate();
        let client_kp = KeyPair::generate();
        let allowed = vec![*client_kp.public_key()];
        let server_pub = *server_kp.public_key();

        let (mut c_stream, mut s_stream) = duplex(65536);

        // Handshake
        let c_handle = tokio::spawn(async move {
            let result = handshake::client_handshake(&mut c_stream, &client_kp, &server_pub)
                .await
                .unwrap();
            (c_stream, result)
        });

        let s_handle = tokio::spawn(async move {
            let result = handshake::server_handshake(&mut s_stream, &server_kp, &allowed)
                .await
                .unwrap();
            (s_stream, result)
        });

        let (c_stream, c_result) = c_handle.await.unwrap();
        let (s_stream, s_result) = s_handle.await.unwrap();

        let client_session = EncryptedSession::new(c_stream, c_result).unwrap();
        let server_session = EncryptedSession::new(s_stream, s_result).unwrap();

        (client_session, server_session)
    }

    #[tokio::test]
    async fn test_send_recv() {
        let (mut client, mut server) = setup_session().await;

        let message = b"Hello from ShadowLink!";
        client.send(message).await.unwrap();

        let received = server.recv().await.unwrap().unwrap();
        assert_eq!(received, message);
    }

    #[tokio::test]
    async fn test_bidirectional() {
        let (mut client, mut server) = setup_session().await;

        // Client -> Server
        client.send(b"ping").await.unwrap();
        let r1 = server.recv().await.unwrap().unwrap();
        assert_eq!(r1, b"ping");

        // Server -> Client
        server.send(b"pong").await.unwrap();
        let r2 = client.recv().await.unwrap().unwrap();
        assert_eq!(r2, b"pong");
    }

    #[tokio::test]
    async fn test_large_data() {
        let (mut client, mut server) = setup_session().await;

        // Send data larger than one frame
        let large_data = vec![0xAB; 50000];
        client.send(&large_data).await.unwrap();

        // Collect all chunks
        let mut received = Vec::new();
        while received.len() < large_data.len() {
            let chunk = server.recv().await.unwrap().unwrap();
            received.extend_from_slice(&chunk);
        }

        assert_eq!(received, large_data);
    }

    #[tokio::test]
    async fn test_keepalive() {
        let (mut client, mut server) = setup_session().await;

        client.send_keepalive().await.unwrap();
        client.send(b"after-keepalive").await.unwrap();

        // recv should skip the keepalive and return the data
        let received = server.recv().await.unwrap().unwrap();
        assert_eq!(received, b"after-keepalive");
    }

    #[tokio::test]
    async fn test_graceful_close() {
        let (mut client, mut server) = setup_session().await;

        client.close().await.unwrap();

        let result = server.recv().await.unwrap();
        assert!(result.is_none());
    }
}
