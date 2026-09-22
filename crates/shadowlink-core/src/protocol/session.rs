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
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;
use zeroize::{Zeroize, Zeroizing};

use super::frame::{FrameReader, FrameWriter, MAX_FRAME_PAYLOAD};
use super::handshake::HandshakeResult;
use crate::obfuscation::padding::{pad_data, unpad_data, PaddingConfig};

/// AEAD tag overhead (16 bytes for Poly1305)
const AEAD_TAG_SIZE: usize = 16;
/// Nonce size for ChaCha20-Poly1305
const NONCE_SIZE: usize = 12;
/// Maximum plaintext per frame (accounting for nonce + tag)
pub const MAX_PLAINTEXT_PER_FRAME: usize = MAX_FRAME_PAYLOAD - NONCE_SIZE - AEAD_TAG_SIZE;

pub const REKEY_THRESHOLD_FRAMES: u64 = 500_000;
pub const REKEY_INTERVAL_FRAMES: u64 = 1_000_000;

/// Special frame types for control messages
const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_KEEPALIVE: u8 = 0x01;
const FRAME_TYPE_CLOSE: u8 = 0x02;
const FRAME_TYPE_DUMMY: u8 = 0x03;
const FRAME_TYPE_REKEY: u8 = 0x04;

fn ratchet_key(key: &mut [u8; 32]) {
    let mut hasher = Blake2s256::new();
    hasher.update(b"ShadowLink-v1-ratchet");
    hasher.update(&key[..]);
    let result = hasher.finalize();
    key.copy_from_slice(&result);
}

struct ReplayWindow {
    highest: u64,
    bitmap: u64, // bit i set = nonce (highest - i) was received
}

impl ReplayWindow {
    fn new() -> Self { Self { highest: 0, bitmap: 0 } }
    
    fn check_and_advance(&mut self, nonce: u64) -> bool {
        if nonce > self.highest {
            let shift = nonce - self.highest;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = nonce;
            true
        } else {
            let offset = self.highest - nonce;
            if offset >= 64 { return false; } // too old
            let bit = 1u64 << offset;
            if self.bitmap & bit != 0 { return false; } // duplicate
            self.bitmap |= bit;
            true
        }
    }
}

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
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_nonce_counter: u64,
    replay_window: ReplayWindow,
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

        let send_key = Zeroizing::new(handshake.send_key);
        let recv_key = Zeroizing::new(handshake.recv_key);

        // Zeroize the keys now that ciphers are initialized
        handshake.send_key.zeroize();
        handshake.recv_key.zeroize();

        let (read_half, write_half) = tokio::io::split(stream);

        Ok(Self {
            reader: FrameReader::new(read_half),
            writer: FrameWriter::new(write_half),
            send_cipher,
            recv_cipher,
            send_key,
            recv_key,
            send_nonce_counter: 0,
            replay_window: ReplayWindow::new(),
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
                recv_key: self.recv_key,
                replay_window: self.replay_window,
                closed: self.closed,
            },
            EncryptedSessionWriteHalf {
                writer: self.writer,
                send_cipher: self.send_cipher,
                send_key: self.send_key,
                send_nonce_counter: self.send_nonce_counter,
                closed: self.closed,
            },
        )
    }

    /// Rotate the send key and send an in-band REKEY frame to the peer.
    pub async fn ratchet_send(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        let plaintext = vec![FRAME_TYPE_REKEY];
        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send rekey frame")?;
        ratchet_key(&mut self.send_key);
        self.send_cipher = ChaCha20Poly1305::new_from_slice(&*self.send_key)
            .map_err(|e| anyhow!("Failed to ratchet send cipher: {}", e))?;
        self.send_nonce_counter = 0;
        debug!("Ratchet: send key rotated, counter reset to 0");
        Ok(())
    }

    /// Rotate the recv key upon receiving an in-band REKEY frame from the peer.
    pub fn ratchet_recv(&mut self) -> Result<()> {
        ratchet_key(&mut self.recv_key);
        self.recv_cipher = ChaCha20Poly1305::new_from_slice(&*self.recv_key)
            .map_err(|e| anyhow!("Failed to ratchet recv cipher: {}", e))?;
        self.replay_window = ReplayWindow::new();
        debug!("Ratchet: recv key rotated, replay window reset");
        Ok(())
    }

    /// Send a dummy frame with randomized length and content for traffic shaping.
    pub async fn send_dummy(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
        }
        let dummy = crate::obfuscation::padding::generate_dummy_packet(&PaddingConfig::default());
        let mut plaintext = Vec::with_capacity(1 + dummy.len());
        plaintext.push(FRAME_TYPE_DUMMY);
        plaintext.extend_from_slice(&dummy);

        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send dummy frame")
    }

    /// Send encrypted data to the peer.
    ///
    /// Data is automatically chunked if it exceeds the maximum frame size.
    /// Each chunk is individually encrypted with a unique nonce.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
        }

        if data.is_empty() {
            return Ok(());
        }

        // Chunk the data if necessary, reserving space for padding (~300 bytes)
        let pad_config = PaddingConfig::default();
        let chunk_size = MAX_PLAINTEXT_PER_FRAME.saturating_sub(300).max(1);
        for chunk in data.chunks(chunk_size) {
            if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
                self.ratchet_send().await?;
            }
            let padded_chunk = pad_data(chunk, &pad_config);
            // 1 byte for frame type
            let mut plaintext = Vec::with_capacity(1 + padded_chunk.len());
            plaintext.push(FRAME_TYPE_DATA);
            plaintext.extend_from_slice(&padded_chunk);

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
                    let unpadded = unpad_data(payload).map_err(|e| anyhow!("Unpad failed: {}", e))?;
                    return Ok(Some(unpadded));
                }
                FRAME_TYPE_KEEPALIVE | FRAME_TYPE_DUMMY => {
                    // Silently consume keepalive and dummy frames
                    continue;
                }
                FRAME_TYPE_REKEY => {
                    self.ratchet_recv()?;
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
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
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
        let received_nonce_bytes = &frame_data[..NONCE_SIZE];
        let ciphertext = &frame_data[NONCE_SIZE..];
        
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&received_nonce_bytes[4..12]);
        let received_counter = u64::from_be_bytes(counter_bytes);
        
        if !self.replay_window.check_and_advance(received_counter) {
            return Err(anyhow!("Replay or duplicate frame rejected (counter {})", received_counter));
        }
        
        let nonce = chacha20poly1305::Nonce::from_slice(received_nonce_bytes);
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

    /// Get the highest received nonce seen so far (useful for diagnostics).
    pub fn recv_counter(&self) -> u64 {
        self.replay_window.highest
    }
}

pub struct EncryptedSessionReadHalf<R: AsyncRead + Unpin> {
    reader: FrameReader<R>,
    recv_cipher: ChaCha20Poly1305,
    recv_key: Zeroizing<[u8; 32]>,
    replay_window: ReplayWindow,
    closed: bool,
}

impl<R: AsyncRead + Unpin> EncryptedSessionReadHalf<R> {
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Rotate the recv key upon receiving an in-band REKEY frame from the peer.
    pub fn ratchet_recv(&mut self) -> Result<()> {
        ratchet_key(&mut self.recv_key);
        self.recv_cipher = ChaCha20Poly1305::new_from_slice(&*self.recv_key)
            .map_err(|e| anyhow!("Failed to ratchet recv cipher: {}", e))?;
        self.replay_window = ReplayWindow::new();
        debug!("Ratchet: recv key rotated, replay window reset");
        Ok(())
    }

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
                    let unpadded = unpad_data(payload).map_err(|e| anyhow!("Unpad failed: {}", e))?;
                    return Ok(Some(unpadded));
                }
                FRAME_TYPE_KEEPALIVE | FRAME_TYPE_DUMMY => {
                    continue;
                }
                FRAME_TYPE_REKEY => {
                    self.ratchet_recv()?;
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
        let received_nonce_bytes = &frame_data[..NONCE_SIZE];
        let ciphertext = &frame_data[NONCE_SIZE..];
        
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&received_nonce_bytes[4..12]);
        let received_counter = u64::from_be_bytes(counter_bytes);
        
        if !self.replay_window.check_and_advance(received_counter) {
            return Err(anyhow!("Replay or duplicate frame rejected (counter {})", received_counter));
        }
        
        let nonce = chacha20poly1305::Nonce::from_slice(received_nonce_bytes);
        self.recv_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed — data corrupted or tampered"))
    }
}

pub struct EncryptedSessionWriteHalf<W: AsyncWrite + Unpin> {
    writer: FrameWriter<W>,
    send_cipher: ChaCha20Poly1305,
    send_key: Zeroizing<[u8; 32]>,
    send_nonce_counter: u64,
    closed: bool,
}

impl<W: AsyncWrite + Unpin> EncryptedSessionWriteHalf<W> {
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Rotate the send key and send an in-band REKEY frame to the peer.
    pub async fn ratchet_send(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        let plaintext = vec![FRAME_TYPE_REKEY];
        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send rekey frame")?;
        ratchet_key(&mut self.send_key);
        self.send_cipher = ChaCha20Poly1305::new_from_slice(&*self.send_key)
            .map_err(|e| anyhow!("Failed to ratchet send cipher: {}", e))?;
        self.send_nonce_counter = 0;
        debug!("Ratchet: send key rotated, counter reset to 0");
        Ok(())
    }

    /// Send a dummy frame with randomized length and content for traffic shaping.
    pub async fn send_dummy(&mut self) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
        }
        let dummy = crate::obfuscation::padding::generate_dummy_packet(&PaddingConfig::default());
        let mut plaintext = Vec::with_capacity(1 + dummy.len());
        plaintext.push(FRAME_TYPE_DUMMY);
        plaintext.extend_from_slice(&dummy);

        let encrypted = self.encrypt_frame(&plaintext)?;
        self.writer
            .write_frame(&encrypted)
            .await
            .context("Failed to send dummy frame")
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(anyhow!("Session is closed"));
        }
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
        }

        if data.is_empty() {
            return Ok(());
        }

        let pad_config = PaddingConfig::default();
        let chunk_size = MAX_PLAINTEXT_PER_FRAME.saturating_sub(300).max(1);
        for chunk in data.chunks(chunk_size) {
            if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
                self.ratchet_send().await?;
            }
            let padded_chunk = pad_data(chunk, &pad_config);
            let mut plaintext = Vec::with_capacity(1 + padded_chunk.len());
            plaintext.push(FRAME_TYPE_DATA);
            plaintext.extend_from_slice(&padded_chunk);

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
        if self.send_nonce_counter >= REKEY_THRESHOLD_FRAMES {
            self.ratchet_send().await?;
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

    #[test]
    fn test_replay_window_rejects_duplicates() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(0));
        assert!(!w.check_and_advance(0)); // duplicate
        assert!(w.check_and_advance(1));
        assert!(w.check_and_advance(63)); // within window
        assert!(!w.check_and_advance(63)); // duplicate
    }

    #[test]
    fn test_replay_window_rejects_old() {
        let mut w = ReplayWindow::new();
        for i in 0..100u64 { w.check_and_advance(i); }
        assert!(!w.check_and_advance(0)); // 100 slots old — too old
        assert!(!w.check_and_advance(35)); // 65 slots old — too old
        assert!(w.check_and_advance(100)); // new nonce — ok
    }

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

    #[tokio::test]
    async fn test_dummy_frames_ignored() {
        let (mut client, mut server) = setup_session().await;

        client.send_dummy().await.unwrap();
        client.send(b"real data").await.unwrap();
        client.send_dummy().await.unwrap();

        let received = server.recv().await.unwrap().unwrap();
        assert_eq!(received, b"real data");
    }

    #[tokio::test]
    async fn test_rekey_ratchet() {
        let (mut client, mut server) = setup_session().await;

        client.send(b"message before rekey").await.unwrap();
        let r1 = server.recv().await.unwrap().unwrap();
        assert_eq!(r1, b"message before rekey");

        // Manually trigger ratcheting on client
        client.ratchet_send().await.unwrap();

        client.send(b"message after rekey").await.unwrap();
        let r2 = server.recv().await.unwrap().unwrap();
        assert_eq!(r2, b"message after rekey");
    }

    #[tokio::test]
    async fn test_split_half_ratchet_and_dummy() {
        let (client, server) = setup_session().await;
        let (_c_read, mut c_write) = client.into_split();
        let (mut s_read, _s_write) = server.into_split();

        c_write.send(b"split message 1").await.unwrap();
        let r1 = s_read.recv().await.unwrap().unwrap();
        assert_eq!(r1, b"split message 1");

        c_write.send_dummy().await.unwrap();
        c_write.ratchet_send().await.unwrap();

        c_write.send(b"split message 2").await.unwrap();
        let r2 = s_read.recv().await.unwrap().unwrap();
        assert_eq!(r2, b"split message 2");
    }
}
