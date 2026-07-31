//! # ShadowLink Binary Framing Layer
//!
//! Provides length-prefixed framing over TCP streams for encrypted messages.
//!
//! ## Wire Format:
//! ```text
//! +--------+--------+---------------------------+
//! | Length (2 bytes) |     Encrypted Payload     |
//! |    Big-Endian    |   (up to 16384 bytes)     |
//! +--------+--------+---------------------------+
//! ```
//!
//! ## Why 16KB max?
//! TLS 1.3 record maximum is 16384 bytes. By matching this limit,
//! our framed messages look identical in size to normal TLS records
//! when wrapped in the TLS camouflage layer.

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum payload size per frame (matches TLS 1.3 record limit)
pub const MAX_FRAME_PAYLOAD: usize = 16384;

/// Minimum frame size (2-byte length header)
pub const FRAME_HEADER_SIZE: usize = 2;

/// Reads exactly one framed message from an async reader.
///
/// Returns the payload bytes (without the length header).
/// Returns `Ok(None)` if the connection was cleanly closed (EOF).
///
/// # Errors
/// - Returns error if the frame is too large (>16KB)
/// - Returns error on I/O failure
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    // Read the 2-byte length header
    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Clean connection close
            return Ok(None);
        }
        Err(e) => return Err(e).context("Failed to read frame header"),
    }

    let payload_len = u16::from_be_bytes(len_buf) as usize;

    if payload_len == 0 {
        return Err(anyhow!("Received zero-length frame"));
    }

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(anyhow!(
            "Frame too large: {} bytes (max {})",
            payload_len,
            MAX_FRAME_PAYLOAD
        ));
    }

    // Read the payload
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("Failed to read frame payload")?;

    Ok(Some(payload))
}

/// Writes a framed message to an async writer.
///
/// Prepends a 2-byte big-endian length header to the payload.
///
/// # Errors
/// - Returns error if payload exceeds 16KB
/// - Returns error on I/O failure
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        return Err(anyhow!("Cannot write empty frame"));
    }

    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(anyhow!(
            "Payload too large: {} bytes (max {})",
            payload.len(),
            MAX_FRAME_PAYLOAD
        ));
    }

    let len = payload.len() as u16;
    let mut frame = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame.put_u16(len);
    frame.extend_from_slice(payload);

    writer
        .write_all(&frame)
        .await
        .context("Failed to write frame")?;
    writer.flush().await.context("Failed to flush frame")?;

    Ok(())
}

/// A buffered frame reader that handles partial TCP reads efficiently.
///
/// This is the recommended way to read frames from a long-lived connection,
/// as it maintains an internal buffer and handles TCP stream reassembly.
pub struct FrameReader<R: AsyncRead + Unpin> {
    reader: R,
    buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Create a new frame reader with default buffer capacity.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: BytesMut::with_capacity(MAX_FRAME_PAYLOAD + FRAME_HEADER_SIZE),
        }
    }

    /// Read the next complete frame from the stream.
    ///
    /// Returns `Ok(None)` on clean EOF.
    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            // Try to parse a frame from the buffer
            if self.buffer.len() >= FRAME_HEADER_SIZE {
                let payload_len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;

                if payload_len == 0 {
                    return Err(anyhow!("Received zero-length frame"));
                }

                if payload_len > MAX_FRAME_PAYLOAD {
                    return Err(anyhow!(
                        "Frame too large: {} bytes (max {})",
                        payload_len,
                        MAX_FRAME_PAYLOAD
                    ));
                }

                let total_len = FRAME_HEADER_SIZE + payload_len;
                if self.buffer.len() >= total_len {
                    // We have a complete frame
                    self.buffer.advance(FRAME_HEADER_SIZE); // skip length header
                    let payload = self.buffer.split_to(payload_len).to_vec();
                    return Ok(Some(payload));
                }
            }

            // Need more data — read from the underlying stream
            let mut read_buf = [0u8; 4096];
            let n = self
                .reader
                .read(&mut read_buf)
                .await
                .context("Failed to read from stream")?;

            if n == 0 {
                if self.buffer.is_empty() {
                    return Ok(None); // Clean EOF
                } else {
                    return Err(anyhow!(
                        "Connection closed with {} bytes of partial frame remaining",
                        self.buffer.len()
                    ));
                }
            }

            self.buffer.extend_from_slice(&read_buf[..n]);
        }
    }

    /// Get a reference to the inner reader
    pub fn inner(&self) -> &R {
        &self.reader
    }

    /// Consume the frame reader and return the inner reader
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// A frame writer that provides a convenient interface for sending frames.
pub struct FrameWriter<W: AsyncWrite + Unpin> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Create a new frame writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write a framed message.
    pub async fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.writer, payload).await
    }

    /// Get a reference to the inner writer
    pub fn inner(&self) -> &W {
        &self.writer
    }

    /// Consume the frame writer and return the inner writer
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_write_and_read_frame() {
        let (mut client, mut server) = duplex(65536);

        let payload = b"Hello, ShadowLink!";
        write_frame(&mut client, payload).await.unwrap();
        drop(client); // Close the write side

        let received = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let (mut client, mut server) = duplex(65536);

        let messages = vec![b"First".to_vec(), b"Second".to_vec(), b"Third".to_vec()];

        for msg in &messages {
            write_frame(&mut client, msg).await.unwrap();
        }
        drop(client);

        let mut reader = FrameReader::new(server);
        for expected in &messages {
            let received = reader.read_frame().await.unwrap().unwrap();
            assert_eq!(received, *expected);
        }

        // Should get None on EOF
        assert!(reader.read_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_max_size_frame() {
        let (mut client, mut server) = duplex(65536);

        let payload = vec![0xAB; MAX_FRAME_PAYLOAD];
        write_frame(&mut client, &payload).await.unwrap();
        drop(client);

        let received = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(received.len(), MAX_FRAME_PAYLOAD);
    }

    #[tokio::test]
    async fn test_oversized_frame_rejected() {
        let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let (mut client, _server) = duplex(65536);
        let result = write_frame(&mut client, &payload).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_frame_rejected() {
        let (mut client, _server) = duplex(65536);
        let result = write_frame(&mut client, &[]).await;
        assert!(result.is_err());
    }
}
