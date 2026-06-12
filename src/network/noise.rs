//! Noise Protocol transport layer for Arkos P2P connections.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
//!   - XX  = mutual authentication (both sides authenticate)
//!   - 25519 = X25519 Diffie-Hellman
//!   - ChaChaPoly = ChaCha20-Poly1305 AEAD
//!   - BLAKE2s = hash function
//!
//! The XX handshake provides:
//!   - Forward secrecy (ephemeral keys discarded after handshake)
//!   - Mutual authentication (both sides verify the other's static key)
//!   - Identity hiding (static keys are encrypted during handshake)
//!
//! Message framing uses a 4-byte big-endian length prefix.
//! Each Noise transport message is limited to NOISE_MAX_PLAINTEXT bytes.
//! Larger payloads are automatically split across multiple transport frames.

use anyhow::{bail, Result};
use snow::{Builder, HandshakeState, TransportState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as TokioMutex;

/// Noise_XX pattern descriptor
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext bytes per Noise transport message (protocol limit is 65535;
/// we stay well below to leave room for the 16-byte AEAD tag).
const NOISE_MAX_PLAINTEXT: usize = 65_519;

/// Maximum total message size (32 MB) — enforced at the framing layer.
pub const NOISE_MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// A Noise-encrypted peer connection.
///
/// The `transport` is behind a `Mutex` so the read and write halves can
/// be used concurrently from different async tasks.
pub struct NoiseConn {
    pub addr: String,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    transport: Arc<TokioMutex<TransportState>>,
}

/// Read-only half of a split `NoiseConn`.
///
/// Obtained via [`NoiseConn::into_split`].  Owns the TCP read half and a shared
/// reference to the Noise transport state.  Read and write operations use
/// separate Noise nonces so holding the transport mutex independently is safe.
pub struct NoiseReader {
    reader: OwnedReadHalf,
    transport: Arc<TokioMutex<TransportState>>,
}

/// Write-only half of a split `NoiseConn`.
///
/// Obtained via [`NoiseConn::into_split`].
pub struct NoiseWriter {
    writer: OwnedWriteHalf,
    transport: Arc<TokioMutex<TransportState>>,
}

impl NoiseConn {
    /// Perform the Noise_XX initiator handshake and return the encrypted connection.
    pub async fn connect(
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        _addr: String,
        local_keypair: &snow::Keypair,
    ) -> Result<TransportState> {
        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&local_keypair.private)
            .build_initiator()?;
        handshake(builder, reader, writer).await
    }

    /// Perform the Noise_XX responder handshake and return the encrypted connection.
    pub async fn accept(
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        local_keypair: &snow::Keypair,
    ) -> Result<TransportState> {
        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&local_keypair.private)
            .build_responder()?;
        handshake(builder, reader, writer).await
    }

    /// Wrap an already-completed transport into a `NoiseConn`.
    pub fn from_transport(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        transport: TransportState,
        addr: String,
    ) -> Self {
        NoiseConn {
            addr,
            reader,
            writer,
            transport: Arc::new(TokioMutex::new(transport)),
        }
    }

    /// Split this connection into independent read and write halves.
    ///
    /// After splitting, the caller is responsible for ensuring that neither
    /// half outlives the underlying TCP connection.  The Noise transport state
    /// is shared via `Arc<Mutex<...>>`; read and write use separate nonces so
    /// concurrent use of the two halves is safe.
    pub fn into_split(self) -> (NoiseReader, NoiseWriter) {
        let transport = self.transport;
        (
            NoiseReader {
                reader: self.reader,
                transport: transport.clone(),
            },
            NoiseWriter {
                writer: self.writer,
                transport,
            },
        )
    }

    /// Send a plaintext message, encrypting it with Noise transport.
    /// Automatically splits messages larger than NOISE_MAX_PLAINTEXT.
    pub async fn send_raw(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; NOISE_MAX_PLAINTEXT + 16]; // +16 for AEAD tag
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + NOISE_MAX_PLAINTEXT).min(plaintext.len());
            let chunk = &plaintext[offset..end];
            let n = {
                let mut transport = self.transport.lock().await;
                transport.write_message(chunk, &mut buf)?
            };
            // Write 4-byte length + ciphertext
            self.writer.write_all(&(n as u32).to_be_bytes()).await?;
            self.writer.write_all(&buf[..n]).await?;
            offset = end;
        }
        Ok(())
    }

    /// Receive and decrypt the next message.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > NOISE_MAX_MESSAGE {
            bail!("noise message too large: {} bytes", len);
        }
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).await?;
        let mut plaintext = vec![0u8; len]; // plaintext is always ≤ ciphertext
        let n = {
            let mut transport = self.transport.lock().await;
            transport.read_message(&ciphertext, &mut plaintext)?
        };
        plaintext.truncate(n);
        Ok(plaintext)
    }
}

/// Run the Noise handshake (initiator or responder) to completion.
///
/// The Noise_XX pattern requires 3 handshake messages:
///   → e
///   ← e, ee, s, es
///   → s, se
async fn handshake(
    mut state: HandshakeState,
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
) -> Result<TransportState> {
    let mut buf = vec![0u8; 65535];

    while !state.is_handshake_finished() {
        if state.is_my_turn() {
            // Write the next handshake message
            let n = state.write_message(&[], &mut buf)?;
            writer.write_all(&(n as u32).to_be_bytes()).await?;
            writer.write_all(&buf[..n]).await?;
        } else {
            // Read the next handshake message
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > buf.len() {
                bail!("noise handshake message too large: {} bytes", len);
            }
            reader.read_exact(&mut buf[..len]).await?;
            let mut payload = vec![0u8; len];
            state.read_message(&buf[..len], &mut payload)?;
        }
    }

    Ok(state.into_transport_mode()?)
}

impl NoiseReader {
    /// Receive and decrypt the next Noise transport frame.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > NOISE_MAX_MESSAGE {
            bail!("noise message too large: {} bytes", len);
        }
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).await?;
        let mut plaintext = vec![0u8; len];
        let n = {
            let mut transport = self.transport.lock().await;
            transport.read_message(&ciphertext, &mut plaintext)?
        };
        plaintext.truncate(n);
        Ok(plaintext)
    }
}

impl NoiseWriter {
    /// Encrypt and send `plaintext`.  Splits automatically at NOISE_MAX_PLAINTEXT.
    pub async fn send_raw(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; NOISE_MAX_PLAINTEXT + 16];
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + NOISE_MAX_PLAINTEXT).min(plaintext.len());
            let chunk = &plaintext[offset..end];
            let n = {
                let mut transport = self.transport.lock().await;
                transport.write_message(chunk, &mut buf)?
            };
            self.writer.write_all(&(n as u32).to_be_bytes()).await?;
            self.writer.write_all(&buf[..n]).await?;
            offset = end;
        }
        Ok(())
    }
}

/// Generate a new X25519 static keypair for use with the Noise protocol.
pub fn generate_keypair() -> Result<snow::Keypair> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    Ok(builder.generate_keypair()?)
}
