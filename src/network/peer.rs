//! P2P peer connection with Noise_XX_25519_ChaChaPoly_BLAKE2s transport encryption.
//!
//! All P2P messages are:
//!   1. Serialized as JSON
//!   2. Encrypted + authenticated by the Noise transport
//!   3. Framed with a 4-byte big-endian length prefix
//!
//! The Noise handshake runs immediately after the TCP connection is established.
//! No application-level messages are exchanged until both sides have completed
//! mutual authentication.

use crate::network::noise::{generate_keypair, NoiseConn, NOISE_MAX_MESSAGE};
use crate::network::protocol::Message;
use anyhow::Result;
use tokio::net::TcpStream;

pub const MAX_MSG_SIZE: usize = NOISE_MAX_MESSAGE;

/// An encrypted, authenticated P2P peer connection.
pub struct Peer {
    pub addr: String,
    pub(crate) conn: NoiseConn,
}

impl Peer {
    /// Connect to a remote peer and perform the Noise_XX initiator handshake.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let (mut reader, mut writer) = stream.into_split();
        let keypair = generate_keypair()?;
        let transport =
            NoiseConn::connect(&mut reader, &mut writer, addr.to_string(), &keypair).await?;
        let conn = NoiseConn::from_transport(reader, writer, transport, addr.to_string());
        Ok(Peer {
            addr: addr.to_string(),
            conn,
        })
    }

    /// Accept an inbound connection and perform the Noise_XX responder handshake.
    pub async fn from_stream(stream: TcpStream, addr: String) -> Result<Self> {
        let (mut reader, mut writer) = stream.into_split();
        let keypair = generate_keypair()?;
        let transport =
            NoiseConn::accept(&mut reader, &mut writer, &keypair).await?;
        let conn = NoiseConn::from_transport(reader, writer, transport, addr.clone());
        Ok(Peer { addr, conn })
    }

    /// Send a length-prefixed JSON message, encrypted via Noise transport.
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let payload = serde_json::to_vec(msg)?;
        if payload.len() > MAX_MSG_SIZE {
            anyhow::bail!("message too large to send: {} bytes", payload.len());
        }
        self.conn.send_raw(&payload).await
    }

    /// Read the next length-prefixed JSON message, decrypted via Noise transport.
    pub async fn recv(&mut self) -> Result<Message> {
        let plaintext = self.conn.recv_raw().await?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

// ─── Internal helpers (used by node.rs for split reader/writer loops) ─────────

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// Write a length-prefixed JSON message to a raw (pre-Noise) write half.
/// Only used during tests or fallback scenarios.
pub async fn write_message(writer: &mut OwnedWriteHalf, msg: &Message) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_MSG_SIZE {
        anyhow::bail!("message too large to send: {} bytes", payload.len());
    }
    use tokio::io::AsyncWriteExt;
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Read a length-prefixed JSON message from a raw (pre-Noise) read half.
/// Only used during tests or fallback scenarios.
pub async fn read_message(reader: &mut OwnedReadHalf) -> Result<Message> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        anyhow::bail!("message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg = serde_json::from_slice(&buf)?;
    Ok(msg)
}
