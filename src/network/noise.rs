//! Noise Protocol transport layer for Arkos P2P connections.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` + ML-KEM-768 hybrid layer
//!
//! CLASSICAL LAYER (Noise_XX):
//!   - XX  = mutual authentication (both sides authenticate)
//!   - 25519 = X25519 Diffie-Hellman
//!   - ChaChaPoly = ChaCha20-Poly1305 AEAD
//!   - BLAKE2s = hash function
//!   - Provides: forward secrecy, mutual auth, identity hiding
//!
//! POST-QUANTUM LAYER (ML-KEM-768 hybrid):
//!   After the Noise XX handshake, both peers perform an ephemeral ML-KEM-768
//!   key encapsulation through the (already encrypted) Noise channel:
//!     1. Initiator generates ephemeral ML-KEM-768 key pair (ek, dk)
//!     2. Initiator sends ek (1184 bytes) through Noise
//!     3. Responder encapsulates: (mlkem_ss, ct) = ML-KEM.Encaps(ek)
//!     4. Responder sends ct (1088 bytes) through Noise
//!     5. Initiator decapsulates: mlkem_ss = ML-KEM.Decaps(dk, ct)
//!     6. Both derive pq_key = HKDF-SHA256(mlkem_ss, "arkos-pq-v1")
//!   All subsequent application messages are wrapped with a second
//!   ChaCha20-Poly1305 layer keyed by pq_key before being handed to Noise:
//!     plaintext → ChaCha20Poly1305(pq_key, nonce) → Noise encryption → wire
//!   Both layers must be broken simultaneously to compromise confidentiality.
//!
//! Message framing uses a 4-byte big-endian length prefix.
//! Each Noise transport message is limited to NOISE_MAX_PLAINTEXT bytes.
//! Larger payloads are automatically split across multiple transport frames.

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit as AeadKeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::{
    EncapsulationKey, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit},
};
use sha2::Sha256;
use snow::{Builder, HandshakeState, TransportState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as TokioMutex;

/// Noise_XX pattern descriptor
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext bytes per Noise transport message (protocol limit is 65535;
/// we stay well below to leave room for the 16-byte AEAD tag + PQ AEAD tag).
const NOISE_MAX_PLAINTEXT: usize = 65_487; // 65519 - 32 byte PQ tag overhead

/// Maximum total message size (32 MB) — enforced at the framing layer.
pub const NOISE_MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// Derive a 32-byte PQ session key from the ML-KEM-768 shared secret.
fn derive_pq_key(mlkem_ss: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, mlkem_ss);
    let mut pq_key = [0u8; 32];
    hk.expand(b"arkos-pq-v1", &mut pq_key)
        .expect("32-byte HKDF output fits");
    pq_key
}

/// Encrypt `plaintext` in-place with ChaCha20-Poly1305 using the PQ key.
/// The 12-byte nonce is derived from `counter` (8 LE bytes, 4 zero bytes prepended).
fn pq_encrypt(pq_key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(pq_key).expect("32-byte key");
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce, b"", &mut buf)
        .expect("ChaCha20Poly1305 encrypt");
    buf
}

/// Decrypt a ChaCha20-Poly1305 ciphertext (with 16-byte auth tag appended).
fn pq_decrypt(pq_key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(pq_key).expect("32-byte key");
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place(nonce, b"", &mut buf)
        .map_err(|_| anyhow::anyhow!("PQ layer authentication failed — possible quantum attack or tampering"))?;
    Ok(buf)
}

/// A Noise-encrypted + ML-KEM-768 hybrid peer connection.
///
/// The `transport` is behind a `Mutex` so the read and write halves can
/// be used concurrently from different async tasks.
///
/// `send_counter` and `recv_counter` track the ChaCha20-Poly1305 nonces for
/// the PQ layer.  They start at 0 and increment monotonically.
pub struct NoiseConn {
    pub addr: String,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    transport: Arc<TokioMutex<TransportState>>,
    /// Post-quantum session key derived from ML-KEM-768 shared secret.
    pq_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

/// Read-only half of a split `NoiseConn`.
///
/// Obtained via [`NoiseConn::into_split`].  Owns the TCP read half and a shared
/// reference to the Noise transport state.  Read and write operations use
/// separate Noise nonces so holding the transport mutex independently is safe.
pub struct NoiseReader {
    reader: OwnedReadHalf,
    transport: Arc<TokioMutex<TransportState>>,
    pq_key: [u8; 32],
    recv_counter: u64,
}

/// Write-only half of a split `NoiseConn`.
///
/// Obtained via [`NoiseConn::into_split`].
pub struct NoiseWriter {
    writer: OwnedWriteHalf,
    transport: Arc<TokioMutex<TransportState>>,
    pq_key: [u8; 32],
    send_counter: u64,
}

impl NoiseConn {
    /// Perform the Noise_XX initiator handshake followed by the ML-KEM-768
    /// post-quantum key exchange.  Returns a fully hybrid-encrypted connection.
    pub async fn connect(
        mut reader: OwnedReadHalf,
        mut writer: OwnedWriteHalf,
        addr: String,
        local_keypair: &snow::Keypair,
    ) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&local_keypair.private)
            .build_initiator()?;
        let transport = Arc::new(TokioMutex::new(
            handshake(builder, &mut reader, &mut writer).await?,
        ));
        let pq_key = mlkem_initiator(&mut reader, &mut writer, &transport).await?;
        Ok(NoiseConn {
            addr,
            reader,
            writer,
            transport,
            pq_key,
            send_counter: 0,
            recv_counter: 0,
        })
    }

    /// Perform the Noise_XX responder handshake followed by the ML-KEM-768
    /// post-quantum key exchange.  Returns a fully hybrid-encrypted connection.
    pub async fn accept(
        mut reader: OwnedReadHalf,
        mut writer: OwnedWriteHalf,
        local_keypair: &snow::Keypair,
        addr: String,
    ) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&local_keypair.private)
            .build_responder()?;
        let transport = Arc::new(TokioMutex::new(
            handshake(builder, &mut reader, &mut writer).await?,
        ));
        let pq_key = mlkem_responder(&mut reader, &mut writer, &transport).await?;
        Ok(NoiseConn {
            addr,
            reader,
            writer,
            transport,
            pq_key,
            send_counter: 0,
            recv_counter: 0,
        })
    }

    /// Split this connection into independent read and write halves.
    ///
    /// The Noise transport state is shared via `Arc<Mutex<...>>`; read and
    /// write use separate Noise nonces so concurrent use of both halves is safe.
    /// Each half gets its own PQ-layer counter.
    pub fn into_split(self) -> (NoiseReader, NoiseWriter) {
        let transport = self.transport;
        (
            NoiseReader {
                reader: self.reader,
                transport: transport.clone(),
                pq_key: self.pq_key,
                recv_counter: self.recv_counter,
            },
            NoiseWriter {
                writer: self.writer,
                transport,
                pq_key: self.pq_key,
                send_counter: self.send_counter,
            },
        )
    }

    /// Send a plaintext message.  The PQ layer encrypts first, then Noise
    /// wraps the result.  Automatically splits at NOISE_MAX_PLAINTEXT.
    pub async fn send_raw(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; NOISE_MAX_PLAINTEXT + 16];
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + NOISE_MAX_PLAINTEXT - 16).min(plaintext.len());
            let chunk = &plaintext[offset..end];
            let pq_ct = pq_encrypt(&self.pq_key, self.send_counter, chunk);
            self.send_counter += 1;
            let n = {
                let mut transport = self.transport.lock().await;
                transport.write_message(&pq_ct, &mut buf)?
            };
            self.writer.write_all(&(n as u32).to_be_bytes()).await?;
            self.writer.write_all(&buf[..n]).await?;
            offset = end;
        }
        Ok(())
    }

    /// Receive and decrypt the next message (Noise outer → PQ inner).
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > NOISE_MAX_MESSAGE {
            bail!("noise message too large: {} bytes", len);
        }
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).await?;
        let mut noise_pt = vec![0u8; len];
        let n = {
            let mut transport = self.transport.lock().await;
            transport.read_message(&ciphertext, &mut noise_pt)?
        };
        noise_pt.truncate(n);
        let plaintext = pq_decrypt(&self.pq_key, self.recv_counter, &noise_pt)?;
        self.recv_counter += 1;
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
    /// Receive and decrypt the next Noise + PQ hybrid frame.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > NOISE_MAX_MESSAGE {
            bail!("noise message too large: {} bytes", len);
        }
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).await?;
        let mut noise_pt = vec![0u8; len];
        let n = {
            let mut transport = self.transport.lock().await;
            transport.read_message(&ciphertext, &mut noise_pt)?
        };
        noise_pt.truncate(n);
        let plaintext = pq_decrypt(&self.pq_key, self.recv_counter, &noise_pt)?;
        self.recv_counter += 1;
        Ok(plaintext)
    }
}

impl NoiseWriter {
    /// Encrypt with PQ layer then Noise.  Splits automatically at NOISE_MAX_PLAINTEXT.
    pub async fn send_raw(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; NOISE_MAX_PLAINTEXT + 16];
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + NOISE_MAX_PLAINTEXT - 16).min(plaintext.len());
            let chunk = &plaintext[offset..end];
            let pq_ct = pq_encrypt(&self.pq_key, self.send_counter, chunk);
            self.send_counter += 1;
            let n = {
                let mut transport = self.transport.lock().await;
                transport.write_message(&pq_ct, &mut buf)?
            };
            self.writer.write_all(&(n as u32).to_be_bytes()).await?;
            self.writer.write_all(&buf[..n]).await?;
            offset = end;
        }
        Ok(())
    }
}

/// ML-KEM-768 key exchange — initiator side.
///
/// Sends the encapsulation key, receives the ciphertext, decapsulates,
/// and returns the 32-byte PQ session key.
async fn mlkem_initiator(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    transport: &Arc<TokioMutex<TransportState>>,
) -> Result<[u8; 32]> {
    // Generate ephemeral ML-KEM-768 keypair
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes();

    // Send encapsulation key (1184 bytes) through the Noise channel
    noise_send_raw(writer, transport, ek_bytes.as_ref()).await?;

    // Receive ciphertext (1088 bytes) from responder, decapsulate
    let ct_bytes = noise_recv_raw(reader, transport).await?;
    let ss = dk.decapsulate_slice(&ct_bytes)
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 decapsulation failed (ciphertext size mismatch)"))?;

    Ok(derive_pq_key(ss.as_ref()))
}

/// ML-KEM-768 key exchange — responder side.
///
/// Receives the encapsulation key, encapsulates, sends ciphertext,
/// and returns the 32-byte PQ session key.
async fn mlkem_responder(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    transport: &Arc<TokioMutex<TransportState>>,
) -> Result<[u8; 32]> {
    // Receive initiator's encapsulation key (1184 bytes)
    let ek_bytes = noise_recv_raw(reader, transport).await?;
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(&ek_bytes)
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key from initiator"))?;

    // Encapsulate → (ciphertext, shared secret)
    let (ct, ss) = ek.encapsulate();

    // Send ciphertext (1088 bytes) back through Noise channel
    noise_send_raw(writer, transport, ct.as_ref()).await?;

    Ok(derive_pq_key(ss.as_ref()))
}

/// Send a raw buffer through the Noise transport without any PQ layer.
/// Used only during the ML-KEM handshake exchange itself.
async fn noise_send_raw(
    writer: &mut OwnedWriteHalf,
    transport: &Arc<TokioMutex<TransportState>>,
    plaintext: &[u8],
) -> Result<()> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let n = {
        let mut t = transport.lock().await;
        t.write_message(plaintext, &mut buf)?
    };
    writer.write_all(&(n as u32).to_be_bytes()).await?;
    writer.write_all(&buf[..n]).await?;
    Ok(())
}

/// Receive a raw buffer from the Noise transport without any PQ layer.
/// Used only during the ML-KEM handshake exchange itself.
async fn noise_recv_raw(
    reader: &mut OwnedReadHalf,
    transport: &Arc<TokioMutex<TransportState>>,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > NOISE_MAX_MESSAGE {
        bail!("ML-KEM handshake message too large: {} bytes", len);
    }
    let mut ciphertext = vec![0u8; len];
    reader.read_exact(&mut ciphertext).await?;
    let mut plaintext = vec![0u8; len];
    let n = {
        let mut t = transport.lock().await;
        t.read_message(&ciphertext, &mut plaintext)?
    };
    plaintext.truncate(n);
    Ok(plaintext)
}

/// Generate a new X25519 static keypair for use with the Noise protocol.
pub fn generate_keypair() -> Result<snow::Keypair> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    Ok(builder.generate_keypair()?)
}
