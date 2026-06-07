//! Vault: AES-256-GCM encrypted key storage with Argon2id key derivation.
//!
//! Keys are NEVER stored in plaintext. The vault file is an encrypted blob.
//! Even if someone steals the file, they cannot read it without the passphrase.
//!
//! Flow:  passphrase → Argon2id → 256-bit key → AES-256-GCM(encrypt/decrypt)

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{bail, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher, PasswordVerifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

/// What gets encrypted inside the vault
#[derive(Serialize, Deserialize)]
pub struct VaultContents {
    pub secret_keys: Vec<String>, // hex-encoded secret keys
    pub labels: Vec<String>,      // human-friendly label per key
    pub created_at: u64,
}

/// The encrypted file format
#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub argon2_salt: String,     // base64-encoded 16-byte salt
    pub nonce: String,           // base64-encoded 12-byte nonce
    pub ciphertext: String,      // base64-encoded encrypted blob
    pub passphrase_hash: String, // argon2 hash to verify passphrase before decrypt
}

/// Derive a 256-bit encryption key from a passphrase using Argon2id.
///
/// Parameters:
///   - Memory: 64 MB  (m=65536)
///   - Iterations: 3  (t=3)
///   - Parallelism: 4 (p=4)
///   - Output: 32 bytes (AES-256 key)
///
/// Argon2id is the OWASP-recommended KDF for password storage and key
/// derivation. The 64 MB memory cost makes GPU/ASIC brute-force expensive.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("argon2 params"),
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .expect("argon2 kdf");
    key
}

pub fn create_vault(
    passphrase: &str,
    secret_keys: Vec<String>,
    labels: Vec<String>,
    path: &Path,
) -> Result<()> {
    if passphrase.len() < 12 {
        bail!("Passphrase must be at least 12 characters");
    }

    let contents = VaultContents {
        secret_keys,
        labels,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let plaintext = serde_json::to_vec(&contents)?;

    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive encryption key
    let mut enc_key = derive_key(passphrase.as_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&enc_key).expect("aes key");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    // Zero out the key from memory immediately
    enc_key.zeroize();

    // Hash passphrase for quick verification
    let salt_string =
        SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt encode failed: {}", e))?;
    let argon2 = Argon2::default();
    let pass_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("hash failed: {}", e))?
        .to_string();

    let vault_file = VaultFile {
        version: 1,
        argon2_salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes),
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
        passphrase_hash: pass_hash,
    };

    let json = serde_json::to_string_pretty(&vault_file)?;

    // Write with restrictive permissions (owner-only read/write)
    std::fs::write(path, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn open_vault(passphrase: &str, path: &Path) -> Result<VaultContents> {
    let json = std::fs::read_to_string(path)?;
    let vault_file: VaultFile = serde_json::from_str(&json)?;

    if vault_file.version != 1 {
        bail!("unsupported vault version: {}", vault_file.version);
    }

    // Verify passphrase first (fast fail)
    let parsed_hash = argon2::password_hash::PasswordHash::new(&vault_file.passphrase_hash)
        .map_err(|e| anyhow::anyhow!("invalid hash: {}", e))?;
    Argon2::default()
        .verify_password(passphrase.as_bytes(), &parsed_hash)
        .map_err(|_| anyhow::anyhow!("wrong passphrase"))?;

    // Decrypt
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD.decode(&vault_file.argon2_salt)?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&vault_file.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&vault_file.ciphertext)?;

    let mut enc_key = derive_key(passphrase.as_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&enc_key).expect("aes key");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — tampered vault or wrong passphrase"))?;

    enc_key.zeroize();

    let contents: VaultContents = serde_json::from_slice(&plaintext)?;
    Ok(contents)
}
