//! Access control system for the Arkos network.
//!
//! Architecture:
//!   - You hold a MASTER KEY (Ed25519 signing key).
//!   - You generate signed ACCESS TOKENS for anyone you want to grant access.
//!   - Each token has: permissions, expiry, and your signature.
//!   - Nodes verify tokens against your public master key.
//!   - Only you can issue tokens. Tokens can be revoked.
//!
//! This makes the network owner-controlled: nobody can connect, mine,
//! or submit transactions without a valid token signed by you.

use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// What a token holder is allowed to do
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Permission {
    Connect,   // connect to the network as a peer
    Mine,      // submit mined blocks
    Transact,  // send transactions
    ReadChain, // query blockchain data
    Admin,     // full access — can do anything
}

/// A signed access token — grants specific permissions to a holder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub holder_name: String,   // human label ("Alice", "Node-EU-1")
    pub holder_pubkey: String, // hex-encoded Ed25519 pubkey of the holder
    pub permissions: Vec<Permission>,
    pub issued_at: u64,    // unix timestamp
    pub expires_at: u64,   // unix timestamp (0 = never)
    pub token_id: String,  // unique ID for revocation
    pub signature: String, // hex-encoded Ed25519 signature by master key
}

/// The master key pair — only you hold this
pub struct MasterKey {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl MasterKey {
    /// Generate a new master key
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        MasterKey {
            signing_key,
            verifying_key,
        }
    }

    /// Load from a 32-byte secret
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        MasterKey {
            signing_key,
            verifying_key,
        }
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Issue an access token to someone
    pub fn issue_token(
        &self,
        holder_name: &str,
        holder_pubkey: &str,
        permissions: Vec<Permission>,
        expires_in_days: u64,
    ) -> AccessToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = if expires_in_days == 0 {
            0
        } else {
            now + expires_in_days * 86400
        };

        // Token ID = first 16 chars of SHA-256(holder_pubkey + issued_at)
        let id_data = format!("{}{}", holder_pubkey, now);
        let id_hash = sha2::Sha256::digest(id_data.as_bytes());
        let token_id = hex::encode(&id_hash[..8]);

        let mut token = AccessToken {
            holder_name: holder_name.to_string(),
            holder_pubkey: holder_pubkey.to_string(),
            permissions,
            issued_at: now,
            expires_at,
            token_id,
            signature: String::new(),
        };

        // Sign the canonical token data
        let signable = token.signable_bytes();
        let sig: Signature = self.signing_key.sign(&signable);
        token.signature = hex::encode(sig.to_bytes());
        token
    }

    /// Save master public key to a file (this is safe to share with nodes)
    pub fn save_public_key(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.public_hex())?;
        Ok(())
    }
}

impl AccessToken {
    /// The canonical bytes that get signed (everything except the signature field)
    fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.holder_name.as_bytes());
        data.extend_from_slice(self.holder_pubkey.as_bytes());
        for p in &self.permissions {
            data.extend_from_slice(format!("{:?}", p).as_bytes());
        }
        data.extend_from_slice(&self.issued_at.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        data.extend_from_slice(self.token_id.as_bytes());
        data
    }

    /// Verify this token was signed by the given master public key.
    ///
    /// Checks (in order):
    ///   1. Ed25519 signature is valid for the master public key.
    ///   2. Token has not expired (if `expires_at > 0`).
    ///   3. Token is not in the revocation list (if provided).
    pub fn verify(&self, master_pubkey_hex: &str) -> Result<()> {
        self.verify_with_revocation(master_pubkey_hex, None)
    }

    /// Same as `verify`, but also checks the provided revocation list.
    /// Pass `Some(&revocation_list)` from any path that has loaded one.
    pub fn verify_with_revocation(
        &self,
        master_pubkey_hex: &str,
        revocation: Option<&RevocationList>,
    ) -> Result<()> {
        let pubkey_bytes = hex::decode(master_pubkey_hex)?;
        if pubkey_bytes.len() != 32 {
            bail!("invalid master pubkey length");
        }
        let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|_| anyhow::anyhow!("invalid master pubkey"))?;

        let sig_bytes = hex::decode(&self.signature)?;
        if sig_bytes.len() != 64 {
            bail!("invalid signature length");
        }
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);

        let signable = self.signable_bytes();
        verifying_key
            .verify(&signable, &sig)
            .map_err(|_| anyhow::anyhow!("INVALID TOKEN: signature verification failed"))?;

        // Check expiry
        if self.expires_at > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > self.expires_at {
                bail!("TOKEN EXPIRED at {}", self.expires_at);
            }
        }

        // Check revocation list — must happen AFTER signature verification so
        // an attacker cannot probe the revocation list with forged token IDs.
        if let Some(rev) = revocation {
            if rev.is_revoked(&self.token_id) {
                bail!("TOKEN REVOKED (id: {})", self.token_id);
            }
        }

        Ok(())
    }

    pub fn has_permission(&self, p: &Permission) -> bool {
        self.permissions.contains(&Permission::Admin) || self.permissions.contains(p)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Revocation list — token IDs that have been revoked
#[derive(Default, Serialize, Deserialize)]
pub struct RevocationList {
    pub revoked_ids: Vec<String>,
}

impl RevocationList {
    pub fn revoke(&mut self, token_id: &str) {
        if !self.revoked_ids.contains(&token_id.to_string()) {
            self.revoked_ids.push(token_id.to_string());
        }
    }

    pub fn is_revoked(&self, token_id: &str) -> bool {
        self.revoked_ids.contains(&token_id.to_string())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

use sha2::Digest;
