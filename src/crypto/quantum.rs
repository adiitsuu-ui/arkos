//! Hybrid post-quantum signature scheme: ECDSA (secp256k1) + CRYSTALS-Dilithium Level 3.
//!
//! WHY HYBRID?
//!   - If quantum computers break ECDSA → Dilithium still protects you
//!   - If Dilithium has an undiscovered flaw → ECDSA still protects you
//!   - Both must verify for a signature to be valid (belt AND suspenders)
//!
//! CRYSTALS-Dilithium (NIST FIPS 204 / ML-DSA):
//!   - Based on lattice problems (Module-LWE / Module-SIS)
//!   - No known quantum algorithm can break it
//!   - NIST selected it as the primary post-quantum signature standard (2024)
//!   - Level 3 provides ~128-bit post-quantum security
//!
//! KEY SIZES (Dilithium Level 3):
//!   Public key:  1,952 bytes
//!   Secret key:  4,000 bytes
//!   Signature:   3,293 bytes
//!
//! TOTAL HYBRID SIGNATURE:
//!   ECDSA compact sig (64 bytes) + Dilithium sig (3,293 bytes) = 3,357 bytes
//!   This is larger than pure ECDSA but the quantum security is worth it.

use anyhow::{bail, Result};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

/// A hybrid keypair: classical ECDSA + post-quantum Dilithium
pub struct HybridKeyPair {
    // Classical (ECDSA secp256k1)
    pub ecdsa_secret: SecretKey,
    pub ecdsa_public: PublicKey,
    // Post-quantum (Dilithium Level 3)
    pub dilithium_secret: Vec<u8>,
    pub dilithium_public: Vec<u8>,
}

/// A hybrid signature: both ECDSA and Dilithium signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ecdsa_sig: Vec<u8>,     // 64 bytes (compact ECDSA)
    pub dilithium_sig: Vec<u8>, // 3,293 bytes (Dilithium Level 3)
}

/// A hybrid public key for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ecdsa_pubkey: Vec<u8>,     // 33 bytes (compressed secp256k1)
    pub dilithium_pubkey: Vec<u8>, // 1,952 bytes (Dilithium Level 3)
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Self {
        // Classical ECDSA
        let secp = Secp256k1::new();
        let (ecdsa_secret, ecdsa_public) = secp.generate_keypair(&mut rand::thread_rng());

        // Post-quantum Dilithium
        let (pq_pk, pq_sk) = dilithium3::keypair();
        let dilithium_public = pq_pk.as_bytes().to_vec();
        let dilithium_secret = pq_sk.as_bytes().to_vec();

        HybridKeyPair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret,
            dilithium_public,
        }
    }

    /// Reconstruct a stored hybrid keypair from all three key components.
    ///
    /// This is the **only** correct way to reconstruct a keypair from stored bytes.
    /// All three components are required: ECDSA secret, Dilithium secret, and
    /// Dilithium public key. Both are validated before returning.
    ///
    /// The Dilithium public key cannot be re-derived from the secret key using
    /// the `pqcrypto` API, so it must always be stored alongside the secret.
    pub fn from_parts(
        ecdsa_secret_bytes: &[u8],
        dilithium_secret_bytes: &[u8],
        dilithium_public_bytes: &[u8],
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let ecdsa_secret = SecretKey::from_slice(ecdsa_secret_bytes)?;
        let ecdsa_public = PublicKey::from_secret_key(&secp, &ecdsa_secret);

        // Validate the Dilithium secret key
        dilithium3::SecretKey::from_bytes(dilithium_secret_bytes)
            .map_err(|_| anyhow::anyhow!("invalid dilithium secret key"))?;

        // Validate the Dilithium public key
        dilithium3::PublicKey::from_bytes(dilithium_public_bytes)
            .map_err(|_| anyhow::anyhow!("invalid dilithium public key"))?;

        Ok(HybridKeyPair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret: dilithium_secret_bytes.to_vec(),
            dilithium_public: dilithium_public_bytes.to_vec(),
        })
    }

    /// Get the hybrid public key
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ecdsa_pubkey: self.ecdsa_public.serialize().to_vec(),
            dilithium_pubkey: self.dilithium_public.clone(),
        }
    }

    /// Sign a message with BOTH algorithms
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // 1. ECDSA signature
        let secp = Secp256k1::new();
        let msg_hash = crate::crypto::hash::hash256(message);
        let ecdsa_msg = secp256k1::Message::from_digest(msg_hash);
        let ecdsa_sig = secp.sign_ecdsa(&ecdsa_msg, &self.ecdsa_secret);

        // 2. Dilithium signature (signs the raw message, not just the hash)
        let pq_sk =
            dilithium3::SecretKey::from_bytes(&self.dilithium_secret).expect("valid dilithium sk");
        let pq_sig = dilithium3::detached_sign(message, &pq_sk);

        HybridSignature {
            ecdsa_sig: ecdsa_sig.serialize_compact().to_vec(),
            dilithium_sig: pq_sig.as_bytes().to_vec(),
        }
    }

    /// Hex-encoded secrets for vault storage
    pub fn ecdsa_secret_hex(&self) -> String {
        hex::encode(self.ecdsa_secret.secret_bytes())
    }

    pub fn dilithium_secret_hex(&self) -> String {
        hex::encode(&self.dilithium_secret)
    }

    pub fn dilithium_public_hex(&self) -> String {
        hex::encode(&self.dilithium_public)
    }
}

impl HybridPublicKey {
    pub fn to_hex(&self) -> String {
        // Concatenate both pubkeys with a separator length prefix
        let ecdsa_len = self.ecdsa_pubkey.len() as u16;
        let mut data = Vec::new();
        data.extend_from_slice(&ecdsa_len.to_be_bytes());
        data.extend_from_slice(&self.ecdsa_pubkey);
        data.extend_from_slice(&self.dilithium_pubkey);
        hex::encode(&data)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let data = hex::decode(hex_str)?;
        if data.len() < 4 {
            bail!("hybrid pubkey too short");
        }
        let ecdsa_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + ecdsa_len {
            bail!("hybrid pubkey truncated");
        }
        let ecdsa_pubkey = data[2..2 + ecdsa_len].to_vec();
        let dilithium_pubkey = data[2 + ecdsa_len..].to_vec();

        Ok(HybridPublicKey {
            ecdsa_pubkey,
            dilithium_pubkey,
        })
    }
}

impl HybridSignature {
    /// Verify that BOTH the classical and post-quantum signatures are valid.
    /// BOTH must pass — if either fails, the signature is rejected.
    pub fn verify(&self, message: &[u8], pubkey: &HybridPublicKey) -> Result<()> {
        // 1. Verify ECDSA
        let secp = Secp256k1::new();
        let msg_hash = crate::crypto::hash::hash256(message);
        let ecdsa_msg = secp256k1::Message::from_digest(msg_hash);
        let ecdsa_pk = PublicKey::from_slice(&pubkey.ecdsa_pubkey)
            .map_err(|_| anyhow::anyhow!("invalid ECDSA public key"))?;
        let ecdsa_sig = secp256k1::ecdsa::Signature::from_compact(&self.ecdsa_sig)
            .map_err(|_| anyhow::anyhow!("invalid ECDSA signature format"))?;
        secp.verify_ecdsa(&ecdsa_msg, &ecdsa_sig, &ecdsa_pk)
            .map_err(|_| anyhow::anyhow!("ECDSA signature verification FAILED"))?;

        // 2. Verify Dilithium (post-quantum)
        let pq_pk = dilithium3::PublicKey::from_bytes(&pubkey.dilithium_pubkey)
            .map_err(|_| anyhow::anyhow!("invalid Dilithium public key"))?;
        let pq_sig = dilithium3::DetachedSignature::from_bytes(&self.dilithium_sig)
            .map_err(|_| anyhow::anyhow!("invalid Dilithium signature format"))?;
        dilithium3::verify_detached_signature(&pq_sig, message, &pq_pk).map_err(|_| {
            anyhow::anyhow!("DILITHIUM signature verification FAILED — possible quantum attack")
        })?;

        Ok(())
    }

    /// Total size of the hybrid signature in bytes
    pub fn size(&self) -> usize {
        self.ecdsa_sig.len() + self.dilithium_sig.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let kp = HybridKeyPair::generate();
        let msg = b"transfer 100 ARKOS to alice";
        let sig = kp.sign(msg);
        let pk = kp.public_key();
        assert!(sig.verify(msg, &pk).is_ok());
    }

    #[test]
    fn test_hybrid_tampered_message() {
        let kp = HybridKeyPair::generate();
        let msg = b"transfer 100 ARKOS to alice";
        let sig = kp.sign(msg);
        let pk = kp.public_key();
        // Tampered message
        let tampered = b"transfer 999 ARKOS to eve";
        assert!(sig.verify(tampered, &pk).is_err());
    }

    #[test]
    fn test_hybrid_wrong_key() {
        let kp1 = HybridKeyPair::generate();
        let kp2 = HybridKeyPair::generate();
        let msg = b"hello quantum world";
        let sig = kp1.sign(msg);
        // Verify with wrong key
        assert!(sig.verify(msg, &kp2.public_key()).is_err());
    }

    #[test]
    fn test_hybrid_partial_forgery_ecdsa_only() {
        // Attacker has a quantum computer, forges ECDSA but not Dilithium
        let kp = HybridKeyPair::generate();
        let msg = b"steal all the coins";
        let sig = kp.sign(msg);

        // Tamper: replace Dilithium sig with garbage (simulating broken Dilithium)
        let mut forged = sig.clone();
        forged.dilithium_sig = vec![0u8; forged.dilithium_sig.len()];
        assert!(
            forged.verify(msg, &kp.public_key()).is_err(),
            "forged Dilithium sig must be rejected"
        );
    }

    #[test]
    fn test_hybrid_partial_forgery_dilithium_only() {
        // Classical attacker forges Dilithium but not ECDSA
        let kp = HybridKeyPair::generate();
        let msg = b"steal all the coins";
        let sig = kp.sign(msg);

        // Tamper: replace ECDSA sig with garbage
        let mut forged = sig.clone();
        forged.ecdsa_sig = vec![0u8; 64];
        assert!(
            forged.verify(msg, &kp.public_key()).is_err(),
            "forged ECDSA sig must be rejected"
        );
    }

    #[test]
    fn test_hybrid_pubkey_roundtrip() {
        let kp = HybridKeyPair::generate();
        let pk = kp.public_key();
        let hex_str = pk.to_hex();
        let recovered = HybridPublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(pk.ecdsa_pubkey, recovered.ecdsa_pubkey);
        assert_eq!(pk.dilithium_pubkey, recovered.dilithium_pubkey);
    }

    #[test]
    fn test_signature_sizes() {
        let kp = HybridKeyPair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(
            sig.ecdsa_sig.len(),
            64,
            "ECDSA compact sig should be 64 bytes"
        );
        assert_eq!(
            sig.dilithium_sig.len(),
            3309,
            "Dilithium3 sig should be 3309 bytes"
        );
        println!("Hybrid signature total size: {} bytes", sig.size());
        println!("  ECDSA:     {} bytes", sig.ecdsa_sig.len());
        println!("  Dilithium: {} bytes", sig.dilithium_sig.len());
    }
}
