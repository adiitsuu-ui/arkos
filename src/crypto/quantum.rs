//! Hybrid post-quantum signature scheme: ECDSA (secp256k1) + ML-DSA-65 (NIST FIPS 204).
//!
//! WHY HYBRID?
//!   - If quantum computers break ECDSA → ML-DSA still protects you
//!   - If ML-DSA has an undiscovered flaw → ECDSA still protects you
//!   - Both must verify for a signature to be valid (belt AND suspenders)
//!
//! ML-DSA-65 (NIST FIPS 204 / CRYSTALS-Dilithium successor):
//!   - Based on lattice problems (Module-LWE / Module-SIS)
//!   - No known quantum algorithm can break it
//!   - NIST selected it as the primary post-quantum digital signature standard (FIPS 204, 2024)
//!   - Level 65 provides ~128-bit post-quantum security (equivalent to Dilithium3)
//!
//! KEY SIZES (ML-DSA-65):
//!   Public key:  1,952 bytes
//!   Seed (stored as secret): 32 bytes — the signing key is derived on-the-fly at sign time
//!   Signature:   3,309 bytes
//!
//! KEY STORAGE DESIGN:
//!   The ML-DSA secret stored in the vault is a 32-byte seed, not the full signing key.
//!   The full signing key (~2 kB expanded form) is rederived from the seed for each signing
//!   operation. This keeps vault storage compact and makes phrase recovery possible.
//!
//! QUANTUM SECURITY NOTE ON PHRASE RECOVERY:
//!   For wallets restored via generate() the ML-DSA seed is independently random and
//!   is NOT derivable from the ECDSA public key — fully quantum-secure when used with vault backup.
//!   For wallets restored from BIP39 phrase alone (from_ecdsa_secret_bytes), the ML-DSA seed is
//!   derived deterministically from the ECDSA secret, so a quantum attacker who derives the ECDSA
//!   private key can also derive the ML-DSA key. Use vault backup for full quantum security.

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Seed, SignatureEncoding, Signer, Verifier,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A hybrid keypair: classical ECDSA + post-quantum ML-DSA-65
pub struct HybridKeyPair {
    // Classical (ECDSA secp256k1)
    pub ecdsa_secret: SecretKey,
    pub ecdsa_public: PublicKey,
    // Post-quantum (ML-DSA-65)
    // 32-byte seed stored; full signing key is derived at sign time
    pub dilithium_secret: Vec<u8>, // 32 bytes: the ML-DSA seed
    pub dilithium_public: Vec<u8>, // 1,952 bytes: encoded verifying key
}

/// A hybrid signature: both ECDSA and ML-DSA signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ecdsa_sig: Vec<u8>,      // 64 bytes (compact ECDSA)
    pub dilithium_sig: Vec<u8>,  // 3,309 bytes (ML-DSA-65)
}

/// A hybrid public key for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ecdsa_pubkey: Vec<u8>,     // 33 bytes (compressed secp256k1)
    pub dilithium_pubkey: Vec<u8>, // 1,952 bytes (ML-DSA-65 encoded verifying key)
}

/// Derive an ML-DSA-65 seed deterministically from an ECDSA secret key.
/// Used for BIP39 phrase recovery so the same phrase always gives the same ML-DSA key.
///
/// SECURITY: this is safe against classical attackers. A quantum attacker who breaks
/// secp256k1 and recovers the ECDSA private key can also derive this seed. For full
/// quantum security, use the vault backup which stores an independently-random ML-DSA seed.
fn derive_mldsa_seed_from_ecdsa(ecdsa_secret: &SecretKey) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(b"arkos-mldsa-v1")
        .expect("HMAC accepts any key length");
    mac.update(&ecdsa_secret.secret_bytes());
    mac.finalize().into_bytes().into()
}

fn mldsa_signing_key_from_seed(seed_bytes: &[u8]) -> Result<MlDsaSigningKey<MlDsa65>> {
    let arr: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-DSA seed must be exactly 32 bytes"))?;
    let seed = Seed::from(arr);
    Ok(MlDsaSigningKey::<MlDsa65>::from_seed(&seed))
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair with independently random ECDSA and ML-DSA seeds.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (ecdsa_secret, ecdsa_public) = secp.generate_keypair(&mut rand::thread_rng());

        // Generate an independent random 32-byte seed for ML-DSA
        let mut mldsa_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut mldsa_seed);

        let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&Seed::from(mldsa_seed));
        let vk = sk.verifying_key();
        let vk_bytes = vk.encode().as_slice().to_vec();

        HybridKeyPair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret: mldsa_seed.to_vec(),
            dilithium_public: vk_bytes,
        }
    }

    /// Reconstruct a stored hybrid keypair from all components.
    /// `dilithium_secret_bytes` must be exactly 32 bytes (the ML-DSA seed).
    pub fn from_parts(
        ecdsa_secret_bytes: &[u8],
        dilithium_secret_bytes: &[u8],
        dilithium_public_bytes: &[u8],
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let ecdsa_secret = SecretKey::from_slice(ecdsa_secret_bytes)?;
        let ecdsa_public = PublicKey::from_secret_key(&secp, &ecdsa_secret);

        // Validate: must be exactly 32 bytes (the ML-DSA seed)
        if dilithium_secret_bytes.len() != 32 {
            bail!(
                "ML-DSA seed must be 32 bytes, got {}",
                dilithium_secret_bytes.len()
            );
        }
        // Validate: derive signing key from seed and check public key matches
        let sk = mldsa_signing_key_from_seed(dilithium_secret_bytes)?;
        let derived_vk = sk.verifying_key();
        let derived_vk_bytes = derived_vk.encode().as_slice().to_vec();
        if derived_vk_bytes != dilithium_public_bytes {
            bail!("ML-DSA public key does not match seed");
        }

        Ok(HybridKeyPair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret: dilithium_secret_bytes.to_vec(),
            dilithium_public: dilithium_public_bytes.to_vec(),
        })
    }

    /// Restore a keypair from just the ECDSA secret bytes, deriving the ML-DSA seed
    /// deterministically. Used when recovering from a BIP39 mnemonic phrase.
    ///
    /// See module-level docs for the quantum-security caveat on this derivation.
    pub fn from_ecdsa_secret_bytes(ecdsa_secret_bytes: &[u8]) -> Result<Self> {
        let secp = Secp256k1::new();
        let ecdsa_secret = SecretKey::from_slice(ecdsa_secret_bytes)?;
        let ecdsa_public = PublicKey::from_secret_key(&secp, &ecdsa_secret);

        let mldsa_seed = derive_mldsa_seed_from_ecdsa(&ecdsa_secret);
        let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&Seed::from(mldsa_seed));
        let vk_bytes = sk.verifying_key().encode().as_slice().to_vec();

        Ok(HybridKeyPair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret: mldsa_seed.to_vec(),
            dilithium_public: vk_bytes,
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

        // 2. ML-DSA-65 signature (derived from seed on-the-fly)
        let sk = mldsa_signing_key_from_seed(&self.dilithium_secret)
            .expect("valid ML-DSA seed stored in keypair");
        let ml_sig = sk.sign(message);
        let ml_sig_bytes = ml_sig.to_vec();

        HybridSignature {
            ecdsa_sig: ecdsa_sig.serialize_compact().to_vec(),
            dilithium_sig: ml_sig_bytes,
        }
    }

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
        Ok(HybridPublicKey { ecdsa_pubkey, dilithium_pubkey })
    }
}

impl HybridSignature {
    /// Verify that BOTH the classical and post-quantum signatures are valid.
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

        // 2. Verify ML-DSA-65
        let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(pubkey.dilithium_pubkey.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 public key (wrong size)"))?;
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc_vk);
        let ml_sig = ml_dsa::Signature::<MlDsa65>::try_from(self.dilithium_sig.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 signature format"))?;
        vk.verify(message, &ml_sig)
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 signature verification FAILED — possible quantum attack"))?;

        Ok(())
    }

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
        assert!(sig.verify(b"transfer 999 ARKOS to eve", &pk).is_err());
    }

    #[test]
    fn test_hybrid_wrong_key() {
        let kp1 = HybridKeyPair::generate();
        let kp2 = HybridKeyPair::generate();
        let msg = b"hello quantum world";
        let sig = kp1.sign(msg);
        assert!(sig.verify(msg, &kp2.public_key()).is_err());
    }

    #[test]
    fn test_hybrid_partial_forgery_ecdsa_only() {
        let kp = HybridKeyPair::generate();
        let msg = b"steal all the coins";
        let sig = kp.sign(msg);
        let mut forged = sig.clone();
        forged.dilithium_sig = vec![0u8; forged.dilithium_sig.len()];
        assert!(forged.verify(msg, &kp.public_key()).is_err());
    }

    #[test]
    fn test_hybrid_partial_forgery_dilithium_only() {
        let kp = HybridKeyPair::generate();
        let msg = b"steal all the coins";
        let sig = kp.sign(msg);
        let mut forged = sig.clone();
        forged.ecdsa_sig = vec![0u8; 64];
        assert!(forged.verify(msg, &kp.public_key()).is_err());
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
    fn test_deterministic_recovery() {
        // generate() uses an independent random ML-DSA seed; the deterministic
        // derivation is only triggered by from_ecdsa_secret_bytes (phrase recovery).
        // Verify that calling from_ecdsa_secret_bytes twice with the same ECDSA bytes
        // always produces the same ML-DSA keys.
        let ecdsa_secret = secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let ecdsa_bytes = ecdsa_secret.secret_bytes();

        let kp1 = HybridKeyPair::from_ecdsa_secret_bytes(&ecdsa_bytes).unwrap();
        let kp2 = HybridKeyPair::from_ecdsa_secret_bytes(&ecdsa_bytes).unwrap();

        assert_eq!(kp1.dilithium_public, kp2.dilithium_public,
            "ML-DSA public key must be deterministic from ECDSA secret");
        assert_eq!(kp1.dilithium_secret, kp2.dilithium_secret,
            "ML-DSA seed must be deterministic from ECDSA secret");
        assert_eq!(kp1.ecdsa_public, kp2.ecdsa_public,
            "ECDSA public key must be deterministic from ECDSA secret");
    }

    #[test]
    fn test_from_parts_roundtrip() {
        let kp = HybridKeyPair::generate();
        let restored = HybridKeyPair::from_parts(
            &kp.ecdsa_secret.secret_bytes(),
            &kp.dilithium_secret,
            &kp.dilithium_public,
        ).unwrap();
        let msg = b"roundtrip test";
        let sig = restored.sign(msg);
        assert!(sig.verify(msg, &kp.public_key()).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let kp = HybridKeyPair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(sig.ecdsa_sig.len(), 64, "ECDSA compact sig should be 64 bytes");
        assert_eq!(sig.dilithium_sig.len(), 3309, "ML-DSA-65 sig should be 3309 bytes");
        println!("Hybrid signature total size: {} bytes", sig.size());
        println!("  ECDSA:     {} bytes", sig.ecdsa_sig.len());
        println!("  ML-DSA-65: {} bytes", sig.dilithium_sig.len());
    }
}
