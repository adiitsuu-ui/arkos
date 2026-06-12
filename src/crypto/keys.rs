use anyhow::Result;
use p256::ecdsa::signature::Verifier;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub type Address = [u8; 20];

pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret, public) = secp.generate_keypair(&mut rand::thread_rng());
        KeyPair { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(bytes)?;
        let public = PublicKey::from_secret_key(&secp, &secret);
        Ok(KeyPair { secret, public })
    }

    pub fn address(&self) -> Address {
        pubkey_to_address(&self.public)
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.secret_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.serialize())
    }

    pub fn address_hex(&self) -> String {
        hex::encode(self.address())
    }
}

/// Derive a 20-byte address from a compressed public key (ECDSA-only).
///
/// DEPRECATED: commits only to the ECDSA key. Use hybrid_pubkey_to_address
/// for all new code so that addresses bind both ECDSA and ML-DSA keys.
pub fn pubkey_to_address(pubkey: &PublicKey) -> Address {
    let sha = Sha256::digest(pubkey.serialize());
    let sha2 = Sha256::digest(&sha);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sha2[..20]);
    addr
}

/// Hybrid address: commits to BOTH the ECDSA and ML-DSA-65 public keys.
///
/// Algorithm: SHA256(SHA256(ecdsa_pk_compressed || ml_dsa_pk))[..20]
///
/// This prevents a quantum attacker who has broken secp256k1 ECDSA from
/// substituting their own ML-DSA key and spending UTXOs. Both keys are bound
/// at address creation time, so any substitution produces a different address.
pub fn hybrid_pubkey_to_address(ecdsa_pk: &PublicKey, ml_dsa_pk: &[u8]) -> Address {
    let mut preimage = Vec::with_capacity(33 + ml_dsa_pk.len());
    preimage.extend_from_slice(&ecdsa_pk.serialize());
    preimage.extend_from_slice(ml_dsa_pk);
    let sha1 = Sha256::digest(&preimage);
    let sha2 = Sha256::digest(&sha1);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sha2[..20]);
    addr
}

pub fn sign(secret: &SecretKey, hash: &[u8; 32]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest(*hash);
    let sig = secp.sign_ecdsa(&msg, secret);
    sig.serialize_compact().to_vec()
}

pub fn verify(pubkey: &PublicKey, hash: &[u8; 32], sig_bytes: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest(*hash);
    if let Ok(sig) = secp256k1::ecdsa::Signature::from_compact(sig_bytes) {
        secp.verify_ecdsa(&msg, &sig, pubkey).is_ok()
    } else {
        false
    }
}

/// Verify a signature given a raw compressed public key (33 bytes).
/// Returns false on any parse error rather than panicking.
pub fn verify_raw(pubkey_bytes: &[u8], hash: &[u8; 32], sig_bytes: &[u8]) -> bool {
    match PublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => verify(&pk, hash, sig_bytes),
        Err(_) => false,
    }
}

/// Verify a DER-encoded P-256 ECDSA signature against a SEC1 public key.
///
/// iOS Secure Enclave and Android Keystore both expose P-256 hardware-backed
/// signing. Their public keys are SEC1 points (usually 65-byte uncompressed)
/// and their ECDSA signatures are DER encoded.
pub fn verify_p256_der(pubkey_bytes: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    let Ok(verifying_key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey_bytes) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_der(sig_der) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}
