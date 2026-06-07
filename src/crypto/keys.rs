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

/// Derive a 20-byte address from a compressed public key.
///
/// Algorithm: SHA-256(SHA-256(pubkey))[..20]
///
/// Note: this is intentionally NOT Bitcoin's RIPEMD-160(SHA-256(pubkey)).
/// Arkos uses a double-SHA-256 with 20-byte truncation. This is documented
/// as the canonical Arkos address derivation algorithm.
pub fn pubkey_to_address(pubkey: &PublicKey) -> Address {
    let sha = Sha256::digest(pubkey.serialize());
    let sha2 = Sha256::digest(&sha);
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
