use crate::crypto::keys::hybrid_pubkey_to_address;
use crate::crypto::quantum::HybridKeyPair;
use crate::transaction::tx::{Transaction, TxInput, TxOutput};
use crate::transaction::utxo::UtxoSet;
use anyhow::Result;
use hmac::{Hmac, Mac};
use secp256k1::{Scalar, Secp256k1};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;
type HmacSha256Hd = Hmac<Sha256>;

pub struct Wallet {
    pub keypair: HybridKeyPair,
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            keypair: HybridKeyPair::generate(),
        }
    }

    pub fn from_secret_hex(hex: &str) -> Result<Self> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 4 || parts[0] != "hybrid" {
            anyhow::bail!("wallet key is not a hybrid Arkos key");
        }
        let ecdsa_secret = hex::decode(parts[1])?;
        let dilithium_secret = hex::decode(parts[2])?;
        let dilithium_public = hex::decode(parts[3])?;
        Ok(Wallet {
            keypair: HybridKeyPair::from_parts(
                &ecdsa_secret,
                &dilithium_secret,
                &dilithium_public,
            )?,
        })
    }

    pub fn address(&self) -> String {
        hex::encode(hybrid_pubkey_to_address(
            &self.keypair.ecdsa_public,
            &self.keypair.dilithium_public,
        ))
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.ecdsa_public.serialize())
    }

    /// Returns the full hybrid secret in `hybrid:<ecdsa>:<dil_sk>:<dil_pk>` format.
    /// Wrapped in `Zeroizing` so the 4000-byte Dilithium secret is wiped from
    /// the heap when the caller drops it.
    pub fn secret_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "hybrid:{}:{}:{}",
            self.keypair.ecdsa_secret_hex(),
            self.keypair.dilithium_secret_hex(),
            self.keypair.dilithium_public_hex()
        ))
    }

    /// Generate a new wallet and return it together with its 24-word BIP39
    /// recovery phrase.  The phrase encodes the ECDSA private key; restoring
    /// it via [`from_phrase`] recovers the same ECDSA key and the same
    /// ML-DSA-65 key (derived deterministically via HMAC-SHA256 from the
    /// ECDSA secret).  See the quantum module for the security caveat on
    /// phrase-only recovery.
    pub fn generate_with_phrase() -> (Self, String) {
        use bip39::{Language, Mnemonic};
        use rand::RngCore;
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("32-byte entropy is valid for BIP39");
        let keypair = HybridKeyPair::from_ecdsa_secret_bytes(&entropy)
            .expect("32-byte entropy is valid for secp256k1");
        (Wallet { keypair }, mnemonic.to_string())
    }

    /// Derive the 24-word BIP39 recovery phrase from this wallet's ECDSA secret.
    pub fn phrase(&self) -> String {
        use bip39::{Language, Mnemonic};
        let entropy = self.keypair.ecdsa_secret.secret_bytes();
        Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("32-byte ECDSA secret is valid BIP39 entropy")
            .to_string()
    }

    /// Restore a wallet from a 24-word BIP39 recovery phrase.
    ///
    /// The phrase must be 24 words (256-bit entropy).  Both the ECDSA key
    /// and the ML-DSA-65 key are fully recovered — the ML-DSA seed is
    /// derived deterministically from the ECDSA secret (HMAC-SHA256 with
    /// domain tag "arkos-mldsa-v1"), so the same phrase always restores
    /// the same address and signing keys.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        use bip39::{Language, Mnemonic};
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| anyhow::anyhow!("invalid recovery phrase: {}", e))?;
        let entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            anyhow::bail!("phrase must be 24 words (256-bit / 32-byte entropy)");
        }
        let keypair = HybridKeyPair::from_ecdsa_secret_bytes(&entropy)?;
        Ok(Wallet { keypair })
    }

    /// Build and sign a transaction sending `amount` arkes to `recipient`.
    pub fn send(
        &self,
        recipient: &str,
        amount: u64,
        fee: u64,
        utxo_set: &UtxoSet,
        network_magic: u32,
    ) -> Result<Transaction> {
        let my_addr = self.address();
        let mut utxos = utxo_set.utxos_for(&my_addr);

        // Simple coin selection: accumulate until we have enough
        let needed = amount + fee;
        let mut collected: u64 = 0;
        let mut selected = Vec::new();
        for utxo in utxos.drain(..) {
            collected += utxo.output.value;
            selected.push(utxo);
            if collected >= needed {
                break;
            }
        }
        if collected < needed {
            anyhow::bail!("insufficient funds: have {}, need {}", collected, needed);
        }

        let mut outputs = vec![TxOutput {
            value: amount,
            address: recipient.to_string(),
        }];
        let change = collected - needed;
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                address: my_addr.clone(),
            });
        }

        // Build unsigned transaction to get sig_hash
        let inputs_unsigned: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                prev_tx_hash: u.tx_hash.clone(),
                prev_index: u.index,
                signature: crate::crypto::quantum::HybridSignature {
                    ecdsa_sig: vec![],
                    dilithium_sig: vec![],
                },
                pubkey: self.keypair.public_key(),
                coinbase_extra: vec![],
            })
            .collect();

        let unsigned = Transaction::new(inputs_unsigned, outputs.clone());
        let sig_hash = unsigned.sig_hash(network_magic);
        let sig_message = sig_hash;
        let signature = self.keypair.sign(&sig_message);

        // Sign each input
        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                prev_tx_hash: u.tx_hash.clone(),
                prev_index: u.index,
                signature: signature.clone(),
                pubkey: self.keypair.public_key(),
                coinbase_extra: vec![],
            })
            .collect();

        Ok(Transaction::new(inputs, outputs))
    }
}

/// Hierarchical Deterministic wallet — BIP32-equivalent key derivation for Arkos.
///
/// From 32-byte entropy a master key and chain code are derived using
/// `HMAC-SHA512(key="Arkos seed", data=entropy)`.  Child keys are derived
/// with the same BIP32 non-hardened formula:
///   `I = HMAC-SHA512(key=chain_code, data=compressed_ecdsa_pubkey || index_BE)`
///   `child_ecdsa_secret = (parent_secret + I[..32]) mod n`
///   `child_chain_code = I[32..]`
///   `child_mldsa_seed = HMAC-SHA256(child_ecdsa_secret, "arkos-mldsa-v1")`
///
/// Derivation paths (unhardened):
///   - External receiving addresses: index 0 … u32::MAX (path equivalent: m/0/index)
///   - Internal change addresses: use `derive_change(index)` (path equivalent: m/1/index)
pub struct HdWallet {
    master_secret: secp256k1::SecretKey,
    master_chain_code: [u8; 32],
}

impl HdWallet {
    /// Create a master HD wallet from 32 bytes of BIP39 entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let mut mac = HmacSha512::new_from_slice(b"Arkos seed")
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(entropy);
        let result = mac.finalize().into_bytes();
        let master_secret = secp256k1::SecretKey::from_slice(&result[..32])
            .map_err(|_| anyhow::anyhow!("master key derivation produced an invalid scalar"))?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);
        Ok(HdWallet { master_secret, master_chain_code: chain_code })
    }

    /// Derive the Nth external (receiving) address wallet.
    pub fn derive_receiving(&self, index: u32) -> Result<Wallet> {
        self.derive_child_wallet(&self.master_secret, &self.master_chain_code, 0, index)
    }

    /// Derive the Nth internal (change) address wallet.
    pub fn derive_change(&self, index: u32) -> Result<Wallet> {
        self.derive_child_wallet(&self.master_secret, &self.master_chain_code, 1, index)
    }

    fn derive_child_wallet(
        &self,
        parent_secret: &secp256k1::SecretKey,
        parent_chain: &[u8; 32],
        account: u32,
        index: u32,
    ) -> Result<Wallet> {
        // First level: m / account
        let (acct_secret, acct_chain) = derive_child_key(parent_secret, parent_chain, account)?;
        // Second level: m / account / index
        let (child_secret, _) = derive_child_key(&acct_secret, &acct_chain, index)?;

        // Derive ML-DSA seed deterministically from the child ECDSA secret
        let keypair = HybridKeyPair::from_ecdsa_secret_bytes(&child_secret.secret_bytes())?;
        Ok(Wallet { keypair })
    }
}

/// BIP32-style non-hardened child key derivation.
///
/// Returns `(child_secret, child_chain_code)`.
fn derive_child_key(
    parent_secret: &secp256k1::SecretKey,
    parent_chain: &[u8; 32],
    index: u32,
) -> Result<(secp256k1::SecretKey, [u8; 32])> {
    let secp = Secp256k1::new();
    let parent_pub = secp256k1::PublicKey::from_secret_key(&secp, parent_secret);
    let parent_pub_bytes = parent_pub.serialize(); // 33 bytes compressed

    let mut mac = HmacSha512::new_from_slice(parent_chain)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(&parent_pub_bytes);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let tweak_bytes: [u8; 32] = result[..32].try_into().expect("32 bytes");
    let scalar = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| anyhow::anyhow!("child key derivation tweak is out of range at index {}", index))?;
    let child_secret = parent_secret
        .add_tweak(&scalar)
        .map_err(|_| anyhow::anyhow!("child key derivation failed at index {}", index))?;

    let mut child_chain = [0u8; 32];
    child_chain.copy_from_slice(&result[32..]);
    Ok((child_secret, child_chain))
}

#[cfg(test)]
mod hd_tests {
    use super::*;

    #[test]
    fn test_hd_wallet_deterministic() {
        let entropy = [0x11u8; 32];
        let hd = HdWallet::from_entropy(&entropy).unwrap();
        let w0a = hd.derive_receiving(0).unwrap();
        let w0b = hd.derive_receiving(0).unwrap();
        assert_eq!(w0a.address(), w0b.address(), "index 0 must be deterministic");

        let w1 = hd.derive_receiving(1).unwrap();
        assert_ne!(w0a.address(), w1.address(), "different indices must give different addresses");
    }

    #[test]
    fn test_hd_wallet_change_vs_receiving() {
        let entropy = [0x22u8; 32];
        let hd = HdWallet::from_entropy(&entropy).unwrap();
        let recv = hd.derive_receiving(0).unwrap();
        let change = hd.derive_change(0).unwrap();
        assert_ne!(recv.address(), change.address(), "receiving and change paths must differ");
    }

    #[test]
    fn test_hd_wallet_from_phrase() {
        use bip39::{Language, Mnemonic};
        let mut entropy = [0u8; 32];
        entropy[0] = 0xAB;
        let phrase = Mnemonic::from_entropy_in(Language::English, &entropy)
            .unwrap()
            .to_string();
        let hd1 = HdWallet::from_entropy(&entropy).unwrap();
        // Recover from phrase
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase).unwrap();
        let recovered_entropy = mnemonic.to_entropy();
        let hd2 = HdWallet::from_entropy(&recovered_entropy).unwrap();
        assert_eq!(
            hd1.derive_receiving(0).unwrap().address(),
            hd2.derive_receiving(0).unwrap().address(),
            "HD wallet must be recoverable from phrase entropy"
        );
    }
}
