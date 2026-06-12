use crate::crypto::keys::hybrid_pubkey_to_address;
use crate::crypto::quantum::HybridKeyPair;
use crate::transaction::tx::{Transaction, TxInput, TxOutput};
use crate::transaction::utxo::UtxoSet;
use anyhow::Result;
use zeroize::Zeroizing;

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
