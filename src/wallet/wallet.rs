use crate::crypto::keys::pubkey_to_address;
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
        hex::encode(pubkey_to_address(&self.keypair.ecdsa_public))
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

    /// Build and sign a transaction sending `amount` arkes to `recipient`.
    pub fn send(
        &self,
        recipient: &str,
        amount: u64,
        fee: u64,
        utxo_set: &UtxoSet,
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
        let sig_hash = unsigned.sig_hash();
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
