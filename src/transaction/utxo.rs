use crate::transaction::tx::{Transaction, TxOutput};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub index: u32,
    pub output: TxOutput,
}

/// Blocks until a coinbase output can be spent (matches Bitcoin).
pub const COINBASE_MATURITY: u64 = 100;

/// In-memory UTXO set. In production this would be backed by RocksDB.
#[derive(Default, Clone)]
pub struct UtxoSet {
    // key: "txhash:index"
    utxos: HashMap<String, TxOutput>,
    // coinbase txid -> block height at which it was mined
    coinbase_heights: HashMap<String, u64>,
}

impl UtxoSet {
    fn key(tx_hash: &str, index: u32) -> String {
        format!("{}:{}", tx_hash, index)
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) {
        // Remove spent outputs
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let k = Self::key(&input.prev_tx_hash, input.prev_index);
                self.utxos.remove(&k);
            }
        }
        // Add new outputs
        let txid = tx.txid_hex();
        if tx.is_coinbase() {
            // Extract block height from coinbase_extra (little-endian u64)
            let height = tx.inputs[0].coinbase_extra
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            self.coinbase_heights.insert(txid.clone(), height);
        }
        for (i, output) in tx.outputs.iter().enumerate() {
            let k = Self::key(&txid, i as u32);
            self.utxos.insert(k, output.clone());
        }
    }

    /// Returns true if the UTXO is a coinbase output that has not yet matured.
    /// `current_height` is the height of the block being validated.
    pub fn is_immature_coinbase(&self, tx_hash: &str, current_height: u64) -> bool {
        if let Some(&mined_at) = self.coinbase_heights.get(tx_hash) {
            let confirmations = current_height.saturating_sub(mined_at);
            confirmations < COINBASE_MATURITY
        } else {
            false
        }
    }

    pub fn get(&self, tx_hash: &str, index: u32) -> Option<&TxOutput> {
        self.utxos.get(&Self::key(tx_hash, index))
    }

    pub fn balance_of(&self, address: &str) -> u64 {
        self.utxos
            .values()
            .filter(|o| o.address == address)
            .map(|o| o.value)
            .sum()
    }

    pub fn utxos_for(&self, address: &str) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter(|(_, o)| o.address == address)
            .map(|(k, o)| {
                let parts: Vec<&str> = k.splitn(2, ':').collect();
                Utxo {
                    tx_hash: parts[0].to_string(),
                    index: parts[1].parse().unwrap_or(0),
                    output: o.clone(),
                }
            })
            .collect()
    }
}
