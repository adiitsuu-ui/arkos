use crate::crypto::hash::{hash256, hash_to_hex, Hash};
use crate::crypto::quantum::{HybridPublicKey, HybridSignature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_tx_hash: String, // hex hash of previous transaction
    pub prev_index: u32,      // output index in previous tx
    pub signature: HybridSignature,
    pub pubkey: HybridPublicKey,
    /// Arbitrary data for coinbase inputs (stores block height + miner tag).
    /// Empty for all non-coinbase inputs.
    #[serde(default)]
    pub coinbase_extra: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,      // arkes (smallest unit; 1 ARKOS = 1_000_000_000 arkes)
    pub address: String, // hex-encoded 20-byte address
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub version: u32,
    pub lock_time: u64,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Transaction {
            inputs,
            outputs,
            version: 1,
            lock_time: 0,
        }
    }

    /// Coinbase transaction — block reward with no inputs.
    ///
    /// Block height is stored in `coinbase_extra` as a little-endian u64.
    /// The `signature` and `pubkey` fields are empty for coinbase inputs —
    /// they carry no spending authority and must never be validated as signatures.
    pub fn coinbase(miner_address: &str, reward: u64, block_height: u64) -> Self {
        Transaction {
            inputs: vec![TxInput {
                prev_tx_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                prev_index: u32::MAX,
                signature: HybridSignature {
                    ecdsa_sig: vec![],
                    dilithium_sig: vec![],
                },
                pubkey: HybridPublicKey {
                    ecdsa_pubkey: vec![],
                    dilithium_pubkey: vec![],
                },
                coinbase_extra: block_height.to_le_bytes().to_vec(),
            }],
            outputs: vec![TxOutput {
                value: reward,
                address: miner_address.to_string(),
            }],
            version: 1,
            lock_time: 0,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_tx_hash
                == "0000000000000000000000000000000000000000000000000000000000000000"
            && self.inputs[0].prev_index == u32::MAX
    }

    /// Hash used for signing — excludes signature fields
    pub fn sig_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_le_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.prev_tx_hash.as_bytes());
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            data.extend_from_slice(&input.pubkey.ecdsa_pubkey);
            data.extend_from_slice(&input.pubkey.dilithium_pubkey);
        }
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(output.address.as_bytes());
        }
        hash256(&data)
    }

    pub fn txid(&self) -> Hash {
        let serialized = bincode::serialize(self).expect("tx serialize");
        hash256(&serialized)
    }

    pub fn txid_hex(&self) -> String {
        hash_to_hex(&self.txid())
    }
}
