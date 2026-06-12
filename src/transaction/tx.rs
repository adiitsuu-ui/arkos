use crate::crypto::hash::{hash256, hash_to_hex, Hash};
use crate::crypto::quantum::{HybridPublicKey, HybridSignature};
use serde::{Deserialize, Serialize};

/// Output locking script.  Determines how the output can be spent.
///
/// P2PKH is the existing default (one ECDSA + ML-DSA-65 signature pair).
/// P2MS (m-of-n multisig) requires m valid signatures from the n registered keys.
/// TimeLocked wraps any other script with an absolute OP_CHECKLOCKTIMEVERIFY guard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Script {
    /// Pay-to-public-key-hash: standard single-key address output.
    /// The `address` field is the hex-encoded 20-byte hybrid pubkey hash.
    P2PKH { address: String },
    /// m-of-n multisig.  Spending requires exactly `m` valid signatures,
    /// each covering a distinct key from `pubkeys`.
    P2MS {
        m: u8,
        pubkeys: Vec<HybridPublicKey>,
    },
    /// Absolute time lock (OP_CHECKLOCKTIMEVERIFY).  The `inner` script
    /// can only be satisfied once `block_time >= lock_until` (Unix seconds).
    TimeLocked {
        lock_until: u64,
        inner: Box<Script>,
    },
}

impl Script {
    /// Canonical 20-byte hex address for UTXO indexing.
    ///
    /// P2PKH: the address as stored.
    /// P2MS: SHA256d("p2ms" || m || all_pubkeys_bytes)[..20].
    /// TimeLocked: address of the inner script.
    pub fn address(&self) -> String {
        match self {
            Script::P2PKH { address } => address.clone(),
            Script::P2MS { m, pubkeys } => {
                let mut data = Vec::new();
                data.extend_from_slice(b"p2ms");
                data.push(*m);
                data.push(pubkeys.len() as u8);
                for pk in pubkeys {
                    data.extend_from_slice(&pk.ecdsa_pubkey);
                    data.extend_from_slice(&pk.dilithium_pubkey);
                }
                let hash = hash256(&data);
                hex::encode(&hash[..20])
            }
            Script::TimeLocked { inner, .. } => inner.address(),
        }
    }

    /// Serialise this script to bytes for commitment in sig_hash.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Script serializes to JSON")
    }
}

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
    /// Additional witness entries for multi-signature inputs (P2MS).
    /// Empty for P2PKH inputs (use `signature`/`pubkey` fields instead).
    #[serde(default)]
    pub witnesses: Vec<(HybridSignature, HybridPublicKey)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    /// Locking script.  When absent (legacy), defaults to P2PKH using `address`.
    #[serde(default)]
    pub script: Option<Script>,
    /// Hex-encoded 20-byte address for UTXO indexing.
    /// For new outputs created with a `script`, this is `script.address()`.
    /// For legacy outputs, this is the direct P2PKH address.
    pub address: String,
}

impl TxOutput {
    /// Construct a standard P2PKH output.
    pub fn p2pkh(address: impl Into<String>, value: u64) -> Self {
        let address = address.into();
        TxOutput {
            value,
            script: Some(Script::P2PKH { address: address.clone() }),
            address,
        }
    }

    /// Construct a P2MS (m-of-n multisig) output.
    pub fn p2ms(m: u8, pubkeys: Vec<HybridPublicKey>, value: u64) -> Self {
        let script = Script::P2MS { m, pubkeys };
        let address = script.address();
        TxOutput {
            value,
            script: Some(script),
            address,
        }
    }

    /// Construct a time-locked output (wraps any inner script with CLTV).
    pub fn time_locked(lock_until: u64, inner: Script, value: u64) -> Self {
        let script = Script::TimeLocked { lock_until, inner: Box::new(inner) };
        let address = script.address();
        TxOutput {
            value,
            script: Some(script),
            address,
        }
    }

    /// The effective locking script for this output.
    /// Legacy outputs (no `script` field) default to P2PKH.
    pub fn effective_script(&self) -> Script {
        match &self.script {
            Some(s) => s.clone(),
            None => Script::P2PKH { address: self.address.clone() },
        }
    }
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
                witnesses: vec![],
            }],
            outputs: vec![TxOutput {
                value: reward,
                script: Some(Script::P2PKH { address: miner_address.to_string() }),
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

    /// Hash used for signing — excludes signature fields and witnesses.
    /// `network_magic` is committed to prevent cross-network replay attacks.
    /// The output scripts are committed to so signers bind to the locking conditions.
    pub fn sig_hash(&self, network_magic: u32) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&network_magic.to_le_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.prev_tx_hash.as_bytes());
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            data.extend_from_slice(&input.pubkey.ecdsa_pubkey);
            data.extend_from_slice(&input.pubkey.dilithium_pubkey);
        }
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            // Commit to the full script (not just address) so P2MS parameters are bound
            let script_bytes = output.effective_script().to_bytes();
            data.extend_from_slice(&(script_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&script_bytes);
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
