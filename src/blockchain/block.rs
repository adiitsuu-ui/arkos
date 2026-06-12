use crate::crypto::hash::{hash256, hash_to_hex, Hash};
use crate::transaction::tx::Transaction;
use serde::{Deserialize, Serialize};

/// Maximum number of transactions allowed in a single block.
/// Caps block size and validation cost.  A block with more than this many
/// transactions is invalid and must be rejected.
pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;

/// Maximum serialised byte size of a block (4 MB).
/// Checked before any signature verification to bound Dilithium verification cost.
pub const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;

/// Maximum total number of UTXO operations (inputs + outputs) across all
/// transactions in a single block.  A miner could craft transactions with
/// very few bytes but many outputs, exploding the UTXO set.  This limit
/// bounds UTXO set growth independently of the byte-size cap.
pub const MAX_BLOCK_UTXO_OPS: usize = 50_000;

// Hard-capped total supply: 31,415,926 ARKOS = π × 10^7
// Archimedes (ΑΡΧΙ-μήδης) shares the ΑΡΧΗ root with Arkos — he gave the world π
pub const BLOCK_REWARD_INITIAL: u64 = 32_188_184_932; // arkes ≈ 32.188 ARKOS/block
pub const HALVING_INTERVAL: u64 = 488_004; // blocks ≈ 3 years at 194s blocks
pub const ARKES_PER_ARKOS: u64 = 1_000_000_000;
pub const MAX_SUPPLY_ARKOS: u64 = 31_415_926; // ARKOS = π × 10^7
pub const MAX_SUPPLY_ARKES: u64 = MAX_SUPPLY_ARKOS * ARKES_PER_ARKOS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub bits: u32, // compact difficulty target
    pub nonce: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        let data = self.pow_bytes();
        hash256(&data)
    }

    pub fn hash_hex(&self) -> String {
        hash_to_hex(&self.hash())
    }

    /// Validate header-only (PoW check only — no UTXO, no transaction validation).
    ///
    /// Used during headers-first sync: validate PoW on all headers before
    /// committing resources to download full blocks.  This prevents a malicious
    /// peer from forcing us to download and fully validate large invalid blocks.
    /// Validate this header against a known parent hash and expected difficulty bits.
    ///
    /// `expected_bits` should come from the chain's `next_bits()` at the relevant height,
    /// or from the previously validated header's bits when validating a consecutive chain.
    /// Passing `None` skips the bits check (used only when the expected difficulty is not
    /// yet known — e.g. during early peer message processing).
    pub fn validate_header_only(
        &self,
        prev_hash: &str,
        expected_bits: Option<u32>,
    ) -> anyhow::Result<()> {
        if self.prev_hash != prev_hash {
            anyhow::bail!("header prev_hash mismatch");
        }
        if let Some(bits) = expected_bits {
            if self.bits != bits {
                anyhow::bail!(
                    "header bits 0x{:08x} does not match expected 0x{:08x}",
                    self.bits, bits
                );
            }
        }
        if !self.meets_target() {
            anyhow::bail!("header hash does not meet difficulty target");
        }
        Ok(())
    }

    /// Check if header hash meets the difficulty target
    pub fn meets_target(&self) -> bool {
        let hash = self.hash();
        let target = bits_to_target(self.bits);
        hash_le_target(&hash, &target)
    }

    fn pow_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(89);
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&hex_32_or_bytes(&self.prev_hash));
        data.extend_from_slice(&hex_32_or_bytes(&self.merkle_root));
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.bits.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.push(0x00);
        data
    }
}

fn hex_32_or_bytes(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(value, &mut out).is_ok() {
        return out;
    }
    let bytes = value.as_bytes();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub height: u64,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn hash_hex(&self) -> String {
        self.header.hash_hex()
    }

    pub fn block_reward(height: u64) -> u64 {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            0
        } else {
            BLOCK_REWARD_INITIAL >> halvings
        }
    }

    pub fn validate(&self, prev_hash: &str) -> anyhow::Result<()> {
        if self.header.prev_hash != prev_hash {
            anyhow::bail!("block prev_hash mismatch");
        }
        if !self.header.meets_target() {
            anyhow::bail!("block hash does not meet difficulty target");
        }
        if self.transactions.is_empty() {
            anyhow::bail!("block has no transactions");
        }
        if self.transactions.len() > MAX_BLOCK_TRANSACTIONS {
            anyhow::bail!(
                "block has {} transactions, exceeding limit of {}",
                self.transactions.len(),
                MAX_BLOCK_TRANSACTIONS
            );
        }
        let block_bytes = bincode::serialized_size(self).unwrap_or(u64::MAX) as usize;
        if block_bytes > MAX_BLOCK_BYTES {
            anyhow::bail!(
                "block is {} bytes, exceeding limit of {} bytes",
                block_bytes,
                MAX_BLOCK_BYTES
            );
        }
        let total_utxo_ops: usize = self
            .transactions
            .iter()
            .map(|tx| tx.inputs.len() + tx.outputs.len())
            .sum();
        if total_utxo_ops > MAX_BLOCK_UTXO_OPS {
            anyhow::bail!(
                "block has {} UTXO operations (inputs + outputs), exceeding limit of {}",
                total_utxo_ops,
                MAX_BLOCK_UTXO_OPS
            );
        }
        if !self.transactions[0].is_coinbase() {
            anyhow::bail!("first transaction must be coinbase");
        }
        let computed = merkle_root(&self.transactions);
        if computed != self.header.merkle_root {
            anyhow::bail!("block merkle root mismatch");
        }
        Ok(())
    }
}

/// Mainnet genesis difficulty: Bitcoin-genesis equivalent.
/// Mining this takes real hardware time; set once before mainnet launch.
pub const MAINNET_GENESIS_BITS: u32 = 0x1d00ffff;

/// Regtest/testnet genesis difficulty: mines instantly for development and tests.
pub const REGTEST_GENESIS_BITS: u32 = 0x207fffff;

pub fn genesis_block() -> Block {
    genesis_block_with_bits(REGTEST_GENESIS_BITS)
}

pub fn genesis_block_mainnet() -> Block {
    genesis_block_with_bits(MAINNET_GENESIS_BITS)
}

pub fn genesis_block_with_bits(bits: u32) -> Block {
    use crate::transaction::tx::Transaction;
    let coinbase = Transaction::coinbase(
        "0000000000000000000000000000000000000000", // burn address for genesis
        Block::block_reward(0),
        0,
    );
    let txs = vec![coinbase];
    let merkle = merkle_root(&txs);
    let mut header = BlockHeader {
        version: 1,
        prev_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        merkle_root: merkle,
        timestamp: 1_700_000_000,
        bits,
        nonce: 0,
    };
    mine_block_header(&mut header);
    Block {
        header,
        transactions: txs,
        height: 0,
    }
}

/// Compute the Merkle root of a list of transactions.
///
/// # Security: CVE-2012-2459 mitigation
///
/// Bitcoin's original Merkle tree duplicates the last leaf when the level
/// count is odd.  This creates Merkle ambiguity: two distinct transaction
/// lists can produce the same root hash, allowing an attacker to forge a
/// "valid" block containing fabricated transactions.
///
/// Arkos uses a **length-commitment padding** strategy instead:
/// when a level has an odd number of hashes, the right-hand "phantom"
/// leaf is `hash256(tree_length_as_u64_le)` — a value that is unique per
/// tree size.  This breaks the ambiguity because a tree of length N and a
/// tree of length N−1 can never produce the same root.
pub fn merkle_root(txs: &[Transaction]) -> String {
    if txs.is_empty() {
        return "0000000000000000000000000000000000000000000000000000000000000000".into();
    }
    let mut hashes: Vec<Hash> = txs.iter().map(|tx| tx.txid()).collect();
    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            // Pad with a commitment to the current tree length so that no two
            // different-length trees can collide.  This is safe because the
            // padding value is a function of the length, not a copy of a real leaf.
            let len_bytes = (hashes.len() as u64).to_le_bytes();
            hashes.push(hash256(&len_bytes));
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0]);
                combined[32..].copy_from_slice(&pair[1]);
                hash256(&combined)
            })
            .collect();
    }
    hash_to_hex(&hashes[0])
}

/// Expand compact bits representation to full 32-byte target
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    let mut target = [0u8; 32];
    if exp >= 1 && exp <= 32 {
        let start = 32 - exp;
        target[start] = ((mantissa >> 16) & 0xff) as u8;
        if start + 1 < 32 {
            target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if start + 2 < 32 {
            target[start + 2] = (mantissa & 0xff) as u8;
        }
    }
    target
}

fn hash_le_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true
}

/// Simple CPU miner — increments nonce until hash meets target
pub fn mine_block_header(header: &mut BlockHeader) {
    loop {
        if header.meets_target() {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
        if header.nonce == 0 {
            // Nonce exhausted — bump timestamp as Bitcoin does
            header.timestamp += 1;
        }
    }
}
