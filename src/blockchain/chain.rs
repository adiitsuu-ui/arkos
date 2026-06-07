use crate::blockchain::block::{
    genesis_block, merkle_root, mine_block_header, Block, BlockHeader, MAX_SUPPLY_ARKES,
};
use crate::blockchain::consensus::{
    adjust_difficulty, validate_timestamp, DIFFICULTY_ADJUSTMENT_INTERVAL,
};
use crate::storage::db::BlockStore;
use crate::transaction::mempool::Mempool;
use crate::transaction::tx::Transaction;
use crate::transaction::utxo::UtxoSet;
use anyhow::{bail, Result};
use log::info;
use std::collections::HashMap;

/// Maximum coinbase outputs allowed in a single block.
const MAX_COINBASE_OUTPUTS: usize = 16;

/// After this many blocks of finality, orphan side-chain blocks are pruned.
/// Blocks buried more than FINALITY_DEPTH deep are exceedingly unlikely to
/// be part of any future reorg and waste memory/disk if retained.
const FINALITY_DEPTH: u64 = 200;

pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub block_index: HashMap<String, usize>, // hash -> height
    pub all_blocks: HashMap<String, Block>,
    chain_work: HashMap<String, u128>,
    pub utxo_set: UtxoSet,
    pub mempool: Mempool,
    pub total_minted: u64,
    store: Option<BlockStore>,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis = genesis_block();
        Self::from_genesis(genesis, None)
    }

    pub fn open(path: &str) -> Result<Self> {
        let store = BlockStore::open(path)?;
        if let Some(tip_hash) = store.load_tip()? {
            let tip = store
                .load_block_by_hash(&tip_hash)?
                .ok_or_else(|| anyhow::anyhow!("stored tip block {} is missing", tip_hash))?;
            let mut blocks = Vec::with_capacity(tip.height as usize + 1);
            for height in 0..=tip.height {
                let block = store.load_block_by_height(height)?.ok_or_else(|| {
                    anyhow::anyhow!("stored block at height {} is missing", height)
                })?;
                blocks.push(block);
            }
            return Self::from_blocks(blocks, Some(store));
        }

        let chain = Self::from_genesis(genesis_block(), Some(store));
        if let Some(store) = &chain.store {
            store.save_block(chain.tip())?;
            store.save_tip(&chain.tip().hash_hex())?;
        }
        Ok(chain)
    }

    fn from_genesis(genesis: Block, store: Option<BlockStore>) -> Self {
        let hash = genesis.hash_hex();
        info!("Genesis block: {}", hash);

        let mut utxo_set = UtxoSet::default();
        for tx in &genesis.transactions {
            utxo_set.apply_transaction(tx);
        }
        let total_minted = coinbase_value(&genesis);

        let mut block_index = HashMap::new();
        block_index.insert(hash.clone(), 0usize);
        let mut all_blocks = HashMap::new();
        all_blocks.insert(hash.clone(), genesis.clone());
        let mut chain_work = HashMap::new();
        chain_work.insert(hash, block_work(genesis.header.bits));

        Blockchain {
            blocks: vec![genesis],
            block_index,
            all_blocks,
            chain_work,
            utxo_set,
            mempool: Mempool::new(),
            total_minted,
            store,
        }
    }

    fn from_blocks(blocks: Vec<Block>, store: Option<BlockStore>) -> Result<Self> {
        if blocks.is_empty() {
            bail!("cannot load an empty chain");
        }
        let mut iter = blocks.into_iter();
        let genesis = iter.next().unwrap();
        let mut chain = Self::from_genesis(genesis, store);
        for block in iter {
            chain.add_block(block)?;
        }
        Ok(chain)
    }

    pub fn tip(&self) -> &Block {
        self.blocks.last().unwrap()
    }

    pub fn height(&self) -> u64 {
        self.tip().height
    }

    pub fn remaining_supply(&self) -> u64 {
        MAX_SUPPLY_ARKES.saturating_sub(self.total_minted)
    }

    pub fn capped_block_reward(&self, height: u64) -> u64 {
        Block::block_reward(height).min(self.remaining_supply())
    }

    pub fn next_block_timestamp(&self) -> u64 {
        now_secs().max(self.median_past_time() + 1)
    }

    /// Attempt to add a mined block to the chain.
    ///
    /// # Complexity
    /// O(1) for the common case (extending the current tip): the block is
    /// validated against its direct parent only.  Full UTXO rebuild only
    /// happens when a genuine reorg is needed (`activate_chain`), which is rare.
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        let hash = block.hash_hex();
        if self.all_blocks.contains_key(&hash) {
            return Ok(());
        }

        let parent_hash = block.header.prev_hash.clone();
        if !self.all_blocks.contains_key(&parent_hash) {
            bail!("unknown parent block {}", parent_hash);
        }

        // Validate the block structurally (PoW, merkle, tx count, coinbase).
        // This does NOT need the full UTXO state — it only checks the block header
        // and transaction structure.
        let parent = self
            .all_blocks
            .get(&parent_hash)
            .ok_or_else(|| anyhow::anyhow!("parent block missing"))?;
        block.validate(&parent.hash_hex())?;

        // Validate difficulty and timestamp against the *current active chain* state.
        // For side-chain blocks this is approximate; full UTXO validation happens
        // during activate_chain if the side chain ever gains more work.
        if self.block_index.contains_key(&parent_hash) {
            // Parent is on the active chain — we can do the full contextual check.
            self.validate_block_difficulty(&block)?;
            self.validate_block_timestamp(&block)?;
            self.validate_coinbase_subsidy(&block)?;
            for tx in &block.transactions {
                if !tx.is_coinbase() {
                    self.validate_tx(tx)?;
                }
            }
        }

        let parent_work = *self
            .chain_work
            .get(&parent_hash)
            .ok_or_else(|| anyhow::anyhow!("missing parent chain work"))?;
        let candidate_work = parent_work
            .checked_add(block_work(block.header.bits))
            .ok_or_else(|| anyhow::anyhow!("chain work overflow"))?;

        if let Some(store) = &self.store {
            store.save_block(&block)?;
        }
        self.chain_work.insert(hash.clone(), candidate_work);
        self.all_blocks.insert(hash.clone(), block);

        let current_work = *self
            .chain_work
            .get(&self.tip().hash_hex())
            .ok_or_else(|| anyhow::anyhow!("missing tip chain work"))?;
        if candidate_work > current_work {
            self.activate_chain(&hash)?;
            info!(
                "Best chain is now block {} at height {}",
                self.tip().hash_hex(),
                self.height()
            );
        } else {
            info!("Stored side-chain block {}", hash);
        }

        // Prune orphan blocks buried beyond FINALITY_DEPTH to avoid unbounded growth.
        self.prune_stale_orphans();

        Ok(())
    }

    /// Remove blocks from `all_blocks` that are no longer reachable from any
    /// chain tip within FINALITY_DEPTH blocks of the current best tip.
    fn prune_stale_orphans(&mut self) {
        let tip_height = self.height();
        if tip_height < FINALITY_DEPTH {
            return;
        }
        let cutoff_height = tip_height - FINALITY_DEPTH;
        // Collect hashes of active blocks at or below the cutoff.
        let active_hashes: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .filter(|b| b.height <= cutoff_height)
            .map(|b| b.hash_hex())
            .collect();
        // Remove anything below the cutoff that isn't on the active chain.
        self.all_blocks.retain(|hash, block| {
            block.height > cutoff_height || active_hashes.contains(hash)
        });
        self.chain_work.retain(|hash, _| {
            self.all_blocks.contains_key(hash)
        });
    }

    /// Mine a new block using transactions from the mempool
    pub fn mine_block(&mut self, miner_address: &str) -> Block {
        let prev = self.tip();
        let height = prev.height + 1;
        let bits = self.next_bits();
        let reward = self.capped_block_reward(height);

        let coinbase = Transaction::coinbase(miner_address, reward, height);
        let mut txs = vec![coinbase];
        txs.extend(self.mempool.take(500).into_iter().cloned());

        let merkle = merkle_root(&txs);
        let mut header = BlockHeader {
            version: 1,
            prev_hash: prev.hash_hex(),
            merkle_root: merkle,
            timestamp: self.next_block_timestamp(),
            bits,
            nonce: 0,
        };

        info!(
            "Mining block {} with difficulty bits 0x{:08x}...",
            height, bits
        );
        mine_block_header(&mut header);

        let block = Block {
            header,
            transactions: txs,
            height,
        };
        info!(
            "Mined block {} nonce={}",
            block.hash_hex(),
            block.header.nonce
        );
        block
    }

    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<String> {
        let fee = self.validate_tx(&tx)?;
        self.mempool
            .add_with_fee(tx, fee)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Validate a transaction and return the fee (input_sum - output_sum).
    fn validate_tx(&self, tx: &Transaction) -> Result<u64> {
        use crate::crypto::keys::pubkey_to_address;
        use secp256k1::PublicKey;

        let mut input_sum: u64 = 0;
        let sig_hash = tx.sig_hash();

        for input in &tx.inputs {
            let utxo = self
                .utxo_set
                .get(&input.prev_tx_hash, input.prev_index)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "UTXO not found: {}:{}",
                        input.prev_tx_hash,
                        input.prev_index
                    )
                })?;
            input_sum = input_sum
                .checked_add(utxo.value)
                .ok_or_else(|| anyhow::anyhow!("input sum overflow"))?;

            // Verify signature
            let pubkey = PublicKey::from_slice(&input.pubkey.ecdsa_pubkey)
                .map_err(|_| anyhow::anyhow!("invalid pubkey"))?;
            input
                .signature
                .verify(&sig_hash, &input.pubkey)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "invalid hybrid signature on input {}:{}: {}",
                        input.prev_tx_hash,
                        input.prev_index,
                        e
                    )
                })?;
            // Verify pubkey matches address
            let derived_addr = hex::encode(pubkey_to_address(&pubkey));
            if derived_addr != utxo.address {
                bail!("pubkey does not match UTXO address");
            }
        }

        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if input_sum < output_sum {
            bail!("transaction outputs exceed inputs");
        }
        Ok(input_sum - output_sum)
    }

    fn validate_next_block(&self, block: &Block) -> Result<()> {
        let prev = self.tip();
        block.validate(&prev.hash_hex())?;
        self.validate_block_difficulty(block)?;
        self.validate_block_timestamp(block)?;
        self.validate_coinbase_subsidy(block)?;

        for tx in &block.transactions {
            if !tx.is_coinbase() {
                self.validate_tx(tx)?;
            }
        }
        Ok(())
    }

    fn activate_chain(&mut self, tip_hash: &str) -> Result<()> {
        let new_blocks = self.chain_to_hash(tip_hash)?;
        self.rebuild_active_state(new_blocks)?;
        if let Some(store) = &self.store {
            for block in &self.blocks {
                store.save_block(block)?;
            }
            store.save_tip(&self.tip().hash_hex())?;
        }
        Ok(())
    }

    fn rebuild_active_state(&mut self, blocks: Vec<Block>) -> Result<()> {
        let mut utxo_set = UtxoSet::default();
        let mut block_index = HashMap::new();
        let mut total_minted = 0u64;

        for (height, block) in blocks.iter().enumerate() {
            block_index.insert(block.hash_hex(), height);
            total_minted = total_minted
                .checked_add(coinbase_value(block))
                .ok_or_else(|| anyhow::anyhow!("total minted supply overflow"))?;
            for tx in &block.transactions {
                utxo_set.apply_transaction(tx);
                self.mempool.remove(&tx.txid_hex());
            }
        }

        self.blocks = blocks;
        self.block_index = block_index;
        self.utxo_set = utxo_set;
        self.total_minted = total_minted;
        Ok(())
    }

    fn chain_to_hash(&self, tip_hash: &str) -> Result<Vec<Block>> {
        let mut chain = Vec::new();
        let mut cursor = tip_hash.to_string();

        loop {
            let block = self
                .all_blocks
                .get(&cursor)
                .ok_or_else(|| anyhow::anyhow!("unknown block {}", cursor))?
                .clone();
            let is_genesis = block.height == 0;
            cursor = block.header.prev_hash.clone();
            chain.push(block);
            if is_genesis {
                break;
            }
        }

        chain.reverse();
        Ok(chain)
    }

    fn validate_coinbase_subsidy(&self, block: &Block) -> Result<()> {
        if block.height != self.height() + 1 {
            bail!(
                "block height mismatch: expected {}, got {}",
                self.height() + 1,
                block.height
            );
        }

        // Limit coinbase outputs to prevent bloating the UTXO set.
        let coinbase_tx = &block.transactions[0];
        if coinbase_tx.outputs.len() > MAX_COINBASE_OUTPUTS {
            bail!(
                "coinbase has {} outputs, exceeding limit of {}",
                coinbase_tx.outputs.len(),
                MAX_COINBASE_OUTPUTS
            );
        }

        // Compute total fees from non-coinbase transactions.
        // Fee = sum(input values) - sum(output values) for each tx.
        let mut total_fees: u64 = 0;
        for tx in block.transactions.iter().skip(1) {
            let input_sum: u64 = tx
                .inputs
                .iter()
                .filter_map(|inp| self.utxo_set.get(&inp.prev_tx_hash, inp.prev_index))
                .map(|utxo| utxo.value)
                .sum();
            let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
            total_fees = total_fees.saturating_add(input_sum.saturating_sub(output_sum));
        }

        let minted = coinbase_value(block);
        let scheduled_reward = Block::block_reward(block.height);
        let allowed_reward = scheduled_reward
            .min(self.remaining_supply())
            .saturating_add(total_fees);

        if minted > allowed_reward {
            bail!(
                "coinbase value {} exceeds allowed reward {} (subsidy {} + fees {})",
                minted,
                allowed_reward,
                scheduled_reward.min(self.remaining_supply()),
                total_fees
            );
        }
        Ok(())
    }

    fn validate_block_difficulty(&self, block: &Block) -> Result<()> {
        let expected_bits = self.next_bits();
        if block.header.bits != expected_bits {
            bail!(
                "block difficulty bits mismatch: expected 0x{:08x}, got 0x{:08x}",
                expected_bits,
                block.header.bits
            );
        }
        Ok(())
    }

    fn validate_block_timestamp(&self, block: &Block) -> Result<()> {
        if !validate_timestamp(block.header.timestamp, self.median_past_time(), now_secs()) {
            bail!(
                "block timestamp {} is outside the allowed range",
                block.header.timestamp
            );
        }
        Ok(())
    }

    fn median_past_time(&self) -> u64 {
        let mut timestamps: Vec<u64> = self
            .blocks
            .iter()
            .rev()
            .take(11)
            .map(|block| block.header.timestamp)
            .collect();
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    pub fn next_bits(&self) -> u32 {
        let height = self.height() + 1;
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return self.tip().header.bits;
        }
        let interval_start_height =
            height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL) as usize;

        // Use the 11 blocks around each endpoint to compute median timestamps.
        // This matches Bitcoin's MTP rule and prevents time-warp manipulation.
        let start_window: Vec<u64> = self.blocks[interval_start_height
            .saturating_sub(5)
            ..=(interval_start_height + 5).min(self.blocks.len() - 1)]
            .iter()
            .map(|b| b.header.timestamp)
            .collect();

        let tip_idx = self.blocks.len() - 1;
        let end_window: Vec<u64> = self.blocks[tip_idx.saturating_sub(10)..=tip_idx]
            .iter()
            .map(|b| b.header.timestamp)
            .collect();

        adjust_difficulty(self.tip().header.bits, &start_window, &end_window)
    }

    pub fn block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.all_blocks.get(hash)
    }

    pub fn balance_of(&self, address: &str) -> u64 {
        self.utxo_set.balance_of(address)
    }
}

fn coinbase_value(block: &Block) -> u64 {
    block
        .transactions
        .first()
        .map(|tx| tx.outputs.iter().map(|o| o.value).sum())
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn block_work(bits: u32) -> u128 {
    let target = crate::blockchain::block::bits_to_target(bits);
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&target[..16]);
    let target_prefix = u128::from_be_bytes(prefix);
    if target_prefix == 0 {
        u128::MAX
    } else {
        u128::MAX / target_prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::block::mine_block_header;

    fn build_next_block(chain: &Blockchain, miner_address: &str, reward: u64) -> Block {
        let height = chain.height() + 1;
        let coinbase = Transaction::coinbase(miner_address, reward, height);
        let txs = vec![coinbase];
        let merkle = merkle_root(&txs);
        let mut header = BlockHeader {
            version: 1,
            prev_hash: chain.tip().hash_hex(),
            merkle_root: merkle,
            timestamp: now_secs(),
            bits: chain.tip().header.bits,
            nonce: 0,
        };
        mine_block_header(&mut header);
        Block {
            header,
            transactions: txs,
            height,
        }
    }

    #[test]
    fn capped_reward_uses_only_remaining_supply() {
        let mut chain = Blockchain::new();
        chain.total_minted = MAX_SUPPLY_ARKES - 1;

        assert_eq!(chain.remaining_supply(), 1);
        assert_eq!(chain.capped_block_reward(chain.height() + 1), 1);
    }

    #[test]
    fn rejects_coinbase_above_remaining_supply() {
        let mut chain = Blockchain::new();
        chain.total_minted = MAX_SUPPLY_ARKES - 1;
        // Allowed = 1 arke subsidy + 0 fees; paying out 2 must be rejected.
        let block = build_next_block(&chain, "miner", 2);

        let err = chain
            .validate_coinbase_subsidy(&block)
            .unwrap_err()
            .to_string();
        assert!(err.contains("coinbase value 2 exceeds allowed reward 1"));
    }

    #[test]
    fn rejects_unexpected_difficulty_bits() {
        let mut chain = Blockchain::new();
        let mut block = build_next_block(&chain, "miner", chain.capped_block_reward(1));
        block.header.bits = 0x1f0f_ffff;
        mine_block_header(&mut block.header);

        let err = chain.add_block(block).unwrap_err().to_string();
        assert!(err.contains("block difficulty bits mismatch"));
    }

    #[test]
    fn persistent_chain_restores_blocks_and_utxos() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain");
        let miner = "miner";

        {
            let mut chain = Blockchain::open(path.to_string_lossy().as_ref()).unwrap();
            let block = chain.mine_block(miner);
            chain.add_block(block).unwrap();
            assert_eq!(chain.height(), 1);
            assert!(chain.balance_of(miner) > 0);
        }

        let restored = Blockchain::open(path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(restored.height(), 1);
        assert!(restored.balance_of(miner) > 0);
    }

    #[test]
    fn reorgs_to_side_branch_with_more_work() {
        let mut chain = Blockchain::new();
        let genesis = chain.tip().clone();

        let main_block = chain.mine_block("main-miner");
        chain.add_block(main_block).unwrap();
        assert_eq!(chain.height(), 1);
        assert!(chain.balance_of("main-miner") > 0);

        let mut side_context = Blockchain::from_genesis(genesis, None);
        let side_block_1 = side_context.mine_block("side-miner");
        side_context.add_block(side_block_1.clone()).unwrap();
        chain.add_block(side_block_1).unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.balance_of("side-miner"), 0);

        let side_block_2 = side_context.mine_block("side-miner");
        side_context.add_block(side_block_2.clone()).unwrap();
        chain.add_block(side_block_2).unwrap();

        assert_eq!(chain.height(), 2);
        assert!(chain.balance_of("side-miner") > 0);
        assert_eq!(chain.balance_of("main-miner"), 0);
    }
}
