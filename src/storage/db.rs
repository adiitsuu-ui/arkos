use crate::blockchain::block::Block;
use crate::transaction::tx::Transaction;
use anyhow::Result;
use bincode::Options as _;
use rocksdb::{Options, DB};

/// Maximum allowed serialized size for a single block (32 MB).
/// Prevents unbounded memory allocation if the on-disk data is corrupted
/// or maliciously crafted.
const MAX_BLOCK_SIZE: u64 = 32 * 1024 * 1024;
/// Maximum allowed serialized size for a single transaction (4 MB).
const MAX_TX_SIZE: u64 = 4 * 1024 * 1024;

/// Canonical bincode options for all DB serialization.
/// FixintEncoding + AllowTrailing ensures consistent round-trips:
///   - FixintEncoding: fixed-width integers (no varint surprises across versions)
///   - AllowTrailing: safe deserialization even if record has padding bytes
fn db_opts() -> impl bincode::Options {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

pub struct BlockStore {
    db: DB,
}

impl BlockStore {
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(BlockStore { db })
    }

    pub fn save_block(&self, block: &Block) -> Result<()> {
        let key = format!("block:{}", block.hash_hex());
        let val = db_opts().serialize(block)?;
        self.db.put(key.as_bytes(), &val)?;
        let height_key = format!("height:{}", block.height);
        self.db
            .put(height_key.as_bytes(), block.hash_hex().as_bytes())?;
        Ok(())
    }

    pub fn load_block_by_hash(&self, hash: &str) -> Result<Option<Block>> {
        let key = format!("block:{}", hash);
        match self.db.get(key.as_bytes())? {
            Some(val) => {
                let block = db_opts()
                    .with_limit(MAX_BLOCK_SIZE)
                    .deserialize(&val)
                    .map_err(|e| anyhow::anyhow!("block deserialization failed: {}", e))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn load_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let key = format!("height:{}", height);
        match self.db.get(key.as_bytes())? {
            Some(hash_bytes) => {
                let hash = String::from_utf8(hash_bytes)?;
                self.load_block_by_hash(&hash)
            }
            None => Ok(None),
        }
    }

    pub fn save_transaction(&self, tx: &Transaction) -> Result<()> {
        let key = format!("tx:{}", tx.txid_hex());
        let val = db_opts().serialize(tx)?;
        self.db.put(key.as_bytes(), &val)?;
        Ok(())
    }

    pub fn load_transaction(&self, txid: &str) -> Result<Option<Transaction>> {
        let key = format!("tx:{}", txid);
        match self.db.get(key.as_bytes())? {
            Some(val) => {
                let tx = db_opts()
                    .with_limit(MAX_TX_SIZE)
                    .deserialize(&val)
                    .map_err(|e| anyhow::anyhow!("tx deserialization failed: {}", e))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    pub fn save_tip(&self, hash: &str) -> Result<()> {
        self.db.put(b"tip", hash.as_bytes())?;
        Ok(())
    }

    pub fn load_tip(&self) -> Result<Option<String>> {
        match self.db.get(b"tip")? {
            Some(val) => Ok(Some(String::from_utf8(val)?)),
            None => Ok(None),
        }
    }
}
