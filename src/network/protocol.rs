use crate::blockchain::block::Block;
use crate::transaction::tx::Transaction;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAINNET_MAGIC: u32 = 0x4152_4b53; // "ARKS"
pub const TESTNET_MAGIC: u32 = 0x4152_4b54; // "ARKT"
pub const REGTEST_MAGIC: u32 = 0x4152_4b52; // "ARKR"

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Announce our version and best chain height upon connecting
    Version {
        version: u32,
        network_magic: u32,
        best_height: u64,
        user_agent: String,
    },
    /// Acknowledge a Version message
    Verack,
    /// Request blocks starting after `locator_hashes` (most recent first)
    GetBlocks {
        locator_hashes: Vec<String>,
    },
    /// Inventory — announce what we have (block hashes or tx ids)
    Inv {
        items: Vec<InvItem>,
    },
    /// Request full data for inventory items
    GetData {
        items: Vec<InvItem>,
    },
    /// A full block
    BlockMsg(Block),
    /// A full transaction
    TxMsg(Transaction),
    /// Peer list for discovery
    Addr {
        addrs: Vec<String>,
    },
    Ping(u64),
    Pong(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvItem {
    pub kind: InvKind,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvKind {
    Block,
    Transaction,
}
