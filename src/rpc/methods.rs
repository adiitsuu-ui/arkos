use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use crate::blockchain::block::{bits_to_target, merkle_root, Block, BlockHeader};
use crate::blockchain::chain::Blockchain;
use crate::transaction::tx::Transaction;

// ─── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "camelCase")]
pub enum RpcRequest {
    GetBlockTemplate(GetBlockTemplateParams),
    SubmitBlock(SubmitBlockParams),
    GetBalance(GetBalanceParams),
    GetBlockCount,
    GetMiningInfo,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RpcResult {
    BlockTemplate(BlockTemplateResponse),
    SubmitBlock(SubmitBlockResponse),
    Balance(BalanceResponse),
    BlockCount(u64),
    MiningInfo(MiningInfoResponse),
}

// ─── getblocktemplate ──────────────────────────────────────────────────────────

/// Any miner (desktop, server, or mobile) calls this to get the data needed to
/// mine a block.  The miner receives a partially-constructed header and the
/// transaction list to hash.  It then searches for a nonce that meets the
/// difficulty target and calls `submitBlock`.
#[derive(Debug, Deserialize)]
pub struct GetBlockTemplateParams {
    /// The wallet address that will receive the mining reward (coinbase output).
    pub wallet_address: String,
}

#[derive(Debug, Serialize)]
pub struct BlockTemplateResponse {
    pub version: u32,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub bits: u32,
    /// Hex-encoded 32-byte target (for display / progress tracking).
    pub target_hex: String,
    /// Current chain height; the new block will be at height + 1.
    pub height: u64,
    /// Block reward in arkes.
    pub reward_arkes: u64,
    /// Number of pending transactions included in the template.
    pub tx_count: usize,
}

// ─── submitblock ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubmitBlockParams {
    pub version: u32,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    /// Wallet address to receive the block reward (must match the template).
    pub wallet_address: String,
    /// Block height echoed back from the template to detect stale submissions.
    pub height: u64,
}

#[derive(Debug, Serialize)]
pub struct SubmitBlockResponse {
    pub accepted: bool,
    pub block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── getbalance ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetBalanceParams {
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub address: String,
    pub balance_arkes: u64,
    /// Human-readable ARKOS (arkes / 10^9)
    pub balance_arkos: f64,
}

// ─── getmininginfo ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct MiningInfoResponse {
    pub height: u64,
    pub bits: u32,
    pub target_hex: String,
    /// Number of leading zero bits in the current target (rough difficulty display).
    pub difficulty_bits: u32,
    pub mempool_size: usize,
    pub next_reward_arkes: u64,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

pub struct RpcState {
    pub chain: Arc<TokioMutex<Blockchain>>,
}

pub async fn handle(state: Arc<RpcState>, req: RpcRequest) -> Result<RpcResult, String> {
    match req {
        RpcRequest::GetBlockTemplate(p) => get_block_template(state, p).await,
        RpcRequest::SubmitBlock(p) => submit_block(state, p).await,
        RpcRequest::GetBalance(p) => get_balance(state, p).await,
        RpcRequest::GetBlockCount => get_block_count(state).await,
        RpcRequest::GetMiningInfo => get_mining_info(state).await,
    }
}

// ─── Individual handlers ──────────────────────────────────────────────────────

async fn get_block_template(
    state: Arc<RpcState>,
    params: GetBlockTemplateParams,
) -> Result<RpcResult, String> {
    let chain = state.chain.lock().await;
    let tip = chain.tip();
    let height = tip.height + 1;
    let bits = chain.next_bits();
    let reward = chain.capped_block_reward(height);

    // Build template transactions (coinbase + sorted mempool)
    let coinbase = Transaction::coinbase(&params.wallet_address, reward, height);
    let mut txs = vec![coinbase];
    let mempool_txs: Vec<Transaction> = chain.mempool.peek(500).into_iter().cloned().collect();
    let tx_count = mempool_txs.len() + 1; // +1 for coinbase
    txs.extend(mempool_txs);

    let mroot = merkle_root(&txs);
    let timestamp = chain.next_block_timestamp();
    let target = bits_to_target(bits);

    Ok(RpcResult::BlockTemplate(BlockTemplateResponse {
        version: 1,
        prev_hash: tip.hash_hex(),
        merkle_root: mroot,
        timestamp,
        bits,
        target_hex: hex::encode(target),
        height: tip.height,
        reward_arkes: reward,
        tx_count,
    }))
}

async fn submit_block(
    state: Arc<RpcState>,
    params: SubmitBlockParams,
) -> Result<RpcResult, String> {
    let header = BlockHeader {
        version: params.version,
        prev_hash: params.prev_hash.clone(),
        merkle_root: params.merkle_root.clone(),
        timestamp: params.timestamp,
        bits: params.bits,
        nonce: params.nonce,
    };

    // Verify PoW before acquiring the chain lock
    if !header.meets_target() {
        return Ok(RpcResult::SubmitBlock(SubmitBlockResponse {
            accepted: false,
            block_hash: header.hash_hex(),
            error: Some("hash does not meet difficulty target".into()),
        }));
    }

    let mut chain = state.chain.lock().await;

    if params.height != chain.height() {
        return Ok(RpcResult::SubmitBlock(SubmitBlockResponse {
            accepted: false,
            block_hash: header.hash_hex(),
            error: Some(format!(
                "stale block: submitted height {}, chain is at {}",
                params.height,
                chain.height()
            )),
        }));
    }

    // Reconstruct the same transaction set used to build the template
    let reward = chain.capped_block_reward(params.height + 1);
    let coinbase = Transaction::coinbase(&params.wallet_address, reward, params.height + 1);
    let mut txs = vec![coinbase];
    txs.extend(chain.mempool.peek(500).into_iter().cloned());

    let computed_merkle = merkle_root(&txs);
    if computed_merkle != params.merkle_root {
        return Ok(RpcResult::SubmitBlock(SubmitBlockResponse {
            accepted: false,
            block_hash: header.hash_hex(),
            error: Some("merkle root mismatch — stale template".into()),
        }));
    }

    let block_hash = header.hash_hex();
    let block = Block {
        header,
        transactions: txs,
        height: params.height + 1,
    };

    match chain.add_block(block) {
        Ok(()) => Ok(RpcResult::SubmitBlock(SubmitBlockResponse {
            accepted: true,
            block_hash,
            error: None,
        })),
        Err(e) => Ok(RpcResult::SubmitBlock(SubmitBlockResponse {
            accepted: false,
            block_hash,
            error: Some(e.to_string()),
        })),
    }
}

async fn get_balance(state: Arc<RpcState>, params: GetBalanceParams) -> Result<RpcResult, String> {
    let chain = state.chain.lock().await;
    let bal = chain.balance_of(&params.address);
    Ok(RpcResult::Balance(BalanceResponse {
        address: params.address,
        balance_arkes: bal,
        balance_arkos: bal as f64 / 1_000_000_000.0,
    }))
}

async fn get_block_count(state: Arc<RpcState>) -> Result<RpcResult, String> {
    let chain = state.chain.lock().await;
    Ok(RpcResult::BlockCount(chain.height()))
}

async fn get_mining_info(state: Arc<RpcState>) -> Result<RpcResult, String> {
    let chain = state.chain.lock().await;
    let tip = chain.tip();
    let bits = tip.header.bits;
    let target = bits_to_target(bits);
    let difficulty_bits = target.iter().take_while(|&&b| b == 0).count() as u32 * 8;

    Ok(RpcResult::MiningInfo(MiningInfoResponse {
        height: chain.height(),
        bits,
        target_hex: hex::encode(target),
        difficulty_bits,
        mempool_size: chain.mempool.len(),
        next_reward_arkes: chain.capped_block_reward(chain.height() + 1),
    }))
}
