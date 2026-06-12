use crate::blockchain::chain::Blockchain;
use crate::network::peer::Peer;
use crate::network::protocol::{
    InvItem, InvKind, Message, MAX_GETDATA_INFLIGHT, MAX_HEADERS_PER_RESPONSE, PROTOCOL_VERSION,
};
use crate::security::rate_limit::NodeRateLimiter;
use anyhow::Result;
use log::{info, warn};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};

/// Maximum peer addresses accepted in a single `Addr` message.
const MAX_ADDR_PER_MESSAGE: usize = 1_000;

/// Maximum number of peer addresses tracked in the known-peer list.
const MAX_KNOWN_PEERS: usize = 4_096;

/// Maximum length of the user_agent string in a `Version` message.
const MAX_USER_AGENT_LEN: usize = 256;

/// Maximum number of blocks announced per `GetBlocks` response.
const MAX_BLOCKS_PER_GETBLOCKS: usize = 500;
/// Maximum number of ancestor hashes sent in a block locator.
const MAX_LOCATOR_HASHES: usize = 32;

#[derive(Debug, Clone)]
pub(crate) struct RelayMessage {
    pub(crate) source: String,
    pub(crate) message: Message,
}

pub struct Node {
    pub chain: Arc<Mutex<Blockchain>>,
    pub listen_addr: String,
    pub network_magic: u32,
    pub peers: Arc<Mutex<Vec<String>>>,
    pub(crate) relay_tx: broadcast::Sender<RelayMessage>,
    rate_limiters: Arc<Mutex<NodeRateLimiter>>,
}

impl Node {
    pub fn new(chain: Blockchain, listen_addr: String, network_magic: u32) -> Self {
        let (relay_tx, _) = broadcast::channel(256);
        Node {
            chain: Arc::new(Mutex::new(chain)),
            listen_addr,
            network_magic,
            peers: Arc::new(Mutex::new(vec![])),
            relay_tx,
            rate_limiters: Arc::new(Mutex::new(NodeRateLimiter::new())),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("Node listening on {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New connection from {}", addr);
            let addr_str = addr.to_string();
            if !self.rate_limiters.lock().await.connections.check(&addr_str) {
                warn!("Rate-limited new connection from {}", addr_str);
                continue;
            }
            // Perform Noise_XX handshake; drop connection if it fails.
            // P2P authentication uses transport-layer mutual auth (Noise_XX),
            // not application-level AccessTokens.  The AccessToken system is
            // for RPC API permissioning only.
            let mut peer = match Peer::from_stream(stream, addr_str.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("Noise handshake failed for {}: {}", addr_str, e);
                    continue;
                }
            };
            // Announce our height to the connecting peer so they know whether
            // to request headers from us.  Both sides must send Version; the
            // initiator sends first, the acceptor sends immediately after the
            // Noise handshake completes.
            let our_height = self.chain.lock().await.height();
            if peer
                .send(&Message::Version {
                    version: PROTOCOL_VERSION,
                    network_magic: self.network_magic,
                    best_height: our_height,
                    user_agent: "arkos/0.1".into(),
                })
                .await
                .is_err()
            {
                warn!("Failed to send Version to {}", addr_str);
                continue;
            }
            {
                let mut known = self.peers.lock().await;
                if !known.contains(&addr_str) && known.len() < MAX_KNOWN_PEERS {
                    known.push(addr_str.clone());
                }
            }
            let chain = self.chain.clone();
            let peers = self.peers.clone();
            let relay_tx = self.relay_tx.clone();
            let rate_limiters = self.rate_limiters.clone();
            let network_magic = self.network_magic;
            tokio::spawn(async move {
                if let Err(e) = handle_peer(
                    peer,
                    chain,
                    peers.clone(),
                    rate_limiters,
                    relay_tx,
                    network_magic,
                )
                .await
                {
                    warn!("Peer {} error: {}", addr_str, e);
                }
                // Remove peer from known list on disconnect (M-5)
                peers.lock().await.retain(|p| p != &addr_str);
                info!("Peer {} disconnected", addr_str);
            });
        }
    }

    /// Mine one block locally and relay the inventory announcement to all peers.
    ///
    /// Runs the ArkHash miner in `spawn_blocking` to avoid stalling the async
    /// runtime during the CPU-intensive PoW search.
    pub async fn mine_block_and_relay(&self, miner_address: &str) -> Result<()> {
        let chain_arc = self.chain.clone();
        let miner_address = miner_address.to_string();
        let relay_tx = self.relay_tx.clone();

        tokio::task::spawn_blocking(move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let mut chain = chain_arc.lock().await;
                let block = chain.mine_block(&miner_address);
                let hash = block.hash_hex();
                chain.add_block(block)?;
                let _ = relay_tx.send(RelayMessage {
                    source: String::new(),
                    message: Message::Inv {
                        items: vec![InvItem {
                            kind: InvKind::Block,
                            hash,
                        }],
                    },
                });
                anyhow::Ok(())
            })
        })
        .await??;
        Ok(())
    }

    pub async fn connect_to_peer(&self, addr: &str) -> Result<()> {
        let mut peer = Peer::connect(addr).await?;
        let height = self.chain.lock().await.height();
        peer.send(&Message::Version {
            version: PROTOCOL_VERSION,
            network_magic: self.network_magic,
            best_height: height,
            user_agent: "arkos/0.1".into(),
        })
        .await?;
        let chain = self.chain.clone();
        let peers = self.peers.clone();
        let relay_tx = self.relay_tx.clone();
        let rate_limiters = self.rate_limiters.clone();
        let network_magic = self.network_magic;
        let addr_owned = addr.to_string();
        let addr_for_push = addr_owned.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(
                peer,
                chain,
                peers.clone(),
                rate_limiters,
                relay_tx,
                network_magic,
            )
            .await
            {
                warn!("Peer {} error: {}", addr_owned, e);
            }
            // Remove peer from known list on disconnect (M-5)
            peers.lock().await.retain(|p| p != &addr_owned);
            info!("Peer {} disconnected", addr_owned);
        });
        {
            let mut known = self.peers.lock().await;
            if !known.contains(&addr_for_push) && known.len() < MAX_KNOWN_PEERS {
                known.push(addr_for_push);
            }
        }
        Ok(())
    }
}

/// Validate a peer address string before accepting it.
///
/// Accepts only valid `SocketAddr` strings (`ip:port` or `[ipv6]:port`).
/// Rejects garbage strings that merely contain a colon.
fn is_valid_peer_addr(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>().is_ok()
}

fn block_locator(chain: &Blockchain) -> Vec<String> {
    let mut locator = Vec::new();
    let mut height = chain.height();
    let mut step = 1u64;

    loop {
        if let Some(block) = chain.blocks.get(height as usize) {
            locator.push(block.hash_hex());
        }
        if height == 0 || locator.len() >= MAX_LOCATOR_HASHES {
            break;
        }
        height = height.saturating_sub(step);
        if locator.len() > 10 {
            step = step.saturating_mul(2);
        }
    }

    if !locator
        .last()
        .map(|hash| chain.blocks[0].hash_hex() == *hash)
        .unwrap_or(false)
    {
        locator.push(chain.blocks[0].hash_hex());
    }
    locator
}

async fn handle_peer(
    peer: Peer,
    chain: Arc<Mutex<Blockchain>>,
    peers: Arc<Mutex<Vec<String>>>,
    rate_limiters: Arc<Mutex<NodeRateLimiter>>,
    relay_tx: broadcast::Sender<RelayMessage>,
    expected_network_magic: u32,
) -> Result<()> {
    let addr = peer.addr.clone();
    let mut relay_rx = relay_tx.subscribe();

    // Split the peer into independent read/write halves, then move the read
    // half to a dedicated task.  This prevents the select! cancellation-safety
    // hazard: when the relay branch wins, a bare `peer.recv()` future is
    // dropped mid-`read_exact`, leaving the Noise frame stream misaligned and
    // causing the "noise message too large" error on the next read.
    let (mut peer_reader, mut peer_writer) = peer.into_split();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Result<Message>>(128);
    tokio::spawn(async move {
        loop {
            let res = peer_reader.recv().await;
            let is_err = res.is_err();
            if in_tx.send(res).await.is_err() {
                break; // main task has exited
            }
            if is_err {
                break;
            }
        }
    });

    loop {
        let msg = tokio::select! {
            incoming = in_rx.recv() => match incoming {
                Some(Ok(msg)) => msg,
                Some(Err(e)) => return Err(e),
                None => break,
            },
            relay = relay_rx.recv() => {
                match relay {
                    Ok(relay) => {
                        if relay.source != addr {
                            peer_writer.send(&relay.message).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
                continue;
            }
        };
        if !rate_limiters.lock().await.messages.check(&addr) {
            anyhow::bail!("peer {} exceeded message rate limit", addr);
        }
        match msg {
            Message::Version {
                version,
                network_magic,
                best_height,
                user_agent,
            } => {
                // H-6: reject oversized user_agent strings
                if user_agent.len() > MAX_USER_AGENT_LEN {
                    anyhow::bail!(
                        "peer {} sent user_agent of {} bytes (max {})",
                        addr,
                        user_agent.len(),
                        MAX_USER_AGENT_LEN
                    );
                }
                if network_magic != expected_network_magic {
                    anyhow::bail!(
                        "peer {} is on wrong network magic 0x{:08x}",
                        addr,
                        network_magic
                    );
                }
                if version != PROTOCOL_VERSION {
                    anyhow::bail!(
                        "peer {} uses unsupported protocol version {}",
                        addr,
                        version
                    );
                }
                info!(
                    "Peer {} is at height {} ({})",
                    addr, best_height, user_agent
                );
                peer_writer.send(&Message::Verack).await?;
                let our_height = chain.lock().await.height();
                if best_height > our_height {
                    // Headers-first: request headers before full blocks.
                    // We validate PoW on the lighter header objects first, only
                    // downloading full blocks for headers that pass validation.
                    let locator = {
                        let chain = chain.lock().await;
                        block_locator(&chain)
                    };
                    peer_writer
                        .send(&Message::GetHeaders {
                            locator_hashes: locator,
                        })
                        .await?;
                }
            }
            Message::Verack => {}

            Message::GetHeaders { locator_hashes } => {
                let chain = chain.lock().await;
                let start = locator_hashes
                    .iter()
                    .find_map(|h| chain.block_index.get(h).copied())
                    .map(|height| height + 1)
                    .unwrap_or(0);
                let headers: Vec<_> = chain
                    .blocks
                    .iter()
                    .skip(start)
                    .take(MAX_HEADERS_PER_RESPONSE)
                    .map(|b| b.header.clone())
                    .collect();
                drop(chain);
                if !headers.is_empty() {
                    peer_writer.send(&Message::Headers { headers }).await?;
                }
            }

            Message::Headers { headers } => {
                // Validate PoW on each header before committing to download the
                // full blocks.  Invalid headers are dropped silently; we still
                // request the valid ones so one bad apple does not stall sync.
                let mut prev: Option<String> = None;
                let mut to_fetch: Vec<InvItem> = Vec::new();
                for header in headers {
                    let parent_known = {
                        let chain = chain.lock().await;
                        chain.block_by_hash(&header.prev_hash).is_some()
                    };
                    let prev_matches = prev
                        .as_ref()
                        .map(|prev_hash| header.prev_hash == *prev_hash)
                        .unwrap_or(parent_known);

                    // Chain linkage is already verified by `prev_matches` above.
                    // Call validate_header_only with the actual expected parent so the
                    // prev_hash check inside the function is meaningful, not tautological.
                    // We pass None for expected_bits here: we don't know the exact
                    // retarget height for an arbitrary peer's chain tip, so PoW
                    // verification (self.meets_target()) still enforces the bits
                    // field internally — a peer cannot inflate bits without
                    // producing an astronomically hard PoW.
                    let expected_parent = prev.as_deref().unwrap_or(&header.prev_hash);
                    if prev_matches && header.validate_header_only(expected_parent, None).is_ok() {
                        let hash = header.hash_hex();
                        let known = chain.lock().await.block_by_hash(&hash).is_some();
                        if !known {
                            to_fetch.push(InvItem {
                                kind: InvKind::Block,
                                hash: hash.clone(),
                            });
                        }
                        prev = Some(hash);
                    } else {
                        warn!(
                            "Peer {} sent invalid or disconnected header — stopping headers-first batch",
                            addr
                        );
                        break;
                    }
                }

                // Request full blocks in batches of MAX_GETDATA_INFLIGHT to
                // cap memory usage during initial sync.
                for chunk in to_fetch.chunks(MAX_GETDATA_INFLIGHT) {
                    peer_writer
                        .send(&Message::GetData {
                            items: chunk.to_vec(),
                        })
                        .await?;
                }
            }

            Message::GetBlocks { locator_hashes } => {
                // L-3: per-peer bandwidth quota — each response ships up to 500
                // block hashes; without a dedicated limit a peer could drive
                // 50 k announcements/min at the general message rate.
                if !rate_limiters.lock().await.getblocks.check(&addr) {
                    anyhow::bail!("peer {} exceeded GetBlocks rate limit", addr);
                }
                let chain = chain.lock().await;
                // L-6: use block_index (main chain only), not all_blocks
                let start = locator_hashes
                    .iter()
                    .find_map(|h| chain.block_index.get(h).copied())
                    .map(|height| height + 1)
                    .unwrap_or(0);
                // L-3: cap response volume
                let items: Vec<InvItem> = chain
                    .blocks
                    .iter()
                    .skip(start)
                    .take(MAX_BLOCKS_PER_GETBLOCKS)
                    .map(|b| InvItem {
                        kind: InvKind::Block,
                        hash: b.hash_hex(),
                    })
                    .collect();
                drop(chain);
                if !items.is_empty() {
                    peer_writer.send(&Message::Inv { items }).await?;
                }
            }
            Message::Inv { items } => {
                let chain = chain.lock().await;
                let needed: Vec<InvItem> = items
                    .into_iter()
                    .filter(|item| {
                        (matches!(item.kind, InvKind::Block)
                            && chain.block_by_hash(&item.hash).is_none())
                            || (matches!(item.kind, InvKind::Transaction)
                                && !chain.mempool.contains(&item.hash))
                    })
                    .collect();
                drop(chain);
                if !needed.is_empty() {
                    peer_writer
                        .send(&Message::GetData { items: needed })
                        .await?;
                }
            }
            Message::GetData { items } => {
                // Collect all responses while holding the lock once, then send
                // them all after releasing it.  Separating lock from send avoids
                // holding the chain lock across async I/O.
                let responses: Vec<Message> = {
                    let chain = chain.lock().await;
                    items
                        .iter()
                        .filter_map(|item| match item.kind {
                            InvKind::Block => chain
                                .block_by_hash(&item.hash)
                                .map(|b| Message::BlockMsg(b.clone())),
                            InvKind::Transaction => chain
                                .mempool
                                .get(&item.hash)
                                .map(|tx| Message::TxMsg(tx.clone())),
                        })
                        .collect()
                };
                for msg in responses {
                    peer_writer.send(&msg).await?;
                }
            }
            Message::BlockMsg(block) => {
                if !rate_limiters.lock().await.blocks.check(&addr) {
                    anyhow::bail!("peer {} exceeded block rate limit", addr);
                }
                let mut chain = chain.lock().await;
                let hash = block.hash_hex();
                match chain.add_block(block) {
                    Ok(_) => {
                        info!("Added block at height {}", chain.height());
                        let _ = relay_tx.send(RelayMessage {
                            source: addr.clone(),
                            message: Message::Inv {
                                items: vec![InvItem {
                                    kind: InvKind::Block,
                                    hash,
                                }],
                            },
                        });
                    }
                    Err(e) => warn!("Rejected block: {}", e),
                }
            }
            Message::TxMsg(tx) => {
                if !rate_limiters.lock().await.transactions.check(&addr) {
                    anyhow::bail!("peer {} exceeded transaction rate limit", addr);
                }
                let mut chain = chain.lock().await;
                let txid_for_relay = tx.txid_hex();
                match chain.submit_transaction(tx) {
                    Ok(txid) => {
                        info!("Accepted tx {}", txid);
                        let _ = relay_tx.send(RelayMessage {
                            source: addr.clone(),
                            message: Message::Inv {
                                items: vec![InvItem {
                                    kind: InvKind::Transaction,
                                    hash: txid_for_relay,
                                }],
                            },
                        });
                    }
                    Err(e) => warn!("Rejected tx: {}", e),
                }
            }
            Message::Ping(nonce) => {
                peer_writer.send(&Message::Pong(nonce)).await?;
            }
            Message::Pong(_) => {}
            Message::Addr { addrs } => {
                // H-3: cap entries per message and validate each address
                if addrs.len() > MAX_ADDR_PER_MESSAGE {
                    anyhow::bail!(
                        "peer {} sent Addr with {} entries (max {})",
                        addr,
                        addrs.len(),
                        MAX_ADDR_PER_MESSAGE
                    );
                }
                let mut known = peers.lock().await;
                for candidate in addrs {
                    if !is_valid_peer_addr(&candidate) {
                        warn!("Peer {} sent invalid address: {:?}", addr, candidate);
                        continue;
                    }
                    if known.len() >= MAX_KNOWN_PEERS {
                        break;
                    }
                    if !known.contains(&candidate) {
                        known.push(candidate);
                    }
                }
                info!("Known peers: {}", known.len());
            }
        }
    }
    Ok(())
}
