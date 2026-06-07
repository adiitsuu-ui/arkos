use crate::blockchain::chain::Blockchain;
use crate::network::peer::Peer;
use crate::network::protocol::{InvItem, InvKind, Message, PROTOCOL_VERSION};
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

#[derive(Debug, Clone)]
struct RelayMessage {
    source: String,
    message: Message,
}

pub struct Node {
    pub chain: Arc<Mutex<Blockchain>>,
    pub listen_addr: String,
    pub network_magic: u32,
    pub peers: Arc<Mutex<Vec<String>>>,
    relay_tx: broadcast::Sender<RelayMessage>,
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
            let peer = match Peer::from_stream(stream, addr_str.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("Noise handshake failed for {}: {}", addr_str, e);
                    continue;
                }
            };
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
                if let Err(e) =
                    handle_peer(peer, chain, peers.clone(), rate_limiters, relay_tx, network_magic)
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
            if let Err(e) =
                handle_peer(peer, chain, peers.clone(), rate_limiters, relay_tx, network_magic)
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
fn is_valid_peer_addr(addr: &str) -> bool {
    !addr.is_empty() && addr.len() <= 64 && addr.contains(':')
}

async fn handle_peer(
    mut peer: Peer,
    chain: Arc<Mutex<Blockchain>>,
    peers: Arc<Mutex<Vec<String>>>,
    rate_limiters: Arc<Mutex<NodeRateLimiter>>,
    relay_tx: broadcast::Sender<RelayMessage>,
    expected_network_magic: u32,
) -> Result<()> {
    let addr = peer.addr.clone();
    let mut relay_rx = relay_tx.subscribe();

    loop {
        let msg = tokio::select! {
            incoming = peer.recv() => incoming?,
            relay = relay_rx.recv() => {
                match relay {
                    Ok(relay) => {
                        if relay.source != addr {
                            peer.send(&relay.message).await?;
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
                info!("Peer {} is at height {} ({})", addr, best_height, user_agent);
                peer.send(&Message::Verack).await?;
                let our_height = chain.lock().await.height();
                if best_height > our_height {
                    let locator = chain.lock().await.tip().hash_hex();
                    peer.send(&Message::GetBlocks {
                        locator_hashes: vec![locator],
                    })
                    .await?;
                }
            }
            Message::Verack => {}
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
                    peer.send(&Message::Inv { items }).await?;
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
                    peer.send(&Message::GetData { items: needed }).await?;
                }
            }
            Message::GetData { items } => {
                let chain = chain.lock().await;
                for item in items {
                    match item.kind {
                        InvKind::Block => {
                            if let Some(block) = chain.block_by_hash(&item.hash) {
                                let block = block.clone();
                                drop(chain);
                                peer.send(&Message::BlockMsg(block)).await?;
                                break;
                            }
                        }
                        InvKind::Transaction => {
                            if let Some(tx) = chain.mempool.get(&item.hash) {
                                let tx = tx.clone();
                                drop(chain);
                                peer.send(&Message::TxMsg(tx)).await?;
                                break;
                            }
                        }
                    }
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
                peer.send(&Message::Pong(nonce)).await?;
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
