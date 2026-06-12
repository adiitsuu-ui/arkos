use crate::blockchain::chain::Blockchain;
use crate::network::peer::Peer;
use crate::network::peers::{PeerStore, MIN_OUTBOUND};
use crate::network::protocol::{
    InvItem, InvKind, Message, MAX_GETDATA_INFLIGHT, MAX_HEADERS_PER_RESPONSE, PROTOCOL_VERSION,
};
use crate::security::rate_limit::NodeRateLimiter;
use anyhow::Result;
use log::{info, warn};
use std::path::PathBuf;
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

/// How often (seconds) the feeler task probes a random idle known peer.
const FEELER_INTERVAL_SECS: u64 = 120;

/// How often (seconds) the outbound-maintenance task checks peer count.
const OUTBOUND_CHECK_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub(crate) struct RelayMessage {
    pub(crate) source: String,
    pub(crate) message: Message,
}

pub struct Node {
    pub chain: Arc<Mutex<Blockchain>>,
    pub listen_addr: String,
    pub network_magic: u32,
    pub(crate) peer_store: Arc<Mutex<PeerStore>>,
    pub(crate) relay_tx: broadcast::Sender<RelayMessage>,
    rate_limiters: Arc<Mutex<NodeRateLimiter>>,
    anchor_path: PathBuf,
}

impl Node {
    pub fn new(chain: Blockchain, listen_addr: String, network_magic: u32) -> Self {
        let (relay_tx, _) = broadcast::channel(256);
        Node {
            chain: Arc::new(Mutex::new(chain)),
            listen_addr,
            network_magic,
            peer_store: Arc::new(Mutex::new(PeerStore::new())),
            relay_tx,
            rate_limiters: Arc::new(Mutex::new(NodeRateLimiter::new())),
            anchor_path: PathBuf::from("anchors.txt"),
        }
    }

    pub async fn run(&self) -> Result<()> {
        // Dial anchor peers from the previous run before accepting new connections.
        let anchors = PeerStore::load_anchors(&self.anchor_path);
        for addr in anchors {
            info!("Dialing anchor peer {}", addr);
            if let Err(e) = self.connect_to_peer(&addr).await {
                warn!("Anchor peer {} unreachable: {}", addr, e);
            }
        }

        // Background: feeler task — periodically probe a random idle known peer.
        {
            let peer_store = self.peer_store.clone();
            let chain = self.chain.clone();
            let network_magic = self.network_magic;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(FEELER_INTERVAL_SECS))
                        .await;
                    let target = peer_store.lock().await.random_unconnected();
                    if let Some(addr) = target {
                        info!("Feeler connecting to {}", addr);
                        if let Ok(mut peer) = Peer::connect(&addr).await {
                            let height = chain.lock().await.height();
                            let _ = peer
                                .send(&Message::Version {
                                    version: PROTOCOL_VERSION,
                                    network_magic,
                                    best_height: height,
                                    user_agent: "arkos/0.1-feeler".into(),
                                })
                                .await;
                            info!("Feeler confirmed {} is reachable", addr);
                        } else {
                            peer_store.lock().await.remove_known(&addr);
                            info!("Feeler evicted unreachable peer {}", addr);
                        }
                    }
                }
            });
        }

        // Background: outbound-maintenance task — keep at least MIN_OUTBOUND peers.
        {
            let peer_store = self.peer_store.clone();
            let chain = self.chain.clone();
            let relay_tx = self.relay_tx.clone();
            let rate_limiters = self.rate_limiters.clone();
            let network_magic = self.network_magic;
            let anchor_path = self.anchor_path.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        OUTBOUND_CHECK_INTERVAL_SECS,
                    ))
                    .await;

                    {
                        let store = peer_store.lock().await;
                        let _ = store.save_anchors(&anchor_path);
                        if !store.needs_outbound() {
                            continue;
                        }
                    }

                    let candidates = peer_store.lock().await.outbound_candidates();
                    if candidates.is_empty() {
                        continue;
                    }

                    let deficit = {
                        let store = peer_store.lock().await;
                        MIN_OUTBOUND.saturating_sub(store.outbound_count())
                    };

                    use rand::seq::SliceRandom;
                    let mut chosen = candidates;
                    chosen.shuffle(&mut rand::thread_rng());

                    for addr in chosen.into_iter().take(deficit) {
                        info!("Outbound maintenance: dialing {}", addr);
                        if let Ok(mut peer) = Peer::connect(&addr).await {
                            let height = chain.lock().await.height();
                            if peer
                                .send(&Message::Version {
                                    version: PROTOCOL_VERSION,
                                    network_magic,
                                    best_height: height,
                                    user_agent: "arkos/0.1".into(),
                                })
                                .await
                                .is_err()
                            {
                                continue;
                            }
                            peer_store.lock().await.mark_outbound(&addr);
                            let peer_store2 = peer_store.clone();
                            let addr2 = addr.clone();
                            let chain2 = chain.clone();
                            let rl2 = rate_limiters.clone();
                            let rtx2 = relay_tx.clone();
                            let ap2 = anchor_path.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_peer(peer, chain2, peer_store2.clone(), rl2, rtx2, network_magic)
                                        .await
                                {
                                    warn!("Outbound peer {} error: {}", addr2, e);
                                }
                                let mut store = peer_store2.lock().await;
                                store.unmark_outbound(&addr2);
                                let _ = store.save_anchors(&ap2);
                                info!("Outbound peer {} disconnected", addr2);
                            });
                        }
                    }
                }
            });
        }

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
            let mut peer = match Peer::from_stream(stream, addr_str.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("Noise handshake failed for {}: {}", addr_str, e);
                    continue;
                }
            };
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
                let mut store = self.peer_store.lock().await;
                store.add_known(&addr_str);
                store.mark_inbound(&addr_str);
            }
            let chain = self.chain.clone();
            let peer_store = self.peer_store.clone();
            let relay_tx = self.relay_tx.clone();
            let rate_limiters = self.rate_limiters.clone();
            let network_magic = self.network_magic;
            let anchor_path = self.anchor_path.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_peer(
                    peer,
                    chain,
                    peer_store.clone(),
                    rate_limiters,
                    relay_tx,
                    network_magic,
                )
                .await
                {
                    warn!("Peer {} error: {}", addr_str, e);
                }
                {
                    let mut store = peer_store.lock().await;
                    store.unmark_inbound(&addr_str);
                    let _ = store.save_anchors(&anchor_path);
                }
                info!("Peer {} disconnected", addr_str);
            });
        }
    }

    /// Mine one block locally and relay the inventory announcement to all peers.
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

        {
            let mut store = self.peer_store.lock().await;
            store.add_known(addr);
            store.mark_outbound(addr);
        }

        let chain = self.chain.clone();
        let peer_store = self.peer_store.clone();
        let relay_tx = self.relay_tx.clone();
        let rate_limiters = self.rate_limiters.clone();
        let network_magic = self.network_magic;
        let addr_owned = addr.to_string();
        let anchor_path = self.anchor_path.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(
                peer,
                chain,
                peer_store.clone(),
                rate_limiters,
                relay_tx,
                network_magic,
            )
            .await
            {
                warn!("Peer {} error: {}", addr_owned, e);
            }
            {
                let mut store = peer_store.lock().await;
                store.unmark_outbound(&addr_owned);
                let _ = store.save_anchors(&anchor_path);
            }
            info!("Peer {} disconnected", addr_owned);
        });
        Ok(())
    }
}

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
    peer_store: Arc<Mutex<PeerStore>>,
    rate_limiters: Arc<Mutex<NodeRateLimiter>>,
    relay_tx: broadcast::Sender<RelayMessage>,
    expected_network_magic: u32,
) -> Result<()> {
    let addr = peer.addr.clone();
    let mut relay_rx = relay_tx.subscribe();

    let (mut peer_reader, mut peer_writer) = peer.into_split();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Result<Message>>(128);
    tokio::spawn(async move {
        loop {
            let res = peer_reader.recv().await;
            let is_err = res.is_err();
            if in_tx.send(res).await.is_err() {
                break;
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

                for chunk in to_fetch.chunks(MAX_GETDATA_INFLIGHT) {
                    peer_writer
                        .send(&Message::GetData {
                            items: chunk.to_vec(),
                        })
                        .await?;
                }
            }

            Message::GetBlocks { locator_hashes } => {
                if !rate_limiters.lock().await.getblocks.check(&addr) {
                    anyhow::bail!("peer {} exceeded GetBlocks rate limit", addr);
                }
                let chain = chain.lock().await;
                let start = locator_hashes
                    .iter()
                    .find_map(|h| chain.block_index.get(h).copied())
                    .map(|height| height + 1)
                    .unwrap_or(0);
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
                if addrs.len() > MAX_ADDR_PER_MESSAGE {
                    anyhow::bail!(
                        "peer {} sent Addr with {} entries (max {})",
                        addr,
                        addrs.len(),
                        MAX_ADDR_PER_MESSAGE
                    );
                }
                let mut store = peer_store.lock().await;
                let mut added = 0usize;
                for candidate in addrs {
                    if !is_valid_peer_addr(&candidate) {
                        warn!("Peer {} sent invalid address: {:?}", addr, candidate);
                        continue;
                    }
                    if store.known_count() >= MAX_KNOWN_PEERS {
                        break;
                    }
                    if store.add_known(&candidate) {
                        added += 1;
                    }
                }
                info!(
                    "Known peers: {} (+{} from {})",
                    store.known_count(),
                    added,
                    addr
                );
            }
        }
    }
    Ok(())
}
