//! Multi-node integration test: sync, propagation, and fork resolution.
//!
//! Spins up three in-process nodes connected over loopback TCP and exercises
//! block propagation and chain convergence.  ArkHash mining uses the testnet
//! difficulty (0x207fffff, ~50% per nonce) to keep test runtime short.
//!
//! Run with:
//!   cargo test --test multinode -- --test-threads=1
//!
//! The `--test-threads=1` flag prevents port conflicts when the test suite
//! includes other network tests on the same ports.

use arkos::blockchain::chain::Blockchain;
use arkos::network::node::Node;
use arkos::network::protocol::TESTNET_MAGIC;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration};

const MINER_ADDR: &str = "0000000000000000000000000000000000000001";
const MAGIC: u32 = TESTNET_MAGIC;

/// Wait until all nodes agree on the same best height.
/// Returns the common height, or panics if the timeout is exceeded.
async fn wait_sync(nodes: &[Arc<Node>], expected_height: u64, timeout_secs: u64) {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            let heights: Vec<u64> = {
                let mut v = vec![];
                for n in nodes {
                    v.push(n.chain.lock().await.height());
                }
                v
            };
            if heights.iter().all(|&h| h == expected_height) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "nodes did not reach height {} within {}s",
            expected_height, timeout_secs
        )
    });
}

/// Assert all nodes agree on both height and tip hash.
async fn assert_consensus(nodes: &[Arc<Node>]) {
    let mut tips = vec![];
    for n in nodes {
        let chain = n.chain.lock().await;
        tips.push((chain.height(), chain.tip().hash_hex()));
    }
    let (h0, hash0) = &tips[0];
    for (i, (h, hash)) in tips.iter().enumerate() {
        assert_eq!(h, h0, "node {} height {} != node 0 height {}", i, h, h0);
        assert_eq!(hash, hash0, "node {} tip hash differs from node 0", i);
    }
}

#[tokio::test]
async fn test_three_node_block_propagation() {
    let _ = env_logger::try_init();

    let node_a = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19001".into(),
        MAGIC,
    ));
    let node_b = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19002".into(),
        MAGIC,
    ));
    let node_c = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19003".into(),
        MAGIC,
    ));

    // Start listeners for each node
    for node in [node_a.clone(), node_b.clone(), node_c.clone()] {
        let n = node.clone();
        tokio::spawn(async move {
            if let Err(e) = n.run().await {
                log::error!("node error: {}", e);
            }
        });
    }
    // Give listeners time to bind
    sleep(Duration::from_millis(100)).await;

    // Topology: A ↔ B ↔ C  (linear chain)
    node_a
        .connect_to_peer("127.0.0.1:19002")
        .await
        .expect("A→B connection");
    node_b
        .connect_to_peer("127.0.0.1:19003")
        .await
        .expect("B→C connection");
    sleep(Duration::from_millis(100)).await;

    // Mine 3 blocks on A and relay them
    for _ in 0..3 {
        node_a
            .mine_block_and_relay(MINER_ADDR)
            .await
            .expect("mine block on A");
    }

    // B and C should converge to height 3 within 15s
    wait_sync(&[node_a.clone(), node_b.clone(), node_c.clone()], 3, 15).await;
    assert_consensus(&[node_a.clone(), node_b.clone(), node_c.clone()]).await;
}

#[tokio::test]
async fn test_initial_sync_via_headers_first() {
    let _ = env_logger::try_init();

    // A mines 2 blocks before B ever connects.
    // When B connects, A's Version includes height=2 → B sends GetHeaders →
    // A responds with Headers → B validates PoW and requests full blocks.
    let node_a = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19011".into(),
        MAGIC,
    ));
    let node_b = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19012".into(),
        MAGIC,
    ));

    let na = node_a.clone();
    tokio::spawn(async move {
        let _ = na.run().await;
    });
    let nb = node_b.clone();
    tokio::spawn(async move {
        let _ = nb.run().await;
    });
    sleep(Duration::from_millis(100)).await;

    // Mine 2 blocks on A before B connects
    for _ in 0..2 {
        node_a
            .mine_block_and_relay(MINER_ADDR)
            .await
            .expect("mine on A");
    }

    let a_height = node_a.chain.lock().await.height();
    assert_eq!(a_height, 2, "A should have mined 2 blocks");

    // Now B connects to A — headers-first sync should bring B to height 2
    node_b
        .connect_to_peer("127.0.0.1:19011")
        .await
        .expect("B→A connection");

    wait_sync(&[node_a.clone(), node_b.clone()], 2, 15).await;
    assert_consensus(&[node_a, node_b]).await;
}

/// Chain reorganisation: node A builds a 2-block chain, node B independently
/// builds a 3-block chain, then they connect.  All nodes must converge on B's
/// longer chain (more accumulated work).
///
/// This validates the fork-choice rule: heaviest chain wins, not first-seen.
#[tokio::test]
async fn test_reorg_longer_chain_wins() {
    let _ = env_logger::try_init();

    // Two isolated nodes — no connection yet.
    let node_a = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19021".into(),
        MAGIC,
    ));
    let node_b = Arc::new(Node::new(
        Blockchain::new(),
        "127.0.0.1:19022".into(),
        MAGIC,
    ));

    let na = node_a.clone();
    tokio::spawn(async move { let _ = na.run().await; });
    let nb = node_b.clone();
    tokio::spawn(async move { let _ = nb.run().await; });
    sleep(Duration::from_millis(100)).await;

    const MINER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MINER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // A mines 2 blocks — its chain has less accumulated work than B's 3-block chain.
    for _ in 0..2 {
        node_a.mine_block_and_relay(MINER_A).await.expect("A mine");
    }
    assert_eq!(node_a.chain.lock().await.height(), 2, "A should be at height 2");

    // B independently mines 3 blocks (more work).
    for _ in 0..3 {
        node_b.mine_block_and_relay(MINER_B).await.expect("B mine");
    }
    assert_eq!(node_b.chain.lock().await.height(), 3, "B should be at height 3");

    // Capture B's tip hash — all nodes must converge on this.
    let b_tip = node_b.chain.lock().await.tip().hash_hex();

    // Now connect the two nodes — A should reorg to B's longer chain.
    node_a
        .connect_to_peer("127.0.0.1:19022")
        .await
        .expect("A→B connection");

    // Both nodes must reach height 3 (B's chain) within 20 s.
    wait_sync(&[node_a.clone(), node_b.clone()], 3, 20).await;

    // Both must share the same tip (B's chain).
    let a_tip = node_a.chain.lock().await.tip().hash_hex();
    assert_eq!(
        a_tip, b_tip,
        "after reorg A's tip must match B's longer chain"
    );
    // A's miner should have zero balance — its blocks were orphaned.
    assert_eq!(
        node_a.chain.lock().await.balance_of(MINER_A),
        0,
        "A's orphaned blocks must not contribute to balance after reorg"
    );
    // B's miner should have a positive balance — 3 blocks.
    assert!(
        node_a.chain.lock().await.balance_of(MINER_B) > 0,
        "B's miner must have balance on the winning chain"
    );
}
