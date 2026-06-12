//! Integration tests covering Tasks 3–11 (all recent feature additions).
//!
//! Task 3:  ML-DSA deterministic seed derivation
//! Task 4:  Fee-rate mempool ordering, dust limit constant
//! Task 5:  (noise handshake — tested via multinode.rs)
//! Task 6:  HD wallet key derivation
//! Task 7:  Headers-first sync (tested via multinode.rs)
//! Task 8:  Script system — covered in chain.rs unit tests and here (dust)
//! Task 9:  Eclipse mitigations — PeerStore anchors, outbound tracking
//! Task 10: (fuzz targets — compile-time only)
//! Task 11: Bincode serialization roundtrip

use arkos::transaction::tx::{Transaction, TxInput, TxOutput};
use arkos::crypto::quantum::{HybridKeyPair, HybridPublicKey, HybridSignature};
use arkos::transaction::mempool::{Mempool, DUST_LIMIT_ARKES};
use arkos::network::peers::{PeerStore, MIN_OUTBOUND};
use arkos::wallet::wallet::HdWallet;
use arkos::network::protocol::TESTNET_MAGIC;

// ── Task 3: ML-DSA deterministic seed derivation ──────────────────────────

#[test]
fn mldsa_from_parts_mismatched_pubkey_rejected() {
    let kp1 = HybridKeyPair::generate();
    let kp2 = HybridKeyPair::generate();
    // Use kp1's ECDSA secret + kp2's dilithium public key → mismatch
    let result = HybridKeyPair::from_parts(
        &kp1.ecdsa_secret.secret_bytes(),
        &kp1.dilithium_secret,
        &kp2.dilithium_public,
    );
    assert!(result.is_err(), "from_parts must reject when public key doesn't match seed");
    assert!(result.err().unwrap().to_string().contains("does not match seed"));
}

#[test]
fn mldsa_from_parts_wrong_seed_length_rejected() {
    let kp = HybridKeyPair::generate();
    let bad_seed = vec![0u8; 16]; // must be 32 bytes
    let result = HybridKeyPair::from_parts(
        &kp.ecdsa_secret.secret_bytes(),
        &bad_seed,
        &kp.dilithium_public,
    );
    assert!(result.is_err(), "from_parts must reject seed that is not 32 bytes");
    assert!(result.err().unwrap().to_string().contains("32 bytes"));
}

#[test]
fn mldsa_seed_consistent_across_generate_and_from_parts() {
    let kp = HybridKeyPair::generate();
    // Round-trip: reconstruct from stored parts and verify signing still works.
    let kp2 = HybridKeyPair::from_parts(
        &kp.ecdsa_secret.secret_bytes(),
        &kp.dilithium_secret,
        &kp.dilithium_public,
    )
    .expect("from_parts with matching parts must succeed");
    // Both keypairs should produce the same public key
    assert_eq!(kp.public_key().ecdsa_pubkey, kp2.public_key().ecdsa_pubkey);
    assert_eq!(kp.public_key().dilithium_pubkey, kp2.public_key().dilithium_pubkey);
    // Both should produce verifiable signatures
    let msg = [0x42u8; 32];
    let sig = kp2.sign(&msg);
    assert!(sig.verify(&msg, &kp2.public_key()).is_ok(), "reconstructed keypair must sign/verify");
}

#[test]
fn mldsa_phrase_recovery_is_deterministic() {
    // Same ECDSA secret → same ML-DSA public key (deterministic derivation)
    let kp1 = HybridKeyPair::from_ecdsa_secret_bytes(&[0xABu8; 32]).unwrap();
    let kp2 = HybridKeyPair::from_ecdsa_secret_bytes(&[0xABu8; 32]).unwrap();
    assert_eq!(
        kp1.dilithium_public, kp2.dilithium_public,
        "same ECDSA secret must always produce the same ML-DSA verifying key"
    );
    assert_eq!(
        kp1.dilithium_secret, kp2.dilithium_secret,
        "same ECDSA secret must always produce the same ML-DSA seed"
    );
}

// ── Task 4: Mempool fee-rate ordering ─────────────────────────────────────

fn make_tx(recipient: &str) -> Transaction {
    Transaction::new(
        vec![TxInput {
            prev_tx_hash: "00".repeat(32),
            prev_index: 0,
            signature: HybridSignature { ecdsa_sig: vec![0; 64], dilithium_sig: vec![0; 10] },
            pubkey: HybridPublicKey { ecdsa_pubkey: vec![0; 33], dilithium_pubkey: vec![0; 10] },
            coinbase_extra: vec![],
            witnesses: vec![],
        }],
        vec![TxOutput { value: 100_000, address: recipient.into(), script: None }],
    )
}

#[test]
fn mempool_fee_rate_ordering_high_fee_first() {
    let mut mempool = Mempool::new();
    // tx_low: small fee, tx_high: large fee for same-sized tx
    let tx_low = make_tx("low");
    let tx_high = make_tx("high");
    mempool.add_with_fee(tx_low, 1_000).unwrap();
    mempool.add_with_fee(tx_high, 50_000).unwrap();
    let selected = mempool.take(2);
    // The first transaction returned must be the one with the higher fee
    assert_eq!(
        selected[0].outputs[0].address, "high",
        "high-fee transaction must be ordered first"
    );
    assert_eq!(selected[1].outputs[0].address, "low");
}

#[test]
fn mempool_fee_rate_tie_broken_deterministically() {
    // Two identical-size transactions with equal fees → order must be consistent across calls.
    // Both addresses are padded to 40 chars so serialized sizes are equal.
    let tx_a = make_tx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let tx_b = make_tx("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let txid_a = tx_a.txid_hex();
    let txid_b = tx_b.txid_hex();
    assert_ne!(txid_a, txid_b, "test setup: two distinct txids");

    let mut mempool = Mempool::new();
    mempool.add_with_fee(tx_a, 5_000).unwrap();
    mempool.add_with_fee(tx_b, 5_000).unwrap();
    let selected = mempool.take(2);
    let first_txid = selected[0].txid_hex();
    let second_txid = selected[1].txid_hex();
    // Tie-break is ascending txid — lower txid must come first.
    assert!(
        first_txid <= second_txid,
        "equal-fee-rate txs must be ordered by ascending txid; got {} then {}",
        first_txid, second_txid
    );
}

#[test]
fn mempool_fee_for_known_txid() {
    let mut mempool = Mempool::new();
    let tx = make_tx("someone");
    let txid = mempool.add_with_fee(tx, 7_777).unwrap();
    assert_eq!(mempool.fee_for(&txid), 7_777);
}

#[test]
fn dust_limit_constant_is_546() {
    // Regression: dust limit value must not drift
    assert_eq!(DUST_LIMIT_ARKES, 546, "dust limit must be exactly 546 arkes");
}

// ── Task 6: HD wallet ─────────────────────────────────────────────────────

#[test]
fn hd_wallet_different_entropy_gives_different_addresses() {
    let hd1 = HdWallet::from_entropy(&[0x11u8; 32]).unwrap();
    let hd2 = HdWallet::from_entropy(&[0x22u8; 32]).unwrap();
    let addr1 = hd1.derive_receiving(0).unwrap().address();
    let addr2 = hd2.derive_receiving(0).unwrap().address();
    assert_ne!(addr1, addr2, "different entropy must produce different addresses");
}

#[test]
fn hd_wallet_change_addresses_distinct_from_receiving() {
    let hd = HdWallet::from_entropy(&[0x33u8; 32]).unwrap();
    let recv = hd.derive_receiving(0).unwrap().address();
    let change = hd.derive_change(0).unwrap().address();
    assert_ne!(recv, change, "receiving and change wallets at index 0 must differ");
}

#[test]
fn hd_wallet_receiving_indices_are_distinct() {
    let hd = HdWallet::from_entropy(&[0x44u8; 32]).unwrap();
    let addrs: Vec<String> = (0..5).map(|i| hd.derive_receiving(i).unwrap().address()).collect();
    let unique: std::collections::HashSet<_> = addrs.iter().collect();
    assert_eq!(unique.len(), 5, "first 5 receiving indices must all be distinct addresses");
}

#[test]
fn hd_wallet_entropy_produces_valid_signing_keypair() {
    let hd = HdWallet::from_entropy(&[0x55u8; 32]).unwrap();
    let wallet = hd.derive_receiving(0).unwrap();
    let msg = [0x99u8; 32];
    let sig = wallet.keypair.sign(&msg);
    assert!(
        sig.verify(&msg, &wallet.keypair.public_key()).is_ok(),
        "HD-derived keypair must produce valid signatures"
    );
}

// ── Task 9: Eclipse attack mitigations (PeerStore) ────────────────────────

#[test]
fn peer_store_needs_outbound_when_below_minimum() {
    let mut store = PeerStore::new();
    assert!(store.needs_outbound(), "fresh store needs outbound connections");
    for i in 0..MIN_OUTBOUND {
        let addr = format!("{}.0.0.1:8333", i + 1);
        store.add_known(&addr);
        store.mark_outbound(&addr);
    }
    assert!(!store.needs_outbound(), "store with MIN_OUTBOUND peers must not need more");
}

#[test]
fn peer_store_outbound_count_tracks_correctly() {
    let mut store = PeerStore::new();
    store.add_known("10.0.0.1:8333");
    store.mark_outbound("10.0.0.1:8333");
    assert_eq!(store.outbound_count(), 1);
    store.unmark_outbound("10.0.0.1:8333");
    assert_eq!(store.outbound_count(), 0);
}

#[test]
fn peer_store_random_unconnected_excludes_connected_peers() {
    let mut store = PeerStore::new();
    // Add peers across different subnets
    for i in 1u8..=5 {
        let addr = format!("{}.0.0.1:8333", i);
        store.add_known(&addr);
    }
    // Mark first two as outbound (connected)
    store.mark_outbound("1.0.0.1:8333");
    store.mark_inbound("2.0.0.1:8333");

    for _ in 0..20 {
        if let Some(candidate) = store.random_unconnected() {
            assert_ne!(candidate, "1.0.0.1:8333", "outbound peer must not be returned");
            assert_ne!(candidate, "2.0.0.1:8333", "inbound peer must not be returned");
        }
    }
}

#[test]
fn peer_store_anchor_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("anchors.txt");

    let mut store = PeerStore::new();
    for i in 1u8..=3 {
        let addr = format!("{}.0.0.1:8333", i);
        store.add_known(&addr);
        store.mark_outbound(&addr);
    }
    store.save_anchors(&path).expect("save_anchors must succeed");

    let loaded = PeerStore::load_anchors(&path);
    assert!(!loaded.is_empty(), "loaded anchors must not be empty");
    assert!(loaded.len() <= 3, "must not load more anchors than were saved");
    // All loaded anchors must be valid socket addresses (parseable)
    for addr in &loaded {
        addr.parse::<std::net::SocketAddr>()
            .unwrap_or_else(|_| panic!("loaded anchor '{}' is not a valid SocketAddr", addr));
    }
}

#[test]
fn peer_store_load_anchors_missing_file_returns_empty() {
    let path = std::path::Path::new("/tmp/arkos_nonexistent_anchor_file_xyz.txt");
    let loaded = PeerStore::load_anchors(path);
    assert!(loaded.is_empty(), "missing anchor file must return empty vec");
}

// ── Task 11: Bincode serialization roundtrip ──────────────────────────────

#[test]
fn transaction_bincode_roundtrip() {
    let tx = Transaction::coinbase("miner_addr", 50_000_000, 1);
    let encoded = bincode::serialize(&tx).expect("Transaction must encode to bincode");
    let decoded: Transaction =
        bincode::deserialize(&encoded).expect("Transaction must decode from bincode");
    assert_eq!(tx.txid_hex(), decoded.txid_hex(), "txid must survive bincode roundtrip");
    assert_eq!(tx.outputs[0].value, decoded.outputs[0].value);
    assert_eq!(tx.outputs[0].address, decoded.outputs[0].address);
}

#[test]
fn hybrid_signature_bincode_roundtrip() {
    let sig = HybridSignature {
        ecdsa_sig: vec![1u8; 64],
        dilithium_sig: vec![2u8; 3309],
    };
    let encoded = bincode::serialize(&sig).expect("HybridSignature must encode");
    let decoded: HybridSignature =
        bincode::deserialize(&encoded).expect("HybridSignature must decode");
    assert_eq!(sig, decoded);
}

#[test]
fn network_magic_constants_are_distinct() {
    use arkos::network::protocol::{MAINNET_MAGIC, TESTNET_MAGIC, REGTEST_MAGIC};
    assert_ne!(MAINNET_MAGIC, TESTNET_MAGIC);
    assert_ne!(TESTNET_MAGIC, REGTEST_MAGIC);
    assert_ne!(MAINNET_MAGIC, REGTEST_MAGIC);
}
