# Arkos Security Audit Report

**Date:** 2026-06-07  
**Scope:** Full codebase — all 31 `.rs` source files  
**Threat model:** Nation-state adversaries, organised cryptographic attacks, quantum computers, professional exploit developers, DoS campaigns, Sybil/eclipse network attacks.

---

## Severity Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 7 |
| 🟡 Medium | 9 |
| 🔵 Low | 7 |
| **Total** | **28** |

---

## 🔴 CRITICAL

---

### [REMOVED] C-1 — Device attestation is a stub — fake mobile miners can register freely

**Resolution:** The entire device-registration and mobile-mining-bonus subsystem has been removed. Mining is now open to any device (desktop, server, or mobile) using standard proof-of-work — no device identity, attestation blob, Secure Enclave key, or platform-specific API is required. The `DeviceProof`, `DeviceRegistry`, `DeviceRegistration`, and `MobilePlatform` types are gone, along with the `registerDevice` / `getDeviceStatus` RPC methods and the 20% mobile bonus. This eliminates C-1 at the architecture level rather than requiring a complex Apple/Google API integration.

---

### [FIXED] C-2 — Mempool has no size cap — memory exhaustion DoS
**File:** `src/transaction/mempool.rs` — `add`

```rust
pub fn add(&mut self, tx: Transaction) -> String {
    let txid = tx.txid_hex();
    self.txs.insert(txid.clone(), tx); // unbounded HashMap
    txid
}
```

There are no transaction fees and no mempool eviction policy. An attacker can continuously submit valid transactions (with fresh UTXOs or by splitting coins) and exhaust all available RAM, crashing the node.

**Fix:**
1. Enforce a minimum fee rate (arkes per byte of serialised transaction).
2. Cap the mempool at a configurable byte limit (e.g., 300 MB).
3. Evict the lowest-fee-rate transactions when the cap is reached.

---

### [FIXED] C-3 — `all_blocks` grows forever — fork-spam memory exhaustion
**File:** `src/blockchain/chain.rs` — `Blockchain`

```rust
pub struct Blockchain {
    pub all_blocks: HashMap<String, Block>, // every block ever seen, including orphans
    chain_work: HashMap<String, u128>,
    ...
}
```

Every block received from any peer is kept in memory indefinitely, including orphan blocks on competing forks. An attacker can continuously submit PoW-valid orphan blocks (mining them at the current difficulty from a Genesis fork) and fill RAM. Blocks are also loaded entirely into memory on startup (`from_blocks` iterates every stored block), making this a persistent disk-exhaustion vector as well.

**Fix:**
1. Prune orphan blocks that are buried beyond a finality depth (e.g., 100 confirmations).
2. Keep only block headers in memory; load full block bodies from RocksDB on demand.
3. Set a maximum number of tracked fork tips.

---

### [FIXED] C-4 — Chain reorg rebuilds entire chain from genesis — O(n²) CPU DoS
**File:** `src/blockchain/chain.rs` — `add_block`

```rust
let candidate_chain = Blockchain::from_genesis(parent_chain[0].clone(), None);
for ancestor in parent_chain.into_iter().skip(1) {
    candidate_chain.add_block(ancestor)?; // full re-validation from block 0
}
candidate_chain.validate_next_block(&block)?;
```

Every incoming block triggers a full chain reconstruction and re-validation from genesis to evaluate whether it represents more work. At height N this is O(N) work per block, meaning an adversary submitting a stream of competing fork blocks causes O(N²) CPU work. At 100,000 blocks this makes the node unresponsive.

**Fix:** Maintain a per-block cumulative chain-work value (already computed and stored in `chain_work`). To validate a new block you only need to validate it in isolation against its immediate parent, not rebuild the full chain. Only do a full UTXO rebuild during an actual reorg, not during candidate evaluation.

---

### [FIXED] C-5 — Non-deterministic mempool ordering breaks mobile mining
**File:** `src/transaction/mempool.rs` — `take` / `src/rpc/methods.rs` — template vs submit

```rust
pub fn take(&self, limit: usize) -> Vec<&Transaction> {
    self.txs.values().take(limit).collect() // HashMap = random order
}
```

`get_block_template` and `submit_block` both call `peek(500)` on the mempool's `HashMap`. Because `HashMap` has randomised iteration order in Rust, the transaction list—and therefore the Merkle root—will differ between the two calls. The server then correctly rejects the submitted block:

```rust
if computed_merkle != params.merkle_root {
    return Err("merkle root mismatch — stale template")
}
```

This means **all mobile-mined blocks with any mempool transactions will be rejected**. Mobile miners are forced to mine empty-except-coinbase blocks, losing fees and wasting compute.

**Fix:** Sort selected transactions by `txid_hex()` (lexicographic) before computing the Merkle root in both `get_block_template` and `submit_block`. Or store the pending template keyed by `prev_hash` and reuse the exact same transaction list.

---

## 🟠 HIGH

---

### [FIXED] H-1 — No TLS on P2P layer — full MITM exposure
**File:** `src/network/peer.rs`, `src/network/node.rs`

All P2P communication is raw plaintext TCP. Consequences:
- **Traffic analysis:** Governments and ISPs can identify participants, correlate transactions to IP addresses, and deanonymise the entire network.
- **MITM injection:** An on-path attacker can inject or modify blocks and transactions, silently redirecting mining rewards or double-spending.
- **Eclipse attacks:** ISPs or BGP hijackers can intercept all connections and feed a victim node a fake chain.

**Fix:** Wrap TCP connections in Noise Protocol (preferred — used by Lightning Network and libp2p) or TLS 1.3. Perform mutual authentication using each node's static key pair.

---

### [FIXED] H-2 — Merkle tree CVE-2012-2459 — duplicate-leaf collision
**File:** `src/blockchain/block.rs` — `merkle_root`

```rust
if hashes.len() % 2 != 0 {
    hashes.push(*hashes.last().unwrap()); // duplicate last leaf
}
```

This is the exact pattern that caused CVE-2012-2459 in Bitcoin. When a block has an odd number of transactions, the last TXID is duplicated. A block with N transactions can be crafted to produce the same Merkle root as a block with N-1 transactions by carefully choosing the Nth transaction. This breaks SPV (Simplified Payment Verification) proofs and can be used to fool light clients into accepting fake payment confirmations.

**Fix:** When the number of hashes is odd, duplicate the *hash pair* rather than the single leaf, or explicitly detect and reject trees that exhibit this ambiguity. See Bitcoin Core commit `ab91bf3` for the canonical fix.

---

### [FIXED] H-3 — Peer address injection — eclipse attack
**File:** `src/network/node.rs` — `Message::Addr` handler

```rust
Message::Addr { addrs } => {
    let mut known = peers.lock().await;
    for candidate in addrs {
        if !known.contains(&candidate) {
            known.push(candidate); // no validation, no limit
        }
    }
}
```

Any connected peer can advertise unlimited IP addresses with no format validation, no reachability check, no IP reputation, and no cap on the size of the `Addr` message or the resulting peers list. An attacker sends a single `Addr` message with 10,000 entries pointing to their own sybil nodes. All future connections the victim makes go to attacker-controlled peers, enabling a full eclipse attack — the victim node sees a fake chain.

**Fix:**
1. Validate address format before accepting.
2. Cap `Addr` messages at 1,000 entries; disconnect peers that exceed this.
3. Cap total tracked peer addresses (e.g., 4,096).
4. Require cryptographic proof-of-work or stake to advertise addresses.
5. Prefer peers that have been seen before.

---

### [FIXED] H-4 — No maximum block size — block-based DoS
**File:** `src/blockchain/block.rs` — `Block::validate`

```rust
pub fn validate(&self, prev_hash: &str) -> anyhow::Result<()> {
    if self.header.prev_hash != prev_hash { ... }
    if !self.header.meets_target() { ... }
    // ... no check on transactions.len() or total byte size
}
```

A miner can stuff a block with hundreds of thousands of transactions, all of which must be validated (UTXO lookups + dual signature verification including 3,293-byte Dilithium signatures). At Dilithium verification cost this can lock up a node for minutes per block. An attacker mines valid blocks at the current difficulty and fills them maximally.

**Fix:** Enforce a maximum block weight (e.g., 4 MB serialised). Reject blocks that exceed it before doing any signature verification.

---

### [FIXED] H-5 — Access token revocation not enforced anywhere
**File:** `src/security/access.rs` — `RevocationList`; `src/network/node.rs`

`RevocationList` is fully implemented with `revoke()` and `is_revoked()` methods. However:
1. The P2P layer (`node.rs`) does **not** use the access token system at all — any node can connect with only a `network_magic` check.
2. The RPC server checks the token but does **not** consult the `RevocationList`.

This means a revoked token keeps working forever on the RPC, and the P2P layer is entirely ungated.

**Fix:** 
1. Integrate `RevocationList::is_revoked` into `AccessToken::verify`.
2. Either gate P2P connections with token auth or document that P2P is intentionally public.

---

### [FIXED] H-6 — `user_agent` in Version message has no length limit
**File:** `src/network/node.rs` — `Message::Version` handler

```rust
Message::Version { version, network_magic, best_height, user_agent } => {
```

`user_agent` is deserialized from JSON with no length check. A peer can send a 32 MB string as `user_agent`, consuming heap memory proportional to every connected peer simultaneously. Combined with many simultaneous connections this is a remote heap exhaustion.

**Fix:** After deserialising, reject messages where `user_agent.len() > 256`. Alternatively, enforce it in `read_message` by checking message framing against per-message-type size policies.

---

### [FIXED] H-7 — Difficulty time-warp attack
**File:** `src/blockchain/consensus.rs` — `adjust_difficulty`

The difficulty algorithm uses only the first and last block timestamps of the 2016-block interval. A miner with majority hashrate can:
1. Mine the first block of an interval with a minimum timestamp (median past time + 1).
2. Mine the last block with an inflated timestamp (current_time + 7200).
3. This maximally inflates `actual_time`, triggering a 4× difficulty drop.
4. Repeat to drive difficulty to near-zero in a few intervals.

This is the "time-warp attack" that has drained several proof-of-work coins.

**Fix:** Use a rolling window (e.g., Bitcoin's `GetNextWorkRequired` which uses actual elapsed time between adjacent blocks), or apply the Zawy-Digishield algorithm that averages over multiple windows and is resistant to timestamp manipulation.

---

## 🟡 MEDIUM

---

### [FIXED] M-1 — Dead SHA-256 code in `derive_key` — misleading security comment
**File:** `src/security/vault.rs` — `derive_key`

```rust
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    // Use SHA-256 of Argon2 output as the AES key  ← comment is false
    let mut hasher = Sha256::new();
    hasher.update(passphrase);
    hasher.update(salt);
    // hasher.finalize() is never called — result discarded

    let argon2 = Argon2::new(...);
    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase, salt, &mut key)?; // ← actual key
    key
}
```

The SHA-256 computation is dead code. The key is correctly Argon2id output, but the comment claims otherwise. Future developers reading the comment may assume the key is SHA-256(Argon2(·)) and make incorrect security assumptions. The dead SHA-256 also keeps passphrase bytes in Sha256 state on the stack without zeroing.

**Fix:** Remove the dead SHA-256 code and update the comment to accurately describe what the function does.

---

### [FIXED] M-2 — `HybridKeyPair::from_bytes` produces an unusable keypair
**File:** `src/crypto/quantum.rs`

```rust
pub fn from_bytes(ecdsa_secret_bytes: &[u8], dilithium_secret_bytes: &[u8]) -> Result<Self> {
    ...
    Ok(HybridKeyPair {
        ...
        dilithium_public: vec![], // ← empty; filled from vault, supposedly
    })
}
```

`public_key()` called on this keypair returns `HybridPublicKey { dilithium_pubkey: vec![] }`. Any subsequent `HybridSignature::verify` call will fail with "invalid Dilithium public key." If a wallet is reconstructed via `from_bytes` instead of `from_parts`, all funds become permanently unspendable.

**Fix:** Either remove `from_bytes` entirely (it is superseded by `from_parts`) or derive the public key from the secret key. Since `pqcrypto-dilithium` does not expose a pk-from-sk function, the public key must always be stored alongside the secret key. Mark `from_bytes` as `#[deprecated]` and make `from_parts` the only reconstruction path.

---

### [FIXED] M-3 — Auth token comparison is not constant-time
**File:** `src/rpc/server.rs` — `authorized`

```rust
.map(|token| token == expected) // Rust str == is short-circuit
```

String comparison exits on the first differing byte, leaking timing information. Over a local loopback this is unexploitable, but over a network with high-precision timing measurement (or from a co-located attacker) it can enable token recovery via repeated timing measurements.

**Fix:** Use `subtle::ConstantTimeEq` or `hmac::Hmac` MAC comparison:
```rust
use subtle::ConstantTimeEq;
token.as_bytes().ct_eq(expected.as_bytes()).into()
```

---

### [FIXED] M-4 — RPC CORS defaults to `allow-all`
**File:** `src/rpc/server.rs` — `router`

```rust
None => AllowOrigin::any(), // default when cors_origin is not set
```

If the RPC is exposed (even on localhost) with no CORS restriction, any website the node operator visits can make authenticated RPC calls from their browser. This enables CSRF: a malicious webpage silently submits transactions, reads the chain state, or registers devices using the operator's browser session.

**Fix:** Default to `AllowOrigin::exact("http://127.0.0.1")` or require an explicit opt-in to relax the restriction.

---

### [FIXED] M-5 — Peer removal on disconnect is not implemented
**File:** `src/network/node.rs`

Peers are pushed to the list on connect but the list is never cleaned up:
```rust
self.peers.lock().await.push(addr_str.clone());
// ... no removal when the tokio task exits
```

Over time this list accumulates stale entries, consuming memory and causing incorrect count reporting. More importantly, it inflates the peer list sent in `Addr` gossip messages, directing other nodes to dead IPs.

**Fix:** Wrap connection state in a struct that removes the peer from the list on `Drop`, or use a `tokio::sync::watch` channel to signal cleanup.

---

### [FIXED] M-6 — `pubkey_to_address` comment documents the wrong algorithm
**File:** `src/crypto/keys.rs`

```rust
// RIPEMD-160(SHA-256(pubkey)) — simplified: we use SHA-256 twice and take first 20 bytes
```

The comment says RIPEMD-160(SHA-256()) but the implementation uses SHA-256(SHA-256()) truncated to 20 bytes. The security properties differ. Double-SHA-256 truncated to 160 bits provides weaker collision resistance than RIPEMD-160(SHA-256()) because SHA-256 is designed for preimage resistance, not for efficient 160-bit output. This is also a cross-chain confusion risk if users or tooling assume Bitcoin-compatible address derivation.

**Fix:** Either implement the documented algorithm (add `ripemd` crate) or update the comment to match the actual implementation, and document the deliberate divergence from Bitcoin's scheme.

---

### [FIXED] M-7 — Block height stored in `HybridSignature.ecdsa_sig` field — type confusion
**File:** `src/transaction/tx.rs` — `Transaction::coinbase`

```rust
signature: HybridSignature {
    ecdsa_sig: block_height.to_le_bytes().to_vec(), // block height, NOT a signature
    dilithium_sig: vec![],
},
```

The `ecdsa_sig` field of `HybridSignature` is semantically "a compact ECDSA signature." Using it to store an 8-byte integer is a type-safety violation. Any code that attempts to parse this field as an ECDSA signature (e.g., during deserialization of historical blocks) will fail or panic. It also makes the `is_coinbase` check dependent on parsing a field with dual semantics.

**Fix:** Add a dedicated `coinbase_data: Option<Vec<u8>>` field to `TxInput` for non-signature script-style data, mirroring Bitcoin's `scriptSig` in coinbase inputs.

---

### [FIXED] M-8 — No fee collection by miners — economic incentive failure
**File:** `src/blockchain/chain.rs` — `validate_coinbase_subsidy` / `src/transaction/mempool.rs`

The `fee` parameter in `Wallet::send` reduces the change output, but the difference between `input_sum` and `output_sum` is not credited to the miner's coinbase. Miners have no economic incentive to include transactions. At post-halving low subsidy phases, the network will produce empty blocks indefinitely, stalling all user transactions.

**Fix:** In `validate_coinbase_subsidy`, calculate total block fees as `sum(input_sum - output_sum)` for all non-coinbase transactions, and add this to `allowed_reward`.

---

### [FIXED] M-9 — No coinbase output count limit — block inflation attack
**File:** `src/blockchain/chain.rs` — `validate_coinbase_subsidy`

The subsidy check validates only the *total value* of coinbase outputs:
```rust
let minted = coinbase_value(block);  // sum of all outputs
if minted != allowed_reward { bail!(...); }
```

A miner can split 32 ARKOS into 32,000,000,000 outputs of 1 arke each. This massively inflates the UTXO set, consuming disk space and slowing all future balance lookups (which are O(utxos) for `balance_of`).

**Fix:** Add `if block.transactions[0].outputs.len() > MAX_COINBASE_OUTPUTS { bail!(...) }` with a small limit (e.g., 4).

---

## 🔵 LOW

---

### [FIXED] L-1 — No per-block transaction count or weight limit
Related to H-4. Even with a byte-size limit, transactions with many inputs or outputs should be subject to a UTXO-operation weight, similar to Bitcoin's sigop counting.

---

### [FIXED] L-2 — `adjust_difficulty` does not guard against zero mantissa
**File:** `src/blockchain/consensus.rs`

If `mantissa` of `current_bits` is 0 (degenerate but possible via a chain-genesis fork), `new_mantissa = 0 * actual_clamped / expected_time = 0`, resulting in an infinitely easy target. Add a guard: `if mantissa == 0 { return min_difficulty_bits; }`.

---

### [FIXED] L-3 — GetBlocks sends 500 blocks without rate limiting on data volume
**File:** `src/network/node.rs` — `Message::GetBlocks` handler

The `blocks` rate limiter limits *block submissions* (10/min) but `GetBlocks` responses are governed only by the *message* rate limiter (100/min). An attacker can request 500 blocks × 100 times per minute = 50,000 blocks per minute of outbound bandwidth. Add a per-peer bandwidth quota.

---

### [FIXED] L-4 — RPC server address is not validated — may bind to public interface by default
**File:** `src/rpc/server.rs` — `start_rpc_server`

If the operator passes `0.0.0.0:8332`, the RPC is publicly reachable. The code does not warn about this. Document that the default should be `127.0.0.1:8332` and log a prominent warning when binding to a non-loopback interface.

---

### [FIXED] L-5 — `bincode::deserialize` called without size pre-check on DB reads
**File:** `src/storage/db.rs`

```rust
Ok(Some(bincode::deserialize(&val)?))
```

If RocksDB data is corrupted (e.g., by a disk fault or a malicious write), `bincode` will attempt to allocate memory proportional to claimed lengths in the data before failing. Use `bincode::options().with_limit(MAX_BLOCK_SIZE).deserialize(...)` to bound allocation.

---

### [FIXED] L-6 — `GetBlocks` locator can reference blocks not on the main chain
**File:** `src/network/node.rs`

```rust
let start = locator_hashes.iter()
    .find_map(|h| chain.block_by_hash(h))
    .map(|b| b.height + 1)
    .unwrap_or(0);
```

`block_by_hash` searches `all_blocks`, which includes orphans. A peer supplying an orphan block hash in its locator will receive blocks starting from the orphan's height rather than the fork point, potentially causing incorrect sync behaviour.

**Fix:** Use `block_index` (main-chain only) instead of `all_blocks` for locator resolution.

---

### [FIXED] L-7 — `Wallet::secret_key_hex` leaks Dilithium secret in formatted string
**File:** `src/wallet/wallet.rs`

```rust
pub fn secret_key_hex(&self) -> String {
    format!("hybrid:{}:{}:{}", self.keypair.ecdsa_secret_hex(),
        self.keypair.dilithium_secret_hex(), self.keypair.dilithium_public_hex())
}
```

The 4,000-byte Dilithium secret key is assembled into a heap-allocated `String`. This string is not zeroed when dropped (no `Zeroize` impl). In a swap-enabled system, this key material may end up on disk. Add `#[derive(Zeroize, ZeroizeOnDrop)]` on the string wrapper or use `secrecy::Secret<String>`.

---

## Architecture-Level Concerns

These are not individual bugs but structural gaps that must be addressed before mainnet:

**1. No network-time oracle.** `validate_timestamp` uses local system clock only. Nodes with misconfigured clocks will reject valid blocks or accept blocks with skewed timestamps. Implement NTP polling or a peer-median-time algorithm (Bitcoin uses the median of up to 200 peer-reported times).

**2. No transaction malleability protection.** Transactions are serialised with `bincode` which is deterministic, but `txid` is computed from the full transaction including signatures. A relay node that modifies the `ecdsa_sig` bytes (even by re-encoding) before forwarding would produce a different TXID for the same logical transaction, breaking any protocol that depends on pre-signed transaction chains (Lightning-style channels, multisig coordination).

**3. No BIP-32/BIP-39 HD wallet derivation.** Private keys are generated atomically with no derivation path. There is no seed phrase backup mechanism. A user who loses their vault file loses all funds with no recovery path. Implement BIP-32 hierarchical deterministic key derivation.

**4. P2P has no anti-sybil mechanism beyond network magic.** A single attacker can run thousands of nodes with different IPs (VPS, VPN, Tor exit nodes) and eclipse any target. Consider requiring small PoW puzzles for initial connection handshake or using peer reputation scoring.

**5. The `DeviceTransfer` social-recovery path is explicitly marked "not implemented."** Without this, any user who loses or breaks their phone permanently loses their mining identity and must wait `DEVICE_TRANSFER_COOLDOWN` blocks with no device registered. Consider a time-locked multi-signature social recovery scheme.

---

## Priority Remediation Order

| Priority | Finding | Effort |
|----------|---------|--------|
| 1 | C-1 Implement real attestation verification | High |
| 2 | C-5 Fix deterministic mempool ordering | Low |
| 3 | C-4 Remove O(n²) chain reorg | Medium |
| 4 | C-2 Add mempool size cap + fee enforcement | Medium |
| 5 | C-3 Prune orphan blocks + load headers only | Medium |
| 6 | H-1 Add TLS/Noise to P2P | High |
| 7 | H-2 Fix Merkle CVE-2012-2459 | Low |
| 8 | H-4 Add max block weight | Low |
| 9 | H-3 Validate + cap Addr messages | Low |
| 10 | H-5 Enforce token revocation | Low |
| 11 | H-7 Replace difficulty algorithm | Medium |
| 12 | M-8 Implement fee collection | Medium |
| 13 | All remaining M/L findings | Low–Medium |

---

*This report was produced by static analysis of the full source tree. It does not replace a professional third-party audit, fuzzing campaign, or formal verification of the consensus-critical paths.*
