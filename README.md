# Arkos

**The origin of a new financial world.**

Arkos is a Bitcoin-like cryptocurrency built from scratch in Rust. Named after the Greek word *arche* (the primordial origin of all things), Arkos shares its root with Archimedes — the mathematician who gave humanity Pi.

---

## Quick Start

### Prerequisites

- **Rust** (install via [rustup.rs](https://rustup.rs))
- **macOS or Linux** (Windows support is untested)

### Build

```bash
cd arkos
cargo build --release
```

The binary will be at `target/release/arkos`.

### Run the Demo

See everything working end-to-end — wallets, mining, transactions, and security — in one command:

```bash
cargo run --release -- demo
```

---

## Tokenomics

| Parameter | Value |
|---|---|
| **Total supply** | 31,415,926 ARKOS hard cap (Pi x 10^7) |
| **Smallest unit** | 1 arke = 0.000000001 ARKOS |
| **Block time** | 3 minutes 14 seconds (194 seconds) |
| **Initial reward** | ~32.188 ARKOS / block |
| **Halving** | Every 488,004 blocks (~3 years) |
| **Tail emission** | None |
| **Consensus** | Proof of Work (SHA-256d) |

### Supply Schedule

```
Era 1   (year 0-3)    50.00%   15,707,963 ARKOS
Era 2   (year 3-6)    25.00%    7,853,981 ARKOS
Era 3   (year 6-9)    12.50%    3,926,991 ARKOS
Era 4   (year 9-12)    6.25%    1,963,495 ARKOS
Era 5+  (year 12+)     tapering...
Cap     (final)        31,415,926 ARKOS maximum
```

Arkos has no tail emission. The node tracks total minted supply in arkes and rejects any block whose coinbase reward would exceed the 31,415,926 ARKOS consensus cap. Mobile mining bonuses are also paid only from the remaining capped supply.

---

## Commands Reference

### 1. Initialize — First Time Setup

```bash
arkos init
```

This is the first command you run. It:
- Generates your **Master Key** (Ed25519 signing key)
- Creates your first **wallet** (hybrid secp256k1 + CRYSTALS-Dilithium keypair)
- Encrypts everything into `~/.arkos/vault.enc` with your passphrase
- Saves your public master key to `~/.arkos/master.pub`
- Issues yourself an Admin access token

You will be prompted for a passphrase (minimum 12 characters). **There is no recovery if you forget it.**

#### What gets created

```
~/.arkos/
  vault.enc       Encrypted vault (AES-256-GCM + Argon2id)
  master.pub      Your master public key (safe to share with nodes)
  revoked.json    Revocation list
  tokens/
    owner.token   Your own Admin token
```

#### Custom data directory

```bash
arkos --datadir /path/to/your/data init
```

---

### 2. Wallet Management

#### Create a new wallet

```bash
arkos new-wallet --label "savings"
```

You will be prompted for your vault passphrase. The new keypair is encrypted and saved into the vault. You can create as many wallets as you want.

#### List all wallets

```bash
arkos list-wallets
```

Displays all wallet labels and their addresses. Requires your passphrase.

Example output:
```
LABEL                ADDRESS
------------------------------------------------------------
default-wallet       6e77ebd4031a9c1d250d5ad9a32ea7b81a21e395
savings              ec903eb5d00dd5add0355e05e23639475054085f
```

#### Check balance

```bash
arkos balance --address 6e77ebd4031a9c1d250d5ad9a32ea7b81a21e395
```

---

### 3. Mining

#### Mine a single block

```bash
arkos mine --address <YOUR_WALLET_ADDRESS>
```

Mines one block to the specified address and shows the result:
```
Mined block: 00000a5b0a207188...
Height     : 1
Nonce      : 577107
Txs        : 1
Balance    : 9955106218 arkes
```

#### Start a mining node

```bash
arkos node --miner <YOUR_WALLET_ADDRESS>
```

Starts a full node that:
- Loads or creates the network-specific persistent chain database at `~/.arkos/<network>/chain`
- Listens for peer connections on port 8333
- Performs block sync with connected peers
- Tracks side branches and reorganizes to the branch with more accumulated work
- Runs the HTTP JSON-RPC server for mining submissions from any device

The `--miner` address is logged for operator reference. Blocks are mined by explicit `arkos mine` runs or by submitting a solved block via the JSON-RPC `submitBlock` method. Any device — desktop, server, or mobile — can participate using standard proof-of-work. The node does not auto-mine blocks on startup.

#### Network profile and RPC access

```bash
arkos node \
  --network mainnet \
  --rpc-token <LONG_RANDOM_TOKEN> \
  --rpc-cors-origin https://your-app.example \
  --miner <ADDRESS>
```

- `--network` accepts `mainnet`, `testnet`, or `regtest`
- `--rpc-token` can also be supplied with `ARKOS_RPC_TOKEN`
- `--rpc-cors-origin` can also be supplied with `ARKOS_RPC_CORS_ORIGIN`
- Clients send the token as `Authorization: Bearer <token>` or `X-Arkos-Rpc-Token: <token>`

#### Custom listen address

```bash
arkos node --miner <ADDRESS> --listen 0.0.0.0:9000
```

---

### 4. Transactions

#### Send ARKOS

```bash
arkos send --from-label "default-wallet" --to <RECIPIENT_ADDRESS> --amount 5000000000
```

- `--from-label` — the wallet label in your vault (not the address)
- `--to` — recipient's hex address
- `--amount` — amount in **arkes** (1 ARKOS = 1,000,000,000 arkes)

You will be prompted for your vault passphrase to sign the transaction.

#### Amount examples

| You want to send | Use `--amount` |
|---|---|
| 1 ARKOS | `1000000000` |
| 0.5 ARKOS | `500000000` |
| 5 ARKOS | `5000000000` |
| 100 arkes | `100` |

---

### 5. Access Control — Granting and Revoking Access

This is the owner-controlled access layer. The code can issue, verify, expire, and revoke tokens signed by your Master Key. Full network-wide enforcement in every P2P/RPC handler is still a protocol integration item.

#### Grant access to someone

```bash
arkos grant \
  --name "alice" \
  --permissions connect,mine,transact \
  --expires-days 365
```

Available permissions:
| Permission | What it allows |
|---|---|
| `connect` | Connect to the network as a peer |
| `mine` | Submit mined blocks |
| `transact` | Send transactions |
| `read` | Query blockchain data (read-only) |
| `admin` | Full access — all permissions |

The token is saved to `~/.arkos/tokens/alice.token`. Give this file to Alice. She cannot modify it — any change invalidates your Ed25519 signature.

#### Grant read-only access

```bash
arkos grant --name "auditor" --permissions read --expires-days 90
```

#### Grant non-expiring admin access

```bash
arkos grant --name "co-founder" --permissions admin --expires-days 0
```

#### List all issued tokens

```bash
arkos list-tokens
```

Example output:
```
TOKEN ID     HOLDER           PERMISSIONS                    STATUS
---------------------------------------------------------------------------
a1b2c3d4     owner            [Admin]                        ACTIVE (no expiry)
e5f6a7b8     alice            [Connect, Mine, Transact]      ACTIVE
c9d0e1f2     auditor          [ReadChain]                    EXPIRED
```

#### Revoke a token

```bash
arkos revoke --token-id e5f6a7b8
```

The token is immediately invalid. All nodes will reject it.

#### Verify a token

```bash
arkos verify-token --token-file ~/.arkos/tokens/alice.token
```

Checks the Ed25519 signature, expiry date, and revocation status.

---

### 6. Network — Connecting Nodes

#### Start node 1 (seed node)

```bash
arkos node --miner <ADDRESS> --listen 127.0.0.1:8333
```

#### Start node 2 (connect to seed)

```bash
arkos node --miner <ADDRESS> --listen 127.0.0.1:8334 --peer 127.0.0.1:8333
```

#### Connect multiple peers

```bash
arkos node --miner <ADDRESS> \
  --peer 192.168.1.10:8333 \
  --peer 192.168.1.11:8333 \
  --peer 192.168.1.12:8333
```

Nodes automatically:
- Exchange version information, including Arkos network magic
- Reject peers using the wrong network magic or protocol version
- Request and receive missing blocks from connected peers
- Announce accepted block and transaction inventory to connected peers
- Serve requested blocks and mempool transactions by inventory hash
- Accept incoming transactions into the local mempool
- Apply per-peer connection, message, block, transaction, and GetBlocks rate limits
- Encrypt all P2P traffic with Noise_XX mutual authentication

Current limitation: peer discovery is still operator-seeded by `--peer`; DNS seed nodes are not implemented.

---

### 7. Chain Information

```bash
arkos info
```

Output:
```
Height     : 42
Tip hash   : 000002ef6a9a1055...
Difficulty : 0x1e0fffff
Mempool    : 3 txs
```

---

## Security Architecture

### Encryption Layers

| Layer | Algorithm | Quantum Safe? | Purpose |
|---|---|---|---|
| **Transaction signing** | **ECDSA + CRYSTALS-Dilithium** (hybrid) | **YES** | New wallet transactions require both signatures |
| Wallet encryption | **AES-256-GCM** | YES | Encrypt private keys at rest |
| Key derivation | **Argon2id** (64 MB, 3 iterations) | YES | Passphrase to encryption key (GPU/ASIC-resistant) |
| **P2P transport** | **Noise_XX_25519_ChaChaPoly_BLAKE2s** | YES | Mutual-auth encrypted P2P — all peers; forward secrecy |
| Access tokens | **Ed25519** | No (upgrade planned) | Sign/verify access permissions |
| Block hashing | **SHA-256d** (double SHA-256) | YES | Proof of Work |
| Memory safety | **Zeroize / Zeroizing\<T\>** | N/A | Erase secrets from RAM after use |
| File permissions | **0600** | N/A | Owner-only read/write on vault |
| Rate limiting | Per-peer windows | N/A | Limits connections, messages, blocks, tx, and GetBlocks |

### Post-Quantum Cryptography

Arkos uses a **hybrid signature scheme**: every signature contains BOTH a classical ECDSA signature AND a CRYSTALS-Dilithium (ML-DSA) post-quantum signature. Both must verify independently.

```
Hybrid Signature = ECDSA (64 bytes) + Dilithium Level 3 (3,309 bytes)
                   ─────────────────   ──────────────────────────────
                   classical security   quantum security
```

**Why hybrid?**
- If quantum computers break ECDSA → Dilithium still protects you
- If Dilithium has an undiscovered flaw → ECDSA still protects you
- Neither attack alone can forge a transaction

**CRYSTALS-Dilithium** was selected by NIST in 2024 as the primary post-quantum digital signature standard (FIPS 204 / ML-DSA). It is based on lattice problems (Module-LWE and Module-SIS) that no known quantum algorithm can solve.

Key sizes:
| Component | Size |
|---|---|
| ECDSA public key | 33 bytes |
| Dilithium public key | 1,952 bytes |
| ECDSA signature | 64 bytes |
| Dilithium signature | 3,309 bytes |
| **Total hybrid signature** | **3,373 bytes** |

### What each file contains

| File | Encrypted? | Contents | Safe to share? |
|---|---|---|---|
| `vault.enc` | Yes (AES-256-GCM) | Master key + wallet private keys | No — keep offline backups |
| `master.pub` | No (public key) | Your Ed25519 public key | Yes — give to node operators |
| `tokens/*.token` | No (signed) | Access tokens with permissions | Yes — give to token holders |
| `revoked.json` | No | List of revoked token IDs | Yes — distribute to nodes |

### Attack resistance

| Attack | Protection |
|---|---|
| Stolen vault file | AES-256-GCM encrypted, Argon2id makes brute-force infeasible |
| Forged transactions | Hybrid ECDSA + Dilithium signature — both must verify |
| **Quantum computer** | **CRYSTALS-Dilithium lattice-based signatures — immune to Shor's algorithm** |
| Forged access tokens | Ed25519 signature — requires your private master key |
| Permission escalation | Changing any field in a token invalidates the signature |
| Replay attacks | Tokens have unique IDs; can be revoked |
| DoS / mempool spam | Min-fee enforcement (1,000 arkes), 32 MB mempool cap, eviction of lowest-fee txs |
| DoS / oversized blocks | 4 MB block byte limit + 10,000 tx limit + 50,000 UTXO-op limit — checked before sig verification |
| DoS / oversized messages | `user_agent` capped at 256 bytes; messages framed with length limits |
| Sybil / eclipse via Addr | `Addr` capped at 1,000 entries per message; total peer list capped at 4,096; format-validated |
| Orphan-block memory flood | Orphan blocks pruned after 200-block finality depth |
| Time-warp difficulty attack | Difficulty uses median timestamps at both interval endpoints (Bitcoin MTP) |
| O(n²) reorg CPU attack | Chain reorg is O(1) using cumulative work; full UTXO rebuild only on actual reorg |
| Merkle ambiguity (CVE-2012-2459) | Odd-length tree pads with `hash(tree_length)`, not a duplicate leaf |
| CSRF on RPC | CORS defaults to `http://127.0.0.1`; explicit opt-in required to relax |
| Timing oracle on RPC auth | Constant-time token comparison via `subtle::ConstantTimeEq` |
| Memory forensics | `Zeroize` erases ECDSA key bytes; `Zeroizing<String>` wraps exported key strings |
| Double spending | UTXO model — each output can only be spent once |
| 51% attack | Proof of Work — requires majority of network hash power |
| Man-in-the-middle | **Noise_XX_25519_ChaChaPoly_BLAKE2s** mutual-auth encrypted transport on all P2P connections |
| Stale peer entries | Peers are removed from the known list immediately on disconnect |
| Corrupted DB allocation | `bincode` deserialization bounded by `MAX_BLOCK_SIZE` / `MAX_TX_SIZE` |
| Coinbase UTXO set bloat | Coinbase outputs capped at 16 per block |
| Miner fee incentive | Block fees credited to miner coinbase (`input_sum − output_sum` per non-coinbase tx) |
| Open mining | Any device can mine using standard PoW — no registration or attestation required |

### Current Production Readiness

Arkos is still a development network, not a public mainnet release.

**Security hardening completed** (all 27 audit findings from the 2026-06-07 security audit have been resolved):

| Area | Status |
|---|---|
| Supply cap | Consensus-enforced hard cap at 31,415,926 ARKOS |
| Persistence | Nodes load/save accepted blocks through RocksDB at `~/.arkos/<network>/chain` |
| P2P encryption | Noise_XX_25519_ChaChaPoly_BLAKE2s mutual-auth encrypted transport |
| Block limits | 4 MB byte cap, 10,000 tx cap, 50,000 UTXO-op cap — checked before sig verification |
| Mempool | Min-fee enforcement (1,000 arkes), 32 MB size cap |
| Merkle tree | CVE-2012-2459 mitigated via length-commitment padding |
| Difficulty | Median-timestamp endpoints prevent time-warp attacks |
| Chain reorg | O(1) work comparison; UTXO rebuild only on actual reorg |
| Orphan pruning | Side-chain blocks pruned after 200 confirmations of finality |
| Peer management | Addr message capped (1,000 entries), peer list capped (4,096), stale peers removed on disconnect |
| RPC security | CORS defaults to `http://127.0.0.1`; constant-time token auth; non-loopback bind warning |
| Coinbase | Output count capped at 16; fees credited to miner coinbase |
| Key handling | `Zeroize` on ECDSA secret bytes; `Zeroizing<String>` on exported key strings |
| DB safety | `bincode` deserialization bounded by `MAX_BLOCK_SIZE` / `MAX_TX_SIZE` |
| Fork choice | Side branches tracked; active chain reorganizes to more accumulated work |
| P2P relay | Accepted block/transaction inventory announced to connected peers |
| Network separation | `mainnet`, `testnet`, and `regtest` use separate magic values and chain directories |

Known blockers before production mainnet:

| Blocker | Status |
|---|---|
| Headers-first sync | Not implemented; current sync is block-inventory based |
| Automatic peer discovery and DNS seed nodes | Not implemented; peers are operator-configured |
| External cryptography and consensus audit | Not completed |

---

## Project Structure

```
arkos/
  Cargo.toml                    Project manifest and dependencies
  README.md                     This file
  src/
    main.rs                     CLI entry point — all commands
    lib.rs                      Library root (for tests)
    blockchain/
      block.rs                  Block structure, PoW mining, merkle root
      chain.rs                  Blockchain state, validation, UTXO updates
      consensus.rs              Difficulty adjustment algorithm
    crypto/
      hash.rs                   SHA-256d hashing utilities
      keys.rs                   ECDSA keypair, signing, verification
      quantum.rs                Hybrid ECDSA + Dilithium post-quantum signatures
    network/
      node.rs                   P2P node — accept connections, handle messages
      peer.rs                   TCP peer connection (length-prefixed JSON)
      protocol.rs               Message types (Version, Block, Tx, Inv, etc.)
    security/
      access.rs                 Ed25519 access tokens, master key, revocation
      rate_limit.rs             Per-peer rate limiting
      vault.rs                  AES-256-GCM encrypted key storage
    storage/
      db.rs                     RocksDB persistence layer
    transaction/
      tx.rs                     Transaction structure, coinbase, sig_hash
      utxo.rs                   Unspent Transaction Output set
      mempool.rs                Pending transaction pool
    wallet/
      wallet.rs                 Wallet — key management, coin selection, signing
  tests/
    security_test.rs            10 security tests (vault, tokens, revocation)
                                + 7 quantum crypto tests (hybrid sign/verify, attack resistance)
```

---

## Editing the Code

### Changing the supply

Edit `src/blockchain/block.rs`:
```rust
pub const BLOCK_REWARD_INITIAL: u64 = 32_188_184_932; // arkes per block
pub const HALVING_INTERVAL: u64     = 488_004;        // blocks between halvings
pub const MAX_SUPPLY_ARKES: u64     = 31_415_926_000_000_000; // hard cap
```

The chain rejects blocks that mint above `MAX_SUPPLY_ARKES`.

### Changing the block time

Edit `src/blockchain/consensus.rs`:
```rust
pub const TARGET_BLOCK_TIME: u64 = 194; // 3 minutes 14 seconds
```

If you change block time, recalculate `HALVING_INTERVAL`:
```
HALVING_INTERVAL = seconds_per_year * years_per_halving / block_time_seconds
```

### Changing the difficulty

The initial difficulty is set in `src/blockchain/block.rs` in the `genesis_block()` function:
```rust
bits: 0x1e0fffff, // compact difficulty target — lower = harder
```

Difficulty adjusts automatically every `DIFFICULTY_ADJUSTMENT_INTERVAL` blocks (defined in `consensus.rs`).

### Adding a new CLI command

1. Add a variant to the `Command` enum in `src/main.rs`
2. Add the handler in the `match cli.command` block
3. Run `cargo build` to verify

### Adding a new P2P message type

1. Add a variant to `Message` enum in `src/network/protocol.rs`
2. Handle it in `handle_peer()` in `src/network/node.rs`

### Adding a new permission type

1. Add a variant to `Permission` enum in `src/security/access.rs`
2. Check for it in node message handlers using `token.has_permission(&Permission::YourNew)`

---

## Backup and Recovery

### Back up your vault

```bash
cp ~/.arkos/vault.enc /path/to/usb/vault.enc.backup
```

Store the backup offline (USB drive, safe). The vault is encrypted — even if someone finds the backup, they need your passphrase.

### Restore from backup

```bash
mkdir -p ~/.arkos
cp /path/to/usb/vault.enc.backup ~/.arkos/vault.enc
```

### What you need to recover everything

1. The `vault.enc` file
2. Your passphrase

That's it. The master key and all wallet keys are inside.

### What if you lose your passphrase?

**Your keys are gone permanently.** There is no backdoor, no recovery, no reset. This is by design — if there were a recovery mechanism, it would be an attack vector.

---

## Running Tests

```bash
cargo test
```

This runs 10 security tests covering:
- Vault encryption and decryption
- Short passphrase rejection
- Tampered vault detection (AES-GCM authentication)
- Valid token signature verification
- Tampered permissions detection
- Tampered holder name detection
- Wrong master key rejection
- Revocation list behavior
- Revocation persistence
- Permission hierarchy (Admin grants all)

---

## Common Workflows

### "I just installed Arkos, what do I do?"

```bash
cargo build --release
cargo run --release -- init              # Create master key + vault
cargo run --release -- mine --address <YOUR_ADDRESS>   # Mine first block
cargo run --release -- info              # Check the chain
```

### "I want to add a miner to my network"

```bash
# On your machine:
cargo run --release -- grant --name "miner-1" --permissions connect,mine --expires-days 365
# Give tokens/miner-1.token to the miner

# On the miner's machine:
cargo run --release -- node --miner <THEIR_ADDRESS> --peer <YOUR_IP>:8333
```

### "I want someone to only be able to view the chain"

```bash
cargo run --release -- grant --name "viewer" --permissions read --expires-days 30
```

### "I want to remove someone's access immediately"

```bash
cargo run --release -- list-tokens       # Find their token ID
cargo run --release -- revoke --token-id <TOKEN_ID>
```

### "I want to send coins to someone"

```bash
cargo run --release -- send \
  --from-label "default-wallet" \
  --to <THEIR_ADDRESS> \
  --amount 5000000000   # 5 ARKOS
```

### "I want to create a separate wallet for savings"

```bash
cargo run --release -- new-wallet --label "cold-storage"
cargo run --release -- list-wallets      # See all wallets
```

---

## License

Private. All rights reserved.
