# Arkos Public Testnet Parameters

Reference document for joining the Arkos public testnet.
Testnet coins have **no monetary value** — this network exists for testing only.

---

## Network Identity

| Parameter | Value |
|---|---|
| Network name | `testnet` |
| Network magic (hex) | `0x4152_4b54` ("ARKT") |
| P2P default port | `8333` |
| RPC default port | `8334` |

---

## Genesis Block

| Parameter | Value |
|---|---|
| Genesis hash | `0000077d076fe588b47a5d2e92e8c20f89195d65089375be88f2f6ad31066c5d` |
| Genesis timestamp | `1700000000` (2023-11-14 22:13:20 UTC) |
| Genesis bits | `0x1e0fffff` |
| Genesis height | `0` |
| Coinbase recipient | `0000000000000000000000000000000000000000` (burn address) |

The genesis block is deterministic — every node that starts with `--network testnet` will
derive the same block hash from the same parameters. This is the chain anchor; any node
presenting a different genesis is on a different network.

---

## Consensus Parameters

| Parameter | Value |
|---|---|
| Block time target | 194 seconds (3 min 14 s — Pi-themed) |
| Mining algorithm | ArkHash (SHA-256d variant) |
| Initial block reward | ~32.188 ARKOS / block |
| Halving interval | 488,004 blocks (~3 years) |
| Maximum supply | 31,415,926 ARKOS (Pi × 10⁷) |
| Smallest unit | 1 arke = 10⁻⁹ ARKOS |
| Difficulty adjustment | Every 2,016 blocks, using median timestamps |
| Genesis difficulty | `0x1e0fffff` (~1 nonce/block on a modern laptop) |

---

## Seed Peers

```
seed.arkos.network:8333
seed2.arkos.network:8333
```

DNS seeds are resolved automatically on startup. You can override with `--peer`:

```bash
arkos --network testnet node --miner <YOUR_ADDRESS> --peer seed.arkos.network:8333
```

---

## Connecting to Testnet

### 1. Build from source

```bash
git clone https://github.com/arkos-dev/arkos
cd arkos
cargo build --release
```

### 2. Initialize your vault (first time only)

```bash
./target/release/arkos --network testnet init
```

### 3. Start a full node

```bash
./target/release/arkos \
  --network testnet \
  --listen 0.0.0.0:8333 \
  --rpc-listen 127.0.0.1:8334 \
  --rpc-token <LONG_RANDOM_TOKEN> \
  node \
  --miner <YOUR_WALLET_ADDRESS>
```

### 4. Mine a block

```bash
./target/release/arkos --network testnet mine --address <YOUR_WALLET_ADDRESS>
```

### 5. Check chain state

```bash
./target/release/arkos --network testnet info
```

---

## RPC Examples

Start node with a token, then query:

```bash
# Health check
curl http://127.0.0.1:8334/health

# Mining info
curl -X POST http://127.0.0.1:8334/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_RPC_TOKEN>" \
  -d '{"jsonrpc":"2.0","method":"getMiningInfo","params":{},"id":1}'

# Get block template for mobile mining
curl -X POST http://127.0.0.1:8334/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_RPC_TOKEN>" \
  -d '{"jsonrpc":"2.0","method":"getBlockTemplate","params":{"walletAddress":"<YOUR_ADDRESS>"},"id":2}'
```

---

## Sending a Transaction

```bash
./target/release/arkos --network testnet send \
  --from-label default \
  --to <RECIPIENT_ADDRESS> \
  --amount 1000000000   # 1 ARKOS
```

---

## Data Directory

Testnet chain data is stored separately from mainnet:

```
~/.arkos/testnet/chain/    ← RocksDB blocks and UTXO set
~/.arkos/vault.enc         ← shared encrypted vault (all networks)
```

---

## Known Limitations (Testnet)

| Item | Notes |
|---|---|
| bincode 1.x | On-disk format will change before mainnet; testnet chain data may need reset |
| No governance | Protocol upgrades are applied by updating the binary and restarting |
| No fee market | Min fee 1,000 arkes; fee-rate ordering active but no mempool pressure yet |
| Testnet reset | We may reset the testnet chain during development |

---

## Reporting Issues

File issues at: https://github.com/arkos-dev/arkos/issues  
Security vulnerabilities: see `SECURITY.md`
