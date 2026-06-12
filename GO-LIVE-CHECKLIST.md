# Arkos Go-Live Checklist

This checklist defines the tests, checks, and improvements required before
public testnet or mainnet launch.

## Current Status

| Launch type | Status |
|---|---|
| Local devnet / regtest | Ready for continued testing |
| Private multi-node testnet | Candidate |
| Public testnet | Not ready |
| Mainnet / real-value launch | Not ready |

## Checks Already Passing Locally

These checks passed on the current development machine.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test
cargo fmt --manifest-path mobile/native/Cargo.toml --check
cargo clippy --manifest-path mobile/native/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path mobile/native/Cargo.toml
```

Runtime smoke checks also passed:

- regtest chain initialization,
- CLI `info`,
- CLI `mine`,
- chain persistence after mining,
- RPC `/health`,
- RPC token rejection when missing,
- authenticated `getMiningInfo`,
- authenticated `getBlockTemplate`,
- mined nonce submitted through `submitBlock`,
- node height increment after accepted RPC block.

## Known Go-Live Blockers

| Blocker | Required before public testnet | Required before mainnet |
|---|---:|---:|
| Flutter/Dart client analysis and build | Yes, if Flutter client is included | Yes, if Flutter client is included |
| Public seed nodes | Yes | Yes |
| DNS seed / automatic peer discovery | Recommended | Yes |
| Headers-first or robust sync design | Recommended | Yes |
| Multi-node fork/reorg integration test | Yes | Yes |
| Long-running soak test | Yes | Yes |
| External cryptography audit | Recommended | Yes |
| External consensus audit | Recommended | Yes |
| Release artifact checksums | Yes | Yes |
| Signed release artifacts | Recommended | Yes |
| Dependency audit warnings resolved or accepted | Yes | Yes |
| Wallet recovery / backup design | Recommended | Yes |
| Public incident/security contact | Yes | Yes |

## Dependency Audit Warnings

`cargo audit` completed, but reported unmaintained-crate warnings:

| Crate | Current issue |
|---|---|
| `bincode 1.3.3` | Unmaintained -- **risk accepted for testnet**; migrate to bincode 2.x before mainnet |
| `pqcrypto-mldsa 0.1.2` | **Resolved** -- upgraded from pqcrypto-dilithium 0.5.0 |
| `pqcrypto-internals 0.2.11` | Unmaintained, no known CVEs; covered by external crypto audit |
| `pqcrypto-traits 0.3.5` | Unmaintained, no known CVEs; covered by external crypto audit |

**bincode risk acceptance:** Uses the Options builder API with FixintEncoding, AllowTrailing,
and per-call size limits (32 MB blocks, 4 MB txs), which mitigates deserialization-amplification
risk. No known CVEs. Migration to bincode 2.x changes the on-disk format; scheduled as a
pre-mainnet task after testnet stabilises.

Mainnet should not launch until bincode is upgraded to bincode 2.x.

## Required Test Commands

Run from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo audit
```

Run for the Flutter native mining library:

```bash
cargo fmt --manifest-path mobile/native/Cargo.toml --check
cargo clippy --manifest-path mobile/native/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path mobile/native/Cargo.toml
```

Run if Flutter is installed:

```bash
cd mobile
flutter pub get
dart format --set-exit-if-changed lib
flutter analyze
flutter test
flutter build apk --release
```

For iOS release validation:

```bash
cd mobile
flutter build ios --release
```

## RPC Smoke Test

Start a temporary regtest node:

```bash
rm -rf /tmp/arkos-smoke-node
target/release/arkos \
  --datadir /tmp/arkos-smoke-node \
  --network regtest \
  --listen 127.0.0.1:18444 \
  --rpc-listen 127.0.0.1:18445 \
  --rpc-token smoke-test-token \
  node \
  --miner 1111111111111111111111111111111111111111
```

Expected checks:

- `GET /health` returns `{"chain":"arkos","status":"ok"}`.
- RPC calls without token return unauthorized.
- Authenticated `getMiningInfo` returns chain state.
- Authenticated `getBlockTemplate` accepts `walletAddress`.
- A valid nonce can be submitted with `submitBlock`.
- Chain height increases after accepted block.

## Private Multi-Node Testnet

Before any public release, run at least three nodes:

| Node | Purpose |
|---|---|
| Node A | seed / stable peer |
| Node B | miner |
| Node C | sync-only observer |

Required checks:

- nodes connect using `--peer`,
- blocks mined by one node reach the others,
- transactions relay between nodes,
- node restart preserves chain state,
- side branch / reorg behavior works,
- wrong network magic peers are rejected,
- RPC token protection works on every RPC node.

## Long-Running Soak Test

Minimum private-testnet soak target:

| Metric | Minimum |
|---|---:|
| Duration | 72 hours |
| Nodes | 3 |
| Mined blocks | 500+ |
| Restarts | 3 per node |
| Intentional network partitions | 2 |
| Reorg events observed | 1+ |
| Unhandled crashes | 0 |
| Database corruption | 0 |

Record:

- node logs,
- chain height by node,
- tip hash by node,
- memory use,
- disk growth,
- rejected block/tx reasons,
- reorg events.

## Release Artifact Checklist

For each release:

- source commit hash,
- version tag,
- macOS binary,
- Linux binary,
- Windows binary if supported,
- SHA256 checksums,
- signed checksum file,
- release notes,
- known limitations,
- upgrade instructions,
- rollback instructions.

Example checksum command:

```bash
shasum -a 256 target/release/arkos
```

## Public Testnet Launch Requirements

Do not launch public testnet until:

- all required local checks pass,
- RPC smoke test passes,
- private multi-node testnet passes,
- seed node addresses are published,
- testnet launch parameters are documented,
- dependency audit warnings are documented,
- users are told testnet coins have no value.

Document:

- network name,
- network magic,
- genesis hash,
- block time,
- mining algorithm,
- reward schedule,
- maximum supply,
- seed peers,
- RPC examples,
- known limitations.

## Mainnet Launch Requirements

Do not launch mainnet until:

- public testnet has run long enough to expose sync/reorg issues,
- external crypto audit is complete,
- external consensus audit is complete,
- dependency audit warnings are resolved or formally accepted,
- seed/DNS peer discovery is ready,
- release artifacts are signed,
- wallet recovery/backup design is ready,
- governance/update process is documented,
- incident response contact is published.

## Go / No-Go Decision

| Decision | Meaning |
|---|---|
| Go for private testnet | Local tests pass and three controlled nodes can run |
| Go for public testnet | Private testnet and release packaging pass |
| Go for mainnet | Public testnet, audits, dependency risk, and release process pass |
| No-go | Any consensus, crypto, sync, wallet, release, or security blocker remains unresolved |

Current decision:

```text
Go for private multi-node testnet candidate.
No-go for public mainnet.
```
