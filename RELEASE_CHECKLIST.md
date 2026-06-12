# Arkos Release Checklist

Arkos is not ready for production mainnet until every mainnet blocker is closed.
Use this checklist to prepare controlled devnet, public testnet, and mainnet
releases without mixing their requirements.

## Current Release Status

| Track | Status |
|---|---|
| Local demo/devnet | Ready |
| Private multi-node testnet | Ready (soak test complete 2026-06-12) |
| Public testnet | **Ready** — all technical requirements met; seed nodes must be deployed |
| Production mainnet | Not ready — external audits and seed node deployment required |

## Required Before Public Testnet

- `cargo test` passes on a clean checkout.
- `cargo build --release` succeeds.
- All mining clients and node RPC schemas match.
- Public testnet launch parameters are documented:
  - network name,
  - magic value,
  - genesis hash,
  - block time,
  - emission schedule,
  - mining algorithm,
  - seed peers.
- At least two stable seed nodes are running.
- Public RPC examples use `--rpc-token`.
- Release artifacts include checksums.
- Known limitations are disclosed in README/release notes.

## Required Before Mainnet

- [x] Headers-first sync — implemented and tested.
- [x] Automatic peer discovery — DNS seeds implemented in `src/network/discovery.rs`.
- [ ] External cryptography audit — not yet engaged.
- [ ] External consensus/protocol audit — not yet engaged.
- [x] Multi-node fork/reorg test — automated test in `tests/multinode.rs`.
- [x] Wallet backup/recovery design — `arkos backup` command; BIP39 phrase recovery fully deterministic.
- [x] Release artifact checksums — `scripts/release.sh` produces SHA-256 + optional GPG.
- [ ] Signed release artifacts — GPG signing in `release.sh` but no published key yet.
- [ ] Clear license decision for public source distribution.
- [ ] Documented governance/update process.
- [ ] bincode 2.x migration (v1 unmaintained; format migration scheduled post-testnet).
- [ ] Public seed nodes deployed at `seed.arkos.network` / `seed2.arkos.network`.

## Release Commands

```bash
cargo test
cargo build --release
shasum -a 256 target/release/arkos
```

## Launch Notes

- Prefer `testnet` for any public trial.
- Do not launch mainnet from an unreviewed commit.
- Do not expose RPC without `--rpc-token`.
- P2P is public by design; use firewall rules for private devnets.
