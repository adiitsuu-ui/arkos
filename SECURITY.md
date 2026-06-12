# Security Policy

## Supported Versions

Arkos is currently in pre-release (testnet phase). All security reports are
welcome against any version. Once mainnet launches, only the latest release
branch will receive security fixes.

| Version | Supported |
|---------|-----------|
| `main` (testnet) | Yes |
| historical commits | Best-effort only |

---

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Send a report to:

```
security@arkos.network
```

PGP fingerprint (for encrypted reports):

```
[PGP key not yet published — key generation and publication pending before mainnet]
```

Until a PGP key is published, please use the email address above and mark
the subject line: `[SECURITY] <brief description>`.

---

## What to Include

A high-quality report helps us triage and fix issues faster.  Please include:

- Affected component(s) — e.g. `src/crypto/quantum.rs`, P2P protocol, RPC API
- Steps to reproduce or a proof-of-concept (keep it minimal)
- Assessed impact: funds at risk, node crash, data loss, privacy leak, etc.
- Your suggested fix, if you have one

---

## Disclosure Timeline

| Step | Target time |
|------|-------------|
| Acknowledgement of your report | Within 48 hours |
| Initial severity triage | Within 7 days |
| Fix development and internal testing | Depends on severity |
| Coordinated public disclosure | 90 days after report, or sooner if a fix is ready |

For critical vulnerabilities (funds at risk, consensus failure, remote code
execution), we aim to release a patch within 14 days and will coordinate
disclosure timing with you.

We follow a 90-day standard disclosure window, consistent with Project Zero
and most major bug bounty programs.  If you need more time, reach out and
we will discuss.

---

## Severity Definitions

| Severity | Examples |
|----------|---------|
| **Critical** | Remote code execution, consensus fork that can steal funds, signature bypass |
| **High** | Node crash via crafted network message, wallet key extraction, DoS that takes the network down |
| **Medium** | Single-node DoS, timing side-channel on signing, mempool manipulation |
| **Low** | Information disclosure, minor logic error with no fund risk |

---

## In Scope

- Arkos node (`src/` — blockchain, consensus, network, wallet, crypto, RPC)
- Mobile client (`mobile/` — Flutter app, native Rust FFI layer)
- ArkHash Neural PoW algorithm (`src/crypto/arkhash.rs`)
- Hybrid signature scheme (`src/crypto/quantum.rs` — ECDSA + ML-DSA)
- Noise_XX P2P transport (`src/network/noise.rs`, `src/network/peer.rs`)
- Vault encryption (`src/security/vault.rs`)

## Out of Scope

- Third-party dependencies (report those to the relevant upstream project)
- Social engineering
- Physical attacks
- Automated scanner output without manual verification
- Reports against infrastructure not operated by the Arkos project

---

## Cryptographic Design Notes

Arkos uses a hybrid signature scheme for all on-chain transactions:

1. **ECDSA (secp256k1)** — classical security, fast verification
2. **ML-DSA-65 / CRYSTALS-Dilithium Level 3** (NIST FIPS 204) — post-quantum security

**Both signatures are required for a transaction to be valid.**  If ECDSA is
broken by a quantum computer, ML-DSA still protects funds.  If ML-DSA has an
undiscovered flaw, ECDSA still protects funds.

All P2P traffic is encrypted and mutually authenticated via
`Noise_XX_25519_ChaChaPoly_BLAKE2s`.

Mining uses ArkHash, a Neural Proof of Work function based on INT8
fully-connected layers — the universal primitive on mobile and laptop NPUs
(Apple ANE, Qualcomm Hexagon, Google Tensor, Intel NPU).

---

---

## Known Security Limitations

### H-1 --- Post-Quantum Address Gap (planned hard fork)

**Status: known, fix scheduled for the mainnet upgrade block.**

Arkos addresses currently commit only to the ECDSA public key
(SHA256(SHA256(ecdsa_pk))[..20]).  The Dilithium (ML-DSA) public key is
NOT bound in the address.

**Impact:** A sufficiently powerful quantum computer that can break secp256k1
ECDSA could forge the ECDSA signature and substitute its own Dilithium key,
spending any UTXO even though the hybrid scheme would otherwise require both
keys to be valid.

**Planned fix:** The address derivation will change to
SHA256(SHA256(ecdsa_pk || dilithium_pk))[..20] at a hard-fork block height
announced before mainnet launch.  Both keys are then bound in the address at
creation time, so substituting the Dilithium key yields a different address.

**Until mainnet launch:** Arkos operates on testnet only.  No real funds are
at risk.  The cryptographic design is sound if a quantum computer capable of
breaking secp256k1 does not yet exist (no such computer is known as of 2026).

**Caveat for wallet recovery:** After the hard fork, restoring a wallet from a
BIP39 phrase recovers the ECDSA key exactly.  The vault backup (which stores
both keys) is the authoritative recovery path post-upgrade.  Always keep an
encrypted vault backup in addition to your recovery phrase.

---

## Security Posture Summary

| Area | Status |
|------|--------|
| Hybrid signatures (ECDSA + ML-DSA-65) | Both required; neither alone is sufficient |
| Address-key binding | ECDSA-only today; hard fork to hybrid binding before mainnet |
| P2P transport | Noise_XX_25519_ChaChaPoly_BLAKE2s (mutual auth + encryption) |
| RPC authentication | Bearer token, constant-time comparison |
| RPC rate limiting | 60 req/min per IP via per-IP sliding-window limiter |
| Vault encryption | AES-256-GCM + Argon2id key derivation |
| Mining PoW | ArkHash Neural PoW (INT8 neural-net layers) |
| Difficulty adjustment | Median-timestamp anti-time-warp |


## Acknowledgements

We will publicly acknowledge security researchers in our release notes
(with your permission).

Thank you for helping make Arkos secure.
