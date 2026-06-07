# Arkos Mobile Miner

Flutter app prototype for on-device mining of Arkos.  
Targets iOS and Android once the native host-channel files are added.

---

## Architecture

```
mobile/
├── lib/                        Flutter / Dart
│   ├── main.dart               App entry point, providers
│   ├── theme.dart              Dark theme (bgDark #0A0E1A, accent #00E5FF)
│   ├── models/                 Dart models (BlockTemplate, MiningStats, DeviceInfo)
│   ├── services/
│   │   ├── rpc_client.dart     JSON-RPC 2.0 HTTP client → node port 8334
│   │   ├── mining_ffi.dart     dart:ffi bindings → libarkos_mobile native
│   │   ├── mining_service.dart Dart Isolate mining loop + ChangeNotifier
│   │   ├── device_service.dart Flutter MethodChannel → TEE (Secure Enclave / Keystore)
│   │   └── wallet_service.dart Balance / address helpers
│   └── screens/
│       ├── setup_screen.dart   First-run wizard (node URL + wallet address)
│       ├── main_shell.dart     Bottom-nav shell (Mine / Wallet / Settings)
│       ├── mining_screen.dart  Hashrate chart, stats grid, device registration
│       ├── wallet_screen.dart  Balance card, address copy
│       └── settings_screen.dart Node URL, about, security info
├── native/                     Rust cdylib / staticlib (FFI mining core)
│   ├── Cargo.toml
│   └── src/lib.rs              arkos_mine(), arkos_mining_commitment(), …
├── ios/Runner/                 Swift MethodChannel host code
├── android/app/src/main/       Kotlin MethodChannel host code
└── native/                     Rust mining implementation
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Flutter | 3.19+ | App framework |
| Rust + rustup | stable | Native library |
| cargo-ndk | latest | Android cross-compile |
| Android NDK | r26+ | Android toolchain |
| Xcode | 15+ | iOS build |
| lipo / xcodebuild | system | iOS XCFramework |

Install `cargo-ndk`:
```bash
cargo install cargo-ndk
```

---

## Build Steps

### 1 — Start the Arkos node with RPC enabled

```bash
# In the arkos/ repo root:
cargo run --release -- node \
  --datadir ~/.arkos \
  --rpc-listen 0.0.0.0:8334
```

The `--rpc-listen 0.0.0.0:8334` flag is required.  
On your LAN, note the machine's IP address (e.g. `192.168.1.100`).

### 2 — Build the native Rust library

**Android:**
```bash
cd mobile
./scripts/build_native_android.sh --release
```
This places `.so` files in `android/app/src/main/jniLibs/`.

**iOS:**
```bash
cd mobile
./scripts/build_native_ios.sh --release
```
This creates `ios/Frameworks/ArkosNative.xcframework`.  
Add it to Xcode: target → General → Frameworks, Libraries… → **Embed: Do Not Embed**.

### 3 — Flutter pub get

```bash
cd mobile
flutter pub get
```

### 4 — Run / build

```bash
# Run on connected device
flutter run

# Release APK
flutter build apk --release

# Release App Bundle (Play Store)
flutter build appbundle --release

# Release iOS IPA
flutter build ipa --release
```

---

## First Run Flow

1. App opens → `SetupScreen` (no saved wallet address detected).
2. User enters **wallet address** (hex) → taps **Continue**.
4. App navigates to `MiningScreen`.
5. Tap the circle to start mining. First mine attempt triggers device registration:
   - TEE/platform channel provides a P-256 SEC1 public key.
   - `registerDevice` RPC is called with the public key + attestation token.
   - On-chain `DeviceRegistration` is created binding wallet ↔ device.
6. Mining loop runs in a Dart Isolate:
   - Fetches block template from node.
   - Uses the node-provided `miningCommitment`.
   - Signs commitment with TEE key via platform channel.
   - Calls `arkos_mine()` (native) in 500 k-nonce chunks.
   - On nonce found → `submitBlock` RPC → +20% mobile bonus applied by node.

---

## TEE / Device Key Details

### iOS
- Current Swift host code uses P-256 Secure Enclave keys.
- The Rust node accepts P-256 SEC1 public keys and DER ECDSA signatures for device proofs.
- Attestation target: Apple App Attest (`DCAppAttestService`) — returned as base64 DER.

### Android
- Current Kotlin host code uses P-256 Android Keystore keys.
- The Rust node accepts P-256 SEC1 public keys and DER ECDSA signatures for device proofs.
- Attestation target: Google Play Integrity API token.

Both platforms use the Flutter MethodChannel `com.arkos.mobile/tee`.

---

## Node RPC Reference

All requests are `POST /rpc` with JSON-RPC 2.0 body.  
Health check: `GET /health`.

| Method | Params | Returns |
|--------|--------|---------|
| `getBlockTemplate` | `{walletAddress}` | `BlockTemplate` with `miningCommitment` |
| `submitBlock` | `{version, prevHash, merkleRoot, timestamp, bits, nonce, walletAddress, deviceId, deviceSignatureHex, height}` | `{accepted, blockHash, error}` |
| `getBalance` | `{address}` | `{balanceArkes, balanceArkos}` |
| `getBlockCount` | `{}` | chain height |
| `getMiningInfo` | `{}` | `{height, bits, nextMobileRewardArkes, mempoolSize}` |
| `registerDevice` | `{walletAddress, devicePubkeyHex, platform, attestationBlobB64}` | `{deviceId, registeredAtHeight}` |
| `getDeviceStatus` | `{walletAddress}` | `DeviceInfo` or `null` |

---

## Mining Commitment

The `miningCommitment` field in `getBlockTemplate` is:

```
SHA-256²(version_le4 || prev_hash_utf8 || merkle_utf8 || timestamp_le8 || bits_le4)
```

where `prev_hash_utf8` and `merkle_utf8` are the **UTF-8 bytes** of the hex strings  
(matching `BlockHeader::mining_commitment()` in the Rust node).

The device TEE key signs this commitment **before** nonce search begins,  
proving the device committed to these specific block parameters.

---

## Security Notes

- Mining private keys **never leave hardware** (Secure Enclave / StrongBox).
- The node verifies the `device_signature` against the registered `public_key_hex`.
- Play Integrity / App Attest verification still needs platform-service integration; the current node rejects empty placeholder blobs but does not call Apple or Google services.
- The node can require `--rpc-token` / `ARKOS_RPC_TOKEN`; the app sends it as `X-Arkos-Rpc-Token` when configured in Settings.
- Use `--rpc-cors-origin` / `ARKOS_RPC_CORS_ORIGIN` for production browser origins instead of open development CORS.
- The mobile mining bonus (20%) only applies to blocks submitted with a valid `DeviceProof`.
