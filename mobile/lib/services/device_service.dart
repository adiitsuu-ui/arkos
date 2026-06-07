import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/device_info.dart';
import 'rpc_client.dart';

/// Platform channel names — must match the native host code exactly.
const _kTeeChannel = MethodChannel('com.arkos.mobile/tee');

/// Storage keys
const _kDeviceIdKey = 'arkos.device_id';
const _kWalletAddressKey = 'arkos.wallet_address';

/// Manages the device key channel, attestation, and on-chain device registration.
///
/// iOS/Android host code returns P-256 SEC1 public keys and DER ECDSA
/// signatures, which the Rust node accepts for device proofs.
///
/// Platform-channel methods available (implemented in Swift / Kotlin):
///
/// | Method                  | Arguments             | Returns                        |
/// |-------------------------|-----------------------|--------------------------------|
/// | `generateDeviceKey`     | —                     | `{pubkeyHex: String}`          |
/// | `getDevicePublicKey`    | —                     | `{pubkeyHex: String}`          |
/// | `signCommitment`        | `{commitmentHex: str}`| `{signatureHex: String}`       |
/// | `getAttestationToken`   | `{challengeHex: str}` | `{tokenB64: String}`           |
class DeviceService {
  final ArkosRpcClient rpcClient;
  final FlutterSecureStorage _secureStorage;
  final SharedPreferences _prefs;

  DeviceInfo? _cachedDeviceInfo;

  DeviceService._({
    required this.rpcClient,
    required FlutterSecureStorage secureStorage,
    required SharedPreferences prefs,
  })  : _secureStorage = secureStorage,
        _prefs = prefs;

  static Future<DeviceService> create(ArkosRpcClient rpcClient) async {
    final prefs = await SharedPreferences.getInstance();
    return DeviceService._(
      rpcClient: rpcClient,
      secureStorage: const FlutterSecureStorage(),
      prefs: prefs,
    );
  }

  // ─── TEE key operations ────────────────────────────────────────────────────

  /// Generate a new device key in the TEE (one-time setup).
  /// Returns the platform device public key as a hex string.
  Future<String> generateDeviceKey() async {
    final result = await _kTeeChannel.invokeMapMethod<String, dynamic>(
      'generateDeviceKey',
    );
    return result!['pubkeyHex'] as String;
  }

  /// Retrieve the existing TEE public key (hex).  Returns null if no key exists.
  Future<String?> getDevicePublicKey() async {
    try {
      final result = await _kTeeChannel.invokeMapMethod<String, dynamic>(
        'getDevicePublicKey',
      );
      return result?['pubkeyHex'] as String?;
    } on PlatformException {
      return null;
    }
  }

  /// Sign [commitmentHex] with the device's private key.
  /// Returns a DER-encoded P-256 ECDSA signature as hex on iOS/Android.
  Future<String> signCommitment(String commitmentHex) async {
    final result = await _kTeeChannel.invokeMapMethod<String, dynamic>(
      'signCommitment',
      {'commitmentHex': commitmentHex},
    );
    return result!['signatureHex'] as String;
  }

  /// Obtain an attestation token from the OS (Apple App Attest / Google Play
  /// Integrity API).  [challengeHex] is a fresh nonce from the node.
  Future<String> getAttestationToken(String challengeHex) async {
    final result = await _kTeeChannel.invokeMapMethod<String, dynamic>(
      'getAttestationToken',
      {'challengeHex': challengeHex},
    );
    return result!['tokenB64'] as String;
  }

  // ─── Registration flow ─────────────────────────────────────────────────────

  /// Full device registration flow:
  ///   1. Check if already registered on-chain.
  ///   2. Generate / retrieve TEE key.
  ///   3. Obtain attestation token.
  ///   4. Call `registerDevice` RPC.
  ///   5. Persist device info locally.
  Future<DeviceInfo> registerDevice(String walletAddress) async {
    // Already registered?
    final existing = await rpcClient.getDeviceStatus(walletAddress);
    if (existing != null) {
      await _persist(existing);
      return existing;
    }

    // Ensure TEE key exists
    var pubkeyHex = await getDevicePublicKey();
    if (pubkeyHex == null) {
      pubkeyHex = await generateDeviceKey();
    }

    // Derive a challenge from the pubkey (node would supply this in production)
    final challengeHex = pubkeyHex.substring(0, 64);
    final attestationB64 = await getAttestationToken(challengeHex);

    final platform = _platform();
    final deviceInfo = await rpcClient.registerDevice(
      walletAddress: walletAddress,
      devicePubkeyHex: pubkeyHex,
      platform: platform,
      attestationBlobB64: attestationB64,
    );

    await _persist(deviceInfo);
    return deviceInfo;
  }

  /// Load device info from local storage (does not hit the network).
  Future<DeviceInfo?> loadLocalDeviceInfo() async {
    final deviceId = _prefs.getString(_kDeviceIdKey);
    final walletAddress = _prefs.getString(_kWalletAddressKey);
    if (deviceId == null || walletAddress == null) return null;

    // Re-fetch from node to get the authoritative record
    return rpcClient.getDeviceStatus(walletAddress);
  }

  Future<void> _persist(DeviceInfo info) async {
    await _prefs.setString(_kDeviceIdKey, info.deviceId);
    await _prefs.setString(_kWalletAddressKey, info.walletAddress);
    _cachedDeviceInfo = info;
  }

  DeviceInfo? get cachedDeviceInfo => _cachedDeviceInfo;

  String _platform() {
    // flutter/foundation.dart defaultTargetPlatform
    switch (defaultTargetPlatform) {
      case TargetPlatform.iOS:
        return 'ios';
      case TargetPlatform.android:
        return 'android';
      default:
        return 'unknown';
    }
  }
}

TargetPlatform get defaultTargetPlatform {
  return TargetPlatform.values.firstWhere(
    (p) => p.name == const String.fromEnvironment('FLUTTER_PLATFORM', defaultValue: 'android'),
    orElse: () => TargetPlatform.android,
  );
}
