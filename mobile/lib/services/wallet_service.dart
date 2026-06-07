import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'rpc_client.dart';

const _kAddressKey = 'arkos.wallet_address';

/// Manages the wallet address and balance queries.
///
/// Key is stored in `flutter_secure_storage` (backed by iOS Keychain /
/// Android Keystore).  Balance is fetched live from the node.
class WalletService {
  final ArkosRpcClient rpcClient;
  final FlutterSecureStorage _secure;
  final SharedPreferences _prefs;

  WalletService._({
    required this.rpcClient,
    required FlutterSecureStorage secure,
    required SharedPreferences prefs,
  })  : _secure = secure,
        _prefs = prefs;

  static Future<WalletService> create(ArkosRpcClient rpcClient) async {
    final prefs = await SharedPreferences.getInstance();
    return WalletService._(
      rpcClient: rpcClient,
      secure: const FlutterSecureStorage(),
      prefs: prefs,
    );
  }

  // ─── Address management ───────────────────────────────────────────────────

  /// Save [address] as the active wallet address.
  Future<void> saveAddress(String address) async {
    await _secure.write(key: _kAddressKey, value: address);
    await _prefs.setString(_kAddressKey, address);
  }

  /// Load the saved wallet address, or null if none.
  Future<String?> loadAddress() async {
    // Prefer secure storage; fall back to shared prefs (migration path).
    return _secure.read(key: _kAddressKey) ??
        _prefs.getString(_kAddressKey);
  }

  Future<void> clearAddress() async {
    await _secure.delete(key: _kAddressKey);
    await _prefs.remove(_kAddressKey);
  }

  // ─── Balance ──────────────────────────────────────────────────────────────

  /// Returns `{balanceArkes: int, balanceArkos: double}` for [address].
  Future<({int balanceArkes, double balanceArkos})> getBalance(
      String address) async {
    final result = await rpcClient.getBalance(address);
    return (
      balanceArkes: (result['balanceArkes'] as num).toInt(),
      balanceArkos: (result['balanceArkos'] as num).toDouble(),
    );
  }

  // ─── Node connectivity ────────────────────────────────────────────────────

  Future<int> getBlockCount() => rpcClient.getBlockCount();

  Future<Map<String, dynamic>> getMiningInfo() => rpcClient.getMiningInfo();
}
