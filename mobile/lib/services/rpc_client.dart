import 'dart:convert';
import 'package:http/http.dart' as http;

import '../models/block_template.dart';
import '../models/device_info.dart';

/// Thrown when the node returns a JSON-RPC error.
class RpcException implements Exception {
  final int code;
  final String message;
  const RpcException(this.code, this.message);

  @override
  String toString() => 'RpcException($code): $message';
}

/// JSON-RPC 2.0 client for the Arkos node HTTP endpoint.
///
/// All methods throw [RpcException] on node-level errors,
/// or standard [Exception] / [http.ClientException] on network failures.
class ArkosRpcClient {
  final String baseUrl; // e.g. "http://192.168.1.100:8334"
  final String? authToken;
  final http.Client _http;
  int _nextId = 1;

  ArkosRpcClient({required this.baseUrl, this.authToken, http.Client? client})
      : _http = client ?? http.Client();

  void dispose() => _http.close();

  // ─── Core transport ────────────────────────────────────────────────────────

  Future<dynamic> _call(String method, [Map<String, dynamic>? params]) async {
    final id = _nextId++;
    final body = jsonEncode({
      'jsonrpc': '2.0',
      'id': id,
      'method': method,
      if (params != null) 'params': params,
    });

    final response = await _http
        .post(
          Uri.parse('$baseUrl/rpc'),
          headers: {
            'Content-Type': 'application/json',
            if (authToken != null && authToken!.isNotEmpty)
              'X-Arkos-Rpc-Token': authToken!,
          },
          body: body,
        )
        .timeout(const Duration(seconds: 10));

    if (response.statusCode != 200) {
      throw Exception('HTTP ${response.statusCode}: ${response.body}');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;

    if (json.containsKey('error')) {
      final err = json['error'] as Map<String, dynamic>;
      throw RpcException(
        (err['code'] as num).toInt(),
        err['message'] as String,
      );
    }

    return json['result'];
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /// Get a block template for [walletAddress] to mine against.
  Future<BlockTemplate> getBlockTemplate(String walletAddress) async {
    final result = await _call('getBlockTemplate', {'walletAddress': walletAddress});
    return BlockTemplate.fromJson(result as Map<String, dynamic>);
  }

  /// Submit a mined block to the node.
  ///
  /// Returns `true` if accepted; throws [RpcException] on validation failure.
  Future<bool> submitBlock({
    required int version,
    required String prevHash,
    required String merkleRoot,
    required int timestamp,
    required int bits,
    required int nonce,
    required String deviceId,
    required String walletAddress,
    required String deviceSignatureHex,
    required int height,
  }) async {
    final result = await _call('submitBlock', {
      'version': version,
      'prevHash': prevHash,
      'merkleRoot': merkleRoot,
      'timestamp': timestamp,
      'bits': bits,
      'nonce': nonce,
      'deviceId': deviceId,
      'walletAddress': walletAddress,
      'deviceSignatureHex': deviceSignatureHex,
      'height': height,
    });
    final map = result as Map<String, dynamic>;
    if (map['accepted'] != true) {
      throw RpcException(-32000, map['error'] as String? ?? 'block rejected');
    }
    return true;
  }

  /// Get ARKOS balance for [address].
  Future<Map<String, dynamic>> getBalance(String address) async {
    final result = await _call('getBalance', {'address': address});
    return result as Map<String, dynamic>;
  }

  /// Current chain height (number of confirmed blocks).
  Future<int> getBlockCount() async {
    final result = await _call('getBlockCount');
    return (result as num).toInt();
  }

  /// Network mining info: difficulty, mempool size, next reward.
  Future<Map<String, dynamic>> getMiningInfo() async {
    final result = await _call('getMiningInfo');
    return result as Map<String, dynamic>;
  }

  /// Register this device on-chain.
  Future<DeviceInfo> registerDevice({
    required String walletAddress,
    required String devicePubkeyHex,
    required String platform, // "ios" | "android"
    required String attestationBlobB64,
  }) async {
    final result = await _call('registerDevice', {
      'walletAddress': walletAddress,
      'devicePubkeyHex': devicePubkeyHex,
      'platform': platform,
      'attestationBlobB64': attestationBlobB64,
    });
    final map = result as Map<String, dynamic>;
    // Node returns { deviceId, registeredAtHeight }; we add what we know
    return DeviceInfo(
      deviceId: map['deviceId'] as String,
      walletAddress: walletAddress,
      platform: platform,
      registeredAtHeight: (map['registeredAtHeight'] as num).toInt(),
    );
  }

  /// Check whether [walletAddress] has a registered device on-chain.
  Future<DeviceInfo?> getDeviceStatus(String walletAddress) async {
    final result = await _call('getDeviceStatus', {'walletAddress': walletAddress});
    if (result == null) return null;
    return DeviceInfo.fromJson(result as Map<String, dynamic>);
  }

  /// Ping the node. Returns `true` if reachable.
  Future<bool> ping() async {
    try {
      await _http
          .get(Uri.parse('$baseUrl/health'))
          .timeout(const Duration(seconds: 5));
      return true;
    } catch (_) {
      return false;
    }
  }
}
