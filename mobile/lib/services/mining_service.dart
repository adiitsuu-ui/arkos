import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:math';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import '../models/block_template.dart';
import '../models/mining_stats.dart';
import 'mining_ffi.dart';
import 'rpc_client.dart';

// ─── Isolate message types ────────────────────────────────────────────────────

/// Sent from the main isolate → mining isolate to control mining.
sealed class MiningCommand {
  const MiningCommand();
}

class StartMining extends MiningCommand {
  final BlockTemplate template;
  const StartMining({required this.template});
}

class StopMining extends MiningCommand {
  const StopMining();
}

class NewTemplate extends MiningCommand {
  final BlockTemplate template;
  const NewTemplate({required this.template});
}

/// Sent from the mining isolate → main isolate with progress/results.
sealed class MiningEvent {
  const MiningEvent();
}

class HashRateUpdate extends MiningEvent {
  final double hashesPerSecond;
  final int totalHashes;
  const HashRateUpdate(this.hashesPerSecond, this.totalHashes);
}

class BlockFound extends MiningEvent {
  final int nonce;
  final String blockHash;
  final int height;
  const BlockFound(this.nonce, this.blockHash, this.height);
}

class BlockAccepted extends MiningEvent {
  final int height;
  final int rewardArkes;
  const BlockAccepted(this.height, this.rewardArkes);
}

class MiningError extends MiningEvent {
  final String message;
  const MiningError(this.message);
}

// ─── Mining isolate entry point ───────────────────────────────────────────────

/// Parameters bundle sent to the isolate on spawn.
class _IsolateParams {
  final SendPort toMain;
  final ReceivePort fromMain;
  final BlockTemplate initialTemplate;
  final int chunkSize; // nonces per FFI call

  _IsolateParams({
    required this.toMain,
    required this.fromMain,
    required this.initialTemplate,
    required this.chunkSize,
  });
}

void _miningIsolateEntry(_IsolateParams params) {
  final native = ArkosNative.instance;
  var template = params.initialTemplate;
  var startNonce = 0;
  var totalHashes = 0;
  var lastHashrateTs = DateTime.now();
  var hashesInWindow = 0;

  // Stop flag: a native-heap byte the FFI function checks periodically.
  final stopFlagPtr = calloc<Uint8>();
  stopFlagPtr.value = 0;

  // Listen for commands from the main isolate.
  params.fromMain.listen((msg) {
    if (msg is StopMining) {
      stopFlagPtr.value = 1;
    } else if (msg is NewTemplate) {
      // Interrupt current nonce search and restart with new template
      stopFlagPtr.value = 1;
      // Will be cleared and template replaced at the top of the loop.
      template = msg.template;
      startNonce = 0;
    }
  });

  while (stopFlagPtr.value == 0) {
    stopFlagPtr.value = 0; // clear after interrupt
    final endNonce = startNonce + params.chunkSize;

    // Allocate scratch buffers on the native heap.
    final prevHashPtr = template.prevHash.toNativeUtf8();
    final merklePtr = template.merkleRoot.toNativeUtf8();
    final outHashPtr = calloc<Utf8>(65);

    final foundNonce = native.mine(
      template.version,
      prevHashPtr,
      merklePtr,
      template.timestamp,
      template.bits,
      startNonce,
      endNonce,
      stopFlagPtr,
      outHashPtr.cast(),
    );

    final hashesThisChunk = (foundNonce == ArkosNative.nonceNotFound)
        ? params.chunkSize
        : (foundNonce - startNonce + 1);
    totalHashes += hashesThisChunk;
    hashesInWindow += hashesThisChunk;

    // Emit hashrate update every ~2 seconds.
    final now = DateTime.now();
    final elapsed = now.difference(lastHashrateTs).inMilliseconds;
    if (elapsed >= 2000) {
      final hps = hashesInWindow / (elapsed / 1000.0);
      params.toMain.send(HashRateUpdate(hps, totalHashes));
      hashesInWindow = 0;
      lastHashrateTs = now;
    }

    if (foundNonce != ArkosNative.nonceNotFound) {
      final blockHash = outHashPtr.cast<Utf8>().toDartString();
      params.toMain.send(BlockFound(foundNonce, blockHash, template.height + 1));
      // Pause nonce search until main isolate sends a new template.
      stopFlagPtr.value = 1;
    } else {
      startNonce = endNonce;
    }

    calloc.free(prevHashPtr);
    calloc.free(merklePtr);
    calloc.free(outHashPtr);
  }

  calloc.free(stopFlagPtr);
}

// ─── MiningService ────────────────────────────────────────────────────────────

/// Orchestrates proof-of-work mining across the FFI isolate and the node RPC.
///
/// Usage:
/// ```dart
/// final svc = MiningService(rpcClient: client, walletAddress: addr);
/// svc.statsStream.listen((stats) => setState(() => _stats = stats));
/// await svc.start();
/// // later:
/// await svc.stop();
/// ```
class MiningService extends ChangeNotifier {
  ArkosRpcClient rpcClient;
  String _walletAddress;
  String get walletAddress => _walletAddress;

  // Isolate infrastructure
  Isolate? _isolate;
  SendPort? _toIsolate;
  final ReceivePort _fromIsolate = ReceivePort();

  // Stats
  MiningStats _stats = MiningStats.zero;
  MiningStats get stats => _stats;

  // Stream of stat snapshots for UI listeners.
  final _statsController = StreamController<MiningStats>.broadcast();
  Stream<MiningStats> get statsStream => _statsController.stream;

  // How many nonces the FFI function processes per call.
  // Larger = fewer Dart overhead per call, but longer between stop-flag checks.
  static const _chunkSize = 500000;

  MiningService({required this.rpcClient, required String walletAddress})
      : _walletAddress = walletAddress;

  void setRpcClient(ArkosRpcClient rpcClient) {
    this.rpcClient = rpcClient;
  }

  void setWalletAddress(String walletAddress) {
    _walletAddress = walletAddress;
  }

  bool get isRunning => _isolate != null;

  /// True when the native ArkHash library is available on this platform.
  ///
  /// On platforms where the native library cannot be loaded (e.g. web), this
  /// returns false and [start] will throw a user-visible error instead of
  /// crashing the app.
  static bool get nativeMiningAvailable {
    try {
      ArkosNative.instance; // triggers lazy load; throws UnsupportedError on web
      return true;
    } on UnsupportedError {
      return false;
    }
  }

  /// Start mining against the node's standard proof-of-work template.
  Future<void> start() async {
    if (isRunning) return;

    if (!nativeMiningAvailable) {
      _stats = _stats.copyWith(isActive: false);
      _emit();
      throw UnsupportedError(
        'Native mining is not available on this platform. '
        'Connect to a node via RPC for balance and chain queries.',
      );
    }

    // Fetch initial block template
    final template = await rpcClient.getBlockTemplate(walletAddress);

    _stats = MiningStats.zero.copyWith(
      isActive: true,
      currentHeight: template.height + 1,
      bits: template.bits,
    );
    _emit();

    // Spawn the mining isolate
    final toIsolateSend = ReceivePort();
    final isolateParams = _IsolateParams(
      toMain: _fromIsolate.sendPort,
      fromMain: toIsolateSend,
      initialTemplate: template,
      chunkSize: _chunkSize,
    );

    _isolate = await Isolate.spawn(_miningIsolateEntry, isolateParams);

    // Store the isolate's command channel
    // (isolate sends its SendPort first)
    _toIsolate = toIsolateSend.sendPort;

    // Listen for events from the isolate
    _fromIsolate.listen(_handleIsolateEvent());
  }

  void Function(dynamic) _handleIsolateEvent() {
    return (event) async {
      if (event is HashRateUpdate) {
        _stats = _stats.copyWith(
          hashesPerSecond: event.hashesPerSecond,
          totalHashes: event.totalHashes,
        );
        _emit();
      } else if (event is BlockFound) {
        // Ask the RPC to submit. First re-fetch template fields needed for the call.
        final template = await rpcClient.getBlockTemplate(walletAddress);

        try {
          await rpcClient.submitBlock(
            version: template.version,
            prevHash: template.prevHash,
            merkleRoot: template.merkleRoot,
            timestamp: template.timestamp,
            bits: template.bits,
            nonce: event.nonce,
            walletAddress: walletAddress,
            height: template.height,
          );

          _stats = _stats.copyWith(
            blocksFound: _stats.blocksFound + 1,
            arkesMined: _stats.arkesMined + template.rewardArkes,
            lastBlockAt: DateTime.now(),
          );
          _emit();

          // Get fresh template for the next block
          final nextTemplate = await rpcClient.getBlockTemplate(walletAddress);
          _toIsolate?.send(NewTemplate(template: nextTemplate));
        } catch (e) {
          // Block rejected (stale or invalid) — fetch fresh template and continue
          final nextTemplate = await rpcClient.getBlockTemplate(walletAddress);
          _toIsolate?.send(NewTemplate(template: nextTemplate));
        }
      }
    };
  }

  Future<void> stop() async {
    _toIsolate?.send(const StopMining());
    _isolate?.kill(priority: Isolate.immediate);
    _isolate = null;
    _toIsolate = null;

    _stats = _stats.copyWith(isActive: false);
    _emit();
  }

  void _emit() {
    _statsController.add(_stats);
    notifyListeners();
  }

  @override
  void dispose() {
    stop();
    _fromIsolate.close();
    _statsController.close();
    super.dispose();
  }
}
