/// dart:ffi bindings for the native Rust ArkHash mining library (libarkos_mobile).
///
/// # ArkHash — Neural Proof of Work
///
/// The block hash is computed by a chain of 16 INT8 fully-connected (FC) layers
/// whose weights are fixed by the protocol.  This maps directly to the native
/// NPU operation on every modern mobile chip:
///
///   - iOS / macOS  → CoreML `InnerProduct` INT8 (Apple Neural Engine)
///   - Android      → NNAPI `FULLY_CONNECTED` INT8 (Qualcomm Hexagon / MediaTek APU)
///
/// # Mining paths
///
/// 1. **CPU fallback** — call [ArkosNative.mine] directly.  The Rust library
///    runs the reference implementation.  Use only for testing / low-end devices.
///
/// 2. **NPU path (iOS)** — use [ArkosNpuMinerIos] (see mining_service.dart).
///    Loads the 1 MB weight table via [ArkosNative.getWeights] / [ArkosNative.getBiases],
///    builds a CoreML model in Dart, and runs ANE inference for each nonce batch.
///
/// 3. **NPU path (Android)** — use [ArkosNpuMinerAndroid].
///    Same weight table, loaded into an NNAPI model.
///
/// # Weight table layout
///
/// 16 layers × 256 rows × 256 cols = 1,048,576 INT8 bytes.
/// Layer l starts at byte offset `l * 256 * 256`.
/// Row r within layer l starts at offset `l * 256 * 256 + r * 256`.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// ─── ArkHash protocol constants ───────────────────────────────────────────────

/// Hidden dimension (neurons per layer).
const int arkHashD = 256;

/// Number of sequential FC layers.
const int arkHashL = 16;

/// Total weight table size in bytes.
const int arkHashWeightBytes = arkHashL * arkHashD * arkHashD; // 1,048,576

/// Total bias table size in i16 values (2 bytes each).
const int arkHashBiasCount = arkHashL * arkHashD; // 4,096

// ─── Native function type definitions ─────────────────────────────────────────

// u64 arkos_mine(u32, *c_char, *c_char, u64, u32, u64, u64, *u8, *c_char)
typedef _ArkosMineCType = Uint64 Function(
  Uint32 version,
  Pointer<Utf8> prevHashHex,
  Pointer<Utf8> merkleHex,
  Uint64 timestamp,
  Uint32 bits,
  Uint64 startNonce,
  Uint64 endNonce,
  Pointer<Uint8> stopFlag,
  Pointer<Utf8> outHash,
);
typedef ArkosMineDart = int Function(
  int version,
  Pointer<Utf8> prevHashHex,
  Pointer<Utf8> merkleHex,
  int timestamp,
  int bits,
  int startNonce,
  int endNonce,
  Pointer<Uint8> stopFlag,
  Pointer<Utf8> outHash,
);

// void arkos_hash_block(u32, *c_char, *c_char, u64, u32, u64, *c_char)
typedef _ArkosHashBlockCType = Void Function(
  Uint32, Pointer<Utf8>, Pointer<Utf8>, Uint64, Uint32, Uint64, Pointer<Utf8>,
);
typedef ArkosHashBlockDart = void Function(
  int, Pointer<Utf8>, Pointer<Utf8>, int, int, int, Pointer<Utf8>,
);

// i32 arkos_hash_meets_target(*c_char, u32)
typedef _ArkosHashMeetsTargetCType = Int32 Function(Pointer<Utf8>, Uint32);
typedef ArkosHashMeetsTargetDart = int Function(Pointer<Utf8>, int);

// void arkos_get_weights(*u8, *u64)
typedef _ArkosGetWeightsCType = Void Function(Pointer<Uint8>, Pointer<Uint64>);
typedef ArkosGetWeightsDart = void Function(Pointer<Uint8>, Pointer<Uint64>);

// void arkos_get_biases(*u8, *u64)
typedef _ArkosGetBiasesCType = Void Function(Pointer<Uint8>, Pointer<Uint64>);
typedef ArkosGetBiasesDart = void Function(Pointer<Uint8>, Pointer<Uint64>);

// ─── Library loader ───────────────────────────────────────────────────────────

class ArkosNative {
  static ArkosNative? _instance;

  late final DynamicLibrary _lib;
  late final ArkosMineDart mine;
  late final ArkosHashBlockDart hashBlock;
  late final ArkosHashMeetsTargetDart hashMeetsTarget;
  late final ArkosGetWeightsDart _getWeightsNative;
  late final ArkosGetBiasesDart _getBiasesNative;

  ArkosNative._() {
    _lib = _load();
    mine = _lib.lookupFunction<_ArkosMineCType, ArkosMineDart>('arkos_mine');
    hashBlock = _lib
        .lookupFunction<_ArkosHashBlockCType, ArkosHashBlockDart>('arkos_hash_block');
    hashMeetsTarget = _lib
        .lookupFunction<_ArkosHashMeetsTargetCType, ArkosHashMeetsTargetDart>(
            'arkos_hash_meets_target');
    _getWeightsNative = _lib
        .lookupFunction<_ArkosGetWeightsCType, ArkosGetWeightsDart>('arkos_get_weights');
    _getBiasesNative = _lib
        .lookupFunction<_ArkosGetBiasesCType, ArkosGetBiasesDart>('arkos_get_biases');
  }

  static ArkosNative get instance => _instance ??= ArkosNative._();

  static DynamicLibrary _load() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libarkos_mobile.so');
    } else if (Platform.isIOS || Platform.isMacOS) {
      return DynamicLibrary.process();
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('arkos_mobile.dll');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libarkos_mobile.so');
    }
    throw UnsupportedError(
      'Native ArkHash mining is not supported on ${Platform.operatingSystem}. '
      'Use RPC-only mode (node connectivity and balance queries still work).',
    );
  }

  /// Fetch the full INT8 weight table for all 16 FC layers.
  ///
  /// Returns a [Uint8List] of length [arkHashWeightBytes] (1,048,576 bytes).
  /// Values are INT8 reinterpreted as bytes; cast to Int8List for signed values.
  ///
  /// Pass this to the CoreML / NNAPI model builder to create the NPU miner.
  /// Layer l occupies bytes [l * D * D, (l+1) * D * D).
  Uint8List getWeights() {
    final buf = calloc<Uint8>(arkHashWeightBytes);
    final lenPtr = calloc<Uint64>();
    try {
      _getWeightsNative(buf, lenPtr);
      final len = lenPtr.value;
      return Uint8List.fromList(buf.asTypedList(len));
    } finally {
      calloc.free(buf);
      calloc.free(lenPtr);
    }
  }

  /// Fetch the INT16 bias table for all 16 FC layers.
  ///
  /// Returns a [Int16List] of length [arkHashBiasCount] (4,096 values).
  /// Values are in [−64, 64].
  ///
  /// Pass alongside [getWeights] to the CoreML / NNAPI model builder.
  Int16List getBiases() {
    const byteCount = arkHashBiasCount * 2;
    final buf = calloc<Uint8>(byteCount);
    final lenPtr = calloc<Uint64>();
    try {
      _getBiasesNative(buf, lenPtr);
      final bytes = Uint8List.fromList(buf.asTypedList(byteCount));
      return bytes.buffer.asInt16List();
    } finally {
      calloc.free(buf);
      calloc.free(lenPtr);
    }
  }

  /// The u64 sentinel meaning "nonce not found".
  static const int nonceNotFound = 0xFFFFFFFFFFFFFFFF;
}
