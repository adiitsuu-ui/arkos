/// dart:ffi bindings for the native Rust mining library (libarkos_mobile).
///
/// The library is loaded once at startup and reused across mining sessions.
/// All heavy computation runs synchronously inside a [compute] Isolate so
/// the main thread (and therefore the UI) is never blocked.
library;

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

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

// void arkos_mining_commitment(u32, *c_char, *c_char, u64, u32, *c_char)
typedef _ArkosMiningCommitmentCType = Void Function(
  Uint32, Pointer<Utf8>, Pointer<Utf8>, Uint64, Uint32, Pointer<Utf8>,
);
typedef ArkosMiningCommitmentDart = void Function(
  int, Pointer<Utf8>, Pointer<Utf8>, int, int, Pointer<Utf8>,
);

// ─── Library loader ───────────────────────────────────────────────────────────

class ArkosNative {
  static ArkosNative? _instance;

  late final DynamicLibrary _lib;
  late final ArkosMineDart mine;
  late final ArkosHashBlockDart hashBlock;
  late final ArkosHashMeetsTargetDart hashMeetsTarget;
  late final ArkosMiningCommitmentDart miningCommitment;

  ArkosNative._() {
    _lib = _load();
    mine = _lib
        .lookupFunction<_ArkosMineCType, ArkosMineDart>('arkos_mine');
    hashBlock = _lib
        .lookupFunction<_ArkosHashBlockCType, ArkosHashBlockDart>('arkos_hash_block');
    hashMeetsTarget = _lib
        .lookupFunction<_ArkosHashMeetsTargetCType, ArkosHashMeetsTargetDart>(
            'arkos_hash_meets_target');
    miningCommitment = _lib
        .lookupFunction<_ArkosMiningCommitmentCType, ArkosMiningCommitmentDart>(
            'arkos_mining_commitment');
  }

  static ArkosNative get instance => _instance ??= ArkosNative._();

  static DynamicLibrary _load() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libarkos_mobile.so');
    } else if (Platform.isIOS) {
      // On iOS the native library is statically linked into the runner binary.
      return DynamicLibrary.process();
    }
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }

  /// The u64 sentinel meaning "nonce not found".
  static const int nonceNotFound = 0xFFFFFFFFFFFFFFFF;
}
