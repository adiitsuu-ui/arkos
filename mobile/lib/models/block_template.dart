/// Block template returned by the node's `getBlockTemplate` RPC method.
///
/// The app uses this to:
///   1. Compute the `miningCommitment` (already provided by the node).
///   2. Ask the TEE channel to sign the commitment.
///   3. Feed all fields into the native mining FFI.
///   4. Submit the found nonce back via `submitBlock`.
class BlockTemplate {
  final int version;
  final String prevHash;
  final String merkleRoot;
  final int timestamp;
  final int bits;

  /// 64-char hex representation of the 32-byte difficulty target.
  final String targetHex;

  /// Current chain height; the new block will be at [height] + 1.
  final int height;

  /// Block reward in arkes (with 20 % mobile bonus already applied).
  final int rewardArkes;

  /// The value the device TEE key must sign — hex-encoded 32-byte hash.
  final String miningCommitment;

  /// Number of transactions in this template (coinbase + mempool).
  final int txCount;

  const BlockTemplate({
    required this.version,
    required this.prevHash,
    required this.merkleRoot,
    required this.timestamp,
    required this.bits,
    required this.targetHex,
    required this.height,
    required this.rewardArkes,
    required this.miningCommitment,
    required this.txCount,
  });

  factory BlockTemplate.fromJson(Map<String, dynamic> json) {
    return BlockTemplate(
      version: (json['version'] as num).toInt(),
      prevHash: json['prevHash'] as String,
      merkleRoot: json['merkleRoot'] as String,
      timestamp: (json['timestamp'] as num).toInt(),
      bits: (json['bits'] as num).toInt(),
      targetHex: json['targetHex'] as String,
      height: (json['height'] as num).toInt(),
      rewardArkes: (json['rewardArkes'] as num).toInt(),
      miningCommitment: json['miningCommitment'] as String,
      txCount: (json['txCount'] as num).toInt(),
    );
  }

  /// ARKOS display value (arkes / 10^9).
  double get rewardArkos => rewardArkes / 1e9;
}
