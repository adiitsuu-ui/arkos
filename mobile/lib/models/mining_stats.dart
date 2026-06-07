/// Snapshot of the current mining session statistics.
class MiningStats {
  /// Estimated hashes per second computed over the last sample window.
  final double hashesPerSecond;

  /// Total hashes attempted since mining started.
  final int totalHashes;

  /// Number of blocks successfully submitted (and accepted by the node).
  final int blocksFound;

  /// Total arkes earned this session.
  final int arkesMined;

  /// Current block height being worked on.
  final int currentHeight;

  /// Difficulty bits of the current target.
  final int bits;

  /// Whether the mining loop is active.
  final bool isActive;

  /// ISO-8601 timestamp of the last accepted block, or null.
  final DateTime? lastBlockAt;

  const MiningStats({
    required this.hashesPerSecond,
    required this.totalHashes,
    required this.blocksFound,
    required this.arkesMined,
    required this.currentHeight,
    required this.bits,
    required this.isActive,
    this.lastBlockAt,
  });

  static const MiningStats zero = MiningStats(
    hashesPerSecond: 0,
    totalHashes: 0,
    blocksFound: 0,
    arkesMined: 0,
    currentHeight: 0,
    bits: 0,
    isActive: false,
  );

  MiningStats copyWith({
    double? hashesPerSecond,
    int? totalHashes,
    int? blocksFound,
    int? arkesMined,
    int? currentHeight,
    int? bits,
    bool? isActive,
    DateTime? lastBlockAt,
  }) {
    return MiningStats(
      hashesPerSecond: hashesPerSecond ?? this.hashesPerSecond,
      totalHashes: totalHashes ?? this.totalHashes,
      blocksFound: blocksFound ?? this.blocksFound,
      arkesMined: arkesMined ?? this.arkesMined,
      currentHeight: currentHeight ?? this.currentHeight,
      bits: bits ?? this.bits,
      isActive: isActive ?? this.isActive,
      lastBlockAt: lastBlockAt ?? this.lastBlockAt,
    );
  }

  /// Human-readable hashrate string, e.g. "12.3 kH/s" or "1.4 MH/s".
  String get hashrateDisplay {
    if (hashesPerSecond < 1000) return '${hashesPerSecond.toStringAsFixed(0)} H/s';
    if (hashesPerSecond < 1e6) return '${(hashesPerSecond / 1e3).toStringAsFixed(1)} kH/s';
    if (hashesPerSecond < 1e9) return '${(hashesPerSecond / 1e6).toStringAsFixed(2)} MH/s';
    return '${(hashesPerSecond / 1e9).toStringAsFixed(3)} GH/s';
  }

  double get arkosMined => arkesMined / 1e9;
}
