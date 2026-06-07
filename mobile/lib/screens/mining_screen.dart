import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models/mining_stats.dart';
import '../services/mining_service.dart';
import '../services/device_service.dart';
import '../services/rpc_client.dart';
import '../services/wallet_service.dart';
import '../theme.dart';

class MiningScreen extends StatefulWidget {
  const MiningScreen({super.key});

  @override
  State<MiningScreen> createState() => _MiningScreenState();
}

class _MiningScreenState extends State<MiningScreen> {
  DeviceService? _deviceSvc;
  WalletService? _walletSvc;
  String? _walletAddress;
  String? _deviceId;
  bool _initialising = true;
  String? _error;

  // Hashrate history for the sparkline chart (last 30 samples)
  final List<double> _hashrateHistory = [];
  static const _maxHistorySamples = 30;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      final rpc = context.read<ArkosRpcClient>();
      _walletSvc = await WalletService.create(rpc);
      _deviceSvc = await DeviceService.create(rpc);
      _walletAddress = await _walletSvc!.loadAddress();
      if (_walletAddress != null) {
        context.read<MiningService>().setWalletAddress(_walletAddress!);
      }

      if (_walletAddress != null) {
        final deviceInfo = await _deviceSvc!.loadLocalDeviceInfo();
        _deviceId = deviceInfo?.deviceId;
      }
    } catch (e) {
      _error = 'Initialisation failed: $e';
    } finally {
      if (mounted) setState(() => _initialising = false);
    }
  }

  Future<void> _toggleMining() async {
    final svc = context.read<MiningService>();
    if (svc.isRunning) {
      await svc.stop();
      return;
    }

    if (_walletAddress == null) {
      _showError('No wallet configured. Go to Wallet tab.');
      return;
    }

    if (_deviceId == null) {
      final ok = await _registerDevice();
      if (!ok) return;
    }

    try {
      await svc.start(
        deviceId: _deviceId!,
        getDeviceSignature: (commitment) async {
          return _deviceSvc!.signCommitment(commitment);
        },
      );
    } catch (e) {
      _showError('Failed to start mining: $e');
    }
  }

  Future<bool> _registerDevice() async {
    if (_walletAddress == null || _deviceSvc == null) return false;
    try {
      final info = await _deviceSvc!.registerDevice(_walletAddress!);
      setState(() => _deviceId = info.deviceId);
      return true;
    } catch (e) {
      _showError('Device registration failed: $e');
      return false;
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: ArkosTheme.error,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_initialising) {
      return const Scaffold(
        backgroundColor: ArkosTheme.bgDark,
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      backgroundColor: ArkosTheme.bgDark,
      appBar: AppBar(
        title: Row(children: [
          const _ArkosLogo(),
          const SizedBox(width: 8),
          const Text('Arkos Miner'),
        ]),
        actions: [
          _NodeStatusDot(),
          const SizedBox(width: 16),
        ],
      ),
      body: Consumer<MiningService>(
        builder: (ctx, svc, _) {
          final stats = svc.stats;

          // Track hashrate history
          if (stats.hashesPerSecond > 0 &&
              (_hashrateHistory.isEmpty ||
                  _hashrateHistory.last != stats.hashesPerSecond)) {
            _hashrateHistory.add(stats.hashesPerSecond);
            if (_hashrateHistory.length > _maxHistorySamples) {
              _hashrateHistory.removeAt(0);
            }
          }

          return RefreshIndicator(
            onRefresh: _init,
            color: ArkosTheme.accent,
            child: SingleChildScrollView(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // ── Mining toggle card ────────────────────────────────────
                  _MiningToggleCard(
                    isRunning: svc.isRunning,
                    isDeviceRegistered: _deviceId != null,
                    onToggle: _toggleMining,
                    stats: stats,
                  ),
                  const SizedBox(height: 16),

                  // ── Hashrate sparkline ────────────────────────────────────
                  if (_hashrateHistory.isNotEmpty)
                    _HashrateChart(history: _hashrateHistory),
                  if (_hashrateHistory.isNotEmpty) const SizedBox(height: 16),

                  // ── Stats grid ────────────────────────────────────────────
                  _StatsGrid(stats: stats),
                  const SizedBox(height: 16),

                  // ── Network info ──────────────────────────────────────────
                  _NetworkCard(walletAddress: _walletAddress),
                  const SizedBox(height: 16),

                  // ── Device info ───────────────────────────────────────────
                  _DeviceCard(
                    deviceId: _deviceId,
                    onRegister: _registerDevice,
                  ),
                  const SizedBox(height: 32),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ─── Subwidgets ───────────────────────────────────────────────────────────────

class _ArkosLogo extends StatelessWidget {
  const _ArkosLogo();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 28,
      height: 28,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: ArkosTheme.accent, width: 1.5),
        gradient: const RadialGradient(
          colors: [Color(0xFF00E5FF22), ArkosTheme.bgDark],
        ),
      ),
      child: const Center(
        child: Text(
          'A',
          style: TextStyle(
            color: ArkosTheme.accent,
            fontWeight: FontWeight.w700,
            fontSize: 14,
          ),
        ),
      ),
    );
  }
}

class _NodeStatusDot extends StatefulWidget {
  @override
  State<_NodeStatusDot> createState() => _NodeStatusDotState();
}

class _NodeStatusDotState extends State<_NodeStatusDot> {
  bool _online = false;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    final rpc = context.read<ArkosRpcClient>();
    final ok = await rpc.ping();
    if (mounted) setState(() => _online = ok);
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: _check,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: _online ? ArkosTheme.success : ArkosTheme.error,
              boxShadow: _online
                  ? [BoxShadow(color: ArkosTheme.success.withOpacity(0.6), blurRadius: 6)]
                  : null,
            ),
          ),
          const SizedBox(width: 4),
          Text(
            _online ? 'Connected' : 'Offline',
            style: TextStyle(
              fontSize: 11,
              color: _online ? ArkosTheme.success : ArkosTheme.error,
            ),
          ),
        ],
      ),
    );
  }
}

class _MiningToggleCard extends StatelessWidget {
  final bool isRunning;
  final bool isDeviceRegistered;
  final VoidCallback onToggle;
  final MiningStats stats;

  const _MiningToggleCard({
    required this.isRunning,
    required this.isDeviceRegistered,
    required this.onToggle,
    required this.stats,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Animated mining indicator
            AnimatedContainer(
              duration: const Duration(milliseconds: 400),
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: isRunning
                    ? ArkosTheme.accent.withOpacity(0.12)
                    : ArkosTheme.bgCardBorder.withOpacity(0.3),
                border: Border.all(
                  color: isRunning ? ArkosTheme.accent : ArkosTheme.bgCardBorder,
                  width: 2,
                ),
              ),
              child: Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      isRunning ? Icons.bolt : Icons.bolt_outlined,
                      color: isRunning ? ArkosTheme.accent : ArkosTheme.textMuted,
                      size: 36,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      isRunning ? stats.hashrateDisplay : '—',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: isRunning ? ArkosTheme.accent : ArkosTheme.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              isRunning ? 'Mining Active' : 'Mining Stopped',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            if (isRunning) ...[
              const SizedBox(height: 4),
              Text(
                'Block ${stats.currentHeight} · ${_bitsLabel(stats.bits)}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
            const SizedBox(height: 20),
            ElevatedButton.icon(
              onPressed: onToggle,
              icon: Icon(isRunning ? Icons.stop : Icons.play_arrow),
              label: Text(isRunning ? 'Stop Mining' : 'Start Mining'),
              style: ElevatedButton.styleFrom(
                backgroundColor: isRunning ? ArkosTheme.error : ArkosTheme.accent,
                foregroundColor: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _bitsLabel(int bits) {
    if (bits == 0) return '';
    return 'Difficulty 0x${bits.toRadixString(16).toUpperCase()}';
  }
}

class _HashrateChart extends StatelessWidget {
  final List<double> history;

  const _HashrateChart({required this.history});

  @override
  Widget build(BuildContext context) {
    final maxY = history.reduce((a, b) => a > b ? a : b) * 1.2;
    final spots = history.asMap().entries.map((e) {
      return FlSpot(e.key.toDouble(), e.value);
    }).toList();

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 16, 12, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Hashrate', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            SizedBox(
              height: 100,
              child: LineChart(
                LineChartData(
                  minY: 0,
                  maxY: maxY == 0 ? 100 : maxY,
                  gridData: const FlGridData(show: false),
                  titlesData: const FlTitlesData(show: false),
                  borderData: FlBorderData(show: false),
                  lineTouchData: const LineTouchData(enabled: false),
                  lineBarsData: [
                    LineChartBarData(
                      spots: spots,
                      isCurved: true,
                      color: ArkosTheme.accent,
                      barWidth: 2,
                      dotData: const FlDotData(show: false),
                      belowBarData: BarAreaData(
                        show: true,
                        color: ArkosTheme.accent.withOpacity(0.1),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _StatsGrid extends StatelessWidget {
  final MiningStats stats;

  const _StatsGrid({required this.stats});

  @override
  Widget build(BuildContext context) {
    final nf = NumberFormat.compact();
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 1.6,
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      children: [
        _StatCell(
          label: 'Blocks Found',
          value: stats.blocksFound.toString(),
          icon: Icons.check_circle_outline,
          color: ArkosTheme.success,
        ),
        _StatCell(
          label: 'ARKOS Earned',
          value: stats.arkosMined.toStringAsFixed(4),
          icon: Icons.toll,
          color: ArkosTheme.accentGold,
        ),
        _StatCell(
          label: 'Total Hashes',
          value: nf.format(stats.totalHashes),
          icon: Icons.functions,
          color: ArkosTheme.accent,
        ),
        _StatCell(
          label: 'Last Block',
          value: stats.lastBlockAt != null
              ? DateFormat('HH:mm:ss').format(stats.lastBlockAt!)
              : '—',
          icon: Icons.access_time,
          color: ArkosTheme.textMuted,
        ),
      ],
    );
  }
}

class _StatCell extends StatelessWidget {
  final String label;
  final String value;
  final IconData icon;
  final Color color;

  const _StatCell({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(icon, color: color, size: 16),
              const SizedBox(width: 6),
              Text(label, style: Theme.of(context).textTheme.bodySmall),
            ]),
            const Spacer(),
            Text(
              value,
              style: Theme.of(context).textTheme.titleMedium!.copyWith(
                    color: color,
                    fontSize: 18,
                  ),
            ),
          ],
        ),
      ),
    );
  }
}

class _NetworkCard extends StatefulWidget {
  final String? walletAddress;

  const _NetworkCard({this.walletAddress});

  @override
  State<_NetworkCard> createState() => _NetworkCardState();
}

class _NetworkCardState extends State<_NetworkCard> {
  int? _height;
  int? _mempool;
  int? _nextReward;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final rpc = context.read<ArkosRpcClient>();
      final info = await rpc.getMiningInfo();
      setState(() {
        _height = (info['height'] as num?)?.toInt();
        _mempool = (info['mempoolSize'] as num?)?.toInt();
        _nextReward = (info['nextMobileRewardArkes'] as num?)?.toInt();
      });
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Network', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            _Row('Block height', _height?.toString() ?? '…'),
            const SizedBox(height: 6),
            _Row('Mempool txs', _mempool?.toString() ?? '…'),
            const SizedBox(height: 6),
            _Row(
              'Next reward',
              _nextReward != null
                  ? '${(_nextReward! / 1e9).toStringAsFixed(4)} ARKOS (+20%)'
                  : '…',
              valueColor: ArkosTheme.accentGold,
            ),
          ],
        ),
      ),
    );
  }
}

class _Row extends StatelessWidget {
  final String label;
  final String value;
  final Color? valueColor;

  const _Row(this.label, this.value, {this.valueColor});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: Theme.of(context).textTheme.bodySmall),
        Text(
          value,
          style: TextStyle(
            color: valueColor ?? ArkosTheme.textPrimary,
            fontWeight: FontWeight.w600,
            fontSize: 13,
          ),
        ),
      ],
    );
  }
}

class _DeviceCard extends StatelessWidget {
  final String? deviceId;
  final Future<bool> Function() onRegister;

  const _DeviceCard({this.deviceId, required this.onRegister});

  @override
  Widget build(BuildContext context) {
    final registered = deviceId != null;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text('Device Registration',
                    style: Theme.of(context).textTheme.titleMedium),
                const Spacer(),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: registered
                        ? ArkosTheme.success.withOpacity(0.15)
                        : ArkosTheme.warning.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    registered ? 'Registered' : 'Not registered',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      color: registered ? ArkosTheme.success : ArkosTheme.warning,
                    ),
                  ),
                ),
              ],
            ),
            if (registered) ...[
              const SizedBox(height: 8),
              Text(
                'ID: ${deviceId!.substring(0, 16)}…',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 4),
              const Text(
                'TEE key stored in Secure Enclave / Keystore.\n20% mining bonus active.',
                style: TextStyle(color: ArkosTheme.textMuted, fontSize: 12),
              ),
            ] else ...[
              const SizedBox(height: 8),
              const Text(
                'Register this device to claim the 20% mobile mining bonus.',
                style: TextStyle(color: ArkosTheme.textMuted, fontSize: 13),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: onRegister,
                icon: const Icon(Icons.security),
                label: const Text('Register Device'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: ArkosTheme.accent,
                  side: const BorderSide(color: ArkosTheme.accent),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
