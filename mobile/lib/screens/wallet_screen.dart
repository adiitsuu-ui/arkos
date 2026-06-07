import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../services/rpc_client.dart';
import '../services/mining_service.dart';
import '../services/wallet_service.dart';
import '../theme.dart';

class WalletScreen extends StatefulWidget {
  const WalletScreen({super.key});

  @override
  State<WalletScreen> createState() => _WalletScreenState();
}

class _WalletScreenState extends State<WalletScreen> {
  WalletService? _walletSvc;
  String? _address;
  int? _balanceArkes;
  double? _balanceArkos;
  int? _blockCount;
  bool _loading = true;
  bool _refreshing = false;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final rpc = context.read<ArkosRpcClient>();
    _walletSvc = await WalletService.create(rpc);
    _address = await _walletSvc!.loadAddress();
    if (_address != null) await _loadBalance();
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _loadBalance() async {
    if (_address == null || _walletSvc == null) return;
    try {
      final result = await _walletSvc!.getBalance(_address!);
      final count = await _walletSvc!.getBlockCount();
      if (mounted) {
        setState(() {
          _balanceArkes = result.balanceArkes;
          _balanceArkos = result.balanceArkos;
          _blockCount = count;
        });
      }
    } catch (e) {
      // silently ignore if node is unreachable
    }
  }

  Future<void> _setAddress() async {
    final ctrl = TextEditingController(text: _address ?? '');
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: ArkosTheme.bgCard,
        title: const Text('Wallet Address'),
        content: TextField(
          controller: ctrl,
          decoration: const InputDecoration(
            hintText: 'Paste your ARKOS address (hex)',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (confirmed == true && ctrl.text.isNotEmpty) {
      await _walletSvc!.saveAddress(ctrl.text.trim());
      context.read<MiningService>().setWalletAddress(ctrl.text.trim());
      setState(() => _address = ctrl.text.trim());
      await _loadBalance();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(
        backgroundColor: ArkosTheme.bgDark,
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      backgroundColor: ArkosTheme.bgDark,
      appBar: AppBar(
        title: const Text('Wallet'),
        actions: [
          IconButton(
            icon: _refreshing
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.refresh),
            onPressed: () async {
              setState(() => _refreshing = true);
              await _loadBalance();
              setState(() => _refreshing = false);
            },
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _loadBalance,
        color: ArkosTheme.accent,
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // ── Balance card ──────────────────────────────────────────────
              _BalanceCard(
                address: _address,
                balanceArkes: _balanceArkes,
                balanceArkos: _balanceArkos,
                onSetAddress: _setAddress,
              ),
              const SizedBox(height: 16),

              // ── Network summary ───────────────────────────────────────────
              if (_blockCount != null)
                _InfoCard(rows: [
                  ('Chain height', '$_blockCount blocks'),
                  ('Network', 'Arkos Mainnet'),
                  (
                    'Total supply',
                    '31,415,926 ARKOS hard cap',
                  ),
                ]),
              const SizedBox(height: 16),

              // ── Address QR / copy ─────────────────────────────────────────
              if (_address != null) _AddressCard(address: _address!),
              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }
}

class _BalanceCard extends StatelessWidget {
  final String? address;
  final int? balanceArkes;
  final double? balanceArkos;
  final VoidCallback onSetAddress;

  const _BalanceCard({
    this.address,
    this.balanceArkes,
    this.balanceArkos,
    required this.onSetAddress,
  });

  @override
  Widget build(BuildContext context) {
    final arkosStr = balanceArkos != null
        ? NumberFormat('#,##0.########').format(balanceArkos)
        : '—';
    final arkesStr = balanceArkes != null
        ? NumberFormat.compact().format(balanceArkes) + ' arkes'
        : '';

    return Card(
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              ArkosTheme.accent.withOpacity(0.08),
              ArkosTheme.bgCard,
            ],
          ),
        ),
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Balance',
              style: TextStyle(color: ArkosTheme.textMuted, fontSize: 13),
            ),
            const SizedBox(height: 8),
            Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  arkosStr,
                  style: const TextStyle(
                    color: ArkosTheme.textPrimary,
                    fontWeight: FontWeight.w700,
                    fontSize: 32,
                  ),
                ),
                const SizedBox(width: 8),
                const Padding(
                  padding: EdgeInsets.only(bottom: 6),
                  child: Text(
                    'ARKOS',
                    style: TextStyle(
                      color: ArkosTheme.accent,
                      fontWeight: FontWeight.w700,
                      fontSize: 14,
                    ),
                  ),
                ),
              ],
            ),
            if (arkesStr.isNotEmpty) ...[
              const SizedBox(height: 2),
              Text(arkesStr,
                  style: const TextStyle(
                      color: ArkosTheme.textMuted, fontSize: 12)),
            ],
            const SizedBox(height: 20),
            if (address == null)
              OutlinedButton.icon(
                onPressed: onSetAddress,
                icon: const Icon(Icons.add),
                label: const Text('Set Wallet Address'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: ArkosTheme.accent,
                  side: const BorderSide(color: ArkosTheme.accent),
                ),
              )
            else
              GestureDetector(
                onTap: onSetAddress,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: ArkosTheme.bgCardBorder,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        '${address!.substring(0, 8)}…${address!.substring(address!.length - 6)}',
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          color: ArkosTheme.textMuted,
                          fontSize: 12,
                        ),
                      ),
                      const SizedBox(width: 6),
                      const Icon(Icons.edit, size: 12, color: ArkosTheme.textMuted),
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

class _InfoCard extends StatelessWidget {
  final List<(String, String)> rows;

  const _InfoCard({required this.rows});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: rows
              .map((r) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(r.$1,
                            style: Theme.of(context).textTheme.bodySmall),
                        Text(r.$2,
                            style: const TextStyle(
                              color: ArkosTheme.textPrimary,
                              fontWeight: FontWeight.w500,
                              fontSize: 13,
                            )),
                      ],
                    ),
                  ))
              .toList(),
        ),
      ),
    );
  }
}

class _AddressCard extends StatelessWidget {
  final String address;

  const _AddressCard({required this.address});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Receive Address',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: ArkosTheme.bgDark,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: ArkosTheme.bgCardBorder),
              ),
              child: Text(
                address,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11,
                  color: ArkosTheme.textMuted,
                ),
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: address));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Address copied to clipboard'),
                    behavior: SnackBarBehavior.floating,
                    duration: Duration(seconds: 2),
                  ),
                );
              },
              icon: const Icon(Icons.copy, size: 16),
              label: const Text('Copy Address'),
              style: OutlinedButton.styleFrom(
                foregroundColor: ArkosTheme.textMuted,
                side: const BorderSide(color: ArkosTheme.bgCardBorder),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
