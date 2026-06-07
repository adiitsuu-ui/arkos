import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/mining_service.dart';
import '../services/rpc_client.dart';
import '../services/wallet_service.dart';
import '../theme.dart';
import 'main_shell.dart';

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _addressCtrl = TextEditingController();
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _addressCtrl.dispose();
    super.dispose();
  }

  Future<void> _continue() async {
    final address = _addressCtrl.text.trim();
    if (!_isHexAddress(address)) {
      setState(() => _error = 'Enter a valid 40-character Arkos address.');
      return;
    }

    setState(() {
      _saving = true;
      _error = null;
    });

    try {
      final wallet = await WalletService.create(context.read<ArkosRpcClient>());
      await wallet.saveAddress(address);
      context.read<MiningService>().setWalletAddress(address);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const MainShell()),
      );
    } catch (e) {
      if (mounted) setState(() => _error = 'Could not save wallet address: $e');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  bool _isHexAddress(String value) {
    final hex = RegExp(r'^[0-9a-fA-F]{40}$');
    return hex.hasMatch(value);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: ArkosTheme.bgDark,
      appBar: AppBar(title: const Text('Arkos')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            const SizedBox(height: 24),
            Text('Wallet setup', style: Theme.of(context).textTheme.headlineLarge),
            const SizedBox(height: 8),
            const Text(
              'Enter the Arkos address that should receive mobile mining rewards.',
              style: TextStyle(color: ArkosTheme.textMuted, height: 1.4),
            ),
            const SizedBox(height: 24),
            TextField(
              controller: _addressCtrl,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                hintText: '40-character wallet address',
                prefixIcon: const Icon(Icons.account_balance_wallet_outlined),
                errorText: _error,
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _saving ? null : _continue,
              icon: _saving
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.arrow_forward),
              label: const Text('Continue'),
            ),
          ],
        ),
      ),
    );
  }
}
