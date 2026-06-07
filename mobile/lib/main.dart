import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'services/rpc_client.dart';
import 'services/mining_service.dart';
import 'services/device_service.dart';
import 'services/wallet_service.dart';
import 'screens/setup_screen.dart';
import 'screens/main_shell.dart';
import 'theme.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ArkosApp());
}

class ArkosApp extends StatelessWidget {
  const ArkosApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        // The RPC client is re-created when the user changes node URL in settings.
        ChangeNotifierProvider<NodeConfig>(create: (_) => NodeConfig()),
        ChangeNotifierProxyProvider<NodeConfig, ArkosRpcClient>(
          create: (ctx) => ArkosRpcClient(
            baseUrl: ctx.read<NodeConfig>().nodeUrl,
            authToken: ctx.read<NodeConfig>().rpcToken,
          ),
          update: (ctx, config, prev) =>
              ArkosRpcClient(baseUrl: config.nodeUrl, authToken: config.rpcToken),
        ),
        ChangeNotifierProxyProvider<ArkosRpcClient, MiningService>(
          create: (ctx) => MiningService(
            rpcClient: ctx.read<ArkosRpcClient>(),
            walletAddress: '',
          ),
          update: (ctx, rpc, prev) {
            final service = prev ??
                MiningService(
                  rpcClient: rpc,
                  walletAddress: '',
                );
            service.setRpcClient(rpc);
            return service;
          },
        ),
      ],
      child: MaterialApp(
        title: 'Arkos',
        debugShowCheckedModeBanner: false,
        theme: ArkosTheme.dark(),
        home: const AppRouter(),
      ),
    );
  }
}

/// Decides whether to show the setup wizard or the main app.
class AppRouter extends StatefulWidget {
  const AppRouter({super.key});

  @override
  State<AppRouter> createState() => _AppRouterState();
}

class _AppRouterState extends State<AppRouter> {
  bool? _hasWallet;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    final rpc = context.read<ArkosRpcClient>();
    final wallet = await WalletService.create(rpc);
    final addr = await wallet.loadAddress();
    if (mounted) setState(() => _hasWallet = addr != null);
  }

  @override
  Widget build(BuildContext context) {
    if (_hasWallet == null) {
      return const Scaffold(
        backgroundColor: ArkosTheme.bgDark,
        body: Center(child: CircularProgressIndicator()),
      );
    }
    return _hasWallet! ? const MainShell() : const SetupScreen();
  }
}

/// Holds the user-configured node URL; notifies listeners on change.
class NodeConfig extends ChangeNotifier {
  String _nodeUrl = 'http://192.168.1.100:8334';
  String? _rpcToken;

  String get nodeUrl => _nodeUrl;
  String? get rpcToken => _rpcToken;

  void setNodeUrl(String url) {
    _nodeUrl = url;
    notifyListeners();
  }

  void setRpcToken(String token) {
    _rpcToken = token.trim().isEmpty ? null : token.trim();
    notifyListeners();
  }
}
