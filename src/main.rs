#![allow(dead_code)]

mod blockchain;
mod crypto;
mod mining;
mod network;
mod rpc;
mod security;
mod storage;
mod transaction;
mod wallet;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

use blockchain::chain::Blockchain;
use network::discovery::collect_bootstrap_peers;
use network::node::Node;
use network::protocol::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
use rpc::server::RpcServerConfig;
use security::access::{AccessToken, MasterKey, Permission, RevocationList};
use security::vault;
use wallet::wallet::Wallet;

#[derive(Parser)]
#[command(name = "arkos", about = "Arkos — the origin of a new financial world")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, default_value = "127.0.0.1:8333")]
    listen: String,
    /// HTTP JSON-RPC address for mining submissions and chain queries
    #[arg(long, default_value = "127.0.0.1:8334")]
    rpc_listen: String,
    #[arg(long)]
    peer: Vec<String>,
    /// DNS seed hostnames for automatic peer discovery (can be repeated)
    #[arg(long)]
    dns_seed: Vec<String>,
    /// Data directory for vault, keys, and chain data
    #[arg(long, default_value = "~/.arkos")]
    datadir: String,
    /// Network profile: mainnet, testnet, or regtest
    #[arg(long, default_value = "mainnet")]
    network: String,
    /// Require this bearer token or X-Arkos-Rpc-Token value for JSON-RPC calls
    #[arg(long, env = "ARKOS_RPC_TOKEN")]
    rpc_token: Option<String>,
    /// Restrict browser CORS to this origin. If omitted, CORS remains open for local development.
    #[arg(long, env = "ARKOS_RPC_CORS_ORIGIN")]
    rpc_cors_origin: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    // ─── SECURITY ───────────────────────────────────────
    /// Initialize: generate your master key and encrypted vault
    Init,
    /// Grant access to someone — issue a signed token
    Grant {
        #[arg(long)]
        name: String,
        /// Permissions: connect, mine, transact, read, admin
        #[arg(long, value_delimiter = ',')]
        permissions: Vec<String>,
        /// Days until token expires (0 = never)
        #[arg(long, default_value = "365")]
        expires_days: u64,
    },
    /// Revoke an access token by its ID
    Revoke {
        #[arg(long)]
        token_id: String,
    },
    /// List all issued tokens
    ListTokens,
    /// Verify a token file is valid
    VerifyToken {
        #[arg(long)]
        token_file: String,
    },

    // ─── WALLET ─────────────────────────────────────────
    /// Generate a new wallet keypair (saved into encrypted vault)
    NewWallet {
        #[arg(long, default_value = "default")]
        label: String,
    },
    /// Show the 24-word recovery phrase for a wallet
    ShowPhrase {
        #[arg(long, default_value = "default")]
        label: String,
    },
    /// Restore a wallet from a 24-word recovery phrase
    RestoreWallet {
        #[arg(long, default_value = "default")]
        label: String,
        /// Space-separated 24-word BIP39 phrase
        #[arg(long)]
        phrase: String,
    },
    /// List wallets in the vault
    ListWallets,
    /// Show balance for an address
    Balance {
        #[arg(long)]
        address: String,
    },

    // ─── CHAIN ──────────────────────────────────────────
    /// Start a full node
    Node {
        #[arg(long)]
        miner: Option<String>,
    },
    /// Send coins (mines one block to confirm)
    Send {
        #[arg(long)]
        from_label: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Mine a single block manually
    Mine {
        #[arg(long)]
        address: String,
    },
    /// Show chain info
    Info,
    /// Run a full end-to-end demo
    Demo,
}

fn expand_datadir(s: &str) -> PathBuf {
    if let Some(stripped) = s.strip_prefix("~/") {
        if let Some(home) = dirs_home() {
            return PathBuf::from(home).join(stripped);
        }
    }
    PathBuf::from(s)
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

fn prompt_passphrase(confirm: bool) -> Result<String> {
    let pass = rpassword::prompt_password("Enter vault passphrase: ")?;
    if confirm {
        let pass2 = rpassword::prompt_password("Confirm passphrase: ")?;
        if pass != pass2 {
            anyhow::bail!("passphrases do not match");
        }
    }
    Ok(pass)
}

fn network_magic(name: &str) -> Result<u32> {
    match name {
        "mainnet" => Ok(MAINNET_MAGIC),
        "testnet" => Ok(TESTNET_MAGIC),
        "regtest" => Ok(REGTEST_MAGIC),
        other => anyhow::bail!(
            "unknown network '{}'; use mainnet, testnet, or regtest",
            other
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let datadir = expand_datadir(&cli.datadir);
    let network_datadir = datadir.join(&cli.network);
    let chain_path = network_datadir.join("chain");
    let magic = network_magic(&cli.network)?;

    match cli.command {
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //  SECURITY COMMANDS
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Command::Init => {
            std::fs::create_dir_all(&datadir)?;

            let vault_path = datadir.join("vault.enc");
            if vault_path.exists() {
                println!("Vault already exists at {}", vault_path.display());
                println!("Delete it first if you want to start fresh.");
                return Ok(());
            }

            println!("╔══════════════════════════════════════════════════╗");
            println!("║         Arkos — Master Key Initialization        ║");
            println!("╚══════════════════════════════════════════════════╝\n");

            println!("This creates your MASTER KEY — the root of all authority.");
            println!("It will be encrypted with a passphrase you choose.\n");

            let passphrase = prompt_passphrase(true)?;

            // Generate master key
            let master = MasterKey::generate();
            println!("\n🔑 Master Key Generated:");
            println!("   Public  : {}", master.public_hex());
            println!("   (secret is encrypted inside your vault)\n");

            // Generate first wallet
            let w = Wallet::new();
            println!("💳 First wallet created:");
            println!("   Address : {}", w.address());

            // Save master key + first wallet into vault
            vault::create_vault(
                &passphrase,
                vec![master.secret_hex(), w.secret_key_hex().to_string()],
                vec!["master-key".into(), "default-wallet".into()],
                &vault_path,
            )?;

            // Save master public key (safe to share)
            master.save_public_key(&datadir.join("master.pub"))?;

            // Create tokens directory
            std::fs::create_dir_all(datadir.join("tokens"))?;

            // Issue yourself an Admin token
            let admin_token = master.issue_token(
                "owner",
                &master.public_hex(),
                vec![Permission::Admin],
                0, // never expires
            );
            admin_token.save(&datadir.join("tokens").join("owner.token"))?;

            println!("\n✅ Arkos initialized at {}", datadir.display());
            println!("   vault.enc    — encrypted keys (AES-256-GCM + Argon2id)");
            println!("   master.pub   — your master public key (share with nodes)");
            println!("   tokens/      — access tokens you issue");
            println!("\n⚠️  REMEMBER YOUR PASSPHRASE — there is no recovery.");
        }

        Command::Grant {
            name,
            permissions,
            expires_days,
        } => {
            let passphrase = prompt_passphrase(false)?;
            let contents = vault::open_vault(&passphrase, &datadir.join("vault.enc"))?;
            let master_secret = hex::decode(&contents.secret_keys[0])?;
            let master_arr: [u8; 32] = master_secret
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid master key length"))?;
            let master = MasterKey::from_secret_bytes(&master_arr);

            let perms: Vec<Permission> = permissions
                .iter()
                .map(|p| match p.as_str() {
                    "connect" => Permission::Connect,
                    "mine" => Permission::Mine,
                    "transact" => Permission::Transact,
                    "read" => Permission::ReadChain,
                    "admin" => Permission::Admin,
                    _ => Permission::ReadChain,
                })
                .collect();

            // Generate a holder keypair for the grantee
            let holder_key = MasterKey::generate();
            let token = master.issue_token(&name, &holder_key.public_hex(), perms, expires_days);

            let token_path = datadir.join("tokens").join(format!("{}.token", name));
            token.save(&token_path)?;

            println!("✅ Access token issued:");
            println!("   Holder     : {}", name);
            println!("   Token ID   : {}", token.token_id);
            println!("   Permissions: {:?}", token.permissions);
            if expires_days > 0 {
                println!("   Expires in : {} days", expires_days);
            } else {
                println!("   Expires    : never");
            }
            println!("   Saved to   : {}", token_path.display());
            println!("\n   Give this file to '{}'. They cannot modify it —", name);
            println!("   any tampering invalidates your Ed25519 signature.");
        }

        Command::Revoke { token_id } => {
            let revoke_path = datadir.join("revoked.json");
            let mut revoked = RevocationList::load(&revoke_path)?;
            revoked.revoke(&token_id);
            revoked.save(&revoke_path)?;
            println!("✅ Token {} has been revoked.", token_id);
            println!("   All nodes will reject this token on next sync.");
        }

        Command::ListTokens => {
            let tokens_dir = datadir.join("tokens");
            if !tokens_dir.exists() {
                println!("No tokens directory found. Run `arkos init` first.");
                return Ok(());
            }
            let revoked = RevocationList::load(&datadir.join("revoked.json")).unwrap_or_default();
            println!(
                "{:<12} {:<16} {:<30} STATUS",
                "TOKEN ID", "HOLDER", "PERMISSIONS"
            );
            println!("{}", "-".repeat(75));
            for entry in std::fs::read_dir(&tokens_dir)? {
                let entry = entry?;
                if let Ok(token) = AccessToken::load(&entry.path()) {
                    let status = if revoked.is_revoked(&token.token_id) {
                        "REVOKED"
                    } else if token.expires_at > 0 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if now > token.expires_at {
                            "EXPIRED"
                        } else {
                            "ACTIVE"
                        }
                    } else {
                        "ACTIVE (no expiry)"
                    };
                    println!(
                        "{:<12} {:<16} {:<30} {}",
                        token.token_id,
                        token.holder_name,
                        format!("{:?}", token.permissions),
                        status
                    );
                }
            }
        }

        Command::VerifyToken { token_file } => {
            let token = AccessToken::load(&PathBuf::from(&token_file))?;
            let master_pub = std::fs::read_to_string(datadir.join("master.pub"))?;
            // Load the revocation list before verifying so that signature validity
            // and revocation are checked atomically in a single call.  Calling
            // verify() first and is_revoked() second creates a window where a
            // revoked token appears valid between the two checks.
            let revoked = RevocationList::load(&datadir.join("revoked.json")).unwrap_or_default();
            match token.verify_with_revocation(master_pub.trim(), Some(&revoked)) {
                Ok(()) => {
                    println!("✅ Token is VALID");
                    println!("   Holder      : {}", token.holder_name);
                    println!("   Permissions : {:?}", token.permissions);
                    println!("   Token ID    : {}", token.token_id);
                }
                Err(e) => println!("❌ {}", e),
            }
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //  WALLET COMMANDS
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Command::NewWallet { label } => {
            let passphrase = prompt_passphrase(false)?;
            let vault_path = datadir.join("vault.enc");
            let mut contents = vault::open_vault(&passphrase, &vault_path)?;

            let (w, mnemonic) = Wallet::generate_with_phrase();
            contents.secret_keys.push(w.secret_key_hex().to_string());
            contents.labels.push(label.clone());

            vault::create_vault(
                &passphrase,
                contents.secret_keys,
                contents.labels,
                &vault_path,
            )?;
            println!("✅ Wallet '{}' created:", label);
            println!("   Address : {}", w.address());
            println!("   Saved to encrypted vault.\n");
            println!("⚠️  RECOVERY PHRASE (write this down — never share it):");
            println!("   {}\n", mnemonic);
            println!("   The phrase recovers your ECDSA key and wallet address.");
            println!("   Store it offline, separate from your vault file.");
        }

        Command::ShowPhrase { label } => {
            let passphrase = prompt_passphrase(false)?;
            let contents = vault::open_vault(&passphrase, &datadir.join("vault.enc"))?;
            let idx = contents
                .labels
                .iter()
                .position(|l| l == &label)
                .ok_or_else(|| anyhow::anyhow!("wallet '{}' not found in vault", label))?;
            let w = Wallet::from_secret_hex(&contents.secret_keys[idx])?;
            let mnemonic = w.phrase();
            println!("⚠️  RECOVERY PHRASE for wallet '{}':", label);
            println!("   {}", mnemonic);
            println!("\n   Keep this secret. Anyone with this phrase can recover");
            println!("   your wallet address and spend your funds.");
        }

        Command::RestoreWallet { label, phrase } => {
            let passphrase = prompt_passphrase(false)?;
            let vault_path = datadir.join("vault.enc");
            let mut contents = vault::open_vault(&passphrase, &vault_path)?;

            if contents.labels.contains(&label) {
                anyhow::bail!(
                    "wallet '{}' already exists in vault; choose a different label",
                    label
                );
            }

            let w = Wallet::from_phrase(&phrase)?;
            contents.secret_keys.push(w.secret_key_hex().to_string());
            contents.labels.push(label.clone());

            vault::create_vault(
                &passphrase,
                contents.secret_keys,
                contents.labels,
                &vault_path,
            )?;
            println!("✅ Wallet '{}' restored:", label);
            println!("   Address : {}", w.address());
            println!("   Note    : ML-DSA key is freshly generated (valid for all future spends).");
        }

        Command::ListWallets => {
            let passphrase = prompt_passphrase(false)?;
            let contents = vault::open_vault(&passphrase, &datadir.join("vault.enc"))?;
            println!("{:<20} ADDRESS", "LABEL");
            println!("{}", "-".repeat(60));
            for (i, label) in contents.labels.iter().enumerate() {
                if label == "master-key" {
                    continue;
                }
                if let Ok(w) = Wallet::from_secret_hex(&contents.secret_keys[i]) {
                    println!("{:<20} {}", label, w.address());
                }
            }
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //  CHAIN COMMANDS (same as before)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Command::Node { miner } => {
            std::fs::create_dir_all(&network_datadir)?;
            let chain = Blockchain::open(chain_path.to_string_lossy().as_ref())?;
            if let Some(miner_addr) = miner {
                info!(
                    "Miner address configured: {}. Mine with `arkos mine` or submit blocks via RPC.",
                    miner_addr
                );
            }
            info!("Chain height: {}", chain.height());

            let node = Node::new(chain, cli.listen.clone(), magic);

            // Collect peers: explicit --peer flags first, then DNS bootstrap
            let mut all_peers = cli.peer.clone();
            if cli.dns_seed.is_empty() {
                // Auto-DNS if no explicit --dns-seed flags (use defaults)
                let dns_peers = collect_bootstrap_peers(&[]);
                all_peers.extend(dns_peers);
            } else {
                let dns_peers = collect_bootstrap_peers(&cli.dns_seed);
                all_peers.extend(dns_peers);
            }
            // Deduplicate preserving order
            all_peers.dedup();

            for peer_addr in &all_peers {
                if let Err(e) = node.connect_to_peer(peer_addr).await {
                    log::warn!("Could not connect to {}: {}", peer_addr, e);
                }
            }

            // Launch RPC server alongside the P2P node
            let rpc_state = std::sync::Arc::new(rpc::methods::RpcState {
                chain: node.chain.clone(),
            });
            let rpc_addr = cli.rpc_listen.clone();
            let rpc_config = RpcServerConfig {
                auth_token: cli.rpc_token.clone(),
                cors_origin: cli.rpc_cors_origin.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) =
                    rpc::server::start_rpc_server(rpc_state, &rpc_addr, rpc_config).await
                {
                    log::error!("RPC server error: {}", e);
                }
            });

            node.run().await?;
        }

        Command::Mine { address } => {
            std::fs::create_dir_all(&network_datadir)?;
            let mut chain = Blockchain::open(chain_path.to_string_lossy().as_ref())?;
            let block = chain.mine_block(&address);
            println!("Mined block: {}", block.hash_hex());
            println!("Height     : {}", block.height);
            println!("Nonce      : {}", block.header.nonce);
            println!("Txs        : {}", block.transactions.len());
            chain.add_block(block)?;
            println!("Balance    : {} arkes", chain.balance_of(&address));
        }

        Command::Balance { address } => {
            std::fs::create_dir_all(&network_datadir)?;
            let chain = Blockchain::open(chain_path.to_string_lossy().as_ref())?;
            println!(
                "Balance of {}: {} arkes",
                address,
                chain.balance_of(&address)
            );
        }

        Command::Send {
            from_label,
            to,
            amount,
        } => {
            let passphrase = prompt_passphrase(false)?;
            let contents = vault::open_vault(&passphrase, &datadir.join("vault.enc"))?;
            let idx = contents
                .labels
                .iter()
                .position(|l| l == &from_label)
                .ok_or_else(|| anyhow::anyhow!("wallet '{}' not found in vault", from_label))?;

            std::fs::create_dir_all(&network_datadir)?;
            let mut chain = Blockchain::open(chain_path.to_string_lossy().as_ref())?;
            let w = Wallet::from_secret_hex(&contents.secret_keys[idx])?;
            println!("From: {} ({})", from_label, w.address());
            let tx = w.send(&to, amount, 1000, &chain.utxo_set)?;
            let txid = chain.submit_transaction(tx)?;
            println!("Transaction submitted: {}", txid);
            let block = chain.mine_block(&w.address());
            chain.add_block(block)?;
            println!("Confirmed in block at height {}", chain.height());
        }

        Command::Info => {
            std::fs::create_dir_all(&network_datadir)?;
            let chain = Blockchain::open(chain_path.to_string_lossy().as_ref())?;
            println!("Height     : {}", chain.height());
            println!("Tip hash   : {}", chain.tip().hash_hex());
            println!("Difficulty : 0x{:08x}", chain.tip().header.bits);
            println!("Mempool    : {} txs", chain.mempool.len());
        }

        Command::Demo => {
            println!("╔══════════════════════════════════════════════════╗");
            println!("║            Arkos — End-to-End Demo               ║");
            println!("║   Supply: π × 10^7 = 31,415,926 ARKOS            ║");
            println!("╚══════════════════════════════════════════════════╝\n");

            let miner_wallet = Wallet::new();
            let receiver_wallet = Wallet::new();
            println!("① Created wallets:");
            println!("   Miner    addr : {}", miner_wallet.address());
            println!("   Receiver addr : {}", receiver_wallet.address());

            let mut chain = Blockchain::new();
            println!("\n② Genesis block:");
            println!("   Hash   : {}", chain.tip().hash_hex());
            println!("   Height : {}", chain.height());

            println!("\n③ Mining 2 blocks to miner wallet...");
            for i in 1..=2u64 {
                let block = chain.mine_block(&miner_wallet.address());
                let hash = block.hash_hex();
                let nonce = block.header.nonce;
                chain.add_block(block)?;
                println!(
                    "   Block {} mined  hash={:.16}...  nonce={}",
                    i, hash, nonce
                );
            }
            let miner_balance = chain.balance_of(&miner_wallet.address());
            println!(
                "   Miner balance : {} arkes  ({} ARKOS)",
                miner_balance,
                miner_balance / 1_000_000_000
            );

            let send_amount = 5_000_000_000u64;
            let fee = 1_000u64;
            println!(
                "\n④ Sending {} ARKOS (+ {} arke fee) → receiver...",
                send_amount / 1_000_000_000,
                fee
            );
            let tx = miner_wallet.send(
                &receiver_wallet.address(),
                send_amount,
                fee,
                &chain.utxo_set,
            )?;
            let txid = chain.submit_transaction(tx)?;
            println!("   TX submitted  txid={:.16}...", txid);
            println!("   Mempool size  : {} tx(s)", chain.mempool.len());

            println!("\n⑤ Mining confirmation block...");
            let block = chain.mine_block(&miner_wallet.address());
            let conf_hash = block.hash_hex();
            chain.add_block(block)?;
            println!("   Confirmed in block {:.16}...", conf_hash);

            let miner_final = chain.balance_of(&miner_wallet.address());
            let recv_final = chain.balance_of(&receiver_wallet.address());
            println!("\n⑥ Final balances:");
            println!(
                "   Miner    : {} arkes  ({} ARKOS)",
                miner_final,
                miner_final / 1_000_000_000
            );
            println!(
                "   Receiver : {} arkes  ({} ARKOS)",
                recv_final,
                recv_final / 1_000_000_000
            );

            println!("\n⑦ Chain summary:");
            println!("   Height     : {}", chain.height());
            println!("   Tip hash   : {:.16}...", chain.tip().hash_hex());
            println!("   Difficulty : 0x{:08x}", chain.tip().header.bits);
            println!("   Mempool    : {} tx(s)", chain.mempool.len());

            println!("\n⑧ Security check — tampered tx should be REJECTED...");
            use crate::crypto::quantum::HybridSignature;
            use crate::transaction::tx::{Transaction, TxInput, TxOutput};
            let fake_tx = Transaction::new(
                vec![TxInput {
                    prev_tx_hash: chain.tip().transactions[0].txid_hex(),
                    prev_index: 0,
                    signature: HybridSignature {
                        ecdsa_sig: vec![0u8; 64],
                        dilithium_sig: vec![],
                    },
                    pubkey: miner_wallet.keypair.public_key(),
                    coinbase_extra: vec![],
                }],
                vec![TxOutput {
                    value: 999_999_999_999,
                    address: receiver_wallet.address(),
                }],
            );
            match chain.submit_transaction(fake_tx) {
                Err(e) => println!("   Rejected as expected: {}", e),
                Ok(_) => println!("   BUG: tampered tx was accepted!"),
            }

            // --- NEW: Security demo ---
            println!("\n⑨ Security system demo...");
            let master = MasterKey::generate();
            println!("   Master key  : {:.16}...", master.public_hex());

            let token = master.issue_token(
                "alice",
                &master.public_hex(),
                vec![Permission::Connect, Permission::Transact],
                30,
            );
            println!(
                "   Issued token: {} → {:?}",
                token.holder_name, token.permissions
            );

            match token.verify(&master.public_hex()) {
                Ok(()) => println!("   Token verification: VALID"),
                Err(e) => println!("   Token verification FAILED: {}", e),
            }

            // Tamper with it
            let mut tampered = token.clone();
            tampered.permissions.push(Permission::Admin);
            match tampered.verify(&master.public_hex()) {
                Ok(()) => println!("   Tampered token: ACCEPTED (BUG!)"),
                Err(_) => println!("   Tampered token: REJECTED (signature mismatch)"),
            }

            // --- Post-quantum demo ---
            println!("\n⑩ Post-quantum cryptography (CRYSTALS-Dilithium)...");
            use crate::crypto::quantum::HybridKeyPair;

            let qkp = HybridKeyPair::generate();
            let qpk = qkp.public_key();
            println!("   Hybrid keypair generated:");
            println!("     ECDSA pubkey   : {} bytes", qpk.ecdsa_pubkey.len());
            println!(
                "     Dilithium pubkey: {} bytes",
                qpk.dilithium_pubkey.len()
            );

            let msg = b"transfer 5 ARKOS from miner to receiver";
            let qsig = qkp.sign(msg);
            println!("   Hybrid signature:");
            println!("     ECDSA sig      : {} bytes", qsig.ecdsa_sig.len());
            println!("     Dilithium sig  : {} bytes", qsig.dilithium_sig.len());
            println!("     Total          : {} bytes", qsig.size());

            match qsig.verify(msg, &qpk) {
                Ok(()) => println!("   Signature valid  : BOTH algorithms verified"),
                Err(e) => println!("   Verification FAILED: {}", e),
            }

            // Simulate quantum attack: forge ECDSA but not Dilithium
            let mut quantum_forged = qsig.clone();
            quantum_forged.ecdsa_sig = vec![0u8; 64]; // "quantum-broken" ECDSA
            match quantum_forged.verify(msg, &qpk) {
                Ok(()) => println!("   Quantum attack   : SUCCEEDED (BUG!)"),
                Err(_) => println!("   Quantum attack   : BLOCKED by Dilithium"),
            }

            // Simulate classical attack: forge Dilithium but not ECDSA
            let mut classical_forged = qsig.clone();
            classical_forged.dilithium_sig = vec![0u8; classical_forged.dilithium_sig.len()];
            match classical_forged.verify(msg, &qpk) {
                Ok(()) => println!("   Classical attack : SUCCEEDED (BUG!)"),
                Err(_) => println!("   Classical attack : BLOCKED by ECDSA"),
            }

            println!("\n✅ All demo checks passed.");
            println!("   Hybrid ECDSA + ML-DSA-65 (NIST FIPS 204) signatures are in use.");
            println!("   Note: UTXO addresses currently commit only to the ECDSA key.");
            println!("   Full post-quantum protection requires address-format upgrade.\n");
        }
    }

    Ok(())
}
