//! Automatic peer discovery: DNS seeds and hardcoded bootstrap peers.
//!
//! On startup, the node resolves DNS seed hostnames to get initial peers,
//! then falls back to the hardcoded bootstrap list if DNS fails.

use log::{info, warn};
use std::net::ToSocketAddrs;

/// Default P2P port.
const P2P_PORT: u16 = 8333;

/// Hardcoded testnet bootstrap peers — last-resort fallback if DNS is down.
/// Update these with real seed node IPs before mainnet launch.
pub const BOOTSTRAP_PEERS: &[&str] = &["seed.arkosquantum.com:8333", "seed2.arkosquantum.com:8333"];

/// Default DNS seeds for automatic peer discovery.
/// Each hostname should resolve to multiple A records (one per seed node).
pub const DEFAULT_DNS_SEEDS: &[&str] = &["seed.arkosquantum.com", "seed2.arkosquantum.com"];

/// Resolve a DNS seed hostname to a list of `ip:port` peer addresses.
///
/// Uses the system resolver (no extra dependencies).  Returns an empty
/// Vec and logs a warning if resolution fails — callers should fall back
/// to hardcoded peers.
pub fn resolve_dns_seed(host: &str) -> Vec<String> {
    let target = format!("{}:{}", host, P2P_PORT);
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let peers: Vec<String> = addrs.map(|a| a.to_string()).collect();
            if peers.is_empty() {
                warn!("DNS seed {} returned zero A records", host);
            } else {
                info!("DNS seed {} → {} peer(s)", host, peers.len());
            }
            peers
        }
        Err(e) => {
            warn!("DNS seed {} failed to resolve: {}", host, e);
            vec![]
        }
    }
}

/// Build a deduplicated peer list from DNS seeds plus the hardcoded fallback.
///
/// `extra_seeds`: additional hostnames from `--dns-seed` CLI flags.
pub fn collect_bootstrap_peers(extra_seeds: &[String]) -> Vec<String> {
    let mut peers: Vec<String> = Vec::new();

    let all_seeds: Vec<&str> = DEFAULT_DNS_SEEDS
        .iter()
        .copied()
        .chain(extra_seeds.iter().map(String::as_str))
        .collect();

    for seed in all_seeds {
        for addr in resolve_dns_seed(seed) {
            if !peers.contains(&addr) {
                peers.push(addr);
            }
        }
    }

    // Hardcoded fallback — ensures at least some peers are attempted even
    // when DNS is unavailable (split-horizon, captive portal, etc.).
    for &p in BOOTSTRAP_PEERS {
        let p = p.to_string();
        if !peers.contains(&p) {
            peers.push(p);
        }
    }

    peers
}
