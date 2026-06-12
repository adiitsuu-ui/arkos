use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

/// Per-/16-subnet bucket capacity: at most this many addresses per subnet.
pub const BUCKET_LIMIT: usize = 8;

/// Minimum number of outbound connections to maintain.
pub const MIN_OUTBOUND: usize = 8;

/// Number of "anchor" peers written to disk so a restarting node can
/// immediately reconnect to recently-seen peers rather than starting cold.
const ANCHOR_COUNT: usize = 4;

/// Eclipse-resistant peer address store.
///
/// Addresses are bucketed by IPv4 /16 (or the high 16 bits of IPv6) so a
/// single subnet can fill at most `BUCKET_LIMIT` slots.  Inbound and outbound
/// connections are tracked separately to enforce `MIN_OUTBOUND` diversity.
pub struct PeerStore {
    buckets: HashMap<[u8; 2], HashSet<String>>,
    outbound: HashSet<String>,
    inbound: HashSet<String>,
}

impl PeerStore {
    pub fn new() -> Self {
        PeerStore {
            buckets: HashMap::new(),
            outbound: HashSet::new(),
            inbound: HashSet::new(),
        }
    }

    fn subnet(addr: &str) -> [u8; 2] {
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            match sa.ip() {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    [o[0], o[1]]
                }
                std::net::IpAddr::V6(v6) => {
                    // Use first 16-bit segment as the bucket key.
                    let b = v6.segments()[0].to_be_bytes();
                    [b[0], b[1]]
                }
            }
        } else {
            [0, 0]
        }
    }

    /// Add an address to the known set.  Returns false if the /16 bucket is
    /// full or the address was already present.
    pub fn add_known(&mut self, addr: &str) -> bool {
        let key = Self::subnet(addr);
        let bucket = self.buckets.entry(key).or_default();
        if bucket.len() >= BUCKET_LIMIT {
            return false;
        }
        bucket.insert(addr.to_string())
    }

    pub fn remove_known(&mut self, addr: &str) {
        let key = Self::subnet(addr);
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.remove(addr);
        }
    }

    pub fn contains_known(&self, addr: &str) -> bool {
        let key = Self::subnet(addr);
        self.buckets.get(&key).map_or(false, |b| b.contains(addr))
    }

    pub fn known_count(&self) -> usize {
        self.buckets.values().map(|b| b.len()).sum()
    }

    pub fn all_known(&self) -> Vec<String> {
        self.buckets.values().flatten().cloned().collect()
    }

    /// Pick a random known address that is not currently connected.
    /// Used by the feeler task to probe liveness of idle known peers.
    pub fn random_unconnected(&self) -> Option<String> {
        use rand::seq::SliceRandom;
        let connected: HashSet<&str> = self
            .outbound
            .iter()
            .chain(self.inbound.iter())
            .map(|s| s.as_str())
            .collect();
        let candidates: Vec<String> = self
            .all_known()
            .into_iter()
            .filter(|a| !connected.contains(a.as_str()))
            .collect();
        candidates.choose(&mut rand::thread_rng()).cloned()
    }

    /// Known addresses that are not currently connected.
    /// Used by the outbound-maintenance task to find dial targets.
    pub fn outbound_candidates(&self) -> Vec<String> {
        let connected: HashSet<&str> = self
            .outbound
            .iter()
            .chain(self.inbound.iter())
            .map(|s| s.as_str())
            .collect();
        self.all_known()
            .into_iter()
            .filter(|a| !connected.contains(a.as_str()))
            .collect()
    }

    pub fn mark_outbound(&mut self, addr: &str) {
        self.outbound.insert(addr.to_string());
    }

    pub fn unmark_outbound(&mut self, addr: &str) {
        self.outbound.remove(addr);
    }

    pub fn mark_inbound(&mut self, addr: &str) {
        self.inbound.insert(addr.to_string());
    }

    pub fn unmark_inbound(&mut self, addr: &str) {
        self.inbound.remove(addr);
    }

    pub fn outbound_count(&self) -> usize {
        self.outbound.len()
    }

    pub fn needs_outbound(&self) -> bool {
        self.outbound.len() < MIN_OUTBOUND
    }

    /// Write the first `ANCHOR_COUNT` outbound peers to disk so they can be
    /// dialed on the next startup without waiting for peer discovery.
    pub fn save_anchors(&self, path: &Path) -> std::io::Result<()> {
        let content: String = self
            .outbound
            .iter()
            .take(ANCHOR_COUNT)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, content)
    }

    /// Load anchor addresses written by a previous run.
    pub fn load_anchors(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limit_enforced() {
        let mut store = PeerStore::new();
        // All addresses in the same /16 (192.168.x.x)
        for i in 0..BUCKET_LIMIT {
            assert!(store.add_known(&format!("192.168.{}.1:8333", i)));
        }
        // The (BUCKET_LIMIT+1)th address in the same /16 must be rejected
        assert!(!store.add_known(&format!("192.168.{}.1:8333", BUCKET_LIMIT)));
        assert_eq!(store.known_count(), BUCKET_LIMIT);
    }

    #[test]
    fn different_subnets_not_blocked() {
        let mut store = PeerStore::new();
        for i in 0..(BUCKET_LIMIT + 2) as u8 {
            // Each in a different /16
            assert!(store.add_known(&format!("{}.0.0.1:8333", i + 1)));
        }
        assert_eq!(store.known_count(), BUCKET_LIMIT + 2);
    }

    #[test]
    fn needs_outbound_true_when_below_min() {
        let store = PeerStore::new();
        assert!(store.needs_outbound());
    }

    #[test]
    fn anchor_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anchors.txt");
        let mut store = PeerStore::new();
        store.add_known("1.2.3.4:8333");
        store.mark_outbound("1.2.3.4:8333");
        store.save_anchors(&path).unwrap();
        let loaded = PeerStore::load_anchors(&path);
        assert_eq!(loaded, vec!["1.2.3.4:8333"]);
    }
}
