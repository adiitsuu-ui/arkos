//! Rate limiter — per-peer limits on messages, blocks, and transactions.
//! Prevents denial-of-service attacks and spam.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    windows: HashMap<String, Vec<Instant>>,
    max_per_window: usize,
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a rate limiter: at most `max` events per `window_secs` seconds per peer
    pub fn new(max_per_window: usize, window_secs: u64) -> Self {
        RateLimiter {
            windows: HashMap::new(),
            max_per_window,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Check if a peer is allowed to perform an action. Returns true if allowed.
    pub fn check(&mut self, peer_id: &str) -> bool {
        let now = Instant::now();
        let entries = self.windows.entry(peer_id.to_string()).or_default();

        // Remove expired entries
        entries.retain(|t| now.duration_since(*t) < self.window_duration);

        if entries.len() >= self.max_per_window {
            false // rate limited
        } else {
            entries.push(now);
            true
        }
    }

    /// Ban a peer by filling their window
    pub fn ban(&mut self, peer_id: &str) {
        let entries = self.windows.entry(peer_id.to_string()).or_default();
        entries.clear();
        let now = Instant::now();
        for _ in 0..self.max_per_window * 10 {
            entries.push(now);
        }
    }
}

/// Composite rate limiter for different message types
pub struct NodeRateLimiter {
    pub messages: RateLimiter,     // general messages: 100/min
    pub blocks: RateLimiter,       // block submissions: 10/min
    pub transactions: RateLimiter, // tx submissions: 50/min
    pub connections: RateLimiter,  // new connections: 5/min
    /// GetBlocks responses: each response can carry up to 500 block hashes.
    /// Without a dedicated limit a peer could exhaust our outbound bandwidth by
    /// sending GetBlocks at the general message rate (100/min × 500 blocks = 50 k
    /// block announcements per minute per peer).  10 responses/min caps that at
    /// 5,000 — still enough for a syncing peer, but not a DoS amplifier.
    pub getblocks: RateLimiter,
}

impl NodeRateLimiter {
    pub fn new() -> Self {
        NodeRateLimiter {
            messages: RateLimiter::new(100, 60),
            blocks: RateLimiter::new(10, 60),
            transactions: RateLimiter::new(50, 60),
            connections: RateLimiter::new(5, 60),
            getblocks: RateLimiter::new(10, 60),
        }
    }
}
