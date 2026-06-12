//! ArkHash — Neural Proof of Work (NPoW)
//!
//! A proof-of-work function whose inner loop is a chain of INT8 fully-connected
//! (FC) layers — the universal primitive on every modern mobile and laptop NPU:
//!
//!   - Apple ANE (iPhone 8+, all M-series Macs): CoreML `InnerProduct` INT8
//!   - Qualcomm Hexagon (Snapdragon 855+):        NNAPI FULLY_CONNECTED INT8
//!   - MediaTek APU (Dimensity series):           NNAPI FULLY_CONNECTED INT8
//!   - Samsung Exynos NPU (Exynos 990+):          NNAPI FULLY_CONNECTED INT8
//!   - Google Tensor (Pixel 6+):                  NNAPI FULLY_CONNECTED INT8
//!   - Intel NPU (Meteor Lake / Lunar Lake):      OpenVINO INT8 FC
//!
//! # Algorithm
//!
//! ```text
//! seed   = SHA256(pow_bytes)                         -- 32 bytes from header + nonce
//! x₀     = expand_seed(seed)  →  [i8; D]            -- D=256 INT8 activations
//! for l in 0..L:                                     -- L=16 sequential layers
//!   y    = Wₗ · xₗ + bₗ                             -- INT8×INT8→INT32 dot product
//!   xₗ₊₁ = clamp(y >> Q_SHIFT, −127, 127)           -- scale back to INT8
//! result = SHA256(x_L as bytes)                      -- final one-way gate
//! valid  = result ≤ bits_to_target(bits)             -- standard PoW check
//! ```
//!
//! # Weight table
//!
//! Protocol weights are deterministically derived from `WEIGHT_SEED` using
//! SHA256 in counter mode.  They are computed once at startup and cached.
//! Total weight storage: L × D × D = 16 × 256 × 256 = 1,048,576 INT8 bytes (1 MB).
//! Every modern NPU has ≥ 4 MB on-chip SRAM; the full table fits without
//! reloading from DRAM during the inner mining loop.
//!
//! # NPU backend hook
//!
//! Mobile miners replace the `int8_fc_layer` inner loop with a CoreML /
//! NNAPI inference call on the pre-loaded weight table.  The seed expansion
//! (SHA256 of pow_bytes) and the final output hash (SHA256 of activations)
//! remain on CPU — they are a negligible fraction of total compute.
//!
//! The CPU reference implementation below is used by every full node for
//! block validation, regardless of hardware.
//!
//! # Changing this algorithm is a hard fork.
//! Any change to D, L, Q_SHIFT, or WEIGHT_SEED produces a different hash
//! for every block header and must be coordinated with a flag-day block
//! height activation, the same way as any consensus rule change.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// ─── Protocol constants ───────────────────────────────────────────────────────

/// Hidden dimension: neurons per layer.
/// 256 → 1 MB total weight table, fast verification, strong per-layer diffusion.
pub const D: usize = 256;

/// Number of sequential INT8 FC layers.
/// 16 layers × 256² ops = 2.1M INT8 MACs per nonce.
pub const L: usize = 16;

/// Right-shift applied after each INT32 accumulation to rescale to INT8.
/// Max accumulator without bias: D × 127 × 127 = 4,129,024 < i32::MAX.
/// >> 12 → max scaled value 1,008 → clamped to [−127, 127].
const Q_SHIFT: u32 = 12;

/// Protocol seed committing to the weight table.
/// Changing this string is a consensus-breaking hard fork.
pub const WEIGHT_SEED: &[u8] = b"ARKOS_NEUROPOW_V1";

// ─── Weight table ─────────────────────────────────────────────────────────────

struct Net {
    /// Flat weight storage. Index: l * D * D + row * D + col.
    w: Box<[i8]>,
    /// Flat bias storage. Index: l * D + i. Values clamped to [−64, 64].
    b: Box<[i16]>,
}

static NET: OnceLock<Net> = OnceLock::new();

/// Build the protocol weight table deterministically.
///
/// Uses SHA256 in counter mode: each 256-bit keystream block provides 32
/// weight bytes, so the full 1 MB table requires 32,768 SHA256 calls.
/// Runs once at node startup; subsequent calls hit the cache.
fn build_net() -> Net {
    let master: [u8; 32] = Sha256::digest(WEIGHT_SEED).into();

    let total_w = L * D * D;
    let total_b = L * D;

    let mut w = vec![0i8; total_w].into_boxed_slice();
    let mut b = vec![0i16; total_b].into_boxed_slice();

    // Weights: each 32-byte SHA256 block fills 32 weight entries.
    let chunks = total_w.div_ceil(32);
    for chunk in 0u32..chunks as u32 {
        let mut h = Sha256::new();
        h.update(master);
        h.update(b"W");
        h.update(chunk.to_le_bytes());
        let block: [u8; 32] = h.finalize().into();
        let start = chunk as usize * 32;
        let end = (start + 32).min(total_w);
        for (i, &byte) in block[..(end - start)].iter().enumerate() {
            // Map u8 → i8 symmetrically, skipping −128 for clean range.
            w[start + i] = (byte as i8).max(-127);
        }
    }

    // Biases: each 32-byte block gives 16 i16 values, clamped to [−64, 64].
    let bias_chunks = total_b.div_ceil(16);
    for chunk in 0u32..bias_chunks as u32 {
        let mut h = Sha256::new();
        h.update(master);
        h.update(b"B");
        h.update(chunk.to_le_bytes());
        let block: [u8; 32] = h.finalize().into();
        let start = chunk as usize * 16;
        let end = (start + 16).min(total_b);
        for (i, pair) in block.chunks_exact(2).take(end - start).enumerate() {
            let raw = i16::from_le_bytes([pair[0], pair[1]]);
            b[start + i] = raw.clamp(-64, 64);
        }
    }

    Net { w, b }
}

#[inline]
fn net() -> &'static Net {
    NET.get_or_init(build_net)
}

// ─── Core computation ─────────────────────────────────────────────────────────

/// Expand a 32-byte SHA256 seed to D INT8 activations using SHA256 counter mode.
fn expand_seed(seed: &[u8; 32]) -> [i8; D] {
    let chunks = D.div_ceil(32); // D=256 → 8 calls
    let mut out = [0i8; D];
    for c in 0u8..chunks as u8 {
        let mut h = Sha256::new();
        h.update(seed);
        h.update([c]);
        let block: [u8; 32] = h.finalize().into();
        let start = c as usize * 32;
        let end = (start + 32).min(D);
        for (i, &b) in block[..(end - start)].iter().enumerate() {
            out[start + i] = b as i8;
        }
    }
    out
}

/// Single INT8 FC layer: y = clamp( (W·x + b) >> Q_SHIFT, −127, 127 )
///
/// # NPU backend replacement point
///
/// On a mobile device, replace this function's inner loop with a CoreML /
/// NNAPI inference call.  The weight slice passed here corresponds exactly
/// to the `InnerProduct` / `FULLY_CONNECTED` weight matrix for layer `l`.
///
/// The per-layer weight slice starts at `l * D * D` in the flat `net.w` array.
#[inline]
fn int8_fc_layer(net: &Net, l: usize, x: &[i8; D]) -> [i8; D] {
    let w_base = l * D * D;
    let b_base = l * D;
    let mut out = [0i8; D];
    for (row, out_val) in out.iter_mut().enumerate() {
        let mut acc: i32 = net.b[b_base + row] as i32;
        let w_row = w_base + row * D;
        for (col, &x_val) in x.iter().enumerate() {
            acc += net.w[w_row + col] as i32 * x_val as i32;
        }
        *out_val = (acc >> Q_SHIFT).clamp(-127, 127) as i8;
    }
    out
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// ArkHash — Neural Proof of Work hash function.
///
/// Drop-in replacement for `hash256` in block header hashing.
///
/// `input` is the serialised block header as produced by `BlockHeader::pow_bytes()`.
/// The nonce is already embedded in those bytes; changing the nonce changes the
/// SHA256 seed and therefore every layer's output.
///
/// Returns a 32-byte hash.  A block is valid when this value ≤ `bits_to_target(bits)`.
pub fn arkhash(input: &[u8]) -> [u8; 32] {
    let net = net();

    // Phase 1: seed from input
    let seed: [u8; 32] = Sha256::digest(input).into();
    let mut x = expand_seed(&seed);

    // Phase 2: L sequential INT8 FC layers
    // ── NPU BACKEND HOOK ──────────────────────────────────────────────────────
    // A CoreML / NNAPI backend replaces this loop with a single model.predict()
    // call.  The model is a pre-compiled CoreML / NNAPI graph of L InnerProduct
    // layers loaded from the protocol weight table.  Input: x (256 INT8 bytes).
    // Output: the final 256 INT8 activation vector.  Everything outside the
    // loop (SHA256 calls) remains on CPU.
    // ─────────────────────────────────────────────────────────────────────────
    for l in 0..L {
        x = int8_fc_layer(net, l, &x);
    }

    // Phase 3: final one-way hash of the activation vector
    let raw: [u8; D] = std::array::from_fn(|i| x[i] as u8);
    Sha256::digest(raw).into()
}

/// Pre-warm the weight table cache.
///
/// Call once at node startup so the first block validation does not pay
/// the ~30 ms build cost.
pub fn init_weights() {
    let _ = net();
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arkhash_deterministic() {
        let input = b"arkos test input 0000000000000000";
        let h1 = arkhash(input);
        let h2 = arkhash(input);
        assert_eq!(h1, h2, "arkhash must be deterministic");
    }

    #[test]
    fn arkhash_avalanche() {
        let a = [0u8; 89];
        let mut b = [0u8; 89];
        b[0] = 1; // one bit different
        let ha = arkhash(&a);
        let hb = arkhash(&b);
        assert_ne!(ha, hb, "different inputs must give different hashes");
        // Count differing bits — expect roughly 50% (128 of 256)
        let diff_bits: u32 = ha
            .iter()
            .zip(hb.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        assert!(
            diff_bits > 64,
            "avalanche: only {diff_bits}/256 bits differ"
        );
    }

    #[test]
    fn arkhash_nonce_sensitivity() {
        // Simulate two block headers differing only in nonce (last 9 bytes)
        let mut header = vec![0u8; 89];
        let h0 = arkhash(&header);
        // Increment nonce (bytes 81..88 in pow_bytes layout)
        header[81] = 1;
        let h1 = arkhash(&header);
        assert_ne!(h0, h1, "nonce change must change hash");
    }

    #[test]
    fn weight_table_size() {
        init_weights();
        let n = net();
        assert_eq!(n.w.len(), L * D * D);
        assert_eq!(n.b.len(), L * D);
    }
}
