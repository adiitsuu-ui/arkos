//! Arkos mobile mining FFI library.
//!
//! Exposes a C-compatible API callable from Flutter via `dart:ffi`.
//! All functions are `unsafe extern "C"` and designed to be called from a
//! Dart Isolate so they can block without freezing the UI thread.
//!
//! # Mining loop (Dart side)
//!
//! ```dart
//! // 1. Get block template from node RPC.
//! // 2. Sign mining_commitment with TEE key (platform channel).
//! // 3. In a compute Isolate, call arkos_mine() in chunks of ~1M nonces.
//! // 4. If arkos_mine() returns u64::MAX, bump start_nonce and repeat.
//! // 5. On success, call submitBlock via node RPC.
//! ```
//!
//! # Threading model
//!
//! `arkos_mine` blocks its calling thread until either a valid nonce is found
//! or the nonce range [start, end] is exhausted.  Pass `stop_flag` pointing to
//! a `u8` that the main isolate can set to non-zero to interrupt early (e.g.
//! when a new block arrives on the network).

use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

// ─── Public constants (also in Dart as compile-time constants) ────────────────

/// Returned by arkos_mine / arkos_mine_with_stop when no valid nonce was found.
pub const NONCE_NOT_FOUND: u64 = u64::MAX;

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// SHA-256 double hash — identical to the node implementation.
#[inline(always)]
fn hash256(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

/// Serialise a block header into the canonical wire format used for PoW.
/// Must match `BlockHeader::pow_bytes()` on the Rust node.
///
/// Layout (little-endian unless noted):
///   version     u32  4 bytes
///   prev_hash   str  decoded as 32 raw bytes (hex input)
///   merkle_root str  decoded as 32 raw bytes (hex input)
///   timestamp   u64  8 bytes
///   bits        u32  4 bytes
///   nonce       u64  8 bytes
///   device_proof Option<DeviceProof>  — None = 0x00 tag byte (bincode)
///
/// Total fixed-size portion: 4+32+32+8+4+8+1 = 89 bytes
fn serialize_header(
    version: u32,
    prev_hash_bytes: &[u8; 32],
    merkle_root_bytes: &[u8; 32],
    timestamp: u64,
    bits: u32,
    nonce: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(89);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(prev_hash_bytes);
    buf.extend_from_slice(merkle_root_bytes);
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(&bits.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.push(0x00); // bincode Option::None tag
    buf
}

/// Expand compact `bits` to a 32-byte target — identical to the node.
#[inline]
fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    let mut target = [0u8; 32];
    if exp >= 1 && exp <= 32 {
        let start = 32 - exp;
        target[start] = ((mantissa >> 16) & 0xff) as u8;
        if start + 1 < 32 { target[start + 1] = ((mantissa >> 8) & 0xff) as u8; }
        if start + 2 < 32 { target[start + 2] = (mantissa & 0xff) as u8; }
    }
    target
}

/// Check if `hash` (big-endian bytes) is less-than-or-equal to `target`.
#[inline]
fn hash_le_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        if h < t { return true; }
        if h > t { return false; }
    }
    true
}

// ─── Exported FFI functions ───────────────────────────────────────────────────

/// Mine a nonce in the range `[start_nonce, end_nonce)`.
///
/// Parameters
/// ----------
/// - `version`       : block version (u32)
/// - `prev_hash_hex` : 64-char null-terminated hex string (32 bytes decoded)
/// - `merkle_hex`    : 64-char null-terminated hex string (32 bytes decoded)
/// - `timestamp`     : block timestamp (u64)
/// - `bits`          : compact difficulty target (u32)
/// - `start_nonce`   : first nonce to try
/// - `end_nonce`     : exclusive upper bound
/// - `stop_flag`     : pointer to a u8; set to non-zero from Dart to abort early
/// - `out_hash`      : caller-allocated 65-byte buffer; receives hex hash on success
///
/// Returns
/// -------
/// The winning nonce if found, or `NONCE_NOT_FOUND` (= u64::MAX).
///
/// # Safety
/// `prev_hash_hex`, `merkle_hex`, and `out_hash` must be valid non-null pointers.
/// `stop_flag` may be null (treated as "never stop").
#[no_mangle]
pub unsafe extern "C" fn arkos_mine(
    version: u32,
    prev_hash_hex: *const c_char,
    merkle_hex: *const c_char,
    timestamp: u64,
    bits: u32,
    start_nonce: u64,
    end_nonce: u64,
    stop_flag: *const c_uchar,
    out_hash: *mut c_char,
) -> u64 {
    // Decode hex inputs
    let prev_str = match CStr::from_ptr(prev_hash_hex).to_str() {
        Ok(s) => s,
        Err(_) => return NONCE_NOT_FOUND,
    };
    let merkle_str = match CStr::from_ptr(merkle_hex).to_str() {
        Ok(s) => s,
        Err(_) => return NONCE_NOT_FOUND,
    };

    let mut prev_bytes = [0u8; 32];
    let mut merkle_bytes = [0u8; 32];
    if hex::decode_to_slice(prev_str, &mut prev_bytes).is_err() {
        return NONCE_NOT_FOUND;
    }
    if hex::decode_to_slice(merkle_str, &mut merkle_bytes).is_err() {
        return NONCE_NOT_FOUND;
    }

    let target = bits_to_target(bits);

    // Main nonce search loop
    let check_interval = 8_192u64; // check stop_flag every 8k hashes
    let mut nonce = start_nonce;

    while nonce < end_nonce {
        // Periodically check stop flag (if provided)
        if !stop_flag.is_null() && nonce % check_interval == 0 {
            if std::ptr::read_volatile(stop_flag) != 0 {
                return NONCE_NOT_FOUND;
            }
        }

        let data = serialize_header(version, &prev_bytes, &merkle_bytes, timestamp, bits, nonce);
        let hash = hash256(&data);

        if hash_le_target(&hash, &target) {
            // Write hex hash to out_hash buffer
            if !out_hash.is_null() {
                let hex_str = hex::encode(hash);
                let cstr = CString::new(hex_str).unwrap_or_default();
                let bytes = cstr.as_bytes_with_nul();
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_hash, bytes.len());
            }
            return nonce;
        }

        nonce = nonce.wrapping_add(1);
    }

    NONCE_NOT_FOUND
}

/// Compute the double-SHA256 hash of a block header at a given nonce.
///
/// Parameters
/// ----------
/// - `out_hash` : caller-allocated 65-byte buffer; receives 64-hex-char + null.
///
/// # Safety
/// All pointer parameters must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn arkos_hash_block(
    version: u32,
    prev_hash_hex: *const c_char,
    merkle_hex: *const c_char,
    timestamp: u64,
    bits: u32,
    nonce: u64,
    out_hash: *mut c_char,
) {
    let prev_str = CStr::from_ptr(prev_hash_hex).to_str().unwrap_or("");
    let merkle_str = CStr::from_ptr(merkle_hex).to_str().unwrap_or("");

    let mut prev_bytes = [0u8; 32];
    let mut merkle_bytes = [0u8; 32];
    let _ = hex::decode_to_slice(prev_str, &mut prev_bytes);
    let _ = hex::decode_to_slice(merkle_str, &mut merkle_bytes);

    let data = serialize_header(version, &prev_bytes, &merkle_bytes, timestamp, bits, nonce);
    let hash = hash256(&data);
    let hex_str = hex::encode(hash);
    let cstr = CString::new(hex_str).unwrap_or_default();
    let bytes = cstr.as_bytes_with_nul();
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_hash, bytes.len());
}

/// Check if a hex-encoded hash string meets the compact difficulty target.
///
/// Returns 1 if hash ≤ target, 0 otherwise.
///
/// # Safety
/// `hash_hex` must be a valid null-terminated 64-char hex string.
#[no_mangle]
pub unsafe extern "C" fn arkos_hash_meets_target(hash_hex: *const c_char, bits: u32) -> i32 {
    let s = match CStr::from_ptr(hash_hex).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut hash_bytes = [0u8; 32];
    if hex::decode_to_slice(s, &mut hash_bytes).is_err() {
        return 0;
    }
    let target = bits_to_target(bits);
    if hash_le_target(&hash_bytes, &target) { 1 } else { 0 }
}

/// Compute the `mining_commitment` that the mobile device's TEE key must sign.
///
/// This is: double-SHA256(version_le ‖ prev_hash_bytes ‖ merkle_bytes ‖ ts_le ‖ bits_le)
/// — a subset of the full header, intentionally excluding nonce and device_proof.
///
/// Parameters
/// ----------
/// - `out_commitment` : caller-allocated 65-byte buffer (64 hex + null).
///
/// # Safety
/// All pointer parameters must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn arkos_mining_commitment(
    version: u32,
    prev_hash_hex: *const c_char,
    merkle_hex: *const c_char,
    timestamp: u64,
    bits: u32,
    out_commitment: *mut c_char,
) {
    let prev_str = CStr::from_ptr(prev_hash_hex).to_str().unwrap_or("");
    let merkle_str = CStr::from_ptr(merkle_hex).to_str().unwrap_or("");

    let mut prev_bytes = [0u8; 32];
    let mut merkle_bytes = [0u8; 32];
    let _ = hex::decode_to_slice(prev_str, &mut prev_bytes);
    let _ = hex::decode_to_slice(merkle_str, &mut merkle_bytes);

    // Mirrors BlockHeader::mining_commitment() in the node
    let mut data = Vec::with_capacity(4 + 32 + 32 + 8 + 4);
    data.extend_from_slice(&version.to_le_bytes());
    data.extend_from_slice(prev_str.as_bytes()); // node uses string bytes, not decoded bytes
    data.extend_from_slice(merkle_str.as_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.extend_from_slice(&bits.to_le_bytes());

    let commitment = hash256(&data);
    let hex_str = hex::encode(commitment);
    let cstr = CString::new(hex_str).unwrap_or_default();
    let bytes = cstr.as_bytes_with_nul();
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_commitment, bytes.len());
}

/// Returns the current library version string.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process.
#[no_mangle]
pub extern "C" fn arkos_version() -> *const c_char {
    static VERSION: &[u8] = b"arkos_mobile/0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_genesis_bits() {
        // With bits = 0x1e0fffff (very easy), almost any hash should meet target
        let target = bits_to_target(0x1e0fffff);
        // First byte of target should be 0x00 (high difficulty side)
        // exp=0x1e=30, mantissa=0x0fffff
        assert_eq!(target[0], 0x00);
        // 30th byte from end should be non-zero
        let byte_30 = target[32 - 30];
        assert_eq!(byte_30, 0x0f);
    }

    #[test]
    fn test_mine_easy() {
        // Use genesis difficulty bits — should find a nonce quickly
        let prev = "0000000000000000000000000000000000000000000000000000000000000000";
        let merkle = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let bits = 0x1e0fffffu32;

        let prev_c = std::ffi::CString::new(prev).unwrap();
        let merkle_c = std::ffi::CString::new(merkle).unwrap();
        let mut out_buf = vec![0i8; 65];

        let nonce = unsafe {
            arkos_mine(
                1,
                prev_c.as_ptr(),
                merkle_c.as_ptr(),
                1_700_000_000,
                bits,
                0,
                10_000_000,
                std::ptr::null(),
                out_buf.as_mut_ptr(),
            )
        };

        assert_ne!(nonce, NONCE_NOT_FOUND, "should find a nonce at genesis difficulty");
        // Verify the hash meets target
        let hash_hex = unsafe { CStr::from_ptr(out_buf.as_ptr()) }.to_str().unwrap();
        let mut hash_bytes = [0u8; 32];
        hex::decode_to_slice(hash_hex, &mut hash_bytes).unwrap();
        let target = bits_to_target(bits);
        assert!(hash_le_target(&hash_bytes, &target));
    }
}
