#![no_main]

use libfuzzer_sys::fuzz_target;
use arkos::blockchain::block::Block;

fuzz_target!(|data: &[u8]| {
    // Try bincode deserialization.
    if let Ok(block) = bincode::deserialize::<Block>(data) {
        // Run header-only validation against an arbitrary parent hash.
        // This exercises bits_to_target, hash_le_target, and meets_target.
        let _ = block.header.validate_header_only(
            "0000000000000000000000000000000000000000000000000000000000000000",
            None,
        );
        // Exercise the full structural validation (merkle root, tx limits, etc.)
        // without requiring a valid chain tip.
        let _ = block.validate("0000000000000000000000000000000000000000000000000000000000000000");
    }
    // Also try JSON (used in sig_hash script commitment).
    if let Ok(block) = serde_json::from_slice::<Block>(data) {
        let _ = block.header.validate_header_only(
            "0000000000000000000000000000000000000000000000000000000000000000",
            None,
        );
    }
});
