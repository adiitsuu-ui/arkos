#![no_main]

use libfuzzer_sys::fuzz_target;
use arkos::blockchain::block::Block;

fuzz_target!(|data: &[u8]| {
    // Try bincode deserialization.
    if let Ok(block) = bincode::deserialize::<Block>(data) {
        let _ = block.header.validate_header_only(
            "0000000000000000000000000000000000000000000000000000000000000000",
            None,
        );
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
