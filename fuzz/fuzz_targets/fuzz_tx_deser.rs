#![no_main]

use libfuzzer_sys::fuzz_target;
use arkos::transaction::tx::Transaction;

fuzz_target!(|data: &[u8]| {
    // Bincode path — used for block storage and hashing.
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        // sig_hash exercises the full output serialization path including
        // Script::to_bytes() and effective_script().
        let _ = tx.sig_hash(0x41524b4f); // "ARKO"
        let _ = tx.txid();
        let _ = tx.is_coinbase();
    }
    // JSON path — used in RPC responses.
    if let Ok(tx) = serde_json::from_slice::<Transaction>(data) {
        let _ = tx.sig_hash(0x41524b4f);
    }
});
