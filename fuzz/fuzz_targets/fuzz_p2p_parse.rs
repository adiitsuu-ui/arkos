#![no_main]

use libfuzzer_sys::fuzz_target;
use arkos::network::protocol::Message;

fuzz_target!(|data: &[u8]| {
    // P2P messages are length-prefixed bincode on the wire.
    // Fuzz the deserialization layer that runs before any signature or
    // UTXO validation — a panic here would be a remotely-triggerable crash.
    let _ = bincode::deserialize::<Message>(data);

    // Also fuzz JSON because the RPC layer re-encodes some messages as JSON.
    let _ = serde_json::from_slice::<Message>(data);
});
