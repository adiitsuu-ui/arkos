#![no_main]

use libfuzzer_sys::fuzz_target;
use arkos::crypto::quantum::{HybridPublicKey, HybridSignature};
use arkos::crypto::keys::hybrid_pubkey_to_address;

fuzz_target!(|data: &[u8]| {
    // Split the input into two halves: ecdsa_pubkey | dilithium_pubkey.
    let mid = data.len() / 2;
    let pk = HybridPublicKey {
        ecdsa_pubkey: data[..mid].to_vec(),
        dilithium_pubkey: data[mid..].to_vec(),
    };

    // hybrid_pubkey_to_address hashes the key bytes — should never panic.
    let _ = hybrid_pubkey_to_address(&pk.ecdsa_pubkey, &pk.dilithium_pubkey);

    // Try to verify a dummy signature against the fuzz-derived public key.
    // HybridSignature::verify returns an error for invalid keys — must not panic.
    let sig = HybridSignature {
        ecdsa_sig: data[..mid.min(64)].to_vec(),
        dilithium_sig: data[mid.min(data.len())..].to_vec(),
    };
    let message = &[0u8; 32];
    let _ = sig.verify(message, &pk);
});
