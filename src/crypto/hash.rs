use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn hash256(data: &[u8]) -> Hash {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    second.into()
}

pub fn hash_to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

pub fn hex_to_hash(s: &str) -> anyhow::Result<Hash> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid hash length");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
