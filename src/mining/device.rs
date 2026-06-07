use crate::crypto::hash::{hash256, hash_to_hex};
use anyhow::{bail, Result};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};

/// How many blocks must pass before a device can be transferred to a new phone.
pub const DEVICE_TRANSFER_COOLDOWN: u64 = 100;

/// Mobile miners receive a 20% bonus on top of the base block reward.
pub const MOBILE_MINING_BONUS_BPS: u64 = 2_000; // basis points: 2000/10000 = 20%

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MobilePlatform {
    /// Attested via Google Play Integrity API.
    Android,
    /// Attested via Apple App Attest / DeviceCheck.
    IOS,
}

/// On-chain record created when a user registers their mobile device.
///
/// The `device_pubkey` is generated inside the device's Secure Enclave (iOS) or
/// Android Keystore hardware module where supported, so the private key never leaves the chip.
/// `attestation_blob` is the raw token returned by Apple/Google proving the key
/// lives in genuine, unrooted hardware — nodes verify this blob against the
/// respective platform API at registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// SHA-256 of `device_pubkey`, hex-encoded.  Used as the primary key.
    pub device_id: String,
    /// Wallet address this device is permanently bound to.
    pub wallet_address: String,
    /// Device public key.
    /// Accepted formats are compressed secp256k1 SEC1 (33 bytes) or P-256 SEC1 (65 bytes).
    pub device_pubkey: Vec<u8>,
    pub platform: MobilePlatform,
    /// Raw Play Integrity token (Android) or App Attest assertion (iOS).
    /// Stored for auditability; verified once at registration.
    pub attestation_blob: Vec<u8>,
    /// Block height at which the registration was accepted.
    pub registered_at_height: u64,
}

impl DeviceRegistration {
    pub fn new(
        wallet_address: String,
        device_pubkey: Vec<u8>,
        platform: MobilePlatform,
        attestation_blob: Vec<u8>,
        registered_at_height: u64,
    ) -> Self {
        let device_id = hash_to_hex(&hash256(&device_pubkey));
        DeviceRegistration {
            device_id,
            wallet_address,
            device_pubkey,
            platform,
            attestation_blob,
            registered_at_height,
        }
    }
}

/// Embedded in a `BlockHeader` to prove a specific registered mobile device mined it.
///
/// The device signs the *mining commitment* — a hash covering version, prev_hash,
/// merkle_root, timestamp, and bits, but NOT the nonce or the proof itself.
/// This lets the miner sign once and then search for the nonce freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProof {
    /// Identifies the registered device (= SHA-256 of its TEE public key).
    pub device_id: String,
    /// Must match the wallet address in the coinbase output.
    pub wallet_address: String,
    /// device_key.sign(mining_commitment).
    /// secp256k1 devices use compact 64-byte ECDSA; P-256 TEE devices use DER ECDSA.
    pub signature: Vec<u8>,
}

/// Persistent registry mapping wallet addresses ↔ device IDs (1-to-1).
///
/// Key layout in RocksDB:
///   `wallet:<address>`  → device_id          (lookup by wallet)
///   `claim:<device_id>` → wallet_address      (lookup by device, prevents multi-wallet)
///   `device:<device_id>` → bincode(DeviceRegistration)
pub struct DeviceRegistry {
    db: DB,
}

impl DeviceRegistry {
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(DeviceRegistry { db })
    }

    /// Register a new device.  Fails if the wallet already has one, or if this
    /// physical device is already claimed by a different wallet.
    pub fn register(&self, reg: &DeviceRegistration) -> Result<()> {
        let wallet_key = format!("wallet:{}", reg.wallet_address);
        if self.db.get(wallet_key.as_bytes())?.is_some() {
            bail!(
                "wallet {} already has a registered device",
                reg.wallet_address
            );
        }
        let claim_key = format!("claim:{}", reg.device_id);
        if self.db.get(claim_key.as_bytes())?.is_some() {
            bail!("device {} is already registered to a wallet", reg.device_id);
        }

        let blob = bincode::serialize(reg)?;
        self.db
            .put(format!("device:{}", reg.device_id).as_bytes(), &blob)?;
        self.db
            .put(wallet_key.as_bytes(), reg.device_id.as_bytes())?;
        self.db
            .put(claim_key.as_bytes(), reg.wallet_address.as_bytes())?;
        Ok(())
    }

    pub fn get_by_device_id(&self, device_id: &str) -> Result<Option<DeviceRegistration>> {
        match self.db.get(format!("device:{}", device_id).as_bytes())? {
            Some(val) => Ok(Some(bincode::deserialize(&val)?)),
            None => Ok(None),
        }
    }

    pub fn get_device_id_for_wallet(&self, wallet_address: &str) -> Result<Option<String>> {
        match self
            .db
            .get(format!("wallet:{}", wallet_address).as_bytes())?
        {
            Some(val) => Ok(Some(String::from_utf8(val)?)),
            None => Ok(None),
        }
    }

    /// Transfer registration to a new device (e.g. phone upgrade or loss recovery).
    ///
    /// Requires the *old* device key to sign the new device_id, proving intentional
    /// transfer.  If the old phone is lost, a governance/social-recovery path must
    /// be used instead (not implemented here).  Enforces a `DEVICE_TRANSFER_COOLDOWN`
    /// block gap to prevent rapid churning.
    pub fn transfer_device(
        &self,
        wallet_address: &str,
        old_device_signature: &[u8],
        new_reg: &DeviceRegistration,
        current_height: u64,
    ) -> Result<()> {
        let old_device_id = self
            .get_device_id_for_wallet(wallet_address)?
            .ok_or_else(|| anyhow::anyhow!("no device registered for wallet {}", wallet_address))?;

        let old_reg = self
            .get_by_device_id(&old_device_id)?
            .ok_or_else(|| anyhow::anyhow!("device registration not found"))?;

        // Old device must explicitly sign the new device_id to authorise transfer.
        let transfer_hash = hash256(new_reg.device_id.as_bytes());
        let transfer_valid = match old_reg.device_pubkey.len() {
            33 => crate::crypto::keys::verify_raw(
                &old_reg.device_pubkey,
                &transfer_hash,
                old_device_signature,
            ),
            65 => crate::crypto::keys::verify_p256_der(
                &old_reg.device_pubkey,
                &transfer_hash,
                old_device_signature,
            ),
            _ => false,
        };
        if !transfer_valid {
            bail!("invalid transfer signature from old device");
        }

        if current_height < old_reg.registered_at_height + DEVICE_TRANSFER_COOLDOWN {
            bail!(
                "device transfer cooldown: {} blocks remaining",
                (old_reg.registered_at_height + DEVICE_TRANSFER_COOLDOWN) - current_height
            );
        }

        // Remove old bindings, then register the new device.
        self.db
            .delete(format!("device:{}", old_device_id).as_bytes())?;
        self.db
            .delete(format!("claim:{}", old_device_id).as_bytes())?;
        self.db
            .delete(format!("wallet:{}", wallet_address).as_bytes())?;
        self.register(new_reg)?;
        Ok(())
    }
}
