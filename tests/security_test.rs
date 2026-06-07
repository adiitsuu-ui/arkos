use arkos::security::access::*;
use arkos::security::vault;

#[test]
fn test_vault_encrypt_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    // Create vault with 2 secret keys
    vault::create_vault(
        "my-secure-pass-12",
        vec!["aabbccddeeff0011".into(), "1122334455667788".into()],
        vec!["key1".into(), "key2".into()],
        &vault_path,
    )
    .unwrap();

    // Open with correct passphrase — must succeed
    let contents = vault::open_vault("my-secure-pass-12", &vault_path).unwrap();
    assert_eq!(contents.secret_keys.len(), 2);
    assert_eq!(contents.secret_keys[0], "aabbccddeeff0011");
    assert_eq!(contents.secret_keys[1], "1122334455667788");
    assert_eq!(contents.labels[0], "key1");
    assert_eq!(contents.labels[1], "key2");

    // Open with WRONG passphrase — must fail
    let result = vault::open_vault("wrong-passphrase!!", &vault_path);
    assert!(result.is_err(), "wrong passphrase should fail");
}

#[test]
fn test_vault_short_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");
    let result = vault::create_vault("short", vec![], vec![], &vault_path);
    assert!(result.is_err(), "short passphrase should be rejected");
}

#[test]
fn test_vault_tamper_detection() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    vault::create_vault(
        "my-secure-pass-12",
        vec!["secret123".into()],
        vec!["test".into()],
        &vault_path,
    )
    .unwrap();

    // Read the vault file and flip a byte in the ciphertext
    let mut content = std::fs::read_to_string(&vault_path).unwrap();
    // Find ciphertext field and modify it
    content = content.replacen("ciphertext\": \"", "ciphertext\": \"X", 1);
    std::fs::write(&vault_path, &content).unwrap();

    // Must fail — AES-GCM detects tampering
    let result = vault::open_vault("my-secure-pass-12", &vault_path);
    assert!(result.is_err(), "tampered vault should fail decryption");
}

#[test]
fn test_access_token_valid_signature() {
    let master = MasterKey::generate();
    let token = master.issue_token(
        "alice",
        &master.public_hex(),
        vec![Permission::Connect, Permission::Transact],
        365,
    );
    assert!(token.verify(&master.public_hex()).is_ok());
}

#[test]
fn test_access_token_tampered_permissions() {
    let master = MasterKey::generate();
    let token = master.issue_token(
        "alice",
        &master.public_hex(),
        vec![Permission::Connect],
        365,
    );

    let mut tampered = token.clone();
    tampered.permissions.push(Permission::Admin);
    assert!(
        tampered.verify(&master.public_hex()).is_err(),
        "adding Admin to a Connect-only token must fail signature check"
    );
}

#[test]
fn test_access_token_tampered_name() {
    let master = MasterKey::generate();
    let token = master.issue_token("alice", &master.public_hex(), vec![Permission::Mine], 30);

    let mut tampered = token.clone();
    tampered.holder_name = "eve".into();
    assert!(
        tampered.verify(&master.public_hex()).is_err(),
        "changing holder name must fail signature check"
    );
}

#[test]
fn test_access_token_wrong_master_key() {
    let master = MasterKey::generate();
    let imposter = MasterKey::generate();
    let token = master.issue_token("alice", &master.public_hex(), vec![Permission::Admin], 0);

    assert!(
        token.verify(&imposter.public_hex()).is_err(),
        "verifying against wrong master key must fail"
    );
}

#[test]
fn test_revocation_list() {
    let mut revoked = RevocationList::default();
    assert!(!revoked.is_revoked("tok_123"));
    revoked.revoke("tok_123");
    assert!(revoked.is_revoked("tok_123"));
    assert!(!revoked.is_revoked("tok_456"));

    // Revoking twice is idempotent
    revoked.revoke("tok_123");
    assert_eq!(revoked.revoked_ids.len(), 1);
}

#[test]
fn test_revocation_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked.json");

    let mut list = RevocationList::default();
    list.revoke("tok_abc");
    list.save(&path).unwrap();

    let loaded = RevocationList::load(&path).unwrap();
    assert!(loaded.is_revoked("tok_abc"));
}

#[test]
fn test_token_has_permission() {
    let master = MasterKey::generate();

    // Admin has everything
    let admin_token = master.issue_token("admin", &master.public_hex(), vec![Permission::Admin], 0);
    assert!(admin_token.has_permission(&Permission::Mine));
    assert!(admin_token.has_permission(&Permission::Transact));
    assert!(admin_token.has_permission(&Permission::Connect));

    // Limited token
    let limited = master.issue_token("miner", &master.public_hex(), vec![Permission::Mine], 0);
    assert!(limited.has_permission(&Permission::Mine));
    assert!(!limited.has_permission(&Permission::Admin));
    assert!(!limited.has_permission(&Permission::Transact));
}
