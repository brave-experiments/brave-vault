//! At-rest encrypted vault (phase 5).
#![allow(dead_code)]

use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::model::{BookmarkItem, PasswordItem};

const ARGON_SALT_LEN: usize = 16;

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad vault format")]
    Format,
    #[error("decryption failed (wrong password?)")]
    Decrypt,
    #[error("serialize: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Encrypted-at-rest contents. Stores the sync mnemonic plus a cached copy of
/// the last-synced passwords so the app can display them immediately on reopen
/// without waiting for (or requiring) a fresh network sync.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct VaultData {
    pub mnemonic: Option<String>,
    /// Decrypted passwords from the last successful sync.
    #[serde(default)]
    pub cached_items: Vec<PasswordItem>,
    /// Unix seconds of the last successful sync, if any.
    #[serde(default)]
    pub last_sync_unix: Option<u64>,
    /// Item keys (realm|username) the user has starred as favorites.
    #[serde(default)]
    pub favorites: Vec<String>,
    /// Decrypted bookmarks from the last successful sync.
    #[serde(default)]
    pub cached_bookmarks: Vec<BookmarkItem>,
    /// Decrypted identities (autofill profiles) from the last successful sync.
    #[serde(default)]
    pub cached_identities: Vec<crate::model::IdentityItem>,
    #[serde(default)]
    pub cached_reading_list: Vec<crate::model::LinkItem>,
    #[serde(default)]
    pub cached_tab_groups: Vec<crate::model::LinkItem>,
    #[serde(default)]
    pub cached_open_tabs: Vec<crate::model::LinkItem>,
    #[serde(default)]
    pub cached_devices: Vec<crate::model::DeviceItem>,
    /// Durable outbox of not-yet-confirmed mutations. Each entry is an opaque
    /// JSON blob owned by the app layer (an OutboxEntry). Written before a
    /// commit is attempted and removed on success, so a mutation is never lost
    /// if the app closes mid-commit — it is replayed on the next startup.
    #[serde(default)]
    pub outbox: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2 kdf");
    key
}

/// Encrypt and serialize vault data to the on-disk JSON envelope.
pub fn seal(password: &str, data: &VaultData) -> Result<String, VaultError> {
    let mut salt = [0u8; ARGON_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plaintext = serde_json::to_vec(data)?;
    let ct = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| VaultError::Decrypt)?;
    let file = VaultFile {
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ct),
    };
    Ok(serde_json::to_string_pretty(&file)?)
}

/// Decrypt an on-disk JSON envelope.
pub fn open(password: &str, contents: &str) -> Result<VaultData, VaultError> {
    let file: VaultFile = serde_json::from_str(contents).map_err(|_| VaultError::Format)?;
    let salt = B64.decode(&file.salt_b64).map_err(|_| VaultError::Format)?;
    let nonce_bytes = B64.decode(&file.nonce_b64).map_err(|_| VaultError::Format)?;
    let ct = B64
        .decode(&file.ciphertext_b64)
        .map_err(|_| VaultError::Format)?;
    let key = derive_key(password, &salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| VaultError::Decrypt)?;
    Ok(serde_json::from_slice(&pt)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let data = VaultData {
            mnemonic: Some("abandon abandon".into()),
            ..Default::default()
        };
        let sealed = seal("testing", &data).unwrap();
        let opened = open("testing", &sealed).unwrap();
        assert_eq!(opened.mnemonic.as_deref(), Some("abandon abandon"));
        assert!(open("wrong", &sealed).is_err());
    }
}
