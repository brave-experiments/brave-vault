//! Keystore-based Nigori decryption chain.
//!
//! Brave sync encrypts data with keystore encryption, not the passphrase
//! directly. The chain (see keystore_keys_cryptographer.cc, nigori_key_bag.cc):
//!
//! 1. Server sends raw keystore keys in GetUpdatesResponse.encryption_keys.
//! 2. Each keystore key -> Nigori via PBKDF2 over the raw key bytes.
//! 3. NigoriSpecifics.keystore_decryptor_token decrypts (with a keystore-key
//!    Nigori) to a serialized NigoriKey.
//! 4. That NigoriKey decrypts NigoriSpecifics.encryption_keybag -> NigoriKeyBag.
//! 5. The keybag's keys decrypt individual entities (passwords, etc).
//!
//! Key names are computed as Brave does (nigori.cc GetKeyName), but we can also
//! just try every key against a blob since the HMAC authenticates the match.

use prost::Message;

use super::nigori::Nigori;
use crate::sync::proto;

/// A collection of Nigori keys we can try against any encrypted blob.
#[derive(Default)]
pub struct KeyBag {
    keys: Vec<Nigori>,
}

impl KeyBag {
    pub fn new() -> Self {
        KeyBag { keys: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn add(&mut self, n: Nigori) {
        self.keys.push(n);
    }

    /// Add a key from a NigoriKey proto (raw 16-byte enc + 16-byte mac).
    pub fn add_from_proto(&mut self, key: &proto::NigoriKey) {
        let enc = key.encryption_key();
        let mac = key.mac_key();
        if enc.len() == 16 && mac.len() == 16 {
            let mut e = [0u8; 16];
            let mut m = [0u8; 16];
            e.copy_from_slice(enc);
            m.copy_from_slice(mac);
            self.keys.push(Nigori::from_keys(e, m));
        }
    }

    /// Try every key; return the first that decrypts (HMAC-authenticated) blob.
    pub fn decrypt(&self, blob_b64: &str) -> Option<Vec<u8>> {
        for k in &self.keys {
            if let Ok(pt) = k.decrypt(blob_b64) {
                return Some(pt);
            }
        }
        None
    }

    /// Re-encrypt plaintext using the same key that decrypts `orig_blob_b64`,
    /// returning `(key_name, new_blob_b64)`. This keeps the entity on the same
    /// encryption key it already used, so other clients recognize it.
    pub fn reencrypt_matching(
        &self,
        orig_blob_b64: &str,
        plaintext: &[u8],
    ) -> Option<(String, String)> {
        for k in &self.keys {
            if k.decrypt(orig_blob_b64).is_ok() {
                return Some((k.key_name(), k.encrypt(plaintext)));
            }
        }
        None
    }

    /// Encrypt with the first (default) key. Used for brand-new entities.
    pub fn encrypt_default(&self, plaintext: &[u8]) -> Option<(String, String)> {
        let k = self.keys.first()?;
        Some((k.key_name(), k.encrypt(plaintext)))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KeyBagError {
    #[error("no keystore keys from server")]
    NoKeystoreKeys,
    #[error("nigori node has no keystore_decryptor_token")]
    NoDecryptorToken,
    #[error("could not decrypt keystore_decryptor_token with any keystore key")]
    DecryptorTokenFailed,
    #[error("could not decrypt encryption_keybag")]
    KeybagFailed,
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Build the data keybag for a CUSTOM_PASSPHRASE chain (Brave's default).
///
/// The passphrase is the sync mnemonic string. The keybag is encrypted with a
/// Nigori derived from that passphrase via PBKDF2 (kdf=1) or scrypt (kdf=2,
/// using the base64 custom_passphrase_key_derivation_salt).
pub fn build_keybag_custom_passphrase(
    passphrase: &str,
    nigori: &proto::NigoriSpecifics,
) -> Result<KeyBag, KeyBagError> {
    let keybag_enc = nigori
        .encryption_keybag
        .as_ref()
        .ok_or(KeyBagError::KeybagFailed)?;

    // kdf_method: 1 = PBKDF2_HMAC_SHA1_1003, 2 = SCRYPT_8192_8_11.
    let kdf = nigori.custom_passphrase_key_derivation_method();
    let passphrase_nigori = if kdf == 2 {
        let salt_b64 = nigori.custom_passphrase_key_derivation_salt();
        let salt = B64.decode(salt_b64).map_err(|_| KeyBagError::KeybagFailed)?;
        Nigori::from_passphrase_scrypt(passphrase, &salt)
    } else {
        Nigori::from_passphrase_pbkdf2(passphrase)
    };

    let keybag_plain = passphrase_nigori
        .decrypt(keybag_enc.blob())
        .map_err(|_| KeyBagError::KeybagFailed)?;
    let keybag_proto = proto::NigoriKeyBag::decode(keybag_plain.as_slice())?;

    let mut data_bag = KeyBag::new();
    for key in &keybag_proto.key {
        data_bag.add_from_proto(key);
    }
    Ok(data_bag)
}

/// Build the full data keybag from the server keystore keys and the Nigori node.
pub fn build_keybag(
    keystore_keys: &[Vec<u8>],
    nigori: &proto::NigoriSpecifics,
) -> Result<KeyBag, KeyBagError> {
    if keystore_keys.is_empty() {
        return Err(KeyBagError::NoKeystoreKeys);
    }

    // Keystore-key Nigoris: PBKDF2 over each raw keystore key.
    let keystore_nigoris: Vec<Nigori> = keystore_keys
        .iter()
        .map(|k| Nigori::from_password_bytes_pbkdf2(k))
        .collect();

    // Decrypt the keystore_decryptor_token -> a NigoriKey.
    let token = nigori
        .keystore_decryptor_token
        .as_ref()
        .ok_or(KeyBagError::NoDecryptorToken)?;
    let token_blob = token.blob();
    let mut decryptor_key_bytes = None;
    for kn in &keystore_nigoris {
        if let Ok(pt) = kn.decrypt(token_blob) {
            decryptor_key_bytes = Some(pt);
            break;
        }
    }
    let decryptor_key_bytes = decryptor_key_bytes.ok_or(KeyBagError::DecryptorTokenFailed)?;
    let decryptor_key = proto::NigoriKey::decode(decryptor_key_bytes.as_slice())?;

    // Use the decryptor key to decrypt the encryption_keybag.
    let mut decryptor_bag = KeyBag::new();
    decryptor_bag.add_from_proto(&decryptor_key);
    // The keystore keys themselves can also decrypt the keybag in some states.
    for kn in keystore_nigoris {
        decryptor_bag.add(kn);
    }

    let keybag_enc = nigori
        .encryption_keybag
        .as_ref()
        .ok_or(KeyBagError::KeybagFailed)?;
    let keybag_plain = decryptor_bag
        .decrypt(keybag_enc.blob())
        .ok_or(KeyBagError::KeybagFailed)?;
    let keybag_proto = proto::NigoriKeyBag::decode(keybag_plain.as_slice())?;

    // Final data keybag: every key in the decrypted keybag.
    let mut data_bag = KeyBag::new();
    for key in &keybag_proto.key {
        data_bag.add_from_proto(key);
    }
    Ok(data_bag)
}
