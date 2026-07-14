//! Sync seed: 32 random bytes <-> 24-word BIP39 English mnemonic.
//!
//! Matches Brave's `brave_sync::crypto` (crypto.cc): a 32-byte seed encoded as
//! a BIP39 mnemonic. We use the raw entropy, NOT the BIP39 512-bit `to_seed`
//! output, so the bytes round-trip exactly with Brave.

use bip39::{Language, Mnemonic};

pub const SEED_SIZE: usize = 32;

#[derive(thiserror::Error, Debug)]
pub enum SeedError {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error("expected {SEED_SIZE}-byte seed, got {0}")]
    WrongSize(usize),
}

/// Generate a fresh 32-byte seed and its 24-word mnemonic.
pub fn generate() -> (Vec<u8>, String) {
    use rand::RngCore;
    let mut bytes = [0u8; SEED_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let phrase = mnemonic_from_bytes(&bytes).expect("32 bytes is valid entropy");
    (bytes.to_vec(), phrase)
}

/// 32 bytes -> 24-word mnemonic string.
pub fn mnemonic_from_bytes(bytes: &[u8]) -> Result<String, SeedError> {
    if bytes.len() != SEED_SIZE {
        return Err(SeedError::WrongSize(bytes.len()));
    }
    let m = Mnemonic::from_entropy_in(Language::English, bytes)
        .map_err(|e| SeedError::Mnemonic(e.to_string()))?;
    Ok(m.to_string())
}

/// 24-word mnemonic string -> 32 bytes.
pub fn bytes_from_mnemonic(phrase: &str) -> Result<Vec<u8>, SeedError> {
    let phrase = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    let m = Mnemonic::parse_in(Language::English, &phrase)
        .map_err(|e| SeedError::Mnemonic(e.to_string()))?;
    let (entropy, len) = m.to_entropy_array();
    if len != SEED_SIZE {
        return Err(SeedError::WrongSize(len));
    }
    Ok(entropy[..len].to_vec())
}

/// Whether a passphrase is a valid BIP39 mnemonic decoding to 32 bytes.
pub fn is_valid(phrase: &str) -> bool {
    bytes_from_mnemonic(phrase).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random() {
        let (bytes, phrase) = generate();
        assert_eq!(bytes.len(), SEED_SIZE);
        assert_eq!(phrase.split_whitespace().count(), 24);
        let back = bytes_from_mnemonic(&phrase).unwrap();
        assert_eq!(bytes, back);
    }

    #[test]
    fn known_vector_all_zero() {
        // 32 zero bytes is a well-known BIP39 24-word vector.
        let bytes = [0u8; SEED_SIZE];
        let phrase = mnemonic_from_bytes(&bytes).unwrap();
        assert!(phrase.starts_with("abandon abandon abandon"));
        assert_eq!(bytes_from_mnemonic(&phrase).unwrap(), bytes.to_vec());
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_valid("not a real mnemonic phrase"));
    }
}
