//! Brave sync access-token generation (no Google account).
//!
//! Reimplements `BraveSyncAuthManager` (brave_sync_auth_manager.cc:35-121)
//! and `brave_sync::crypto::DeriveSigningKeysFromSeed` (crypto.cc:44-58):
//!
//! 1. HKDF-SHA512(ikm = seed32, salt = HKDF_SALT, info = "sync-auth-key") -> 32 bytes
//! 2. those 32 bytes are the ed25519 private seed -> keypair
//! 3. timestamp = network time in ms since unix epoch, as a decimal STRING
//! 4. token_str = hex(ascii(timestamp)) | hex(sign(ascii(timestamp))) | hex(pubkey)
//! 5. token = base64(token_str)

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha512;

/// 64-byte HKDF salt from brave_sync_auth_manager.cc:40-45.
pub const HKDF_SALT: [u8; 64] = [
    72, 203, 156, 43, 64, 229, 225, 127, 214, 158, 50, 29, 130, 186, 182, 207, 6, 108, 47, 254,
    245, 71, 198, 109, 44, 108, 32, 193, 221, 126, 119, 143, 112, 113, 87, 184, 239, 231, 230,
    234, 28, 135, 54, 42, 9, 243, 39, 30, 179, 147, 194, 211, 212, 239, 225, 52, 192, 219, 145,
    40, 95, 19, 142, 98,
];

const INFO: &[u8] = b"sync-auth-key";

/// ed25519 signing keypair derived from the 32-byte sync seed.
pub struct SyncKeys {
    signing: SigningKey,
}

impl SyncKeys {
    pub fn from_seed(seed32: &[u8]) -> Self {
        let hk = Hkdf::<Sha512>::new(Some(&HKDF_SALT), seed32);
        let mut okm = [0u8; 32];
        hk.expand(INFO, &mut okm).expect("32 is a valid HKDF length");
        let signing = SigningKey::from_bytes(&okm);
        SyncKeys { signing }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Hex-encoded public key; also used as the client id.
    pub fn client_id(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Build the base64 access token for a given timestamp (ms since epoch, as string).
    ///
    /// token_str = hex(ascii(ts)) | hex(sig(ascii(ts))) | hex(pubkey)
    pub fn access_token(&self, timestamp_ms: &str) -> String {
        let ts_bytes = timestamp_ms.as_bytes();
        // Brave uses base::HexEncode, which is UPPERCASE. The server keys the
        // account store by the exact pubkey hex string, so case matters here
        // even though signature verification is case-insensitive.
        let timestamp_hex = hex::encode_upper(ts_bytes);
        let sig = self.signing.sign(ts_bytes);
        let signed_hex = hex::encode_upper(sig.to_bytes());
        let pub_hex = hex::encode_upper(self.public_key_bytes());
        let token_str = format!("{timestamp_hex}|{signed_hex}|{pub_hex}");
        B64.encode(token_str.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seed;

    #[test]
    fn deterministic_pubkey_and_token() {
        // Fixed seed -> deterministic derivation. Values are self-consistent
        // (regression guard); cross-checked structurally against Brave's format.
        let seed = [7u8; 32];
        let keys = SyncKeys::from_seed(&seed);
        let pk1 = keys.public_key_bytes();
        let keys2 = SyncKeys::from_seed(&seed);
        assert_eq!(pk1, keys2.public_key_bytes());

        let token = keys.access_token("1700000000000");
        // token decodes to three hex fields joined by '|'
        let decoded = B64.decode(token.as_bytes()).unwrap();
        let s = String::from_utf8(decoded).unwrap();
        let parts: Vec<&str> = s.split('|').collect();
        assert_eq!(parts.len(), 3);
        // field 0 = UPPERCASE hex(ascii("1700000000000"))
        assert_eq!(parts[0], hex::encode_upper("1700000000000".as_bytes()));
        // field 1 = 64-byte signature => 128 hex chars
        assert_eq!(parts[1].len(), 128);
        // field 2 = 32-byte pubkey => 64 hex chars, UPPERCASE
        assert_eq!(parts[2].len(), 64);
        assert_eq!(parts[2], hex::encode_upper(keys.public_key_bytes()));
    }

    #[test]
    fn matches_brave_known_vector() {
        // From brave crypto_unittest.cc CryptoTest.Ed25519KeyDerivation.
        // seed hex, info = single 0x00 byte, salt = HKDF_SALT.
        let seed =
            hex::decode("5bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb")
                .unwrap();
        let hk = Hkdf::<Sha512>::new(Some(&HKDF_SALT), &seed);
        let mut okm = [0u8; 32];
        hk.expand(&[0u8], &mut okm).unwrap();
        let signing = SigningKey::from_bytes(&okm);
        assert_eq!(
            hex::encode(signing.verifying_key().to_bytes()),
            "f58ca446f0c33ee7e8e9874466da442b2e764afd77ad46034bdff9e01f9b87d4"
        );
    }

    #[test]
    fn client_id_from_mnemonic() {
        let (bytes, phrase) = seed::generate();
        let a = SyncKeys::from_seed(&bytes).client_id();
        let b = SyncKeys::from_seed(&seed::bytes_from_mnemonic(&phrase).unwrap()).client_id();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
