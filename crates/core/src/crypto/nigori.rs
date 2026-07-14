//! Nigori decryption (components/sync/nigori/nigori.cc).
//!
//! Keys are derived from the passphrase (the BIP39 mnemonic string) by either
//! PBKDF2-HMAC-SHA1 or scrypt. Encryption is AES-128-CBC with an HMAC-SHA256
//! tag. Encrypted blob layout (base64):
//!     iv (16 bytes) || ciphertext (16-byte multiple) || hmac_sha256 (32 bytes)

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Mac, SimpleHmac};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = SimpleHmac<sha2::Sha256>;

const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const MAC_SIZE: usize = 32;

/// PBKDF2 salt from nigori.cc:107-111.
const PBKDF2_SALT: [u8; 16] = [
    0xc7, 0xca, 0xfb, 0x23, 0xec, 0x2a, 0x9d, 0x4c, 0x03, 0x5a, 0x90, 0xae, 0xed, 0x8b, 0xa4, 0x98,
];

#[derive(thiserror::Error, Debug)]
pub enum NigoriError {
    #[error("base64 decode failed")]
    Base64,
    #[error("blob too short")]
    TooShort,
    #[error("HMAC verification failed (wrong key?)")]
    BadMac,
    #[error("AES/padding decrypt failed")]
    Decrypt,
}

#[derive(Clone)]
pub struct Nigori {
    encryption_key: [u8; KEY_SIZE],
    mac_key: [u8; KEY_SIZE],
}

impl Nigori {
    /// Derive keys from the passphrase using PBKDF2-HMAC-SHA1.
    /// Kenc = PBKDF2(P, salt, 1003, 16), Kmac = PBKDF2(P, salt, 1004, 16).
    pub fn from_passphrase_pbkdf2(passphrase: &str) -> Self {
        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; KEY_SIZE];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            passphrase.as_bytes(),
            &PBKDF2_SALT,
            1003,
            &mut encryption_key,
        );
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            passphrase.as_bytes(),
            &PBKDF2_SALT,
            1004,
            &mut mac_key,
        );
        Nigori {
            encryption_key,
            mac_key,
        }
    }

    /// Derive keys using scrypt (N=8192, r=8, p=11) over a 32-byte master key,
    /// split into Kenc || Kmac.
    pub fn from_passphrase_scrypt(passphrase: &str, salt: &[u8]) -> Self {
        // log2(8192) = 13
        let params = scrypt::Params::new(13, 8, 11, KEY_SIZE * 2).expect("valid scrypt params");
        let mut out = [0u8; KEY_SIZE * 2];
        scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut out)
            .expect("scrypt output length");
        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; KEY_SIZE];
        encryption_key.copy_from_slice(&out[..KEY_SIZE]);
        mac_key.copy_from_slice(&out[KEY_SIZE..]);
        Nigori {
            encryption_key,
            mac_key,
        }
    }

    /// Derive keys from raw password bytes using PBKDF2-HMAC-SHA1.
    /// Used for keystore keys, whose "password" is raw (non-UTF-8) bytes.
    pub fn from_password_bytes_pbkdf2(password: &[u8]) -> Self {
        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; KEY_SIZE];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &PBKDF2_SALT, 1003, &mut encryption_key);
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &PBKDF2_SALT, 1004, &mut mac_key);
        Nigori {
            encryption_key,
            mac_key,
        }
    }

    /// Import raw 16-byte enc/mac keys (e.g. from a decrypted keybag).
    pub fn from_keys(encryption_key: [u8; KEY_SIZE], mac_key: [u8; KEY_SIZE]) -> Self {
        Nigori {
            encryption_key,
            mac_key,
        }
    }

    /// Encrypt plaintext into a base64 Nigori blob: base64(iv || ct || hmac).
    /// IV is caller-supplied so this is testable; use `encrypt` for production.
    pub fn encrypt_with_iv(&self, iv: [u8; IV_SIZE], plaintext: &[u8]) -> String {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let enc = Aes128CbcEnc::new(self.encryption_key.as_ref().into(), (&iv).into());
        let mut buf = vec![0u8; plaintext.len() + IV_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("cbc encrypt")
            .to_vec();
        let mut h = HmacSha256::new_from_slice(&self.mac_key).expect("hmac key");
        h.update(&ct);
        let mac = h.finalize().into_bytes();
        let mut out = Vec::with_capacity(IV_SIZE + ct.len() + MAC_SIZE);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac);
        B64.encode(out)
    }

    /// Encrypt plaintext with a fresh random IV.
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        use rand::RngCore;
        let mut iv = [0u8; IV_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        self.encrypt_with_iv(iv, plaintext)
    }

    /// The Nigori key name: Permute[Kenc,Kmac](Type::Password || "nigori-key"),
    /// encrypted with a zero IV, base64-encoded (nigori.cc GetKeyName).
    pub fn key_name(&self) -> String {
        // NigoriStream: string -> u32be(len) || bytes; Type -> u32be(4) || u32be(value).
        // Password type value = 1.
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&4u32.to_be_bytes());
        stream.extend_from_slice(&1u32.to_be_bytes()); // Type::Password
        let name = b"nigori-key";
        stream.extend_from_slice(&(name.len() as u32).to_be_bytes());
        stream.extend_from_slice(name);
        // Encrypt with a zero IV, but the key name uses just ciphertext||mac
        // (no IV prefix), so recompute rather than use encrypt_with_iv.
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let iv = [0u8; IV_SIZE];
        let enc = Aes128CbcEnc::new(self.encryption_key.as_ref().into(), (&iv).into());
        let mut buf = vec![0u8; stream.len() + IV_SIZE];
        buf[..stream.len()].copy_from_slice(&stream);
        let ct = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, stream.len())
            .expect("cbc encrypt")
            .to_vec();
        let mut h = HmacSha256::new_from_slice(&self.mac_key).expect("hmac key");
        h.update(&ct);
        let mac = h.finalize().into_bytes();
        let mut out = Vec::with_capacity(ct.len() + MAC_SIZE);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac);
        B64.encode(out)
    }

    /// Decrypt a base64 Nigori blob to plaintext bytes.
    pub fn decrypt(&self, encrypted_b64: &str) -> Result<Vec<u8>, NigoriError> {
        let buf = B64.decode(encrypted_b64.as_bytes()).map_err(|_| NigoriError::Base64)?;
        if buf.len() < IV_SIZE + MAC_SIZE {
            return Err(NigoriError::TooShort);
        }
        let iv = &buf[..IV_SIZE];
        let ciphertext = &buf[IV_SIZE..buf.len() - MAC_SIZE];
        let mac = &buf[buf.len() - MAC_SIZE..];

        // HMAC is computed over the ciphertext only (nigori.cc:242,267).
        let mut h = HmacSha256::new_from_slice(&self.mac_key).expect("hmac key");
        h.update(ciphertext);
        h.verify_slice(mac).map_err(|_| NigoriError::BadMac)?;

        let dec = Aes128CbcDec::new(self.encryption_key.as_ref().into(), iv.into());
        let mut out = ciphertext.to_vec();
        let pt = dec
            .decrypt_padded_mut::<Pkcs7>(&mut out)
            .map_err(|_| NigoriError::Decrypt)?;
        Ok(pt.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    fn encrypt(n: &Nigori, iv: [u8; 16], plaintext: &[u8]) -> String {
        let enc = Aes128CbcEnc::new(n.encryption_key.as_ref().into(), (&iv).into());
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec();
        let mut h = HmacSha256::new_from_slice(&n.mac_key).unwrap();
        h.update(&ct);
        let mac = h.finalize().into_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac);
        B64.encode(out)
    }

    #[test]
    fn encrypt_decrypt_round_trip_pbkdf2() {
        let n = Nigori::from_passphrase_pbkdf2("some sync passphrase");
        let blob = encrypt(&n, [0u8; 16], b"hello nigori payload");
        assert_eq!(n.decrypt(&blob).unwrap(), b"hello nigori payload");
    }

    #[test]
    fn wrong_mac_key_fails() {
        let n1 = Nigori::from_passphrase_pbkdf2("passphrase one");
        let n2 = Nigori::from_passphrase_pbkdf2("passphrase two");
        let blob = encrypt(&n1, [1u8; 16], b"secret");
        assert!(matches!(n2.decrypt(&blob), Err(NigoriError::BadMac)));
    }
}
