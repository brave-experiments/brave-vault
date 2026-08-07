//! Handle authentication: the agent proves possession of its handle secret
//! without ever sending the raw secret over the wire.
//!
//! Flow: broker issues a random `nonce`; the agent replies with
//! `HMAC-SHA256(secret, nonce)` (hex). The broker recomputes and compares in
//! constant time. The secret lives in the OS keychain on the agent host and in
//! the encrypted vault on the broker; it is never printed or transmitted.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a fresh opaque handle id (safe to log and pass around).
pub fn new_handle_id() -> String {
    format!("hnd_{}", random_hex(12))
}

/// Generate a fresh grant id.
pub fn new_grant_id() -> String {
    format!("grt_{}", random_hex(12))
}

/// Generate a high-entropy handle secret (hex). Store in the OS keychain on the
/// agent side; never print after creation.
pub fn new_handle_secret() -> String {
    random_hex(32)
}

/// Generate a random challenge nonce (hex).
pub fn new_nonce() -> String {
    random_hex(16)
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Compute the proof an agent sends: HMAC-SHA256(secret, nonce), hex-encoded.
pub fn compute_proof(secret: &str, nonce: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an agent's proof in constant time.
pub fn verify_proof(secret: &str, nonce: &str, proof: &str) -> bool {
    let expected = compute_proof(secret, nonce);
    let a = expected.as_bytes();
    let b = proof.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_round_trips() {
        let secret = new_handle_secret();
        let nonce = new_nonce();
        let proof = compute_proof(&secret, &nonce);
        assert!(verify_proof(&secret, &nonce, &proof));
    }

    #[test]
    fn wrong_secret_or_nonce_rejected() {
        let secret = new_handle_secret();
        let nonce = new_nonce();
        let proof = compute_proof(&secret, &nonce);
        assert!(!verify_proof("other", &nonce, &proof));
        assert!(!verify_proof(&secret, "othernonce", &proof));
        assert!(!verify_proof(&secret, &nonce, "shortproof"));
    }

    #[test]
    fn ids_have_prefixes_and_entropy() {
        assert!(new_handle_id().starts_with("hnd_"));
        assert!(new_grant_id().starts_with("grt_"));
        assert_ne!(new_handle_secret(), new_handle_secret());
    }
}
