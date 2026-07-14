//! Brave Vault core engine: UI-agnostic sync, crypto, and data model.
//!
//! This crate implements a client compatible with Brave Browser's Sync chain:
//! seed/codes, ed25519 auth, keystore/Nigori decryption, password + bookmark
//! fetch, commit/write-back, the encrypted-at-rest vault, and favicon/title
//! fetching. It has no UI dependency so it can back a desktop or mobile shell.

pub mod config;
pub mod crypto;
pub mod favicon;
pub mod model;
pub mod session;
pub mod sync;
pub mod vault;
