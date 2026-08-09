//! Agent access: capability-based, broker-mediated access to vault items for
//! autonomous agents.
//!
//! The agent never holds the vault mnemonic or the services key. It holds a
//! long-lived **handle** ([`model::HandleRecord`]) that only lets it *ask*. To
//! actually touch an item it exchanges the handle for a short-lived, single-use
//! **grant** ([`model::GrantRecord`]) via the broker (the Vault app), which may
//! prompt the user or match a grant the user pre-created.
//!
//! - [`model`] — handles, grants, and the pure request-decision logic.
//! - [`auth`] — HMAC challenge-response so the raw secret never crosses the wire.
//! - [`protocol`] — the newline-JSON IPC messages and endpoint path.
//! - [`resolve`] — mapping a human item string to a concrete item id.

pub mod auth;
pub mod client;
pub mod model;
pub mod protocol;
pub mod resolve;
pub mod transport;
