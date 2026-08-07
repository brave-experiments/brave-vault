//! Wire protocol between the agent CLI and the broker (the Vault app).
//!
//! Transport is a local IPC endpoint only — a unix domain socket on
//! macOS/Linux, a named pipe on Windows — never TCP. Messages are newline-
//! delimited JSON: each request/response is one JSON object on its own line.
//!
//! The exchange:
//! ```text
//!   agent → HELLO   { handle_id }
//!   broker → NONCE  { nonce }
//!   agent → REQUEST { handle_id, proof, item, action, reason }
//!   broker → GRANT  { grant_id, ttl_secs }          (or ERROR / DENIED)
//!   -- action = reveal --
//!   agent → CONSUME { grant_id, proof }
//!   broker → SECRET { fields }                        (streamed once)
//!   -- action = use --
//!   agent → PERFORM { grant_id, proof, target }
//!   broker → DONE   { ok, detail }
//! ```
//! Every authenticated message carries a fresh `proof` (HMAC over the last
//! nonce the broker issued on this connection).

use serde::{Deserialize, Serialize};

use super::model::Action;

/// A request line from the agent to the broker.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum Request {
    /// Open a session and announce which handle is calling.
    Hello { handle_id: String },
    /// Health check (post-hello, unauthenticated).
    Ping,
    /// Request enrollment of a brand-new handle. The broker prompts the user to
    /// confirm, then mints a handle and returns its id + secret exactly once.
    /// Not authenticated (the agent has no handle yet); gated entirely by the
    /// user confirming the popup.
    Enroll { label: String },
    /// Ask for a capability to an item. `item` is a human string the broker
    /// resolves (e.g. "example.com"); `proof` authenticates the handle.
    Request {
        handle_id: String,
        proof: String,
        item: String,
        action: Action,
        #[serde(default)]
        reason: String,
    },
    /// Redeem a `reveal` grant for the plaintext (single use).
    Consume { grant_id: String, proof: String },
    /// Redeem a `use` grant: the broker performs `target` itself.
    Perform {
        grant_id: String,
        proof: String,
        #[serde(default)]
        target: String,
    },
    /// List the grants currently live for this handle.
    ListGrants { handle_id: String, proof: String },
}

/// A response line from the broker to the agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum Response {
    /// Challenge nonce in reply to HELLO. The agent uses it to compute proofs
    /// for the rest of the connection.
    Nonce {
        nonce: String,
    },
    Pong,
    /// A newly enrolled handle. `secret` is delivered exactly once here and
    /// never again; the agent must store it in the OS keychain immediately.
    Enrolled {
        handle_id: String,
        secret: String,
    },
    /// A capability was minted (or an existing one applies).
    Grant {
        grant_id: String,
        ttl_secs: u64,
    },
    /// The plaintext for a `reveal` grant. Delivered once; the grant is dead
    /// afterward. The agent should route this to an fd/clipboard, not stdout.
    Secret {
        item: RevealedItem,
    },
    /// A `use` action completed.
    Done {
        ok: bool,
        detail: String,
    },
    /// The live grants for a handle (ids + metadata, never secrets).
    Grants {
        grants: Vec<GrantSummary>,
    },
    /// The user denied the request at the approval popup.
    Denied {
        reason: String,
    },
    /// A protocol / auth / resolution error.
    Error {
        message: String,
    },
}

/// The plaintext payload returned for a `reveal`. Only the fields relevant to
/// the item kind are populated.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevealedItem {
    pub id: String,
    pub kind: String, // "password" | "identity" | "bookmark"
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// Extra labeled fields (e.g. identity address parts).
    #[serde(default)]
    pub fields: Vec<(String, String)>,
}

/// Non-secret summary of a grant, for `ListGrants`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantSummary {
    pub grant_id: String,
    pub scope: Vec<String>,
    pub action: Action,
    pub expires_unix: u64,
    pub uses_remaining: u32,
}

/// Serialize a message to a single newline-terminated JSON line.
pub fn encode_line<T: Serialize>(msg: &T) -> String {
    let mut s = serde_json::to_string(msg).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

/// Parse one JSON line into a message.
pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

/// A human-readable label for the IPC endpoint, for log/error messages. The
/// actual bind/connect goes through [`super::transport`], which is the single
/// source of truth for the platform-specific name.
pub fn endpoint_path() -> String {
    super::transport::endpoint_label()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let req = Request::Request {
            handle_id: "hnd_abc".into(),
            proof: "deadbeef".into(),
            item: "example.com".into(),
            action: Action::Reveal,
            reason: "logging in".into(),
        };
        let line = encode_line(&req);
        assert!(line.ends_with('\n'));
        let back: Request = decode_line(&line).unwrap();
        match back {
            Request::Request { item, action, .. } => {
                assert_eq!(item, "example.com");
                assert_eq!(action, Action::Reveal);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_tag_is_uppercase() {
        let line = encode_line(&Response::Grant {
            grant_id: "grt_x".into(),
            ttl_secs: 60,
        });
        assert!(line.contains("\"type\":\"GRANT\""));
    }

    #[test]
    fn secret_response_round_trips() {
        let resp = Response::Secret {
            item: RevealedItem {
                id: "pw:https://x/|u".into(),
                kind: "password".into(),
                username: "u".into(),
                password: "p".into(),
                ..Default::default()
            },
        };
        let line = encode_line(&resp);
        let back: Response = decode_line(&line).unwrap();
        match back {
            Response::Secret { item } => assert_eq!(item.password, "p"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn endpoint_path_is_nonempty() {
        assert!(!endpoint_path().is_empty());
    }
}
