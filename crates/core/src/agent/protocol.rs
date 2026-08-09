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
//!   -- action = use, via = inject (default) --
//!   agent → PERFORM { grant_id, proof, target, via=inject }
//!   broker → DONE   { ok, detail }              (broker drives the injector)
//!   -- injector host (separate connection, injector-kind handle) --
//!   host → AWAITJOB { handle_id, proof }
//!   broker → JOB   { job_id, origin, url, username, password }   (or NOJOB)
//!   host → JOBRESULT { job_id, ok, detail }
//!   broker → JOBACK
//! ```
//! (Message tags are the variant names upper-cased, e.g. `AwaitJob` → `AWAITJOB`.)
//! Every authenticated message carries a fresh `proof` (HMAC over the last
//! nonce the broker issued on this connection).

use serde::{Deserialize, Serialize};

use super::model::Action;

/// How the broker should carry out a `use` (perform) action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    /// Fill the credential into the page's login form via the browser extension
    /// so the plaintext never reaches the agent. The default, and the only
    /// genuinely zero-knowledge path.
    #[default]
    Inject,
    /// Copy the password to the OS clipboard. Explicit opt-in only: any local
    /// process can read the clipboard, so this is NOT zero-knowledge and is
    /// labeled as such in the approval popup and audit log.
    Clipboard,
}

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
        /// How to perform the action. Defaults to `Inject`, so an older agent
        /// binary that omits the field gets the secure form-injection path.
        #[serde(default)]
        via: Via,
    },
    /// List the grants currently live for this handle.
    ListGrants { handle_id: String, proof: String },
    /// The browser-injector native-messaging host registers as the active
    /// injector and blocks waiting for a job. Must authenticate as an
    /// injector-kind handle; the broker rejects ordinary agents here. Replies
    /// with `Job` when one is dispatched, or `NoJob` on keepalive timeout (the
    /// host re-polls). This long-poll inverts the client-initiated protocol so
    /// the broker can push a job without unsolicited frames.
    AwaitJob { handle_id: String, proof: String },
    /// Report the outcome of a previously-dispatched injection job.
    JobResult {
        job_id: String,
        ok: bool,
        #[serde(default)]
        detail: String,
    },
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
    /// An injection job for the injector host to carry out via the extension.
    /// Carries the plaintext credential — the broker only ever writes this to a
    /// connection that authenticated as an injector-kind handle.
    Job {
        job_id: String,
        /// The origin (scheme://host[:port]) the fill is bound to.
        origin: String,
        /// The full URL to open/focus.
        url: String,
        username: String,
        password: String,
    },
    /// Keepalive reply to `AwaitJob`: no job within the poll window; the host
    /// should re-issue `AwaitJob`.
    NoJob,
    /// Acknowledgement of a `JobResult`.
    JobAck,
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

    #[test]
    fn perform_via_defaults_to_inject() {
        // An older agent that omits `via` must decode to the secure default.
        let line = r#"{"type":"PERFORM","grant_id":"g","proof":"p"}"#;
        let back: Request = decode_line(line).unwrap();
        match back {
            Request::Perform { via, target, .. } => {
                assert_eq!(via, Via::Inject);
                assert_eq!(target, "");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn via_serializes_lowercase() {
        let line = encode_line(&Request::Perform {
            grant_id: "g".into(),
            proof: "p".into(),
            target: String::new(),
            via: Via::Clipboard,
        });
        assert!(line.contains("\"via\":\"clipboard\""));
    }

    #[test]
    fn await_job_round_trips() {
        let line = encode_line(&Request::AwaitJob {
            handle_id: "hnd_x".into(),
            proof: "deadbeef".into(),
        });
        assert!(line.contains("\"type\":\"AWAITJOB\""));
        let back: Request = decode_line(&line).unwrap();
        assert!(matches!(back, Request::AwaitJob { .. }));
    }

    #[test]
    fn job_response_round_trips() {
        let resp = Response::Job {
            job_id: "j1".into(),
            origin: "https://example.com".into(),
            url: "https://example.com/login".into(),
            username: "alice".into(),
            password: "p".into(),
        };
        let line = encode_line(&resp);
        let back: Response = decode_line(&line).unwrap();
        match back {
            Response::Job {
                origin, password, ..
            } => {
                assert_eq!(origin, "https://example.com");
                assert_eq!(password, "p");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn job_result_and_acks_round_trip() {
        let line = encode_line(&Request::JobResult {
            job_id: "j1".into(),
            ok: true,
            detail: "filled".into(),
        });
        assert!(matches!(
            decode_line::<Request>(&line).unwrap(),
            Request::JobResult { ok: true, .. }
        ));
        assert!(matches!(
            decode_line::<Response>(&encode_line(&Response::NoJob)).unwrap(),
            Response::NoJob
        ));
        assert!(matches!(
            decode_line::<Response>(&encode_line(&Response::JobAck)).unwrap(),
            Response::JobAck
        ));
    }
}
