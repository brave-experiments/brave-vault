//! Data model for agent access: long-lived handles and short-lived grants.
//!
//! A **handle** authenticates *who is asking* (an enrolled agent). It grants
//! nothing on its own. A **grant** is a narrow, short-lived, use-limited
//! capability to `reveal` or `use` one or more specific items. Grants are what
//! actually authorize access; handles only authorize *requesting* a grant.

use serde::{Deserialize, Serialize};

/// What an agent may do with the item(s) named by a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Return the plaintext secret to the agent once (just-in-time reveal).
    Reveal,
    /// The broker performs the privileged action; the agent never sees the
    /// plaintext (true zero-knowledge).
    Use,
    /// Grab the live browser session (cookies) for an approved origin set and
    /// return it to the agent. The scope holds `origin:<host>` entries rather
    /// than vault item ids; nothing is stored — it's a one-shot live grab.
    Session,
}

/// What kind of client a handle belongs to. Ordinary agents are `Agent`; the
/// browser form-injector (native-messaging host) enrolls as `Injector`. Only an
/// `Injector` handle may service injection jobs, and there is no wire path to
/// enroll one — the app auto-provisions it. This keeps a compromised agent from
/// ever registering as the injector and receiving plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HandleKind {
    #[default]
    Agent,
    Injector,
}

/// How a grant came to exist — recorded for the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovedBy {
    /// The user approved a live approval popup.
    UserPopup,
    /// Matched a grant the user created ahead of time.
    PreCreated,
    /// Allowed automatically by the handle's standing policy.
    HandlePolicy,
}

/// A long-lived agent identity, provisioned once by the user. Persisted inside
/// the encrypted vault (within the broker's trust boundary). The `secret` is
/// used for HMAC challenge-response so the raw secret never crosses the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandleRecord {
    pub handle_id: String,
    /// High-entropy secret (hex). Stored encrypted-at-rest; never returned to
    /// the agent after enrollment and never logged.
    pub secret: String,
    pub label: String,
    pub created_unix: u64,
    #[serde(default)]
    pub last_used_unix: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    /// Standing policy: if set, requests matching it are auto-approved without a
    /// popup. `None` means "always prompt".
    #[serde(default)]
    pub policy: Option<HandlePolicy>,
    /// What kind of client this handle is. Defaults to `Agent` so handles
    /// serialized before this field existed load unchanged.
    #[serde(default)]
    pub kind: HandleKind,
}

impl HandleRecord {
    pub fn is_active(&self) -> bool {
        !self.revoked
    }

    pub fn is_injector(&self) -> bool {
        self.kind == HandleKind::Injector
    }
}

/// A standing auto-approval policy attached to a handle. Deliberately narrow:
/// callers should prefer pre-created grants for anything item-specific.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandlePolicy {
    /// Item ids this handle may access without a popup. Empty = none.
    #[serde(default)]
    pub allowed_items: Vec<String>,
    /// Actions permitted under this policy.
    #[serde(default)]
    pub allowed_actions: Vec<Action>,
}

impl HandlePolicy {
    fn permits(&self, item_id: &str, action: Action) -> bool {
        self.allowed_actions.contains(&action) && self.allowed_items.iter().any(|i| i == item_id)
    }
}

/// A narrow, short-lived, use-limited capability. This is the "one-time token":
/// for `reveal` it may briefly cross into the agent; for `use` it never does.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantRecord {
    pub grant_id: String,
    pub handle_id: String,
    /// Explicit item ids this grant covers (reusing the app id scheme:
    /// `pw:<realm>|<user>`, `bm:<guid>`, `id:<guid>`). Non-empty.
    pub scope: Vec<String>,
    pub action: Action,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub max_uses: u32,
    pub uses_remaining: u32,
    pub approved_by: ApprovedBy,
    /// Free-text reason the agent supplied, surfaced in the audit log.
    #[serde(default)]
    pub reason: String,
}

impl GrantRecord {
    /// True if the grant is still live at `now`: not expired and has uses left.
    pub fn is_live(&self, now_unix: u64) -> bool {
        self.uses_remaining > 0 && now_unix < self.expires_unix
    }

    /// True if this grant authorizes `action` on `item_id` at `now`.
    pub fn covers(&self, item_id: &str, action: Action, now_unix: u64) -> bool {
        self.is_live(now_unix) && self.action == action && self.scope.iter().any(|s| s == item_id)
    }

    /// Consume one use. Returns false if none remained (already exhausted).
    pub fn consume(&mut self) -> bool {
        if self.uses_remaining == 0 {
            return false;
        }
        self.uses_remaining -= 1;
        true
    }
}

/// One append-only audit record. Written on grant issuance and on every
/// consume/perform. Never contains plaintext secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at_unix: u64,
    pub handle_id: String,
    #[serde(default)]
    pub handle_label: String,
    /// "issue" | "reveal" | "perform" | "deny" | "revoke".
    pub event: String,
    #[serde(default)]
    pub item_id: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub detail: String,
}

/// The result of matching a request against the store: either an existing
/// pre-created/policy grant applies, or a popup is required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    /// A pre-created grant with this id already authorizes the request.
    Grant(String),
    /// The handle's standing policy auto-approves; mint a fresh grant.
    AutoApprove,
    /// No standing authorization — the broker must prompt the user.
    Prompt,
}

/// Decide how to satisfy a request for `item_id`/`action` from `handle`, given
/// the current grants. Pure and time-parameterized for testability.
pub fn decide(
    handle: &HandleRecord,
    grants: &[GrantRecord],
    item_id: &str,
    action: Action,
    now_unix: u64,
) -> RequestDecision {
    if let Some(g) = grants
        .iter()
        .find(|g| g.handle_id == handle.handle_id && g.covers(item_id, action, now_unix))
    {
        return RequestDecision::Grant(g.grant_id.clone());
    }
    if handle
        .policy
        .as_ref()
        .map(|p| p.permits(item_id, action))
        .unwrap_or(false)
    {
        return RequestDecision::AutoApprove;
    }
    RequestDecision::Prompt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> HandleRecord {
        HandleRecord {
            handle_id: "h1".into(),
            secret: "deadbeef".into(),
            label: "test".into(),
            created_unix: 1000,
            last_used_unix: None,
            revoked: false,
            policy: None,
            kind: HandleKind::Agent,
        }
    }

    fn grant(id: &str, scope: &[&str], action: Action, expires: u64, uses: u32) -> GrantRecord {
        GrantRecord {
            grant_id: id.into(),
            handle_id: "h1".into(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
            action,
            created_unix: 1000,
            expires_unix: expires,
            max_uses: uses,
            uses_remaining: uses,
            approved_by: ApprovedBy::PreCreated,
            reason: String::new(),
        }
    }

    #[test]
    fn handle_kind_defaults_to_agent_for_old_records() {
        // A handle serialized before `kind` existed has no such field.
        let json = r#"{"handle_id":"h1","secret":"s","label":"l","created_unix":1}"#;
        let h: HandleRecord = serde_json::from_str(json).unwrap();
        assert_eq!(h.kind, HandleKind::Agent);
        assert!(!h.is_injector());
    }

    #[test]
    fn injector_kind_round_trips() {
        let mut h = handle();
        h.kind = HandleKind::Injector;
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"kind\":\"injector\""));
        let back: HandleRecord = serde_json::from_str(&json).unwrap();
        assert!(back.is_injector());
    }

    #[test]
    fn live_requires_uses_and_time() {
        let mut g = grant("g", &["pw:x|u"], Action::Reveal, 2000, 1);
        assert!(g.is_live(1500));
        assert!(!g.is_live(2000)); // expired at boundary
        assert!(g.consume());
        assert!(!g.is_live(1500)); // no uses left
        assert!(!g.consume());
    }

    #[test]
    fn covers_matches_scope_and_action() {
        let g = grant("g", &["pw:x|u"], Action::Reveal, 2000, 1);
        assert!(g.covers("pw:x|u", Action::Reveal, 1500));
        assert!(!g.covers("pw:x|u", Action::Use, 1500)); // wrong action
        assert!(!g.covers("pw:y|u", Action::Reveal, 1500)); // wrong item
        assert!(!g.covers("pw:x|u", Action::Reveal, 3000)); // expired
    }

    #[test]
    fn decide_prefers_existing_grant() {
        let h = handle();
        let grants = vec![grant("g1", &["pw:x|u"], Action::Reveal, 2000, 1)];
        assert_eq!(
            decide(&h, &grants, "pw:x|u", Action::Reveal, 1500),
            RequestDecision::Grant("g1".into())
        );
    }

    #[test]
    fn decide_falls_back_to_policy_then_prompt() {
        let mut h = handle();
        assert_eq!(
            decide(&h, &[], "pw:x|u", Action::Reveal, 1500),
            RequestDecision::Prompt
        );
        h.policy = Some(HandlePolicy {
            allowed_items: vec!["pw:x|u".into()],
            allowed_actions: vec![Action::Reveal],
        });
        assert_eq!(
            decide(&h, &[], "pw:x|u", Action::Reveal, 1500),
            RequestDecision::AutoApprove
        );
        // Wrong action still prompts.
        assert_eq!(
            decide(&h, &[], "pw:x|u", Action::Use, 1500),
            RequestDecision::Prompt
        );
    }

    #[test]
    fn expired_grant_ignored_by_decide() {
        let h = handle();
        let grants = vec![grant("g1", &["pw:x|u"], Action::Reveal, 1000, 1)];
        assert_eq!(
            decide(&h, &grants, "pw:x|u", Action::Reveal, 1500),
            RequestDecision::Prompt
        );
    }
}
