//! Local IPC broker: the trusted mediator between agents and the vault.
//!
//! Agents connect over a unix socket / named pipe (never TCP) and speak the
//! newline-JSON protocol in `brave_vault_core::agent::protocol`. The broker:
//!   - authenticates the calling handle (HMAC challenge-response),
//!   - resolves a human item query to concrete item ids,
//!   - matches pre-created / policy grants, or raises a live approval popup,
//!   - mints short-lived, single-use grants,
//!   - `reveal`s plaintext once (just-in-time) or `perform`s the action itself
//!     so the plaintext never reaches the agent (broker-performs).
//!
//! Everything sensitive is gated on the vault being unlocked. The master
//! secrets (mnemonic, services key) never leave this process.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Emitter, Manager};

use brave_vault_core::agent::auth;
use brave_vault_core::agent::model::{Action, ApprovedBy, AuditEntry, GrantRecord, HandleRecord};
use brave_vault_core::agent::protocol::{
    self, decode_line, encode_line, GrantSummary, Request, Response, RevealedItem,
};
use brave_vault_core::agent::resolve::{self, Match};
use brave_vault_core::agent::transport::{Conn, Listener};

use crate::{load_vault, write_vault, SharedState};

/// How long an ad-hoc grant lives, and how long we wait for the user to answer
/// an approval popup.
const DEFAULT_GRANT_TTL_SECS: u64 = 60;
const APPROVAL_TIMEOUT_SECS: u64 = 120;

/// The user's answer to an approval popup, delivered from a Tauri command back
/// to the blocked broker thread.
#[derive(Clone)]
pub struct ApprovalResponse {
    pub approved: bool,
    pub ttl_secs: u64,
    pub max_uses: u32,
}

/// Shared broker state. Managed by Tauri so commands (the popup responder) can
/// resolve pending approvals.
#[derive(Default)]
pub struct BrokerHandle {
    pending: Mutex<HashMap<String, mpsc::Sender<ApprovalResponse>>>,
}

impl BrokerHandle {
    /// Called by the `agent_respond` command when the user answers a popup.
    pub fn resolve(&self, request_id: &str, resp: ApprovalResponse) -> bool {
        let tx = self.pending.lock().unwrap().remove(request_id);
        match tx {
            Some(tx) => tx.send(resp).is_ok(),
            None => false,
        }
    }

    fn register(&self, request_id: String) -> mpsc::Receiver<ApprovalResponse> {
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(request_id, tx);
        rx
    }

    fn unregister(&self, request_id: &str) {
        self.pending.lock().unwrap().remove(request_id);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append an audit record (best-effort).
fn audit(
    event: &str,
    handle_id: &str,
    handle_label: &str,
    item_id: &str,
    action: Option<Action>,
    detail: &str,
) {
    let mut data = load_vault().unwrap_or_default();
    data.agent_audit.push(AuditEntry {
        at_unix: now_unix(),
        handle_id: handle_id.to_string(),
        handle_label: handle_label.to_string(),
        event: event.to_string(),
        item_id: item_id.to_string(),
        action,
        detail: detail.to_string(),
    });
    let _ = write_vault(&data);
}

/// Start the broker listener on a background thread. Gated per-request on the
/// vault being unlocked; the endpoint itself is bound at startup. Works on all
/// platforms via the cross-platform transport (unix sockets / Windows pipes).
pub fn start(app: AppHandle, state: SharedState) {
    std::thread::spawn(move || {
        let listener = match Listener::bind() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[broker] could not bind {}: {e}", protocol::endpoint_path());
                return;
            }
        };
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let app = app.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                let _ = handle_conn(conn, app, state);
            });
        }
    });
}

/// Handle a single client connection: HELLO handshake, then a request loop.
/// `Conn` implements `Read + Write`; a `BufReader` over `&Conn` reads while we
/// write to a second `&Conn` borrow, so no socket cloning is needed.
fn handle_conn(conn: Conn, app: AppHandle, state: SharedState) -> std::io::Result<()> {
    let mut reader = BufReader::new(&conn);
    let mut nonce: Option<String> = None;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // client hung up
        }
        let req: Request = match decode_line(&line) {
            Ok(r) => r,
            Err(e) => {
                write_resp(
                    &mut &conn,
                    &Response::Error {
                        message: format!("bad request: {e}"),
                    },
                )?;
                continue;
            }
        };
        let resp = dispatch(req, &mut nonce, &app, &state);
        write_resp(&mut &conn, &resp)?;
    }
    Ok(())
}

fn write_resp<W: Write>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    w.write_all(encode_line(resp).as_bytes())?;
    w.flush()
}

/// Route one request to a handler, threading the per-connection nonce.
fn dispatch(
    req: Request,
    nonce: &mut Option<String>,
    app: &AppHandle,
    state: &SharedState,
) -> Response {
    match req {
        Request::Hello { .. } => {
            let n = auth::new_nonce();
            *nonce = Some(n.clone());
            Response::Nonce { nonce: n }
        }
        Request::Ping => Response::Pong,
        Request::Enroll { label } => handle_enroll(label, app),
        Request::Request {
            handle_id,
            proof,
            item,
            action,
            reason,
        } => handle_request(handle_id, proof, item, action, reason, nonce, app, state),
        Request::Consume { grant_id, proof } => handle_consume(grant_id, proof, nonce, state),
        Request::Perform {
            grant_id,
            proof,
            target,
        } => handle_perform(grant_id, proof, target, nonce, app, state),
        Request::ListGrants { handle_id, proof } => handle_list_grants(handle_id, proof, nonce),
    }
}

/// Verify a handle's proof against the current connection nonce and return the
/// (active) handle record.
fn authed_handle(
    handle_id: &str,
    proof: &str,
    nonce: &Option<String>,
) -> Result<HandleRecord, Response> {
    let Some(nonce) = nonce.as_deref() else {
        return Err(Response::Error {
            message: "send HELLO first".into(),
        });
    };
    let data = load_vault().unwrap_or_default();
    let handle = data
        .agent_handles
        .iter()
        .find(|h| h.handle_id == handle_id && h.is_active())
        .cloned();
    let Some(handle) = handle else {
        return Err(Response::Error {
            message: "unknown or revoked handle".into(),
        });
    };
    if !auth::verify_proof(&handle.secret, nonce, proof) {
        return Err(Response::Error {
            message: "authentication failed".into(),
        });
    }
    Ok(handle)
}

/// Require the vault to be unlocked; return a clone of the decrypted collections
/// plus config + mnemonic needed to reveal/perform.
struct UnlockedData {
    passwords: Vec<brave_vault_core::model::PasswordItem>,
    identities: Vec<brave_vault_core::model::IdentityItem>,
    bookmarks: Vec<brave_vault_core::model::BookmarkItem>,
}

fn unlocked(state: &SharedState) -> Result<UnlockedData, Response> {
    let st = state.lock().unwrap();
    if st.config.is_none() {
        return Err(Response::Error {
            message: "vault is locked".into(),
        });
    }
    if st.mnemonic.is_none() {
        return Err(Response::Error {
            message: "no sync chain".into(),
        });
    }
    Ok(UnlockedData {
        passwords: st.passwords.iter().map(|r| r.item.clone()).collect(),
        identities: st.identities.clone(),
        bookmarks: st.bookmarks.clone(),
    })
}

fn handle_enroll(label: String, app: &AppHandle) -> Response {
    // Enrollment must be user-confirmed even though it isn't handle-authed.
    let decision = prompt_user(
        app,
        "enroll",
        "(new agent)",
        &format!("Enroll a new agent handle labeled \"{label}\"?"),
        None,
        "",
    );
    let Some(resp) = decision else {
        return Response::Error {
            message: "approval timed out".into(),
        };
    };
    if !resp.approved {
        return Response::Denied {
            reason: "user declined enrollment".into(),
        };
    }
    let handle_id = auth::new_handle_id();
    let secret = auth::new_handle_secret();
    let mut data = load_vault().unwrap_or_default();
    data.agent_handles.push(HandleRecord {
        handle_id: handle_id.clone(),
        secret: secret.clone(),
        label: label.clone(),
        created_unix: now_unix(),
        last_used_unix: None,
        revoked: false,
        policy: None,
    });
    if write_vault(&data).is_err() {
        return Response::Error {
            message: "failed to persist handle".into(),
        };
    }
    audit("enroll", &handle_id, &label, "", None, "handle enrolled");
    Response::Enrolled { handle_id, secret }
}

#[allow(clippy::too_many_arguments)]
fn handle_request(
    handle_id: String,
    proof: String,
    item: String,
    action: Action,
    reason: String,
    nonce: &Option<String>,
    app: &AppHandle,
    state: &SharedState,
) -> Response {
    let handle = match authed_handle(&handle_id, &proof, nonce) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let data = match unlocked(state) {
        Ok(d) => d,
        Err(r) => return r,
    };

    // Resolve the human query to concrete item id(s).
    let matches = resolve::resolve(&item, &data.passwords, &data.identities, &data.bookmarks);
    let chosen: Match = match matches.len() {
        0 => {
            return Response::Error {
                message: format!("no vault item matches \"{item}\""),
            }
        }
        1 => matches.into_iter().next().unwrap(),
        _ => {
            return Response::Error {
                message: format!(
                    "\"{item}\" is ambiguous ({} matches); be more specific",
                    matches.len()
                ),
            }
        }
    };
    touch_handle_last_used(&handle_id);

    // Decide: existing grant, standing policy, or a live prompt.
    let store = load_vault().unwrap_or_default();
    let now = now_unix();
    use brave_vault_core::agent::model::{decide, RequestDecision};
    match decide(&handle, &store.agent_grants, &chosen.id, action, now) {
        RequestDecision::Grant(grant_id) => {
            let ttl = grant_ttl_remaining(&grant_id).unwrap_or(DEFAULT_GRANT_TTL_SECS);
            audit(
                "issue",
                &handle_id,
                &handle.label,
                &chosen.id,
                Some(action),
                "matched pre-created grant",
            );
            Response::Grant {
                grant_id,
                ttl_secs: ttl,
            }
        }
        RequestDecision::AutoApprove => {
            let g = mint_grant(
                &handle_id,
                &chosen.id,
                action,
                DEFAULT_GRANT_TTL_SECS,
                1,
                ApprovedBy::HandlePolicy,
                &reason,
            );
            audit(
                "issue",
                &handle_id,
                &handle.label,
                &chosen.id,
                Some(action),
                "auto-approved by handle policy",
            );
            Response::Grant {
                grant_id: g.grant_id,
                ttl_secs: DEFAULT_GRANT_TTL_SECS,
            }
        }
        RequestDecision::Prompt => {
            let action_word = match action {
                Action::Reveal => "reveal",
                Action::Use => "use",
            };
            let prompt = format!(
                "Agent \"{}\" wants to {action_word} \"{}\" ({}).",
                handle.label, chosen.label, chosen.kind
            );
            match prompt_user(
                app,
                action_word,
                &chosen.label,
                &prompt,
                Some(action),
                &reason,
            ) {
                None => Response::Error {
                    message: "approval timed out".into(),
                },
                Some(r) if !r.approved => {
                    audit(
                        "deny",
                        &handle_id,
                        &handle.label,
                        &chosen.id,
                        Some(action),
                        "user denied",
                    );
                    Response::Denied {
                        reason: "user denied the request".into(),
                    }
                }
                Some(r) => {
                    let ttl = if r.ttl_secs == 0 {
                        DEFAULT_GRANT_TTL_SECS
                    } else {
                        r.ttl_secs
                    };
                    let uses = r.max_uses.max(1);
                    let g = mint_grant(
                        &handle_id,
                        &chosen.id,
                        action,
                        ttl,
                        uses,
                        ApprovedBy::UserPopup,
                        &reason,
                    );
                    audit(
                        "issue",
                        &handle_id,
                        &handle.label,
                        &chosen.id,
                        Some(action),
                        "user approved",
                    );
                    Response::Grant {
                        grant_id: g.grant_id,
                        ttl_secs: ttl,
                    }
                }
            }
        }
    }
}

fn handle_consume(
    grant_id: String,
    proof: String,
    nonce: &Option<String>,
    state: &SharedState,
) -> Response {
    // Load the grant, then auth as its owning handle.
    let mut data = load_vault().unwrap_or_default();
    let now = now_unix();
    let Some(pos) = data
        .agent_grants
        .iter()
        .position(|g| g.grant_id == grant_id)
    else {
        return Response::Error {
            message: "unknown grant".into(),
        };
    };
    let handle_id = data.agent_grants[pos].handle_id.clone();
    let handle = match authed_handle(&handle_id, &proof, nonce) {
        Ok(h) => h,
        Err(r) => return r,
    };
    {
        let g = &data.agent_grants[pos];
        if g.action != Action::Reveal {
            return Response::Error {
                message: "this grant is not a reveal grant".into(),
            };
        }
        if !g.is_live(now) {
            return Response::Error {
                message: "grant expired or exhausted".into(),
            };
        }
    }
    let item_id = data.agent_grants[pos]
        .scope
        .get(0)
        .cloned()
        .unwrap_or_default();

    // Fetch plaintext from the unlocked, in-memory data.
    let unlocked = match unlocked(state) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Some(item) = reveal_item(&item_id, &unlocked) else {
        return Response::Error {
            message: "item no longer present in vault".into(),
        };
    };

    // Consume one use and persist.
    data.agent_grants[pos].consume();
    if data.agent_grants[pos].uses_remaining == 0 {
        data.agent_grants.remove(pos);
    }
    let _ = write_vault(&data);
    audit(
        "reveal",
        &handle_id,
        &handle.label,
        &item_id,
        Some(Action::Reveal),
        "secret revealed once",
    );
    Response::Secret { item }
}

fn handle_perform(
    grant_id: String,
    proof: String,
    target: String,
    nonce: &Option<String>,
    app: &AppHandle,
    state: &SharedState,
) -> Response {
    let mut data = load_vault().unwrap_or_default();
    let now = now_unix();
    let Some(pos) = data
        .agent_grants
        .iter()
        .position(|g| g.grant_id == grant_id)
    else {
        return Response::Error {
            message: "unknown grant".into(),
        };
    };
    let handle_id = data.agent_grants[pos].handle_id.clone();
    let handle = match authed_handle(&handle_id, &proof, nonce) {
        Ok(h) => h,
        Err(r) => return r,
    };
    {
        let g = &data.agent_grants[pos];
        if g.action != Action::Use {
            return Response::Error {
                message: "this grant is not a use grant".into(),
            };
        }
        if !g.is_live(now) {
            return Response::Error {
                message: "grant expired or exhausted".into(),
            };
        }
    }
    let item_id = data.agent_grants[pos]
        .scope
        .get(0)
        .cloned()
        .unwrap_or_default();
    let unlocked = match unlocked(state) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Some(item) = reveal_item(&item_id, &unlocked) else {
        return Response::Error {
            message: "item no longer present in vault".into(),
        };
    };

    // Broker-performs: open the item's URL (or an explicit target) in the
    // browser and place the password on the clipboard *here*, so the plaintext
    // never crosses to the agent. The agent gets only success/failure.
    let url = if !target.is_empty() {
        target
    } else {
        item.url.clone()
    };
    let mut detail = String::new();
    if !url.is_empty() {
        match app.opener().open_url(&url, None::<&str>) {
            Ok(()) => detail.push_str(&format!("opened {url}")),
            Err(e) => {
                return Response::Done {
                    ok: false,
                    detail: format!("open failed: {e}"),
                }
            }
        }
    }
    if !item.password.is_empty() {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        if app.clipboard().write_text(item.password.clone()).is_ok() {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str("password copied to clipboard by broker");
        }
    }

    data.agent_grants[pos].consume();
    if data.agent_grants[pos].uses_remaining == 0 {
        data.agent_grants.remove(pos);
    }
    let _ = write_vault(&data);
    audit(
        "perform",
        &handle_id,
        &handle.label,
        &item_id,
        Some(Action::Use),
        &detail,
    );
    Response::Done { ok: true, detail }
}

fn handle_list_grants(handle_id: String, proof: String, nonce: &Option<String>) -> Response {
    let handle = match authed_handle(&handle_id, &proof, nonce) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let data = load_vault().unwrap_or_default();
    let now = now_unix();
    let grants = data
        .agent_grants
        .iter()
        .filter(|g| g.handle_id == handle.handle_id && g.is_live(now))
        .map(|g| GrantSummary {
            grant_id: g.grant_id.clone(),
            scope: g.scope.clone(),
            action: g.action,
            expires_unix: g.expires_unix,
            uses_remaining: g.uses_remaining,
        })
        .collect();
    Response::Grants { grants }
}

// ---------- helpers ----------

/// Mint and persist a new grant.
fn mint_grant(
    handle_id: &str,
    item_id: &str,
    action: Action,
    ttl_secs: u64,
    max_uses: u32,
    approved_by: ApprovedBy,
    reason: &str,
) -> GrantRecord {
    let now = now_unix();
    let g = GrantRecord {
        grant_id: auth::new_grant_id(),
        handle_id: handle_id.to_string(),
        scope: vec![item_id.to_string()],
        action,
        created_unix: now,
        expires_unix: now + ttl_secs,
        max_uses,
        uses_remaining: max_uses,
        approved_by,
        reason: reason.to_string(),
    };
    let mut data = load_vault().unwrap_or_default();
    data.agent_grants.push(g.clone());
    let _ = write_vault(&data);
    g
}

fn grant_ttl_remaining(grant_id: &str) -> Option<u64> {
    let data = load_vault()?;
    let g = data.agent_grants.iter().find(|g| g.grant_id == grant_id)?;
    Some(g.expires_unix.saturating_sub(now_unix()))
}

fn touch_handle_last_used(handle_id: &str) {
    let mut data = load_vault().unwrap_or_default();
    if let Some(h) = data
        .agent_handles
        .iter_mut()
        .find(|h| h.handle_id == handle_id)
    {
        h.last_used_unix = Some(now_unix());
        let _ = write_vault(&data);
    }
}

/// Build the plaintext payload for an item id from the unlocked collections.
fn reveal_item(item_id: &str, data: &UnlockedData) -> Option<RevealedItem> {
    if item_id.starts_with("pw:") {
        let it = data
            .passwords
            .iter()
            .find(|p| resolve::password_id(p) == item_id)?;
        return Some(RevealedItem {
            id: item_id.to_string(),
            kind: "password".into(),
            title: it.title(),
            username: it.username.clone(),
            password: it.password.clone(),
            url: it.website(),
            notes: it.notes.clone(),
            fields: Vec::new(),
        });
    }
    if let Some(guid) = item_id.strip_prefix("id:") {
        let it = data.identities.iter().find(|i| i.guid == guid)?;
        let fields = vec![
            ("Name".into(), it.name.clone()),
            ("Email".into(), it.email.clone()),
            ("Phone".into(), it.phone.clone()),
            ("Company".into(), it.company.clone()),
            ("Street".into(), it.street.clone()),
            ("City".into(), it.city.clone()),
            ("State".into(), it.state.clone()),
            ("Zip".into(), it.zip.clone()),
            ("Country".into(), it.country.clone()),
        ]
        .into_iter()
        .filter(|(_, v): &(String, String)| !v.is_empty())
        .collect();
        return Some(RevealedItem {
            id: item_id.to_string(),
            kind: "identity".into(),
            title: it.title(),
            fields,
            ..Default::default()
        });
    }
    if let Some(guid) = item_id.strip_prefix("bm:") {
        let b = data.bookmarks.iter().find(|b| b.guid == guid)?;
        return Some(RevealedItem {
            id: item_id.to_string(),
            kind: "bookmark".into(),
            title: b.title.clone(),
            url: b.url.clone(),
            ..Default::default()
        });
    }
    None
}

/// Emit an approval request to the UI and block until the user answers or the
/// timeout elapses. Returns None on timeout.
fn prompt_user(
    app: &AppHandle,
    action_word: &str,
    item_label: &str,
    message: &str,
    action: Option<Action>,
    reason: &str,
) -> Option<ApprovalResponse> {
    let request_id = auth::new_grant_id();
    let broker = app.state::<BrokerHandle>();
    let rx = broker.register(request_id.clone());

    let _ = app.emit(
        "agent://approval-request",
        serde_json::json!({
            "request_id": request_id,
            "action": action_word,
            "item": item_label,
            "message": message,
            "reason": reason,
            "is_use": matches!(action, Some(Action::Use)),
        }),
    );

    let result = rx
        .recv_timeout(Duration::from_secs(APPROVAL_TIMEOUT_SECS))
        .ok();
    if result.is_none() {
        broker.unregister(&request_id);
    }
    result
}

// Bring the opener extension trait into scope for handle_perform.
use tauri_plugin_opener::OpenerExt;
