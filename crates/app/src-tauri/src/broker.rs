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

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Emitter, Manager};

use brave_vault_core::agent::auth;
use brave_vault_core::agent::model::{Action, ApprovedBy, AuditEntry, GrantRecord, HandleRecord};
use brave_vault_core::agent::protocol::{
    self, decode_line, encode_line, CookieData, GrantSummary, Request, Response, RevealedItem, Via,
};
use brave_vault_core::agent::resolve::{self, Match};
use brave_vault_core::agent::transport::{Conn, Listener};

use crate::{load_vault, write_vault, SharedState};

/// How long an ad-hoc grant lives, and how long we wait for the user to answer
/// an approval popup.
const DEFAULT_GRANT_TTL_SECS: u64 = 60;
const APPROVAL_TIMEOUT_SECS: u64 = 120;
/// How long the agent's PERFORM waits for the injector to finish a fill.
const INJECT_TIMEOUT_SECS: u64 = 30;
/// How long an injector host blocks in AWAITJOB before we return NOJOB so it
/// can re-poll (keepalive).
const INJECTOR_KEEPALIVE_SECS: u64 = 25;

/// The user's answer to an approval popup, delivered from a Tauri command back
/// to the blocked broker thread.
#[derive(Clone)]
pub struct ApprovalResponse {
    pub approved: bool,
    pub ttl_secs: u64,
    pub max_uses: u32,
}

/// A job handed to the connected injector host. Only ever delivered to an
/// injector-authed connection. `Fill` carries the plaintext credential to type;
/// `Grab` carries only the approved origin set (the cookies flow back).
#[derive(Clone)]
enum InjectJob {
    Fill {
        job_id: String,
        origin: String,
        url: String,
        username: String,
        password: String,
    },
    Grab {
        job_id: String,
        origins: Vec<String>,
    },
}

impl InjectJob {
    fn job_id(&self) -> &str {
        match self {
            InjectJob::Fill { job_id, .. } => job_id,
            InjectJob::Grab { job_id, .. } => job_id,
        }
    }
}

/// The outcome the injector host reports back for a job. `cookies` is populated
/// only for a grab; empty for a fill.
pub struct InjectOutcome {
    pub ok: bool,
    pub detail: String,
    pub cookies: Vec<CookieData>,
}

/// Shared broker state. Managed by Tauri so commands (the popup responder) can
/// resolve pending approvals, and so the agent's PERFORM thread and the
/// injector host's AWAITJOB thread can rendezvous.
#[derive(Default)]
pub struct BrokerHandle {
    pending: Mutex<HashMap<String, mpsc::Sender<ApprovalResponse>>>,
    /// Queued injection jobs waiting for an injector host to pick them up.
    inject_queue: (Mutex<VecDeque<InjectJob>>, Condvar),
    /// Routes a JobResult back to the blocked PERFORM thread, keyed by job_id.
    inject_results: Mutex<HashMap<String, mpsc::Sender<InjectOutcome>>>,
    /// Number of injector host connections currently polling. >0 means an
    /// injector is available to service a fill.
    injectors_present: AtomicUsize,
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

    /// True while at least one injector host is connected and polling.
    pub fn injector_present(&self) -> bool {
        self.injectors_present.load(Ordering::SeqCst) > 0
    }

    fn injector_connected(&self) {
        self.injectors_present.fetch_add(1, Ordering::SeqCst);
    }

    fn injector_disconnected(&self) {
        // saturating: never underflow below zero.
        let mut cur = self.injectors_present.load(Ordering::SeqCst);
        while cur > 0 {
            match self.injectors_present.compare_exchange(
                cur,
                cur - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Queue a job for an injector host and register a channel for its result.
    /// Returns the receiver the PERFORM thread blocks on.
    fn dispatch_inject(&self, job: InjectJob) -> mpsc::Receiver<InjectOutcome> {
        let (tx, rx) = mpsc::channel();
        self.inject_results
            .lock()
            .unwrap()
            .insert(job.job_id().to_string(), tx);
        let (q, cv) = &self.inject_queue;
        q.lock().unwrap().push_back(job);
        cv.notify_one();
        rx
    }

    /// Block up to `timeout` for the next queued job. `None` on timeout so the
    /// host re-polls (keepalive).
    fn take_next_job(&self, timeout: Duration) -> Option<InjectJob> {
        let (q, cv) = &self.inject_queue;
        let mut guard = q.lock().unwrap();
        loop {
            if let Some(job) = guard.pop_front() {
                return Some(job);
            }
            let (g, res) = cv.wait_timeout(guard, timeout).unwrap();
            guard = g;
            if res.timed_out() {
                return guard.pop_front();
            }
        }
    }

    /// Deliver a job's outcome to the blocked PERFORM thread.
    fn resolve_inject(&self, job_id: &str, outcome: InjectOutcome) -> bool {
        let tx = self.inject_results.lock().unwrap().remove(job_id);
        match tx {
            Some(tx) => tx.send(outcome).is_ok(),
            None => false,
        }
    }

    /// Drop a job's result channel (e.g. the PERFORM thread timed out).
    fn cancel_inject(&self, job_id: &str) {
        self.inject_results.lock().unwrap().remove(job_id);
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
    // Set true the first time this connection successfully polls as an injector.
    // Used to gate JobResult and to clear injector presence on disconnect.
    let mut is_injector = false;

    let mut line = String::new();
    let result = loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break Ok(()), // client hung up
            Ok(_) => {}
            Err(e) => break Err(e),
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
        let resp = dispatch(req, &mut nonce, &mut is_injector, &app, &state);
        write_resp(&mut &conn, &resp)?;
    };
    // On teardown, release this connection's injector slot if it held one.
    if is_injector {
        app.state::<BrokerHandle>().injector_disconnected();
    }
    result
}

fn write_resp<W: Write>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    w.write_all(encode_line(resp).as_bytes())?;
    w.flush()
}

/// Route one request to a handler, threading the per-connection nonce.
fn dispatch(
    req: Request,
    nonce: &mut Option<String>,
    is_injector: &mut bool,
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
            via,
        } => handle_perform(grant_id, proof, target, via, nonce, app, state),
        Request::ListGrants { handle_id, proof } => handle_list_grants(handle_id, proof, nonce),
        Request::AwaitJob { handle_id, proof } => {
            handle_await_job(handle_id, proof, nonce, is_injector, app)
        }
        Request::JobResult { job_id, ok, detail } => {
            handle_job_result(job_id, ok, detail, *is_injector, app)
        }
        Request::GrabSession { grant_id, proof } => {
            handle_grab_session(grant_id, proof, nonce, app)
        }
        Request::SessionResult {
            job_id,
            ok,
            cookies,
            detail,
        } => handle_session_result(job_id, ok, cookies, detail, *is_injector, app),
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
        kind: brave_vault_core::agent::model::HandleKind::Agent,
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

    // A session grab targets an approved set of browser origins, not a stored
    // vault item, so it skips vault resolution entirely.
    if action == Action::Session {
        return handle_session_request(&handle_id, &handle.label, &item, &reason, app);
    }

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
                Action::Session => "grab the session for",
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

/// Parse the comma-separated host set for a session grab, normalizing each to a
/// bare host (accepts `mail.google.com` or `https://mail.google.com/...`).
/// Returns an error string if any entry has no usable host.
fn parse_origin_set(item: &str) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    for raw in item.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        // Accept a full URL or a bare host; normalize to the host.
        let host = if entry.contains("://") {
            let origin = resolve::origin_of(entry);
            origin
                .split_once("://")
                .map(|(_, h)| h.to_string())
                .unwrap_or_default()
        } else {
            // Reject anything with a path/space — we want a bare host.
            entry
                .split(['/', ' ', '?', '#'])
                .next()
                .unwrap_or("")
                .to_lowercase()
        };
        if host.is_empty() || !host.contains('.') {
            return Err(format!("\"{entry}\" is not a valid host"));
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        Err("no hosts given; pass a comma-separated host set".into())
    } else {
        Ok(hosts)
    }
}

/// Handle a `session` request: always prompt (there's no stored item to
/// pre-authorize against), then mint an origin-scoped grant on approval.
fn handle_session_request(
    handle_id: &str,
    handle_label: &str,
    item: &str,
    reason: &str,
    app: &AppHandle,
) -> Response {
    let hosts = match parse_origin_set(item) {
        Ok(h) => h,
        Err(e) => return Response::Error { message: e },
    };
    touch_handle_last_used(handle_id);
    let host_list = hosts.join(", ");
    let prompt = format!(
        "Agent \"{handle_label}\" wants to grab the logged-in browser session \
         (cookies) for: {host_list}. The agent will receive these cookies."
    );
    match prompt_user(
        app,
        "grab session",
        &host_list,
        &prompt,
        Some(Action::Session),
        reason,
    ) {
        None => Response::Error {
            message: "approval timed out".into(),
        },
        Some(r) if !r.approved => {
            audit(
                "deny",
                handle_id,
                handle_label,
                &host_list,
                Some(Action::Session),
                "user denied session grab",
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
            let scope: Vec<String> = hosts.iter().map(|h| format!("origin:{h}")).collect();
            let g = mint_grant_scoped(
                handle_id,
                scope,
                Action::Session,
                ttl,
                uses,
                ApprovedBy::UserPopup,
                reason,
            );
            audit(
                "issue",
                handle_id,
                handle_label,
                &host_list,
                Some(Action::Session),
                "user approved session grab",
            );
            Response::Grant {
                grant_id: g.grant_id,
                ttl_secs: ttl,
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

#[allow(clippy::too_many_arguments)]
fn handle_perform(
    grant_id: String,
    proof: String,
    target: String,
    via: Via,
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

    // Carry out the action. `inject` is zero-knowledge (the browser extension
    // fills the form); `clipboard` is an explicit, honestly-labeled fallback.
    // A failed attempt does NOT consume the single-use grant, so a transient
    // error leaves the user's approval intact for a retry within the TTL.
    let outcome = match via {
        Via::Inject => perform_inject(&item, &target, app),
        Via::Clipboard => perform_clipboard(&item, &target, app),
    };
    match outcome {
        Ok(detail) => {
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
        Err(detail) => {
            // Grant is left live for a retry within its TTL.
            audit(
                "perform",
                &handle_id,
                &handle.label,
                &item_id,
                Some(Action::Use),
                &format!("failed: {detail}"),
            );
            Response::Done { ok: false, detail }
        }
    }
}

/// Resolve the URL to inject/open: an explicit `target` must share the item's
/// origin (so the agent can't steer a fill to an attacker page); otherwise fall
/// back to the item's own URL.
fn resolve_target(item: &RevealedItem, target: &str) -> Result<String, String> {
    if target.is_empty() {
        return Ok(item.url.clone());
    }
    if item.url.is_empty() || resolve::same_origin(target, &item.url) {
        Ok(target.to_string())
    } else {
        Err("target origin does not match the item's origin".into())
    }
}

/// Zero-knowledge path: hand the plaintext to the connected injector host, which
/// fills the login form via the browser extension. The plaintext never reaches
/// the agent. Fails clearly (no silent clipboard fallback) if no injector is
/// connected. On success returns an audit-friendly detail string.
fn perform_inject(item: &RevealedItem, target: &str, app: &AppHandle) -> Result<String, String> {
    let broker = app.state::<BrokerHandle>();
    if !broker.injector_present() {
        return Err(
            "no injector connected; the Brave extension/native host is not running. \
             Re-run with --via clipboard to fall back explicitly."
                .into(),
        );
    }
    let url = resolve_target(item, target)?;
    let origin = resolve::origin_of(&url);
    if origin.is_empty() {
        return Err("item has no usable URL/origin to inject into".into());
    }
    let job_id = auth::new_grant_id();
    let job = InjectJob::Fill {
        job_id: job_id.clone(),
        origin: origin.clone(),
        url,
        username: item.username.clone(),
        password: item.password.clone(),
    };
    let rx = broker.dispatch_inject(job);
    match rx.recv_timeout(Duration::from_secs(INJECT_TIMEOUT_SECS)) {
        Ok(outcome) if outcome.ok => Ok(format!("injected into {origin}")),
        Ok(outcome) => Err(format!("inject failed: {}", outcome.detail)),
        Err(_) => {
            broker.cancel_inject(&job_id);
            Err("inject timed out (extension did not respond)".into())
        }
    }
}

/// Explicit opt-in fallback: open the URL and copy the password to the OS
/// clipboard. NOT zero-knowledge — any local process can read the clipboard —
/// so the detail says so, and the approval popup labels it too.
fn perform_clipboard(item: &RevealedItem, target: &str, app: &AppHandle) -> Result<String, String> {
    let url = resolve_target(item, target)?;
    let mut detail = String::new();
    if !url.is_empty() {
        app.opener()
            .open_url(&url, None::<&str>)
            .map_err(|e| format!("open failed: {e}"))?;
        detail.push_str(&format!("opened {url}"));
    }
    if !item.password.is_empty() {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        app.clipboard()
            .write_text(item.password.clone())
            .map_err(|e| format!("clipboard write failed: {e}"))?;
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str("password copied to clipboard (readable by other local apps)");
    }
    Ok(detail)
}

/// The injector native-messaging host registers here and blocks for a job. Only
/// an injector-kind handle may poll; ordinary agents are rejected so they can
/// never receive injected plaintext.
fn handle_await_job(
    handle_id: String,
    proof: String,
    nonce: &Option<String>,
    is_injector: &mut bool,
    app: &AppHandle,
) -> Response {
    let handle = match authed_handle(&handle_id, &proof, nonce) {
        Ok(h) => h,
        Err(r) => return r,
    };
    if !handle.is_injector() {
        return Response::Error {
            message: "not an injector handle".into(),
        };
    }
    let broker = app.state::<BrokerHandle>();
    // First successful poll on this connection claims an injector slot.
    if !*is_injector {
        *is_injector = true;
        broker.injector_connected();
    }
    match broker.take_next_job(Duration::from_secs(INJECTOR_KEEPALIVE_SECS)) {
        Some(InjectJob::Fill {
            job_id,
            origin,
            url,
            username,
            password,
        }) => Response::Job {
            job_id,
            origin,
            url,
            username,
            password,
        },
        Some(InjectJob::Grab { job_id, origins }) => Response::GrabJob { job_id, origins },
        None => Response::NoJob,
    }
}

/// The injector host reports a job's outcome; route it back to the blocked
/// PERFORM thread. Gated on this connection having authed as an injector.
fn handle_job_result(
    job_id: String,
    ok: bool,
    detail: String,
    is_injector: bool,
    app: &AppHandle,
) -> Response {
    if !is_injector {
        return Response::Error {
            message: "not an injector connection".into(),
        };
    }
    app.state::<BrokerHandle>().resolve_inject(
        &job_id,
        InjectOutcome {
            ok,
            detail,
            cookies: Vec::new(),
        },
    );
    Response::JobAck
}

/// Redeem a `session` grant: dispatch a grab job to the injector for the grant's
/// approved origin set and return the cookies the extension read. The cookies
/// never touch the vault — this is a live grab returned to the agent.
fn handle_grab_session(
    grant_id: String,
    proof: String,
    nonce: &Option<String>,
    app: &AppHandle,
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
        if g.action != Action::Session {
            return Response::Error {
                message: "this grant is not a session grant".into(),
            };
        }
        if !g.is_live(now) {
            return Response::Error {
                message: "grant expired or exhausted".into(),
            };
        }
    }
    // scope holds "origin:<host>" entries; hand the bare hosts to the extension.
    let origins: Vec<String> = data.agent_grants[pos]
        .scope
        .iter()
        .filter_map(|s| s.strip_prefix("origin:").map(|h| h.to_string()))
        .collect();
    if origins.is_empty() {
        return Response::Error {
            message: "session grant has no origins".into(),
        };
    }

    let broker = app.state::<BrokerHandle>();
    if !broker.injector_present() {
        audit(
            "session",
            &handle_id,
            &handle.label,
            &origins.join(", "),
            Some(Action::Session),
            "failed: no injector connected",
        );
        return Response::Error {
            message: "no injector connected; the Brave extension/native host is not running".into(),
        };
    }
    let job_id = auth::new_grant_id();
    let rx = broker.dispatch_inject(InjectJob::Grab {
        job_id: job_id.clone(),
        origins: origins.clone(),
    });
    match rx.recv_timeout(Duration::from_secs(INJECT_TIMEOUT_SECS)) {
        Ok(outcome) if outcome.ok => {
            data.agent_grants[pos].consume();
            if data.agent_grants[pos].uses_remaining == 0 {
                data.agent_grants.remove(pos);
            }
            let _ = write_vault(&data);
            audit(
                "session",
                &handle_id,
                &handle.label,
                &origins.join(", "),
                Some(Action::Session),
                &format!("grabbed {} cookies", outcome.cookies.len()),
            );
            Response::Session {
                cookies: outcome.cookies,
            }
        }
        Ok(outcome) => {
            audit(
                "session",
                &handle_id,
                &handle.label,
                &origins.join(", "),
                Some(Action::Session),
                &format!("failed: {}", outcome.detail),
            );
            Response::Error {
                message: format!("session grab failed: {}", outcome.detail),
            }
        }
        Err(_) => {
            broker.cancel_inject(&job_id);
            Response::Error {
                message: "session grab timed out (extension did not respond)".into(),
            }
        }
    }
}

/// The injector host returns the cookies it grabbed; route them back to the
/// blocked `handle_grab_session`. Gated on the connection having authed as an
/// injector.
fn handle_session_result(
    job_id: String,
    ok: bool,
    cookies: Vec<CookieData>,
    detail: String,
    is_injector: bool,
    app: &AppHandle,
) -> Response {
    if !is_injector {
        return Response::Error {
            message: "not an injector connection".into(),
        };
    }
    app.state::<BrokerHandle>().resolve_inject(
        &job_id,
        InjectOutcome {
            ok,
            detail,
            cookies,
        },
    );
    Response::JobAck
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

/// Mint and persist a new grant over a single item id.
fn mint_grant(
    handle_id: &str,
    item_id: &str,
    action: Action,
    ttl_secs: u64,
    max_uses: u32,
    approved_by: ApprovedBy,
    reason: &str,
) -> GrantRecord {
    mint_grant_scoped(
        handle_id,
        vec![item_id.to_string()],
        action,
        ttl_secs,
        max_uses,
        approved_by,
        reason,
    )
}

/// Mint and persist a new grant over an explicit scope (one or more entries —
/// item ids, or `origin:<host>` entries for a session grab).
fn mint_grant_scoped(
    handle_id: &str,
    scope: Vec<String>,
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
        scope,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn job(id: &str) -> InjectJob {
        InjectJob::Fill {
            job_id: id.into(),
            origin: "https://example.com".into(),
            url: "https://example.com/login".into(),
            username: "alice".into(),
            password: "p".into(),
        }
    }

    fn ok_outcome(detail: &str) -> InjectOutcome {
        InjectOutcome {
            ok: true,
            detail: detail.into(),
            cookies: Vec::new(),
        }
    }

    // The core rendezvous: a PERFORM thread dispatches a job and blocks; an
    // injector thread picks it up via take_next_job and reports the outcome,
    // which unblocks the PERFORM thread. This is the race-prone heart of the
    // inject path, and it needs no browser or Tauri app to exercise.
    #[test]
    fn dispatch_take_resolve_round_trip() {
        let broker = Arc::new(BrokerHandle::default());
        let rx = broker.dispatch_inject(job("j1"));

        // Injector side, on another thread.
        let b2 = broker.clone();
        let t = std::thread::spawn(move || {
            let j = b2.take_next_job(Duration::from_secs(5)).expect("a job");
            let jid = j.job_id().to_string();
            assert_eq!(jid, "j1");
            match &j {
                InjectJob::Fill { password, .. } => assert_eq!(password, "p"),
                _ => panic!("expected a fill job"),
            }
            b2.resolve_inject(&jid, ok_outcome("filled"));
        });

        let outcome = rx.recv_timeout(Duration::from_secs(5)).expect("outcome");
        assert!(outcome.ok);
        assert_eq!(outcome.detail, "filled");
        t.join().unwrap();
    }

    #[test]
    fn grab_job_returns_cookies_to_waiter() {
        let broker = Arc::new(BrokerHandle::default());
        let rx = broker.dispatch_inject(InjectJob::Grab {
            job_id: "g1".into(),
            origins: vec!["mail.google.com".into()],
        });
        let b2 = broker.clone();
        let t = std::thread::spawn(move || {
            let j = b2.take_next_job(Duration::from_secs(5)).expect("a job");
            match j {
                InjectJob::Grab { job_id, origins } => {
                    assert_eq!(origins, vec!["mail.google.com".to_string()]);
                    b2.resolve_inject(
                        &job_id,
                        InjectOutcome {
                            ok: true,
                            detail: String::new(),
                            cookies: vec![CookieData {
                                name: "SID".into(),
                                ..Default::default()
                            }],
                        },
                    );
                }
                _ => panic!("expected a grab job"),
            }
        });
        let outcome = rx.recv_timeout(Duration::from_secs(5)).expect("outcome");
        assert!(outcome.ok);
        assert_eq!(outcome.cookies.len(), 1);
        assert_eq!(outcome.cookies[0].name, "SID");
        t.join().unwrap();
    }

    #[test]
    fn parse_origin_set_normalizes_and_rejects() {
        assert_eq!(
            parse_origin_set("mail.google.com, accounts.google.com").unwrap(),
            vec![
                "mail.google.com".to_string(),
                "accounts.google.com".to_string()
            ]
        );
        // Full URLs are reduced to their host.
        assert_eq!(
            parse_origin_set("https://mail.google.com/mail/u/0").unwrap(),
            vec!["mail.google.com".to_string()]
        );
        // Dedups.
        assert_eq!(
            parse_origin_set("x.com, x.com").unwrap(),
            vec!["x.com".to_string()]
        );
        // Rejects hostless / empty input.
        assert!(parse_origin_set("").is_err());
        assert!(parse_origin_set("localhost").is_err());
    }

    #[test]
    fn take_next_job_times_out_when_idle() {
        let broker = BrokerHandle::default();
        assert!(broker.take_next_job(Duration::from_millis(50)).is_none());
    }

    #[test]
    fn injector_presence_counts_connections() {
        let broker = BrokerHandle::default();
        assert!(!broker.injector_present());
        broker.injector_connected();
        broker.injector_connected();
        assert!(broker.injector_present());
        broker.injector_disconnected();
        assert!(broker.injector_present());
        broker.injector_disconnected();
        assert!(!broker.injector_present());
        // Never underflows below zero.
        broker.injector_disconnected();
        assert!(!broker.injector_present());
    }

    #[test]
    fn cancel_inject_drops_result_channel() {
        let broker = BrokerHandle::default();
        let rx = broker.dispatch_inject(job("j2"));
        broker.cancel_inject("j2");
        // Resolving a cancelled job returns false (no receiver registered).
        assert!(!broker.resolve_inject("j2", ok_outcome("")));
        drop(rx);
    }

    #[test]
    fn resolve_target_enforces_origin_binding() {
        let item = RevealedItem {
            url: "https://example.com/login".into(),
            ..Default::default()
        };
        // Empty target → item's own URL.
        assert_eq!(
            resolve_target(&item, "").unwrap(),
            "https://example.com/login"
        );
        // Same-origin target is allowed.
        assert!(resolve_target(&item, "https://example.com/account").is_ok());
        // Lookalike / different origin is rejected.
        assert!(resolve_target(&item, "https://evil.example.net/login").is_err());
    }
}
