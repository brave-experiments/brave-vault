//! `brave-vault-injector` — the Chrome/Brave native-messaging host that lets the
//! Vault broker fill a login form without the credential ever reaching an agent.
//!
//! Data flow for a zero-knowledge `use`:
//!   broker → (unix socket) → THIS host → (stdio owned by the browser) →
//!   extension → content script → DOM
//!
//! The browser launches this process via `chrome.runtime.connectNative`, so its
//! stdio is private to the browser. The host authenticates to the broker as the
//! injector-kind handle (secret from the OS keychain), then long-polls for jobs:
//! it forwards each job's credential to the extension, waits for the fill
//! result, and reports it back to the broker.
//!
//! Diagnostics go to STDERR only — stdout is the native-messaging frame stream
//! and any stray byte there corrupts it.

mod nm;
mod store;

use std::io::{self, Read, Write};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use brave_vault_core::agent::auth;
use brave_vault_core::agent::client::Broker;
use brave_vault_core::agent::protocol::{Request, Response};

fn main() {
    if let Err(e) = run() {
        // Never touch stdout; the browser reads framed messages there.
        eprintln!("[injector] fatal: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let handle_id = store::handle_id()?;
    let secret = store::secret_for(&handle_id)?;

    let mut broker = Broker::connect().map_err(|e| anyhow!(e))?;
    broker.hello(&handle_id).map_err(|e| anyhow!(e))?;
    // The broker issues one nonce at HELLO and verifies every later request on
    // this connection against it, so a single proof serves the connection.
    let proof = {
        let nonce = broker.nonce().map_err(|e| anyhow!(e))?;
        auth::compute_proof(&secret, nonce)
    };

    let stdin = io::stdin();
    let stdout = io::stdout();

    loop {
        // Long-poll the broker for the next injection job.
        let resp = broker
            .call(&Request::AwaitJob {
                handle_id: handle_id.clone(),
                proof: proof.clone(),
            })
            .map_err(|e| anyhow!(e))?;

        match resp {
            Response::NoJob => continue, // keepalive; poll again
            Response::Job {
                job_id,
                origin,
                url,
                username,
                password,
            } => {
                let outcome = run_job(
                    &mut stdin.lock(),
                    &mut stdout.lock(),
                    &job_id,
                    &origin,
                    &url,
                    &username,
                    &password,
                );
                let (ok, detail) = match outcome {
                    Ok(detail) => (true, detail),
                    Err(e) => (false, format!("{e}")),
                };
                let ack = broker
                    .call(&Request::JobResult { job_id, ok, detail })
                    .map_err(|e| anyhow!(e))?;
                if !matches!(ack, Response::JobAck) {
                    eprintln!("[injector] unexpected reply to JobResult: {ack:?}");
                }
            }
            Response::Error { message } => bail!("broker error: {message}"),
            other => bail!("unexpected reply to AwaitJob: {other:?}"),
        }
    }
}

/// Forward one fill job to the extension and await its result. The password is
/// held only for the duration of this call and never logged.
fn run_job<R: Read, W: Write>(
    ext_in: &mut R,
    ext_out: &mut W,
    job_id: &str,
    origin: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    let msg = json!({
        "type": "fill",
        "job_id": job_id,
        "origin": origin,
        "url": url,
        "username": username,
        "password": password,
    });
    nm::write_message(ext_out, &msg)?;

    // Await the extension's fill_result for this job.
    loop {
        let Some(reply) = nm::read_message(ext_in)? else {
            bail!("extension closed the port before replying");
        };
        if reply.get("type").and_then(Value::as_str) != Some("fill_result") {
            continue; // ignore unrelated frames
        }
        if reply.get("job_id").and_then(Value::as_str) != Some(job_id) {
            continue; // not our job
        }
        let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let detail = reply
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if ok {
            return Ok(if detail.is_empty() {
                "extension filled the form".into()
            } else {
                detail
            });
        }
        bail!(if detail.is_empty() {
            "extension reported failure".into()
        } else {
            detail
        });
    }
}
