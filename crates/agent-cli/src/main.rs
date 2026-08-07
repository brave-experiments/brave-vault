//! `brave-vault-agent` — the binary an autonomous agent runs to obtain vault
//! items through the broker (the Brave Vault app).
//!
//! The agent holds only a *handle* (id in a config file, secret in the OS
//! keychain). It never holds the vault mnemonic or the services key. To touch
//! an item it asks the broker for a short-lived, single-use *grant*; the broker
//! may prompt the user or match a grant the user pre-created.
//!
//! Security posture:
//! - `enroll` is meant to be run by the *user*, not the agent — it mints a new
//!   identity and requires confirming a popup in the app.
//! - `reveal` never prints the secret to stdout unless `--print` is passed
//!   explicitly; by default it copies to the clipboard so it stays out of logs.
//! - `use` asks the broker to *perform* the action so the plaintext never
//!   reaches this process at all.

mod client;
mod store;

use anyhow::{anyhow, bail, Result};
use brave_vault_core::agent::auth;
use brave_vault_core::agent::model::Action;
use brave_vault_core::agent::protocol::{Request, Response};

use client::Broker;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("enroll") => cmd_enroll(&args[2..]),
        Some("whoami") => cmd_whoami(),
        Some("forget") => store::forget(),
        Some("request") => cmd_request(&args[2..]),
        Some("reveal") => cmd_reveal(&args[2..]),
        Some("use") => cmd_use(&args[2..]),
        Some("list-grants") => cmd_list_grants(),
        Some("ping") => cmd_ping(),
        _ => {
            usage();
            Ok(())
        }
    }
}

fn usage() {
    eprintln!(
        "brave-vault-agent — capability-based vault access for agents

USAGE:
  brave-vault-agent enroll --label <name>        (run by the USER; confirms in-app)
  brave-vault-agent whoami
  brave-vault-agent forget                       (remove local handle)
  brave-vault-agent ping
  brave-vault-agent request --item <q> --action reveal|use [--reason <text>]
  brave-vault-agent reveal --grant <id> [--print]
  brave-vault-agent use --grant <id> [--target <url>]
  brave-vault-agent list-grants

The agent holds only a handle; it never holds the vault master secret. A
'reveal' returns one item once; a 'use' asks the app to perform the action so
the secret never reaches this process."
    );
}

/// Minimal --flag <value> parser. Returns the value for `flag` if present.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Connect + HELLO using the enrolled handle; return the broker plus handle id.
fn connect_authed() -> Result<(Broker, String)> {
    let handle_id = store::current_handle_id()
        .ok_or_else(|| anyhow!("no enrolled handle; run `brave-vault-agent enroll` first"))?;
    let mut broker = Broker::connect()?;
    broker.hello(&handle_id)?;
    Ok((broker, handle_id))
}

/// Compute the HMAC proof for the current connection nonce.
fn proof_for(broker: &Broker, handle_id: &str) -> Result<String> {
    let secret = store::secret_for(handle_id)?;
    Ok(auth::compute_proof(&secret, broker.nonce()?))
}

fn cmd_enroll(args: &[String]) -> Result<()> {
    let label = flag(args, "--label").unwrap_or("agent").to_string();
    let mut broker = Broker::connect()?;
    match broker.call(&Request::Enroll {
        label: label.clone(),
    })? {
        Response::Enrolled { handle_id, secret } => {
            store::save_handle(&handle_id, &secret, &label)?;
            // Print only the id (safe); the secret is now in the keychain.
            println!("enrolled handle: {handle_id}");
            println!("label: {label}");
            println!("(secret stored in OS keychain; it was not printed)");
            Ok(())
        }
        Response::Denied { reason } => bail!("enrollment denied: {reason}"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn cmd_whoami() -> Result<()> {
    match store::current_handle_id() {
        Some(id) => {
            println!("handle: {id}");
            if let Some(l) = store::current_label() {
                println!("label: {l}");
            }
        }
        None => println!("not enrolled"),
    }
    Ok(())
}

fn cmd_ping() -> Result<()> {
    let mut broker = Broker::connect()?;
    // HELLO needs a handle; ping is fine unauthenticated if enrolled, but also
    // works pre-enrollment by sending PING directly.
    if let Some(id) = store::current_handle_id() {
        broker.hello(&id)?;
    }
    match broker.call(&Request::Ping)? {
        Response::Pong => {
            println!("broker: ok");
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn parse_action(s: &str) -> Result<Action> {
    match s {
        "reveal" => Ok(Action::Reveal),
        "use" => Ok(Action::Use),
        _ => bail!("--action must be 'reveal' or 'use'"),
    }
}

fn cmd_request(args: &[String]) -> Result<()> {
    let item = flag(args, "--item").ok_or_else(|| anyhow!("--item is required"))?;
    let action = parse_action(flag(args, "--action").unwrap_or("reveal"))?;
    let reason = flag(args, "--reason").unwrap_or("").to_string();

    let (mut broker, handle_id) = connect_authed()?;
    let proof = proof_for(&broker, &handle_id)?;
    let resp = broker.call(&Request::Request {
        handle_id,
        proof,
        item: item.to_string(),
        action,
        reason,
    })?;
    match resp {
        Response::Grant { grant_id, ttl_secs } => {
            println!("{grant_id}");
            eprintln!("granted (expires in {ttl_secs}s). Next:");
            match action {
                Action::Reveal => eprintln!("  brave-vault-agent reveal --grant {grant_id}"),
                Action::Use => {
                    eprintln!("  brave-vault-agent use --grant {grant_id} --target <url>")
                }
            }
            Ok(())
        }
        Response::Denied { reason } => bail!("denied: {reason}"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn cmd_reveal(args: &[String]) -> Result<()> {
    let grant_id = flag(args, "--grant").ok_or_else(|| anyhow!("--grant is required"))?;
    let print = has_flag(args, "--print");

    let (mut broker, handle_id) = connect_authed()?;
    let proof = proof_for(&broker, &handle_id)?;
    let resp = broker.call(&Request::Consume {
        grant_id: grant_id.to_string(),
        proof,
    })?;
    match resp {
        Response::Secret { item } => {
            deliver_secret(&item, print)?;
            Ok(())
        }
        Response::Denied { reason } => bail!("denied: {reason}"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// Route the revealed secret away from logs by default. `--print` opts into
/// stdout for interactive/manual use.
fn deliver_secret(
    item: &brave_vault_core::agent::protocol::RevealedItem,
    print: bool,
) -> Result<()> {
    if print {
        // Explicit opt-in: emit the value(s) on stdout.
        if !item.password.is_empty() {
            println!("{}", item.password);
        }
        if !item.notes.is_empty() {
            println!("{}", item.notes);
        }
        for (k, v) in &item.fields {
            println!("{k}: {v}");
        }
        return Ok(());
    }
    // Default: copy the primary secret to the clipboard, print only metadata.
    let value = if !item.password.is_empty() {
        item.password.clone()
    } else if !item.notes.is_empty() {
        item.notes.clone()
    } else {
        item.fields
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    match copy_to_clipboard(&value) {
        Ok(()) => {
            eprintln!("copied {} secret to clipboard (not printed)", item.kind);
            if !item.username.is_empty() {
                eprintln!("username: {}", item.username);
            }
        }
        Err(e) => bail!("could not copy to clipboard ({e}); re-run with --print to emit to stdout"),
    }
    Ok(())
}

/// Copy to the OS clipboard via the platform utility. Best-effort; no extra
/// crate dependency.
fn copy_to_clipboard(value: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let cmd = if cfg!(target_os = "macos") {
        "pbcopy"
    } else if cfg!(target_os = "windows") {
        "clip"
    } else {
        "xclip"
    };
    let mut child = Command::new(cmd)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("spawning {cmd}: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("no stdin for {cmd}"))?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("{cmd} exited with {status}");
    }
    Ok(())
}

fn cmd_use(args: &[String]) -> Result<()> {
    let grant_id = flag(args, "--grant").ok_or_else(|| anyhow!("--grant is required"))?;
    let target = flag(args, "--target").unwrap_or("").to_string();

    let (mut broker, handle_id) = connect_authed()?;
    let proof = proof_for(&broker, &handle_id)?;
    let resp = broker.call(&Request::Perform {
        grant_id: grant_id.to_string(),
        proof,
        target,
    })?;
    match resp {
        Response::Done { ok, detail } => {
            if ok {
                println!("done: {detail}");
                Ok(())
            } else {
                bail!("action failed: {detail}")
            }
        }
        Response::Denied { reason } => bail!("denied: {reason}"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn cmd_list_grants() -> Result<()> {
    let (mut broker, handle_id) = connect_authed()?;
    let proof = proof_for(&broker, &handle_id)?;
    let resp = broker.call(&Request::ListGrants { handle_id, proof })?;
    match resp {
        Response::Grants { grants } => {
            if grants.is_empty() {
                println!("no live grants");
            }
            for g in grants {
                let action = match g.action {
                    Action::Reveal => "reveal",
                    Action::Use => "use",
                };
                println!(
                    "{} [{}] scope={:?} uses_left={} expires_unix={}",
                    g.grant_id, action, g.scope, g.uses_remaining, g.expires_unix
                );
            }
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}
