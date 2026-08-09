//! Auto-provisioning for the browser form-injector.
//!
//! On app startup we make sure a dedicated *injector* identity exists so the
//! native-messaging host (`brave-vault-injector`) can authenticate to the
//! broker and receive fill jobs. Provisioning is idempotent:
//!   1. mint an injector-kind handle in the vault (once), store its secret in
//!      the OS keychain under a service distinct from the agent's;
//!   2. write the non-secret handle_id to a sidecar file the host reads;
//!   3. write the Brave native-messaging-host manifest pointing at the host
//!      binary, so `chrome.runtime.connectNative` can launch it.
//!
//! We do NOT spawn the host — Brave launches it on demand. Only Brave on macOS
//! is wired up here; other browsers/OSes are TODO (see `nm_manifest_path`).

use brave_vault_core::agent::auth;
use brave_vault_core::agent::model::{HandleKind, HandleRecord};

use crate::{load_vault, now_unix_secs, write_vault};

/// Native-messaging host name; must match `connectNative(...)` in the extension
/// and the manifest filename.
const NM_HOST_NAME: &str = "com.brave.vault.injector";
/// Keychain service for the injector secret — distinct from the agent CLI's.
const KEYRING_SERVICE: &str = "brave-vault-injector";
/// The extension's stable id (derived from the fixed key in its manifest). Only
/// this origin is allowed to launch the native host. Placeholder until the
/// extension is packed with its key; update both together.
const EXTENSION_ID: &str = "REPLACE_WITH_PACKED_EXTENSION_ID";

fn brave_vault_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = std::path::Path::new(&home).join(".brave_vault");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn sidecar_path() -> std::path::PathBuf {
    brave_vault_dir().join("injector.json")
}

fn keyring_account(handle_id: &str) -> String {
    format!("handle-secret:{handle_id}")
}

/// Ensure the injector handle exists; return its id. Mints + persists + stores
/// the secret in the keychain on first run.
fn ensure_handle() -> Result<String, String> {
    let mut data = load_vault().unwrap_or_default();
    if let Some(h) = data.agent_handles.iter().find(|h| h.is_injector()) {
        return Ok(h.handle_id.clone());
    }
    let handle_id = auth::new_handle_id();
    let secret = auth::new_handle_secret();
    // Store the secret in the OS keychain before persisting the handle, so we
    // never end up with a handle whose secret we can't recover.
    let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_account(&handle_id))
        .map_err(|e| format!("opening injector keychain entry: {e}"))?;
    entry
        .set_password(&secret)
        .map_err(|e| format!("storing injector secret: {e}"))?;
    data.agent_handles.push(HandleRecord {
        handle_id: handle_id.clone(),
        secret,
        label: "Brave form injector".into(),
        created_unix: now_unix_secs(),
        last_used_unix: None,
        revoked: false,
        policy: None,
        kind: HandleKind::Injector,
    });
    write_vault(&data)?;
    Ok(handle_id)
}

/// Write the non-secret handle_id where the native host reads it.
fn write_sidecar(handle_id: &str) -> Result<(), String> {
    let body = serde_json::json!({ "handle_id": handle_id }).to_string();
    std::fs::write(sidecar_path(), body).map_err(|e| format!("writing injector sidecar: {e}"))
}

/// Best-effort location of the installed host binary. Dev builds live beside the
/// app binary in target/{debug,release}; a bundled app can override via env.
fn host_binary_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("BRAVE_VAULT_INJECTOR_BIN") {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join("brave-vault-injector");
    if candidate.exists() {
        return Some(candidate);
    }
    Some(candidate) // return the expected path even if not built yet
}

/// The Brave native-messaging-host manifest path for the current OS. Only macOS
/// is wired up; other platforms return None (TODO: Linux
/// `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/`, Windows
/// registry key).
fn nm_manifest_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").ok()?;
        let dir = std::path::Path::new(&home)
            .join("Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts");
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join(format!("{NM_HOST_NAME}.json")))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Write the Brave native-messaging manifest so the extension can launch the
/// host. Best-effort: returns an error string only for genuine IO failures.
fn write_nm_manifest() -> Result<(), String> {
    let Some(manifest_path) = nm_manifest_path() else {
        eprintln!("[injector] native-messaging manifest not written: unsupported OS (only macOS/Brave wired up)");
        return Ok(());
    };
    let Some(bin) = host_binary_path() else {
        return Err("could not determine injector host binary path".into());
    };
    let manifest = serde_json::json!({
        "name": NM_HOST_NAME,
        "description": "Brave Vault form injector",
        "path": bin.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| format!("writing native-messaging manifest: {e}"))
}

/// Run the full provisioning sequence. Best-effort and idempotent; logs (to
/// stderr) rather than crashing the app if a step fails.
pub fn provision() {
    let handle_id = match ensure_handle() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[injector] could not provision handle: {e}");
            return;
        }
    };
    if let Err(e) = write_sidecar(&handle_id) {
        eprintln!("[injector] {e}");
    }
    if let Err(e) = write_nm_manifest() {
        eprintln!("[injector] {e}");
    }
}
