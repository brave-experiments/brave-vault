//! Local storage on the agent host.
//!
//! The handle *secret* goes into the OS keychain (never a file, never printed).
//! The handle *id* is not secret, so it lives in a small config file so the CLI
//! knows which handle to present on the next run.

use anyhow::{anyhow, Context, Result};

const SERVICE: &str = "brave-vault-agent";
const ACCOUNT: &str = "handle-secret";

fn config_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = std::path::Path::new(&home).join(".brave_vault");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("agent.json")
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct AgentConfig {
    handle_id: Option<String>,
    label: Option<String>,
}

fn load_config() -> AgentConfig {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &AgentConfig) -> Result<()> {
    let s = serde_json::to_string_pretty(cfg)?;
    std::fs::write(config_path(), s).context("writing agent config")?;
    Ok(())
}

/// Persist a freshly enrolled handle: id to the config file, secret to the OS
/// keychain. The secret is keyed by handle_id so multiple handles can coexist.
pub fn save_handle(handle_id: &str, secret: &str, label: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, &keyring_account(handle_id))
        .context("opening keychain entry")?;
    entry
        .set_password(secret)
        .context("storing secret in keychain")?;
    save_config(&AgentConfig {
        handle_id: Some(handle_id.to_string()),
        label: Some(label.to_string()),
    })?;
    Ok(())
}

fn keyring_account(handle_id: &str) -> String {
    format!("{ACCOUNT}:{handle_id}")
}

/// The currently enrolled handle id, if any.
pub fn current_handle_id() -> Option<String> {
    load_config().handle_id
}

/// The current handle's label, if any.
pub fn current_label() -> Option<String> {
    load_config().label
}

/// Fetch the handle secret from the keychain. Never logged by callers.
pub fn secret_for(handle_id: &str) -> Result<String> {
    let entry = keyring::Entry::new(SERVICE, &keyring_account(handle_id))
        .context("opening keychain entry")?;
    entry
        .get_password()
        .map_err(|e| anyhow!("no secret in keychain for {handle_id}: {e}"))
}

/// Remove the current handle from local storage (keychain + config).
pub fn forget() -> Result<()> {
    if let Some(id) = current_handle_id() {
        if let Ok(entry) = keyring::Entry::new(SERVICE, &keyring_account(&id)) {
            let _ = entry.delete_credential();
        }
    }
    let _ = std::fs::remove_file(config_path());
    Ok(())
}
