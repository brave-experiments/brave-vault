//! Local storage the injector host reads.
//!
//! The app auto-provisions the injector identity: it writes the non-secret
//! `handle_id` to a sidecar file and stores the secret in the OS keychain under
//! a service distinct from the agent's. The host reads both here. Requiring the
//! keychain secret (not just socket access) is what stops an ordinary agent
//! from impersonating the injector.

use anyhow::{anyhow, Context, Result};

/// Keychain service for the injector secret — deliberately distinct from the
/// agent CLI's `brave-vault-agent` service.
const SERVICE: &str = "brave-vault-injector";
const ACCOUNT_PREFIX: &str = "handle-secret";

fn sidecar_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home)
        .join(".brave_vault")
        .join("injector.json")
}

#[derive(serde::Deserialize)]
struct InjectorConfig {
    handle_id: String,
}

/// The injector handle id the app provisioned, from the sidecar file.
pub fn handle_id() -> Result<String> {
    let s = std::fs::read_to_string(sidecar_path()).with_context(|| {
        format!(
            "reading injector sidecar {} — is the Brave Vault app installed and run once?",
            sidecar_path().display()
        )
    })?;
    let cfg: InjectorConfig = serde_json::from_str(&s).context("parsing injector sidecar JSON")?;
    Ok(cfg.handle_id)
}

fn keyring_account(handle_id: &str) -> String {
    format!("{ACCOUNT_PREFIX}:{handle_id}")
}

/// Fetch the injector secret from the OS keychain. Never logged.
pub fn secret_for(handle_id: &str) -> Result<String> {
    let entry = keyring::Entry::new(SERVICE, &keyring_account(handle_id))
        .context("opening injector keychain entry")?;
    entry
        .get_password()
        .map_err(|e| anyhow!("no injector secret in keychain for {handle_id}: {e}"))
}
