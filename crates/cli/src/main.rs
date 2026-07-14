//! Brave Vault CLI — debugging tools for the core engine.

use anyhow::{Context, Result};
use brave_vault_core::config::Config;
use brave_vault_core::crypto::{seed, time_words};
use brave_vault_core::favicon;
use brave_vault_core::session::Session;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => cmd_gen(),
        Some("probe") => cmd_probe(args.get(2).cloned()),
        Some("favicon") => {
            let host = args.get(2).cloned().unwrap_or_else(|| "github.com".into());
            match favicon::fetch_and_cache(&host) {
                Some(png) => println!("OK: {host} ({} bytes)", png.len()),
                None => println!("MISS: {host}"),
            }
            Ok(())
        }
        Some("testbm") => cmd_testbm(),
        Some("testid") => cmd_testid(), // debug write tests
        Some("cleanup") => cmd_cleanup(),
        _ => {
            eprintln!("usage: brave_vault_cli <gen | probe [\"words\"] | favicon [host]>");
            Ok(())
        }
    }
}

fn cmd_gen() -> Result<()> {
    let (_bytes, phrase) = seed::generate();
    let session_code = time_words::generate_for_now(&phrase);
    println!("24-word seed:\n{phrase}\n");
    println!("25-word Brave sync code:\n{session_code}");
    Ok(())
}

fn cmd_probe(arg: Option<String>) -> Result<()> {
    let cfg = Config::from_env().map_err(anyhow::Error::msg)?;
    // Use the passed code, or fall back to the saved vault (password "testing").
    let raw = match arg {
        Some(a) => a,
        None => load_vault_mnemonic().context("no code given and no saved vault")?,
    };
    let phrase = time_words::parse(&raw).map_err(anyhow::Error::msg)?;
    let session = Session::new(cfg, phrase);
    println!("client id: {}", session.client_id().map_err(anyhow::Error::msg)?);
    let data = session.fetch_all().map_err(anyhow::Error::msg)?;
    println!(
        "passwords: {}, bookmarks: {}, identities: {}, reading_list: {}, tab_groups: {}, open_tabs: {}, devices: {}",
        data.passwords.len(),
        data.bookmarks.len(),
        data.identities.len(),
        data.reading_list.len(),
        data.tab_groups.iter().filter(|i| !i.is_group).count(),
        data.open_tabs.iter().filter(|i| !i.is_group).count(),
        data.devices.len(),
    );
    for d in &data.devices {
        println!(
            "  device: {} [{} · {}]{}",
            d.name,
            if d.os.is_empty() { "?" } else { &d.os },
            if d.form_factor.is_empty() { "?" } else { &d.form_factor },
            if d.is_current { " (this device)" } else { "" },
        );
    }
    // Quick watchtower counts (mirrors the app's flags).
    use std::collections::{HashMap, HashSet};
    let mut val_counts: HashMap<&str, u32> = HashMap::new();
    for r in &data.passwords {
        if !r.item.password.is_empty() {
            *val_counts.entry(r.item.password.as_str()).or_insert(0) += 1;
        }
    }
    let weak = data.passwords.iter().filter(|r| {
        !r.item.password.is_empty()
            && brave_vault_core::model::password_strength(&r.item.password).0 < 40
    }).count();
    let reused = data.passwords.iter().filter(|r| {
        !r.item.password.is_empty() && val_counts.get(r.item.password.as_str()).copied().unwrap_or(0) > 1
    }).count();
    let mut groups: HashMap<(String, String), HashSet<String>> = HashMap::new();
    for r in &data.passwords {
        groups.entry((r.item.signon_realm.clone(), r.item.username.clone()))
            .or_default().insert(r.item.password.clone());
    }
    let conflicts = data.passwords.iter().filter(|r| {
        groups.get(&(r.item.signon_realm.clone(), r.item.username.clone()))
            .map(|s| s.len() > 1).unwrap_or(false)
    }).count();
    println!("weak: {weak}, reused: {reused}, conflicts: {conflicts}");
    for id in &data.identities {
        println!("  identity: {} | {}", id.title(), id.summary());
    }
    Ok(())
}

/// Create one test bookmark and verify it round-trips (safe write test).
fn cmd_testbm() -> Result<()> {
    let cfg = Config::from_env().map_err(anyhow::Error::msg)?;
    let phrase = load_vault_mnemonic().context("no saved vault")?;
    let session = Session::new(cfg, phrase);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let url = format!("https://brave-vault-test-{stamp}.example.com/");
    let title = format!("Brave Vault Test {stamp}");
    println!("committing bookmark: {title}");
    session.commit_new_bookmark(&title, &url, "").map_err(anyhow::Error::msg)?;
    println!("committed; re-fetching…");
    let data = session.fetch_all().map_err(anyhow::Error::msg)?;
    let found = data.bookmarks.iter().any(|b| b.url == url);
    println!("VERIFIED round-trip: {found}");
    Ok(())
}

/// Create one test identity and verify it round-trips.
fn cmd_testid() -> Result<()> {
    use brave_vault_core::model::IdentityItem;
    let cfg = Config::from_env().map_err(anyhow::Error::msg)?;
    let phrase = load_vault_mnemonic().context("no saved vault")?;
    let session = Session::new(cfg, phrase);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = format!("Test Person {stamp}");
    let it = IdentityItem {
        name: name.clone(),
        email: format!("test{stamp}@example.com"),
        city: "Testville".into(),
        country: "CA".into(),
        ..Default::default()
    };
    println!("committing identity: {name}");
    session.commit_new_identity(&it).map_err(anyhow::Error::msg)?;
    println!("committed; re-fetching…");
    let data = session.fetch_all().map_err(anyhow::Error::msg)?;
    let found = data.identities.iter().any(|i| i.name == name);
    println!("VERIFIED round-trip: {found}");
    Ok(())
}

/// Delete leftover test entries (bookmarks + identities) created during write
/// verification, exercising the delete path in the process.
fn cmd_cleanup() -> Result<()> {
    let cfg = Config::from_env().map_err(anyhow::Error::msg)?;
    let phrase = load_vault_mnemonic().context("no saved vault")?;
    let session = Session::new(cfg, phrase);
    let data = session.fetch_all().map_err(anyhow::Error::msg)?;
    for b in data.bookmarks.iter().filter(|b| b.url.contains("brave-vault-test-")) {
        println!("deleting bookmark {}", b.title);
        session.commit_delete_bookmark(&b.guid).map_err(anyhow::Error::msg)?;
    }
    for i in data.identities.iter().filter(|i| i.name.starts_with("Test Person ")) {
        println!("deleting identity {}", i.name);
        session.commit_delete_identity(&i.guid).map_err(anyhow::Error::msg)?;
    }
    let after = session.fetch_all().map_err(anyhow::Error::msg)?;
    let bm_left = after.bookmarks.iter().filter(|b| b.url.contains("brave-vault-test-")).count();
    let id_left = after.identities.iter().filter(|i| i.name.starts_with("Test Person ")).count();
    println!("remaining test bookmarks: {bm_left}, test identities: {id_left}");
    Ok(())
}

fn load_vault_mnemonic() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".brave_pw").join("vault.json");
    let contents = std::fs::read_to_string(path).ok()?;
    brave_vault_core::vault::open("testing", &contents).ok()?.mnemonic
}
