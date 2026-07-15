//! High-level session API: the unlock -> sync -> decrypt -> commit pipeline,
//! shared by any UI (CLI, Tauri desktop, mobile).

use prost::Message;

use crate::config::Config;
use crate::crypto::auth::SyncKeys;
use crate::crypto::keybag::KeyBag;
use crate::crypto::{keybag, seed};
use crate::model::{BookmarkItem, DeviceItem, IdentityItem, PasswordItem};
use crate::sync::client::SyncClient;
use crate::sync::{commit, proto};

/// Everything needed to losslessly re-commit an edited password.
#[derive(Clone)]
pub struct PasswordRecord {
    pub item: PasswordItem,
    pub entity: proto::SyncEntity,
    pub data: proto::PasswordSpecificsData,
    pub blob: String,
}

/// The decrypted result of a sync.
#[derive(Default)]
pub struct SyncData {
    pub passwords: Vec<PasswordRecord>,
    pub bookmarks: Vec<BookmarkItem>,
    pub identities: Vec<crate::model::IdentityItem>,
    pub reading_list: Vec<crate::model::LinkItem>,
    pub tab_groups: Vec<crate::model::LinkItem>,
    pub open_tabs: Vec<crate::model::LinkItem>,
    pub devices: Vec<DeviceItem>,
}

/// Editable fields for a password (edit or new).
#[derive(Clone, Default)]
pub struct EditFields {
    pub title: String,
    pub username: String,
    pub password: String,
    pub website: String,
    pub notes: String,
}

/// A live session bound to one sync chain.
pub struct Session {
    config: Config,
    mnemonic: String,
}

impl Session {
    pub fn new(config: Config, mnemonic: String) -> Self {
        Session { config, mnemonic }
    }

    fn client(&self) -> Result<SyncClient, String> {
        let bytes = seed::bytes_from_mnemonic(&self.mnemonic).map_err(|e| e.to_string())?;
        Ok(SyncClient::new(SyncKeys::from_seed(&bytes), self.config.clone()))
    }

    fn build_keybag(&self, client: &SyncClient) -> Result<KeyBag, String> {
        let (nigori, _keys) = client.fetch_nigori().map_err(|e| e.to_string())?;
        let nigori = nigori.ok_or("no Nigori node on this chain")?;
        keybag::build_keybag_custom_passphrase(&self.mnemonic, &nigori).map_err(|e| e.to_string())
    }

    /// The client id (derived ed25519 public key hex).
    pub fn client_id(&self) -> Result<String, String> {
        let bytes = seed::bytes_from_mnemonic(&self.mnemonic).map_err(|e| e.to_string())?;
        Ok(SyncKeys::from_seed(&bytes).client_id())
    }

    /// Fetch and decrypt all passwords + bookmarks.
    pub fn fetch_all(&self) -> Result<SyncData, String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;

        // Passwords: inner encrypted blob in specifics.password.encrypted.
        let (entries, _k) = client.fetch_all_passwords().map_err(|e| e.to_string())?;
        let mut passwords = Vec::new();
        for e in &entries {
            if e.deleted() {
                continue;
            }
            let Some(pw) = e.specifics.as_ref().and_then(|s| s.password.as_ref()) else {
                continue;
            };
            let Some(blob) = pw.encrypted.as_ref().and_then(|d| d.blob.clone()) else {
                continue;
            };
            let Some(pt) = keybag.decrypt(&blob) else { continue };
            let Ok(data) = proto::PasswordSpecificsData::decode(pt.as_slice()) else {
                continue;
            };
            passwords.push(PasswordRecord {
                item: PasswordItem::from_specifics(&data),
                entity: e.clone(),
                data,
                blob,
            });
        }
        passwords.sort_by(|a, b| {
            a.item.title().to_lowercase().cmp(&b.item.title().to_lowercase())
        });

        // Bookmarks: whole EntitySpecifics is encrypted in specifics.encrypted.
        let bookmarks = match client.fetch_all_bookmarks() {
            Ok((bentries, _)) => decrypt_bookmarks(&bentries, &keybag),
            Err(_) => Vec::new(),
        };

        // Identities (autofill profiles): same generic-encrypted path.
        let identities = match client.fetch_all_identities() {
            Ok((ientries, _)) => decrypt_identities(&ientries, &keybag),
            Err(_) => Vec::new(),
        };

        // Reading list, saved tab groups, open tabs — all generic-encrypted.
        let reading_list = client
            .fetch_all_reading_list()
            .map(|(e, _)| decrypt_reading_list(&e, &keybag))
            .unwrap_or_default();
        let tab_groups = client
            .fetch_all_tab_groups()
            .map(|(e, _)| decrypt_tab_groups(&e, &keybag))
            .unwrap_or_default();
        let open_tabs = client
            .fetch_all_sessions()
            .map(|(e, _)| decrypt_sessions(&e, &keybag))
            .unwrap_or_default();

        // Devices (DeviceInfo). Upstream Chromium leaves this type unencrypted,
        // but Brave turns on encrypt-everything, so the specifics arrive in the
        // generic specifics.encrypted blob — decode via the keybag.
        let current_guid = format!("brave-vault-{}", self.client_id().unwrap_or_default());
        let devices = client
            .fetch_all_devices()
            .map(|(e, _)| decode_devices(&e, &keybag, &current_guid))
            .unwrap_or_default();

        Ok(SyncData {
            passwords,
            bookmarks,
            identities,
            reading_list,
            tab_groups,
            open_tabs,
            devices,
        })
    }

    /// Edit a password identified by its key ("<realm>|<username>"). Fetches the
    /// current entity fresh so it works even if the caller has no in-memory
    /// record (e.g. editing right after unlock, before the first sync finishes).
    pub fn commit_edit_by_key(&self, key: &str, fields: &EditFields) -> Result<(), String> {
        let data = self.fetch_all()?;
        let rec = data
            .passwords
            .into_iter()
            .find(|r| r.item.key() == key)
            .ok_or("item not found")?;
        self.commit_edit(&rec, fields)
    }

    /// Commit an edit to an existing password (lossless).
    pub fn commit_edit(&self, rec: &PasswordRecord, fields: &EditFields) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let mut data = rec.data.clone();
        data.username_value = Some(fields.username.clone());
        data.password_value = Some(fields.password.clone());
        data.display_name = Some(fields.title.clone());
        data.date_password_modified_windows_epoch_micros = Some(commit::now_ms() * 1000);
        set_primary_note(&mut data, &fields.notes);
        let entity = commit::build_password_entity(&rec.entity, &data, &rec.blob, &keybag)
            .ok_or("could not build edit entity (key mismatch)")?;
        self.commit(&client, entity)
    }

    /// Commit a brand-new password.
    pub fn commit_new(&self, fields: &EditFields) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let mut site = fields.website.trim().to_string();
        if site.is_empty() {
            return Err("website is required for a new item".into());
        }
        if !site.starts_with("http://") && !site.starts_with("https://") {
            site = format!("https://{site}");
        }
        let realm = normalize_realm(&site);
        let mut data = proto::PasswordSpecificsData::default();
        data.signon_realm = Some(realm.clone());
        data.origin = Some(realm);
        data.username_value = Some(fields.username.clone());
        data.password_value = Some(fields.password.clone());
        data.display_name = Some(fields.title.clone());
        data.date_created = Some(commit::now_ms() * 1000);
        set_primary_note(&mut data, &fields.notes);
        let entity = commit::build_new_password_entity(&data, &keybag)
            .ok_or("could not build new entity")?;
        self.commit(&client, entity)
    }

    /// Create a brand-new bookmark. `parent_guid` empty = top level.
    pub fn commit_new_bookmark(
        &self,
        title: &str,
        url: &str,
        parent_guid: &str,
    ) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let mut u = url.trim().to_string();
        if u.is_empty() {
            return Err("URL is required".into());
        }
        if !u.contains("://") {
            u = format!("https://{u}");
        }
        let entity = commit::build_new_bookmark_entity(title, &u, parent_guid, &keybag)
            .ok_or("could not build bookmark entity")?;
        self.commit(&client, entity)
    }

    /// Create a brand-new identity (autofill profile).
    pub fn commit_new_identity(&self, it: &IdentityItem) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let mut p = proto::AutofillProfileSpecifics::default();
        p.guid = Some(commit::random_uuid());
        if !it.name.is_empty() {
            p.name_full = vec![it.name.clone()];
        }
        if !it.email.is_empty() {
            p.email_address = vec![it.email.clone()];
        }
        if !it.phone.is_empty() {
            p.phone_home_whole_number = vec![it.phone.clone()];
        }
        if !it.company.is_empty() {
            p.company_name = Some(it.company.clone());
        }
        if !it.street.is_empty() {
            p.address_home_street_address = Some(it.street.clone());
        }
        if !it.city.is_empty() {
            p.address_home_city = Some(it.city.clone());
        }
        if !it.state.is_empty() {
            p.address_home_state = Some(it.state.clone());
        }
        if !it.zip.is_empty() {
            p.address_home_zip = Some(it.zip.clone());
        }
        if !it.country.is_empty() {
            p.address_home_country = Some(it.country.clone());
        }
        let entity = commit::build_new_identity_entity(p, &keybag)
            .ok_or("could not build identity entity")?;
        self.commit(&client, entity)
    }

    /// Delete a password by its key ("<realm>|<username>"), fetching fresh.
    pub fn commit_delete_password_by_key(&self, key: &str) -> Result<(), String> {
        let data = self.fetch_all()?;
        let rec = data
            .passwords
            .into_iter()
            .find(|r| r.item.key() == key)
            .ok_or("item not found")?;
        self.commit_delete(&rec)
    }

    /// Delete (tombstone) an existing password.
    pub fn commit_delete(&self, rec: &PasswordRecord) -> Result<(), String> {
        let client = self.client()?;
        let mut entity = rec.entity.clone();
        entity.deleted = Some(true);
        entity.specifics = None;
        entity.mtime = Some(commit::now_ms());
        self.commit(&client, entity)
    }

    /// Delete a bookmark by its guid. Re-fetches to find the live entity so the
    /// tombstone carries the correct id_string / version / client_tag_hash.
    pub fn commit_delete_bookmark(&self, guid: &str) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let (entries, _) = client.fetch_all_bookmarks().map_err(|e| e.to_string())?;
        let entity = find_entity_by_guid(&entries, &keybag, |es| {
            es.bookmark.as_ref().map(|b| b.guid().to_string())
        }, guid)
        .ok_or("bookmark not found")?;
        // Tombstone must still identify the datatype (Chromium AddDefaultFieldValue).
        let marker = proto::EntitySpecifics {
            bookmark: Some(proto::BookmarkSpecifics::default()),
            ..Default::default()
        };
        self.tombstone(&client, entity, marker)
    }

    /// Delete an identity by its guid.
    pub fn commit_delete_identity(&self, guid: &str) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let (entries, _) = client.fetch_all_identities().map_err(|e| e.to_string())?;
        let entity = find_entity_by_guid(&entries, &keybag, |es| {
            es.autofill_profile.as_ref().map(|p| p.guid().to_string())
        }, guid)
        .ok_or("identity not found")?;
        let marker = proto::EntitySpecifics {
            autofill_profile: Some(proto::AutofillProfileSpecifics::default()),
            ..Default::default()
        };
        self.tombstone(&client, entity, marker)
    }

    /// Remove a device from the sync chain by its cache_guid (tombstone).
    /// Note: a device that is still online will re-register on its next sync.
    pub fn commit_delete_device(&self, cache_guid: &str) -> Result<(), String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let (entries, _) = client.fetch_all_devices().map_err(|e| e.to_string())?;
        let entity = entries
            .into_iter()
            .find(|e| {
                decode_specifics(e, &keybag)
                    .and_then(|es| es.device_info)
                    .map(|d| d.cache_guid() == cache_guid)
                    .unwrap_or(false)
            })
            .ok_or("device not found")?;
        let marker = proto::EntitySpecifics {
            device_info: Some(proto::DeviceInfoSpecifics::default()),
            ..Default::default()
        };
        self.tombstone(&client, entity, marker)
    }

    /// Tombstone every non-current device whose last-updated time is before
    /// `cutoff_unix` (unix seconds). Devices with an unknown time (0) are kept,
    /// so we only ever purge records we can positively date as stale. Fetches
    /// the device list once, then tombstones matches. Returns the removed names.
    ///
    /// Reclaims chain slots against the server's device cap (go-sync counts
    /// every non-deleted DeviceInfo record, and never expires them itself).
    pub fn commit_delete_stale_devices(&self, cutoff_unix: i64) -> Result<Vec<String>, String> {
        let client = self.client()?;
        let keybag = self.build_keybag(&client)?;
        let current_guid = format!("brave-vault-{}", self.client_id().unwrap_or_default());
        let (entries, _) = client.fetch_all_devices().map_err(|e| e.to_string())?;
        eprintln!(
            "[purge] fetched {} device entrie(s); cutoff_unix={cutoff_unix}, current_guid={current_guid}",
            entries.len()
        );
        let mut removed = Vec::new();
        for e in entries {
            if e.deleted() {
                continue;
            }
            let Some(di) = decode_specifics(&e, &keybag).and_then(|es| es.device_info) else {
                continue;
            };
            let item = DeviceItem::from_specifics(&di);
            let is_current = item.cache_guid == current_guid;
            let stale = item.last_updated_unix > 0 && item.last_updated_unix < cutoff_unix;
            eprintln!(
                "[purge]   device {:?}: last_updated_unix={}, is_current={}, stale={} -> {}",
                item.name,
                item.last_updated_unix,
                is_current,
                stale,
                if is_current || !stale { "keep" } else { "PURGE" }
            );
            if is_current || !stale {
                continue;
            }
            let marker = proto::EntitySpecifics {
                device_info: Some(proto::DeviceInfoSpecifics::default()),
                ..Default::default()
            };
            self.tombstone(&client, e, marker)?;
            removed.push(item.name);
        }
        Ok(removed)
    }

    fn tombstone(
        &self,
        client: &SyncClient,
        entity: proto::SyncEntity,
        marker: proto::EntitySpecifics,
    ) -> Result<(), String> {
        let mut e = entity;
        e.deleted = Some(true);
        e.specifics = Some(marker);
        e.mtime = Some(commit::now_ms());
        self.commit(client, e)
    }

    fn commit(&self, client: &SyncClient, entity: proto::SyncEntity) -> Result<(), String> {
        let birthday = client
            .fetch_store_birthday()
            .map_err(|e| e.to_string())?
            .ok_or("no store birthday")?;
        let cache_guid = format!("brave-vault-{}", self.client_id()?);
        client
            .commit_entity(entity, birthday, cache_guid)
            .map_err(|e| e.to_string())
    }
}

fn decrypt_bookmarks(entries: &[proto::SyncEntity], keybag: &KeyBag) -> Vec<BookmarkItem> {
    let mut out = Vec::new();
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(specifics) = e.specifics.as_ref() else { continue };
        let bookmark = if let Some(blob) =
            specifics.encrypted.as_ref().and_then(|d| d.blob.as_ref())
        {
            keybag
                .decrypt(blob)
                .and_then(|pt| proto::EntitySpecifics::decode(pt.as_slice()).ok())
                .and_then(|es| es.bookmark)
        } else {
            specifics.bookmark.clone()
        };
        let Some(b) = bookmark else { continue };
        let item = BookmarkItem::from_specifics(&b);
        if item.guid.is_empty() {
            continue;
        }
        out.push(item);
    }
    out
}

fn decrypt_identities(entries: &[proto::SyncEntity], keybag: &KeyBag) -> Vec<IdentityItem> {
    let mut out = Vec::new();
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(specifics) = e.specifics.as_ref() else { continue };
        let profile = if let Some(blob) =
            specifics.encrypted.as_ref().and_then(|d| d.blob.as_ref())
        {
            keybag
                .decrypt(blob)
                .and_then(|pt| proto::EntitySpecifics::decode(pt.as_slice()).ok())
                .and_then(|es| es.autofill_profile)
        } else {
            specifics.autofill_profile.clone()
        };
        let Some(p) = profile else { continue };
        let item = IdentityItem::from_specifics(&p);
        if item.guid.is_empty() {
            continue;
        }
        out.push(item);
    }
    out.sort_by(|a, b| a.title().to_lowercase().cmp(&b.title().to_lowercase()));
    out
}

/// Decode the sync chain's devices. Brave encrypt-everything wraps DeviceInfo in
/// the generic specifics.encrypted blob, so decode through the keybag (falling
/// back to the plaintext field for unencrypted chains).
fn decode_devices(
    entries: &[proto::SyncEntity],
    keybag: &KeyBag,
    current_guid: &str,
) -> Vec<DeviceItem> {
    let mut out = Vec::new();
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(di) = decode_specifics(e, keybag).and_then(|es| es.device_info) else {
            continue;
        };
        let mut d = DeviceItem::from_specifics(&di);
        d.is_current = d.cache_guid == current_guid;
        out.push(d);
    }
    // Most recently active first; current device pinned to the top.
    out.sort_by(|a, b| {
        b.is_current
            .cmp(&a.is_current)
            .then(b.last_updated_unix.cmp(&a.last_updated_unix))
    });
    out
}

/// Decode a (possibly generic-encrypted) entity into its EntitySpecifics.
fn decode_specifics(e: &proto::SyncEntity, keybag: &KeyBag) -> Option<proto::EntitySpecifics> {
    let specifics = e.specifics.as_ref()?;
    if let Some(blob) = specifics.encrypted.as_ref().and_then(|d| d.blob.as_ref()) {
        keybag
            .decrypt(blob)
            .and_then(|pt| proto::EntitySpecifics::decode(pt.as_slice()).ok())
    } else {
        Some(specifics.clone())
    }
}

fn decrypt_reading_list(entries: &[proto::SyncEntity], keybag: &KeyBag) -> Vec<crate::model::LinkItem> {
    let mut out = Vec::new();
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(rl) = decode_specifics(e, keybag).and_then(|es| es.reading_list) else { continue };
        if rl.url().is_empty() {
            continue;
        }
        out.push(crate::model::LinkItem {
            id: format!("rl:{}", rl.entry_id()),
            title: rl.title().to_string(),
            url: rl.url().to_string(),
            group: String::new(),
            is_group: false,
        });
    }
    out.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
    out
}

fn decrypt_tab_groups(entries: &[proto::SyncEntity], keybag: &KeyBag) -> Vec<crate::model::LinkItem> {
    use std::collections::HashMap;
    // First pass: collect group names by guid; second pass: tabs under them.
    let mut group_name: HashMap<String, String> = HashMap::new();
    let mut tabs: Vec<(String, crate::model::LinkItem)> = Vec::new(); // (group_guid, tab)
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(stg) = decode_specifics(e, keybag).and_then(|es| es.saved_tab_group) else { continue };
        if let Some(g) = &stg.group {
            group_name.insert(stg.guid().to_string(), g.title().to_string());
        } else if let Some(t) = &stg.tab {
            tabs.push((
                t.group_guid().to_string(),
                crate::model::LinkItem {
                    id: format!("tg:{}", stg.guid()),
                    title: t.title().to_string(),
                    url: t.url().to_string(),
                    group: String::new(),
                    is_group: false,
                },
            ));
        }
    }
    // Emit a group header row followed by its tabs, grouped.
    let mut by_group: HashMap<String, Vec<crate::model::LinkItem>> = HashMap::new();
    for (gg, mut tab) in tabs {
        tab.group = group_name.get(&gg).cloned().unwrap_or_default();
        by_group.entry(gg).or_default().push(tab);
    }
    let mut out = Vec::new();
    let mut groups: Vec<(&String, &String)> = group_name.iter().collect();
    groups.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
    for (guid, name) in groups {
        let name = if name.is_empty() { "Unnamed group".to_string() } else { name.clone() };
        out.push(crate::model::LinkItem {
            id: format!("tggrp:{guid}"),
            title: name.clone(),
            url: String::new(),
            group: String::new(),
            is_group: true,
        });
        if let Some(list) = by_group.get(guid) {
            let mut list = list.clone();
            list.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
            for mut t in list {
                t.group = name.clone();
                out.push(t);
            }
        }
    }
    out
}

fn decrypt_sessions(entries: &[proto::SyncEntity], keybag: &KeyBag) -> Vec<crate::model::LinkItem> {
    // Each session entity is either a header (device + windows) or a tab. We
    // list the tabs, labeled by their device (client_name).
    let mut device_of: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut tabs: Vec<(String, crate::model::LinkItem)> = Vec::new(); // (session_tag, tab)
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(s) = decode_specifics(e, keybag).and_then(|es| es.session) else { continue };
        let tag = s.session_tag().to_string();
        if let Some(h) = &s.header {
            if !h.client_name().is_empty() {
                device_of.insert(tag, h.client_name().to_string());
            }
        } else if let Some(t) = &s.tab {
            // Current navigation is the visible URL/title.
            let idx = t.current_navigation_index().max(0) as usize;
            let nav = t.navigation.get(idx).or_else(|| t.navigation.last());
            if let Some(nav) = nav {
                if !nav.virtual_url().is_empty() {
                    tabs.push((
                        tag,
                        crate::model::LinkItem {
                            id: format!("tab:{}:{}", e.id_string(), t.tab_id()),
                            title: nav.title().to_string(),
                            url: nav.virtual_url().to_string(),
                            group: String::new(),
                            is_group: false,
                        },
                    ));
                }
            }
        }
    }
    // Group tabs by device.
    let mut by_dev: std::collections::HashMap<String, Vec<crate::model::LinkItem>> =
        std::collections::HashMap::new();
    for (tag, mut tab) in tabs {
        let dev = device_of.get(&tag).cloned().unwrap_or_else(|| "This device".into());
        tab.group = dev.clone();
        by_dev.entry(dev).or_default().push(tab);
    }
    let mut out = Vec::new();
    let mut devs: Vec<&String> = by_dev.keys().collect();
    devs.sort();
    for dev in devs {
        out.push(crate::model::LinkItem {
            id: format!("tabdev:{dev}"),
            title: dev.clone(),
            url: String::new(),
            group: String::new(),
            is_group: true,
        });
        if let Some(list) = by_dev.get(dev) {
            let mut list = list.clone();
            list.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
            out.extend(list);
        }
    }
    out
}

/// Find the raw SyncEntity whose (generic-encrypted) specifics decode to a
/// record with the given guid. `guid_of` extracts the guid from a decoded
/// EntitySpecifics. Returns a clone of the matching entity.
fn find_entity_by_guid(
    entries: &[proto::SyncEntity],
    keybag: &KeyBag,
    guid_of: impl Fn(&proto::EntitySpecifics) -> Option<String>,
    want: &str,
) -> Option<proto::SyncEntity> {
    for e in entries {
        if e.deleted() {
            continue;
        }
        let Some(specifics) = e.specifics.as_ref() else { continue };
        let decoded = if let Some(blob) =
            specifics.encrypted.as_ref().and_then(|d| d.blob.as_ref())
        {
            keybag
                .decrypt(blob)
                .and_then(|pt| proto::EntitySpecifics::decode(pt.as_slice()).ok())
        } else {
            Some(specifics.clone())
        };
        if let Some(es) = decoded {
            if guid_of(&es).as_deref() == Some(want) {
                return Some(e.clone());
            }
        }
    }
    None
}

/// Set the primary note (empty unique_display_name) on a PasswordSpecificsData.
fn set_primary_note(data: &mut proto::PasswordSpecificsData, note: &str) {
    let notes = data.notes.get_or_insert_with(Default::default);
    if let Some(n) = notes
        .note
        .iter_mut()
        .find(|n| n.unique_display_name().is_empty())
    {
        n.value = Some(note.to_string());
    } else {
        notes.note.push(proto::password_specifics_data::notes::Note {
            unique_display_name: Some(String::new()),
            value: Some(note.to_string()),
            date_created_windows_epoch_micros: None,
            hide_by_default: None,
        });
    }
}

/// Reduce a URL to scheme://host[:port]/ (Brave's signon_realm form).
fn normalize_realm(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("https", url),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}/")
}

/// Friendly display title: user's custom name, else cached site title, else a
/// prettified domain. Never returns junk like "/" or an empty string.
pub fn resolve_title(it: &PasswordItem) -> String {
    if !it.display_name.is_empty() {
        return it.display_name.clone();
    }
    // Try to derive a host from origin, then signon_realm, then website().
    let host = crate::favicon::host_of(&it.origin)
        .or_else(|| crate::favicon::host_of(&it.signon_realm))
        .or_else(|| crate::favicon::host_of(&it.website()));
    if let Some(host) = host {
        if let Some(t) = crate::favicon::load_cached_title(&host) {
            return t;
        }
        return prettify_domain(&host);
    }
    // Fall back to the model title, but reject junk (empty, "/", "android://…").
    let t = it.title();
    let trimmed = t.trim().trim_matches('/');
    if trimmed.is_empty() || t.starts_with("android://") {
        // Last resort: raw host-ish piece of the realm.
        let realm = it.signon_realm.trim_matches('/');
        if realm.is_empty() { "Untitled".to_string() } else { realm.to_string() }
    } else {
        t
    }
}

/// "accounts.google.com" -> "Google"; short labels stay uppercase (BMO).
pub fn prettify_domain(host: &str) -> String {
    let host = host.trim_start_matches("www.");
    let labels: Vec<&str> = host.split('.').collect();
    let name = if labels.len() >= 3 {
        let second_last = labels[labels.len() - 2];
        let two_part = ["co", "com", "org", "net", "gov", "ac", "edu"];
        if second_last.len() <= 3 && two_part.contains(&second_last) {
            labels[labels.len() - 3]
        } else {
            second_last
        }
    } else if labels.len() == 2 {
        labels[0]
    } else {
        host
    };
    if name.len() <= 4 {
        name.to_uppercase()
    } else {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => host.to_string(),
        }
    }
}
