//! Brave Vault — Tauri backend. Bridges the web UI to brave_vault_core.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::State;

use brave_vault_core::config::Config;
use brave_vault_core::crypto::{pwgen, seed, time_words};
use brave_vault_core::favicon;
use brave_vault_core::model::{
    password_strength, BookmarkItem, DeviceItem, IdentityItem, LinkItem, PasswordItem,
};
use brave_vault_core::session::{self, EditFields, PasswordRecord, Session};
use brave_vault_core::vault::{self, VaultData};

const VAULT_PASSWORD: &str = "testing";

/// App state held across commands (UI thread; Tauri serializes command calls).
#[derive(Default)]
struct AppState {
    config: Option<Config>,
    mnemonic: Option<String>,
    passwords: Vec<PasswordRecord>,
    bookmarks: Vec<BookmarkItem>,
    identities: Vec<IdentityItem>,
    reading_list: Vec<LinkItem>,
    tab_groups: Vec<LinkItem>,
    open_tabs: Vec<LinkItem>,
    devices: Vec<DeviceItem>,
    favorites: Vec<String>,
    /// Prebuilt DTOs (favicon data URIs baked in) so list_items is a cheap
    /// filter with no per-call base64/disk work. Rebuilt after sync/favicons.
    pw_dtos: Vec<ItemDto>,
    bm_dtos: Vec<ItemDto>,
    id_dtos: Vec<ItemDto>,
    rl_dtos: Vec<ItemDto>,
    tg_dtos: Vec<ItemDto>,
    ot_dtos: Vec<ItemDto>,
    dev_dtos: Vec<ItemDto>,
}

type SharedState = Arc<Mutex<AppState>>;

/// Rebuild the cached DTOs from the current passwords/bookmarks. Reads favicon
/// files from disk once here (not on every list_items call).
fn rebuild_dtos(st: &mut AppState) {
    st.pw_dtos = st.passwords.iter().map(|r| password_dto(r, false)).collect();
    st.bm_dtos = st.bookmarks.iter().map(|b| bookmark_dto(b, false)).collect();
    st.id_dtos = st.identities.iter().map(identity_dto).collect();
    st.rl_dtos = st.reading_list.iter().map(link_dto).collect();
    st.tg_dtos = st.tab_groups.iter().map(link_dto).collect();
    st.ot_dtos = st.open_tabs.iter().map(link_dto).collect();
    st.dev_dtos = st.devices.iter().map(device_dto).collect();
    stamp_uids(&mut st.pw_dtos);
    compute_password_flags(&mut st.pw_dtos);
    compute_bookmark_flags(&mut st.bm_dtos);
    // Keep any not-yet-committed edits visible over the fresh server data.
    apply_outbox_overlay(st);
}

/// Flag duplicate bookmarks: a URL saved by more than one (non-folder) entry.
/// Reuses the `reused` field to mean "duplicate URL" for bookmarks.
fn compute_bookmark_flags(bm: &mut [ItemDto]) {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for d in bm.iter() {
        if d.kind == "bookmark" && !d.url.is_empty() {
            *counts.entry(d.url.as_str()).or_insert(0) += 1;
        }
    }
    let dups: std::collections::HashSet<String> = counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(u, _)| u.to_string())
        .collect();
    for d in bm.iter_mut() {
        d.reused = d.kind == "bookmark" && dups.contains(&d.url);
    }
}

/// Give each password DTO a unique uid (id + index) for UI selection, since the
/// `id` can collide for conflicting entries that share realm+username.
fn stamp_uids(pw: &mut [ItemDto]) {
    for (i, d) in pw.iter_mut().enumerate() {
        d.uid = format!("{}#{i}", d.id);
    }
}

/// Set the `reused` and `conflict` flags across a set of password DTOs.
/// - reused: a non-empty password value shared by >1 entry.
/// - conflict: same realm+username but 2+ distinct password values.
fn compute_password_flags(pw: &mut [ItemDto]) {
    use std::collections::{HashMap, HashSet};
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for d in pw.iter() {
        if !d.password.is_empty() {
            *counts.entry(d.password.as_str()).or_insert(0) += 1;
        }
    }
    let reused: HashSet<String> = counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(p, _)| p.to_string())
        .collect();

    let mut groups: HashMap<(String, String), HashSet<String>> = HashMap::new();
    for d in pw.iter() {
        groups
            .entry((d.realm.clone(), d.username.clone()))
            .or_default()
            .insert(d.password.clone());
    }
    for d in pw.iter_mut() {
        d.reused = !d.password.is_empty() && reused.contains(&d.password);
        d.conflict = groups
            .get(&(d.realm.clone(), d.username.clone()))
            .map(|s| s.len() > 1)
            .unwrap_or(false);
    }
}

// ---------- DTOs sent to the web UI ----------

#[derive(Serialize, Clone)]
struct ItemDto {
    id: String,       // stable fav/lookup key: "pw:.." / "bm:.." (may collide
                      // for conflicting entries that share realm+username)
    uid: String,      // unique per entry, for UI selection/highlight
    kind: String,     // "password" | "bookmark" | "folder"
    title: String,
    subtitle: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    initials: String,
    favicon: String,  // data URI or ""
    favorite: bool,
    strength: i32,
    strength_label: String,
    guid: String,       // bookmark guid (for folders)
    parent_guid: String,
    // Sorting keys (microseconds since Windows epoch, as Brave stores).
    date_created: i64,
    date_used: i64,
    date_modified: i64,
    // Watchtower flags (passwords only).
    weak: bool,
    reused: bool,
    conflict: bool,   // same realm+username, different password
    realm: String,    // signon_realm, for grouping related items
    favkey: String,   // favicon host key; JS resolves the image from a cache
    #[serde(default)]
    current: bool,    // devices: this is the current device
    #[serde(default)]
    pending: bool,    // has an uncommitted change queued in the outbox
}

#[derive(Serialize, Clone)]
struct SyncResult {
    password_count: usize,
    bookmark_count: usize,
    pending_count: usize,
}

// ---------- durable outbox ----------
//
// Every mutation is written to the encrypted vault's `outbox` BEFORE its
// network commit is attempted, and removed only after the commit succeeds. If
// the app closes mid-commit, the entry survives and is replayed on the next
// unlock — so an edit is never silently lost. Replay is at-least-once: a commit
// that reached the server but whose entry wasn't yet cleared will run again
// (edits/deletes are idempotent; a re-run "new" item could rarely duplicate).

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "op")]
enum OutboxOp {
    SavePassword(SaveArgs),
    SaveBookmark(BookmarkArgs),
    SaveIdentity(IdentityArgs),
    DeleteItem { id: String },
    DeleteDevice { cache_guid: String },
}

#[derive(Serialize, Deserialize, Clone)]
struct OutboxEntry {
    id: String,
    op: OutboxOp,
}

/// Append a mutation to the durable outbox; returns its entry id.
fn outbox_push(op: OutboxOp) -> String {
    let id = brave_vault_core::sync::commit::random_uuid();
    let entry = OutboxEntry { id: id.clone(), op };
    let blob = serde_json::to_string(&entry).unwrap_or_default();
    let mut data = load_vault().unwrap_or_default();
    data.outbox.push(blob);
    let _ = write_vault(&data);
    id
}

/// Remove a confirmed entry from the outbox by id.
fn outbox_remove(entry_id: &str) {
    let mut data = load_vault().unwrap_or_default();
    let before = data.outbox.len();
    data.outbox.retain(|b| {
        serde_json::from_str::<OutboxEntry>(b)
            .map(|e| e.id != entry_id)
            .unwrap_or(false) // drop unparseable entries too
    });
    if data.outbox.len() != before {
        let _ = write_vault(&data);
    }
}

/// Run one outbox operation against the sync chain.
fn apply_outbox_op(sess: &Session, op: &OutboxOp) -> Result<(), String> {
    match op {
        OutboxOp::SavePassword(args) => {
            let fields = EditFields {
                title: args.title.clone(),
                username: args.username.clone(),
                password: args.password.clone(),
                website: args.website.clone(),
                notes: args.notes.clone(),
            };
            if args.id.is_empty() {
                sess.commit_new(&fields)
            } else {
                let key = args.id.strip_prefix("pw:").unwrap_or(&args.id);
                sess.commit_edit_by_key(key, &fields)
            }
        }
        OutboxOp::SaveBookmark(args) => {
            sess.commit_new_bookmark(&args.title, &args.url, &args.parent_guid)
        }
        OutboxOp::SaveIdentity(args) => {
            let it = IdentityItem {
                guid: String::new(),
                name: args.name.clone(),
                email: args.email.clone(),
                phone: args.phone.clone(),
                company: args.company.clone(),
                street: args.street.clone(),
                city: args.city.clone(),
                state: args.state.clone(),
                zip: args.zip.clone(),
                country: args.country.clone(),
            };
            sess.commit_new_identity(&it)
        }
        OutboxOp::DeleteItem { id } => {
            if let Some(guid) = id.strip_prefix("bm:") {
                sess.commit_delete_bookmark(guid)
            } else if let Some(guid) = id.strip_prefix("id:") {
                sess.commit_delete_identity(guid)
            } else {
                let key = id.strip_prefix("pw:").unwrap_or(id);
                sess.commit_delete_password_by_key(key)
            }
        }
        OutboxOp::DeleteDevice { cache_guid } => sess.commit_delete_device(cache_guid),
    }
}

/// Commit one mutation with durability: persist to the outbox first, run it,
/// then clear the outbox entry on success. Runs the blocking network work on a
/// worker thread. On failure the entry stays queued for replay on next unlock.
async fn commit_durable(cfg: Config, mnemonic: String, op: OutboxOp) -> Result<(), String> {
    let entry_id = outbox_push(op.clone());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let sess = Session::new(cfg, mnemonic);
        apply_outbox_op(&sess, &op)
    })
    .await
    .map_err(|e| e.to_string())?;
    if result.is_ok() {
        outbox_remove(&entry_id);
    }
    result
}

/// Load the queued outbox entries (best effort).
fn outbox_entries() -> Vec<OutboxEntry> {
    load_vault()
        .map(|d| {
            d.outbox
                .iter()
                .filter_map(|b| serde_json::from_str::<OutboxEntry>(b).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Overlay not-yet-committed mutations onto the freshly-built DTOs so the UI
/// reflects the state we KNOW will be remote once the outbox drains — instead of
/// the stale server snapshot. Affected rows are flagged `pending`. Applied both
/// on unlock (over cached data) and after every sync (over fresh server data),
/// so an in-flight change is never clobbered. Idempotent.
fn apply_outbox_overlay(st: &mut AppState) {
    let entries = outbox_entries();
    if entries.is_empty() {
        return;
    }
    for entry in &entries {
        match &entry.op {
            OutboxOp::SavePassword(args) if !args.id.is_empty() => {
                // Edit of an existing password: patch the matching row in place.
                let key = args.id.strip_prefix("pw:").unwrap_or(&args.id);
                for d in st.pw_dtos.iter_mut().filter(|d| d.id == format!("pw:{key}")) {
                    d.title = if args.title.is_empty() { d.title.clone() } else { args.title.clone() };
                    d.username = args.username.clone();
                    d.subtitle = args.username.clone();
                    d.password = args.password.clone();
                    d.notes = args.notes.clone();
                    d.pending = true;
                }
            }
            OutboxOp::SavePassword(args) => {
                // Brand-new password: add a synthetic pending row.
                let mut it = PasswordItem::default();
                it.display_name = args.title.clone();
                it.username = args.username.clone();
                it.password = args.password.clone();
                it.notes = args.notes.clone();
                it.signon_realm = args.website.clone();
                it.origin = args.website.clone();
                let mut d = password_item_dto(&it);
                d.pending = true;
                st.pw_dtos.insert(0, d);
            }
            OutboxOp::DeleteItem { id } => {
                if id.starts_with("bm:") {
                    st.bm_dtos.retain(|d| &d.id != id);
                } else if id.starts_with("id:") {
                    st.id_dtos.retain(|d| &d.id != id);
                } else {
                    let key = id.strip_prefix("pw:").unwrap_or(id);
                    st.pw_dtos.retain(|d| d.id != format!("pw:{key}"));
                }
            }
            OutboxOp::DeleteDevice { cache_guid } => {
                st.dev_dtos.retain(|d| &d.guid != cache_guid);
            }
            // New bookmark/identity rows will simply appear after the next sync;
            // no reliable local key to synthesize a stable row, so we skip the
            // optimistic insert here (they were never lost — they're in the
            // outbox and will commit).
            OutboxOp::SaveBookmark(_) | OutboxOp::SaveIdentity(_) => {}
        }
    }
    // Re-stamp uids/flags since we inserted/removed password rows.
    stamp_uids(&mut st.pw_dtos);
    compute_password_flags(&mut st.pw_dtos);
    // Preserve pending flags clobbered by compute_password_flags? It only sets
    // reused/conflict, so pending is untouched.
}

/// Number of mutations still queued in the outbox.
fn outbox_len() -> usize {
    load_vault().map(|d| d.outbox.len()).unwrap_or(0)
}

// ---------- helpers ----------

fn vault_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = std::path::Path::new(&home).join(".brave_vault");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("vault.json")
}

fn load_vault() -> Option<VaultData> {
    let contents = std::fs::read_to_string(vault_path()).ok()?;
    vault::open(VAULT_PASSWORD, &contents).ok()
}

/// Snapshot the config + mnemonic needed to talk to the sync chain.
fn creds(state: &State<'_, SharedState>) -> Result<(Config, String), String> {
    let st = state.lock().unwrap();
    Ok((
        st.config.clone().ok_or("not unlocked")?,
        st.mnemonic.clone().ok_or("no chain")?,
    ))
}

fn write_vault(data: &VaultData) -> Result<(), String> {
    let sealed = vault::seal(VAULT_PASSWORD, data).map_err(|e| e.to_string())?;
    std::fs::write(vault_path(), sealed).map_err(|e| e.to_string())
}

fn pw_key(it: &PasswordItem) -> String {
    format!("pw:{}", it.key())
}
fn bm_key(b: &BookmarkItem) -> String {
    format!("bm:{}", b.guid)
}

fn initials_from(title: &str) -> String {
    let mut chars = title.chars().filter(|c| c.is_alphanumeric());
    match chars.next() {
        Some(c) => {
            let mut s = c.to_uppercase().collect::<String>();
            if let Some(second) = chars.next() {
                s.push(second.to_ascii_lowercase());
            }
            s
        }
        None => String::new(),
    }
}

fn password_dto(rec: &PasswordRecord, favorite: bool) -> ItemDto {
    password_item_dto_fav(&rec.item, favorite)
}

fn password_item_dto(it: &PasswordItem) -> ItemDto {
    password_item_dto_fav(it, false)
}

fn password_item_dto_fav(it: &PasswordItem, favorite: bool) -> ItemDto {
    let title = session::resolve_title(it);
    // favkey = host; the actual favicon image is fetched separately and cached
    // client-side, so list payloads stay small (no base64 per row).
    let favkey = favicon::host_of(&it.website()).unwrap_or_default();
    let (strength, label) = password_strength(&it.password);
    ItemDto {
        id: pw_key(it),
        uid: String::new(), // stamped after build (unique per entry)
        kind: "password".into(),
        initials: initials_from(&title),
        title,
        subtitle: it.username.clone(),
        username: it.username.clone(),
        password: it.password.clone(),
        url: it.website(),
        notes: it.notes.clone(),
        favicon: String::new(),
        favkey,
        current: false,
        pending: false,
        favorite,
        strength,
        strength_label: label.into(),
        guid: String::new(),
        parent_guid: String::new(),
        date_created: it.date_created,
        date_used: it.date_last_used,
        date_modified: it.date_password_modified,
        weak: !it.password.is_empty() && strength < 40,
        reused: false,   // set in rebuild_dtos (needs cross-item view)
        conflict: false, // set in rebuild_dtos
        realm: it.signon_realm.clone(),
    }
}

fn bookmark_dto(b: &BookmarkItem, favorite: bool) -> ItemDto {
    let favkey = if b.is_folder {
        String::new()
    } else {
        favicon::host_of(&b.url).unwrap_or_default()
    };
    ItemDto {
        id: bm_key(b),
        uid: bm_key(b), // bookmark guids are unique
        kind: if b.is_folder { "folder".into() } else { "bookmark".into() },
        initials: initials_from(&b.title),
        title: b.title.clone(),
        subtitle: b.url.clone(),
        username: String::new(),
        password: String::new(),
        url: b.url.clone(),
        notes: String::new(),
        favicon: String::new(),
        favkey,
        current: false,
        pending: false,
        favorite,
        strength: 0,
        strength_label: String::new(),
        guid: b.guid.clone(),
        parent_guid: b.parent_guid.clone(),
        date_created: 0,
        date_used: 0,
        date_modified: 0,
        weak: false,
        reused: false,
        conflict: false,
        realm: b.url.clone(),
    }
}

fn identity_dto(it: &IdentityItem) -> ItemDto {
    // Pack detail fields into notes as labeled lines the UI renders read-only.
    let mut lines: Vec<String> = Vec::new();
    let mut push = |label: &str, v: &str| {
        if !v.is_empty() {
            lines.push(format!("{label}: {v}"));
        }
    };
    push("Name", &it.name);
    push("Email", &it.email);
    push("Phone", &it.phone);
    push("Company", &it.company);
    push("Street", &it.street);
    push("City", &it.city);
    push("State", &it.state);
    push("Zip", &it.zip);
    push("Country", &it.country);
    ItemDto {
        id: format!("id:{}", it.guid),
        uid: format!("id:{}", it.guid), // identity guids are unique
        kind: "identity".into(),
        initials: initials_from(&it.title()),
        title: it.title(),
        subtitle: it.summary(),
        username: it.email.clone(),
        password: String::new(),
        url: String::new(),
        notes: lines.join("\n"),
        favicon: String::new(),
        favkey: String::new(),
        current: false,
        pending: false,
        favorite: false,
        strength: 0,
        strength_label: String::new(),
        guid: it.guid.clone(),
        parent_guid: String::new(),
        date_created: 0,
        date_used: 0,
        date_modified: 0,
        weak: false,
        reused: false,
        conflict: false,
        realm: String::new(),
    }
}

/// DTO for a reading-list item / tab-group tab / open tab. Group header rows
/// use kind "group" (rendered like a folder label, not clickable to open).
fn link_dto(it: &LinkItem) -> ItemDto {
    let favkey = if it.is_group { String::new() } else { favicon::host_of(&it.url).unwrap_or_default() };
    ItemDto {
        id: it.id.clone(),
        uid: it.id.clone(),
        kind: if it.is_group { "group".into() } else { "link".into() },
        initials: initials_from(&it.title),
        title: it.title.clone(),
        subtitle: it.url.clone(),
        username: String::new(),
        password: String::new(),
        url: it.url.clone(),
        notes: String::new(),
        favicon: String::new(),
        favkey,
        current: false,
        pending: false,
        favorite: false,
        strength: 0,
        strength_label: String::new(),
        guid: String::new(),
        parent_guid: String::new(),
        date_created: 0,
        date_used: 0,
        date_modified: 0,
        weak: false,
        reused: false,
        conflict: false,
        realm: it.group.clone(),
    }
}

/// DTO for a sync-chain device. Subtitle shows OS · form factor · last active.
fn device_dto(d: &DeviceItem) -> ItemDto {
    let mut bits: Vec<String> = Vec::new();
    if !d.os.is_empty() {
        bits.push(d.os.clone());
    }
    if !d.form_factor.is_empty() {
        bits.push(d.form_factor.clone());
    }
    if d.is_current {
        bits.push("This device".into());
    } else if let Some(rel) = relative_time(d.last_updated_unix) {
        bits.push(format!("Active {rel}"));
    }
    ItemDto {
        id: format!("dev:{}", d.cache_guid),
        uid: format!("dev:{}", d.cache_guid),
        kind: "device".into(),
        initials: initials_from(&d.name),
        title: d.name.clone(),
        subtitle: bits.join(" · "),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        favicon: String::new(),
        favkey: String::new(),
        current: d.is_current,
        pending: false,
        favorite: false,
        strength: 0,
        strength_label: String::new(),
        guid: d.cache_guid.clone(),
        parent_guid: String::new(),
        date_created: 0,
        date_used: d.last_updated_unix,
        date_modified: 0,
        weak: false,
        reused: false,
        conflict: false,
        realm: String::new(),
    }
}

/// Human-readable "time ago" from a unix-seconds timestamp (0 = unknown).
fn relative_time(unix_secs: i64) -> Option<String> {
    if unix_secs <= 0 {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let diff = now - unix_secs;
    if diff < 0 {
        return Some("just now".into());
    }
    let mins = diff / 60;
    let hours = diff / 3600;
    let days = diff / 86400;
    Some(if mins < 1 {
        "just now".into()
    } else if mins < 60 {
        format!("{mins}m ago")
    } else if hours < 24 {
        format!("{hours}h ago")
    } else if days < 30 {
        format!("{days}d ago")
    } else {
        format!("{}mo ago", days / 30)
    })
}

// ---------- commands ----------

/// Return favicon data URIs for the given hosts (only those cached on disk).
/// The web UI calls this once and caches the map, so list payloads stay tiny.
#[tauri::command]
fn favicons(hosts: Vec<String>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for h in hosts {
        if map.contains_key(&h) || h.is_empty() {
            continue;
        }
        if let Some(uri) = favicon::cached_data_uri(&h) {
            map.insert(h, uri);
        }
    }
    map
}

#[tauri::command]
fn has_config() -> bool {
    Config::from_env().is_ok()
}

#[tauri::command]
fn has_chain() -> bool {
    load_vault().and_then(|d| d.mnemonic).is_some()
}

/// Unlock with the vault password. Returns true on success and loads cached data.
#[tauri::command]
fn unlock(password: String, state: State<SharedState>) -> Result<bool, String> {
    if password != VAULT_PASSWORD {
        return Ok(false);
    }
    let cfg = Config::from_env().map_err(|e| e)?;
    let mut st = state.lock().unwrap();
    st.config = Some(cfg);
    if let Some(data) = load_vault() {
        st.mnemonic = data.mnemonic;
        st.favorites = data.favorites;
        st.bookmarks = data.cached_bookmarks.clone();
        // Show cached passwords instantly (display-only DTOs) before the live
        // sync replaces them with full editable records. Editing is disabled
        // until sync completes (no record backing yet).
        st.pw_dtos = data
            .cached_items
            .iter()
            .map(|it| password_item_dto(it))
            .collect();
        stamp_uids(&mut st.pw_dtos);
        compute_password_flags(&mut st.pw_dtos); // so Weak/Reused/Conflict work pre-sync
        st.bm_dtos = data.cached_bookmarks.iter().map(|b| bookmark_dto(b, false)).collect();
        compute_bookmark_flags(&mut st.bm_dtos);
        st.identities = data.cached_identities.clone();
        st.id_dtos = data.cached_identities.iter().map(identity_dto).collect();
        st.reading_list = data.cached_reading_list.clone();
        st.tab_groups = data.cached_tab_groups.clone();
        st.open_tabs = data.cached_open_tabs.clone();
        st.rl_dtos = data.cached_reading_list.iter().map(link_dto).collect();
        st.tg_dtos = data.cached_tab_groups.iter().map(link_dto).collect();
        st.ot_dtos = data.cached_open_tabs.iter().map(link_dto).collect();
        st.devices = data.cached_devices.clone();
        st.dev_dtos = data.cached_devices.iter().map(device_dto).collect();
        // Show pending (uncommitted) changes over the cached snapshot, so an
        // edit made before a previous close is visible immediately on reopen.
        apply_outbox_overlay(&mut st);
    }
    Ok(true)
}

#[tauri::command]
fn generate_chain(state: State<SharedState>) -> Result<String, String> {
    let (_bytes, phrase) = seed::generate();
    let mut st = state.lock().unwrap();
    let mut data = load_vault().unwrap_or_default();
    data.mnemonic = Some(phrase.clone());
    write_vault(&data)?;
    st.mnemonic = Some(phrase.clone());
    // Return the 25-word Brave-format code to display.
    Ok(time_words::generate_for_now(&phrase))
}

#[tauri::command]
fn join_chain(code: String, state: State<SharedState>) -> Result<(), String> {
    let pure = time_words::parse(code.trim()).map_err(|e| e.to_string())?;
    let mut data = load_vault().unwrap_or_default();
    data.mnemonic = Some(pure.clone());
    write_vault(&data)?;
    state.lock().unwrap().mnemonic = Some(pure);
    Ok(())
}

/// Full network sync + decrypt. Runs the blocking network work on a worker
/// thread so the UI never freezes. Persists to the encrypted vault.
#[tauri::command]
async fn sync(state: State<'_, SharedState>) -> Result<SyncResult, String> {
    let shared = state.inner().clone();
    let (cfg, mnemonic) = {
        let st = shared.lock().unwrap();
        (
            st.config.clone().ok_or("not unlocked")?,
            st.mnemonic.clone().ok_or("no chain")?,
        )
    };
    // Heavy blocking network + crypto off the UI thread.
    let data = tauri::async_runtime::spawn_blocking(move || {
        Session::new(cfg, mnemonic.clone()).fetch_all().map(|d| (mnemonic, d))
    })
    .await
    .map_err(|e| e.to_string())??;
    let (mnemonic, data) = data;

    // Persist to vault.
    let mut vd = load_vault().unwrap_or_default();
    vd.mnemonic = Some(mnemonic);
    vd.cached_items = data.passwords.iter().map(|r| r.item.clone()).collect();
    vd.cached_bookmarks = data.bookmarks.clone();
    vd.cached_identities = data.identities.clone();
    vd.cached_reading_list = data.reading_list.clone();
    vd.cached_tab_groups = data.tab_groups.clone();
    vd.cached_open_tabs = data.open_tabs.clone();
    vd.cached_devices = data.devices.clone();
    let _ = write_vault(&vd);

    let mut st = shared.lock().unwrap();
    let counts = (data.passwords.len(), data.bookmarks.len());
    st.passwords = data.passwords;
    st.bookmarks = data.bookmarks;
    st.identities = data.identities;
    st.reading_list = data.reading_list;
    st.tab_groups = data.tab_groups;
    st.open_tabs = data.open_tabs;
    st.devices = data.devices;
    rebuild_dtos(&mut st);
    Ok(SyncResult {
        password_count: counts.0,
        bookmark_count: counts.1,
        pending_count: outbox_len(),
    })
}

/// List items for a view: "all" | "passwords" | "favorites" | "bookmarks".
/// Cheap: filters prebuilt DTO caches, stamps the live favorite flag. No disk
/// or base64 work here — that happened once in rebuild_dtos.
/// Sort a list of DTOs in place by the given mode.
fn sort_items(items: &mut [ItemDto], mode: &str) {
    match mode {
        "created" => items.sort_by(|a, b| b.date_created.cmp(&a.date_created)),
        "used" => items.sort_by(|a, b| b.date_used.cmp(&a.date_used)),
        "modified" => items.sort_by(|a, b| b.date_modified.cmp(&a.date_modified)),
        "weakest" => items.sort_by(|a, b| a.strength.cmp(&b.strength)),
        _ => items.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase())),
    }
}

/// sort: "name" | "created" | "used" | "modified" | "weakest"
/// filter: "" | "weak" | "reused"  (applies to password rows)
#[tauri::command]
fn list_items(
    view: String,
    query: String,
    folder: String,
    sort: String,
    filter: String,
    state: State<SharedState>,
) -> Vec<ItemDto> {
    let st = state.lock().unwrap();
    let q = query.to_lowercase();
    let favset: std::collections::HashSet<&str> = st.favorites.iter().map(|s| s.as_str()).collect();
    let mut out: Vec<ItemDto> = Vec::new();

    if view == "identities" {
        for d in st.id_dtos.iter().filter(|d| {
            q.is_empty()
                || d.title.to_lowercase().contains(&q)
                || d.subtitle.to_lowercase().contains(&q)
                || d.notes.to_lowercase().contains(&q)
        }) {
            let mut d = d.clone();
            d.favorite = favset.contains(d.id.as_str());
            out.push(d);
        }
        return out;
    }

    if view == "devices" {
        for d in st.dev_dtos.iter().filter(|d| {
            q.is_empty()
                || d.title.to_lowercase().contains(&q)
                || d.subtitle.to_lowercase().contains(&q)
        }) {
            out.push(d.clone());
        }
        return out;
    }

    // Link-based views (reading list, tab groups, open tabs). Group header
    // rows are kept in place; only non-group rows are query-filtered.
    let link_src = match view.as_str() {
        "reading" => Some(&st.rl_dtos),
        "tabgroups" => Some(&st.tg_dtos),
        "opentabs" => Some(&st.ot_dtos),
        _ => None,
    };
    if let Some(src) = link_src {
        for d in src.iter() {
            if !q.is_empty() && d.kind != "group"
                && !(d.title.to_lowercase().contains(&q) || d.url.to_lowercase().contains(&q))
            {
                continue;
            }
            out.push(d.clone());
        }
        return out;
    }

    if view == "bookmarks" {
        // Duplicate filter: flat list of all bookmarks with a repeated URL.
        if filter == "dupes" {
            let mut dups: Vec<ItemDto> = st
                .bm_dtos
                .iter()
                .filter(|b| b.reused) // reused == duplicate URL for bookmarks
                .filter(|b| {
                    q.is_empty()
                        || b.title.to_lowercase().contains(&q)
                        || b.url.to_lowercase().contains(&q)
                })
                .cloned()
                .collect();
            // Group duplicates together by URL, then title.
            dups.sort_by(|a, b| {
                a.url.to_lowercase().cmp(&b.url.to_lowercase())
                    .then(a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            });
            for mut b in dups {
                b.favorite = favset.contains(b.id.as_str());
                out.push(b);
            }
            return out;
        }
        let known: std::collections::HashSet<&str> =
            st.bm_dtos.iter().map(|b| b.guid.as_str()).collect();
        let mut kids: Vec<ItemDto> = st
            .bm_dtos
            .iter()
            .filter(|b| {
                if !q.is_empty() {
                    b.kind != "folder"
                        && (b.title.to_lowercase().contains(&q) || b.url.to_lowercase().contains(&q))
                } else if folder.is_empty() {
                    !known.contains(b.parent_guid.as_str())
                } else {
                    b.parent_guid == folder
                }
            })
            .cloned()
            .collect();
        kids.sort_by(|a, b| {
            (b.kind == "folder")
                .cmp(&(a.kind == "folder"))
                .then(a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        for mut b in kids {
            b.favorite = favset.contains(b.id.as_str());
            out.push(b);
        }
        return out;
    }

    let fav_only = view == "favorites";
    let mut pw: Vec<ItemDto> = st
        .pw_dtos
        .iter()
        .filter(|d| !fav_only || favset.contains(d.id.as_str()))
        .filter(|d| match filter.as_str() {
            "weak" => d.weak,
            "reused" => d.reused,
            "conflict" => d.conflict,
            _ => true,
        })
        .filter(|d| {
            q.is_empty()
                || d.title.to_lowercase().contains(&q)
                || d.username.to_lowercase().contains(&q)
                || d.url.to_lowercase().contains(&q)
        })
        .cloned()
        .collect();
    sort_items(&mut pw, &sort);
    for mut d in pw {
        d.favorite = favset.contains(d.id.as_str());
        out.push(d);
    }
    // Favorited bookmarks appear in "all"/"favorites" — but NOT when a
    // password-only filter (weak/reused) is active, since those don't apply.
    if view != "passwords" && filter.is_empty() {
        let mut bm: Vec<ItemDto> = st
            .bm_dtos
            .iter()
            .filter(|b| b.kind != "folder" && favset.contains(b.id.as_str()))
            .filter(|b| q.is_empty() || b.title.to_lowercase().contains(&q) || b.url.to_lowercase().contains(&q))
            .cloned()
            .collect();
        bm.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        for mut b in bm {
            b.favorite = true;
            out.push(b);
        }
    }
    out
}

/// Other password entries that share the same site (signon_realm) as the item
/// with `uid`, excluding that exact entry. Used for "related items".
#[tauri::command]
fn related_items(uid: String, state: State<SharedState>) -> Vec<ItemDto> {
    let st = state.lock().unwrap();
    let favset: std::collections::HashSet<&str> = st.favorites.iter().map(|s| s.as_str()).collect();
    let Some(me) = st.pw_dtos.iter().find(|d| d.uid == uid) else { return Vec::new() };
    if me.realm.is_empty() {
        return Vec::new();
    }
    let realm = me.realm.clone();
    let mut rel: Vec<ItemDto> = st
        .pw_dtos
        .iter()
        .filter(|d| d.uid != uid && d.realm == realm)
        .cloned()
        .collect();
    rel.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    for d in &mut rel {
        d.favorite = favset.contains(d.id.as_str());
    }
    rel
}

#[tauri::command]
fn toggle_favorite(id: String, state: State<SharedState>) -> Result<bool, String> {
    let mut st = state.lock().unwrap();
    let now_fav;
    if let Some(pos) = st.favorites.iter().position(|f| f == &id) {
        st.favorites.remove(pos);
        now_fav = false;
    } else {
        st.favorites.push(id);
        now_fav = true;
    }
    let mut data = load_vault().unwrap_or_default();
    data.favorites = st.favorites.clone();
    let _ = write_vault(&data);
    Ok(now_fav)
}

#[tauri::command]
fn generate_password(length: usize, digits: bool, symbols: bool, avoid_ambiguous: bool) -> String {
    pwgen::generate(length, digits, symbols, avoid_ambiguous)
}

#[derive(Deserialize, Serialize, Clone)]
struct SaveArgs {
    id: String, // "" for new
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
}

#[tauri::command]
async fn save_item(args: SaveArgs, state: State<'_, SharedState>) -> Result<(), String> {
    let (cfg, mnemonic) = creds(&state)?;
    commit_durable(cfg, mnemonic, OutboxOp::SavePassword(args)).await
}

#[derive(Deserialize, Serialize, Clone)]
struct BookmarkArgs {
    title: String,
    url: String,
    parent_guid: String,
}

#[tauri::command]
async fn save_bookmark(args: BookmarkArgs, state: State<'_, SharedState>) -> Result<(), String> {
    let (cfg, mnemonic) = creds(&state)?;
    commit_durable(cfg, mnemonic, OutboxOp::SaveBookmark(args)).await
}

#[derive(Deserialize, Serialize, Clone)]
struct IdentityArgs {
    name: String,
    email: String,
    phone: String,
    company: String,
    street: String,
    city: String,
    state: String,
    zip: String,
    country: String,
}

#[tauri::command]
async fn save_identity(args: IdentityArgs, state: State<'_, SharedState>) -> Result<(), String> {
    let (cfg, mnemonic) = creds(&state)?;
    commit_durable(cfg, mnemonic, OutboxOp::SaveIdentity(args)).await
}

/// Remove a device from the sync chain by its cache_guid. The device will
/// re-register if it is still online and syncing.
#[tauri::command]
async fn delete_device(cache_guid: String, state: State<'_, SharedState>) -> Result<(), String> {
    let (cfg, mnemonic) = creds(&state)?;
    commit_durable(cfg, mnemonic, OutboxOp::DeleteDevice { cache_guid }).await
}

/// Tombstone every non-current device on the chain that hasn't synced in the
/// last `days` days. Only affects this chain (keyed by our mnemonic). Returns
/// the number of devices removed. Runs the blocking network work off the UI
/// thread; drops the purged rows from the cached DTOs on success.
#[tauri::command]
async fn purge_stale_devices(days: i64, state: State<'_, SharedState>) -> Result<usize, String> {
    let (cfg, mnemonic) = creds(&state)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cutoff = now - days.max(0) * 86400;
    let shared = state.inner().clone();
    let removed = tauri::async_runtime::spawn_blocking(move || {
        Session::new(cfg, mnemonic).commit_delete_stale_devices(cutoff)
    })
    .await
    .map_err(|e| e.to_string())??;
    if !removed.is_empty() {
        let mut st = shared.lock().unwrap();
        let gone: std::collections::HashSet<&str> = removed.iter().map(|s| s.as_str()).collect();
        st.devices.retain(|d| d.is_current || !gone.contains(d.name.as_str()));
        st.dev_dtos.retain(|d| d.current || !gone.contains(d.title.as_str()));
    }
    Ok(removed.len())
}

#[tauri::command]
async fn delete_item(id: String, state: State<'_, SharedState>) -> Result<(), String> {
    let (cfg, mnemonic) = creds(&state)?;
    commit_durable(cfg, mnemonic, OutboxOp::DeleteItem { id }).await
}

/// Replay any mutations left in the durable outbox from a previous run (e.g. the
/// app closed mid-commit). Runs sequentially on a worker thread; each entry is
/// cleared only after its commit succeeds, so failures stay queued. Returns the
/// number of entries successfully flushed.
#[tauri::command]
async fn replay_outbox(state: State<'_, SharedState>) -> Result<usize, String> {
    let (cfg, mnemonic) = creds(&state)?;
    let entries: Vec<OutboxEntry> = load_vault()
        .map(|d| {
            d.outbox
                .iter()
                .filter_map(|b| serde_json::from_str::<OutboxEntry>(b).ok())
                .collect()
        })
        .unwrap_or_default();
    if entries.is_empty() {
        return Ok(0);
    }
    tauri::async_runtime::spawn_blocking(move || {
        let sess = Session::new(cfg, mnemonic);
        let mut flushed = 0;
        for entry in entries {
            match apply_outbox_op(&sess, &entry.op) {
                Ok(()) => {
                    outbox_remove(&entry.id);
                    flushed += 1;
                }
                // Leave this (and remaining) entries queued for the next attempt.
                Err(_) => break,
            }
        }
        flushed
    })
    .await
    .map_err(|e| e.to_string())
}

/// Fetch favicons + titles for all current items in parallel on worker threads
/// (never blocks the UI). Rebuilds DTOs so new icons/titles show. Returns the
/// number newly fetched.
#[tauri::command]
async fn fetch_favicons(state: State<'_, SharedState>) -> Result<usize, String> {
    let shared = state.inner().clone();
    let hosts: Vec<String> = {
        let st = shared.lock().unwrap();
        let mut hs: Vec<String> = st
            .passwords
            .iter()
            .filter_map(|r| favicon::host_of(&r.item.website()))
            .collect();
        hs.extend(
            st.bookmarks
                .iter()
                .filter(|b| !b.is_folder)
                .filter_map(|b| favicon::host_of(&b.url)),
        );
        hs
    };
    // If the fetch rules changed since the cache was built, re-evaluate
    // everything (ignore stale .miss markers); otherwise trust the cache.
    let rules_current = favicon::cache_is_current();
    let mut seen = std::collections::HashSet::new();
    let todo: Vec<String> = hosts
        .into_iter()
        .filter(|h| seen.insert(h.clone()))
        .filter(|h| {
            let have_icon = favicon::is_cached(h);
            let have_title = favicon::load_cached_title(h).is_some();
            if rules_current {
                // Fully cached (icon + title) or a known miss -> skip.
                !(have_icon && have_title) && !favicon::is_known_miss(h)
            } else {
                // Rules changed: refetch unless we already have BOTH under the
                // new rules (titles are re-validated by load_cached_title).
                !(have_icon && have_title)
            }
        })
        .collect();
    if todo.is_empty() {
        favicon::mark_cache_current();
        return Ok(0);
    }

    // Parallel fetch across a bounded worker pool.
    let count = tauri::async_runtime::spawn_blocking(move || {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let queue = Arc::new(Mutex::new(todo));
        let n = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let queue = queue.clone();
            let n = n.clone();
            handles.push(std::thread::spawn(move || loop {
                let host = { queue.lock().unwrap().pop() };
                let Some(host) = host else { break };
                if favicon::fetch_and_cache(&host).is_some() {
                    n.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        n.load(Ordering::Relaxed)
    })
    .await
    .map_err(|e| e.to_string())?;

    // Record that the cache is now built with the current rules.
    favicon::mark_cache_current();
    // Refresh DTOs so the newly cached icons/titles are used.
    {
        let mut st = shared.lock().unwrap();
        rebuild_dtos(&mut st);
    }
    Ok(count)
}

#[tauri::command]
fn lock(state: State<SharedState>) {
    let mut st = state.lock().unwrap();
    st.passwords.clear();
    st.bookmarks.clear();
    st.pw_dtos.clear();
    st.bm_dtos.clear();
    st.mnemonic = None;
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(SharedState::default())
        .invoke_handler(tauri::generate_handler![
            has_config,
            has_chain,
            unlock,
            generate_chain,
            join_chain,
            sync,
            list_items,
            related_items,
            favicons,
            toggle_favorite,
            generate_password,
            save_item,
            save_bookmark,
            save_identity,
            delete_item,
            delete_device,
            purge_stale_devices,
            replay_outbox,
            fetch_favicons,
            lock,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Brave Vault");
}
