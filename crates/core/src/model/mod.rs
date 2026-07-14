//! App-facing data model.

use serde::{Deserialize, Serialize};

use crate::sync::proto;

/// A decrypted bookmark (URL or folder). Hierarchy is via `parent_guid`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BookmarkItem {
    pub guid: String,
    pub parent_guid: String,
    pub title: String,
    pub url: String,
    pub is_folder: bool,
}

/// A generic link entry: reading list item, saved-tab-group tab, or open tab.
/// `group` labels which collection it belongs to (for grouped display).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LinkItem {
    pub id: String,     // stable per-entry id
    pub title: String,
    pub url: String,
    pub group: String,  // e.g. tab-group name, device name, or ""
    pub is_group: bool, // true for a group/device header row
}

impl BookmarkItem {
    pub fn from_specifics(b: &proto::BookmarkSpecifics) -> Self {
        let title = if !b.full_title().is_empty() {
            b.full_title().to_string()
        } else {
            b.legacy_canonicalized_title().to_string()
        };
        // Type: 2 = FOLDER, 1 = URL. Fall back to "folder if no url".
        let is_folder = b.r#type() == proto::bookmark_specifics::Type::Folder
            || (b.r#type() == proto::bookmark_specifics::Type::Unspecified && b.url().is_empty());
        BookmarkItem {
            guid: b.guid().to_string(),
            parent_guid: b.parent_guid().to_string(),
            title,
            url: b.url().to_string(),
            is_folder,
        }
    }
}

/// A device registered on the sync chain (DeviceInfo, never encrypted).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceItem {
    pub cache_guid: String,
    pub name: String,
    pub form_factor: String,      // human label: Desktop / Phone / Tablet / …
    pub os: String,               // human label: Windows / macOS / Linux / …
    pub last_updated_unix: i64,   // seconds since epoch (0 if unknown)
    pub is_current: bool,         // this device (our cache_guid)
}

impl DeviceItem {
    pub fn from_specifics(d: &proto::DeviceInfoSpecifics) -> Self {
        DeviceItem {
            cache_guid: d.cache_guid().to_string(),
            name: d.client_name().to_string(),
            form_factor: form_factor_label(d.device_form_factor(), d.device_type()),
            os: os_label(d.os_type()),
            last_updated_unix: d.last_updated_timestamp() / 1000,
            is_current: false,
        }
    }
}

/// SyncEnums.DeviceFormFactor (fall back to legacy DeviceType if unset).
fn form_factor_label(form_factor: i32, device_type: i32) -> String {
    match form_factor {
        1 => "Desktop",
        2 => "Phone",
        3 => "Tablet",
        4 => "Automotive",
        5 => "Wearable",
        6 => "TV",
        _ => match device_type {
            // Legacy SyncEnums.DeviceType (deprecated but still populated).
            1 | 2 | 3 | 4 => "Desktop", // Win / Mac / Linux / CrOS
            6 => "Phone",
            7 => "Tablet",
            _ => "Device",
        },
    }
    .to_string()
}

/// SyncEnums.OsType.
fn os_label(os_type: i32) -> String {
    match os_type {
        1 => "Windows",
        2 => "macOS",
        3 => "Linux",
        4 | 7 => "ChromeOS",
        5 => "Android",
        6 => "iOS",
        8 => "Fuchsia",
        _ => "",
    }
    .to_string()
}

/// A decrypted autofill identity (name / email / phone / address).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IdentityItem {
    pub guid: String,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub company: String,
    pub street: String,
    pub city: String,
    pub state: String,
    pub zip: String,
    pub country: String,
}

impl IdentityItem {
    pub fn from_specifics(a: &proto::AutofillProfileSpecifics) -> Self {
        // Most name/email/phone fields are `repeated`; take the first non-empty.
        let first = |v: &[String]| v.iter().find(|s| !s.is_empty()).cloned().unwrap_or_default();
        let street = if !a.address_home_street_address().is_empty() {
            a.address_home_street_address().to_string()
        } else {
            [a.address_home_line1(), a.address_home_line2()]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        IdentityItem {
            guid: a.guid().to_string(),
            name: first(&a.name_full),
            email: first(&a.email_address),
            phone: first(&a.phone_home_whole_number),
            company: a.company_name().to_string(),
            street,
            city: a.address_home_city().to_string(),
            state: a.address_home_state().to_string(),
            zip: a.address_home_zip().to_string(),
            country: a.address_home_country().to_string(),
        }
    }

    /// Best display title: name, else email, else company, else "Address".
    pub fn title(&self) -> String {
        for c in [&self.name, &self.email, &self.company] {
            if !c.is_empty() {
                return c.clone();
            }
        }
        "Address".to_string()
    }

    /// One-line address summary for the subtitle.
    pub fn summary(&self) -> String {
        let parts: Vec<&str> = [
            self.city.as_str(),
            self.state.as_str(),
            self.country.as_str(),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
        if !parts.is_empty() {
            parts.join(", ")
        } else if !self.email.is_empty() && self.title() != self.email {
            self.email.clone()
        } else {
            self.phone.clone()
        }
    }
}

/// A decrypted password entry for display.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PasswordItem {
    pub signon_realm: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    pub display_name: String,
    /// The primary note (empty unique_display_name in Brave's Notes list).
    #[serde(default)]
    pub notes: String,
    /// Microseconds since the Windows epoch (as Brave stores it).
    #[serde(default)]
    pub date_created: i64,
    #[serde(default)]
    pub date_last_used: i64,
    #[serde(default)]
    pub date_password_modified: i64,
}

impl PasswordItem {
    pub fn from_specifics(d: &proto::PasswordSpecificsData) -> Self {
        // Brave's primary note is the one with an empty unique_display_name.
        let notes = d
            .notes
            .as_ref()
            .and_then(|n| {
                n.note
                    .iter()
                    .find(|nt| nt.unique_display_name().is_empty())
                    .or_else(|| n.note.first())
            })
            .map(|nt| nt.value().to_string())
            .unwrap_or_default();
        PasswordItem {
            signon_realm: d.signon_realm().to_string(),
            origin: d.origin().to_string(),
            username: d.username_value().to_string(),
            password: d.password_value().to_string(),
            display_name: d.display_name().to_string(),
            notes,
            date_created: d.date_created(),
            date_last_used: d.date_last_used(),
            date_password_modified: d.date_password_modified_windows_epoch_micros(),
        }
    }

    /// A human title: display name, else host of the realm, else the realm.
    pub fn title(&self) -> String {
        if !self.display_name.is_empty() {
            return self.display_name.clone();
        }
        let src = if self.origin.is_empty() {
            &self.signon_realm
        } else {
            &self.origin
        };
        strip_scheme(src).trim_end_matches('/').to_string()
    }

    /// Stable identity used to persist favorites and de-dup: realm + username.
    pub fn key(&self) -> String {
        format!("{}|{}", self.signon_realm, self.username)
    }

    /// One- or two-letter uppercase initials for the avatar.
    pub fn initials(&self) -> String {
        let t = self.title();
        let host = strip_scheme(&t);
        let mut chars = host.chars().filter(|c| c.is_alphanumeric());
        let a = chars.next();
        match a {
            Some(c) => c.to_uppercase().collect::<String>(),
            None => "?".to_string(),
        }
    }

    /// A deterministic avatar color index (0..N) from the title.
    pub fn color_index(&self, n: u32) -> i32 {
        let mut h: u32 = 2166136261;
        for b in self.title().to_lowercase().bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(16777619);
        }
        (h % n) as i32
    }

    /// Best-effort website URL to open in a browser.
    pub fn website(&self) -> String {
        let src = if !self.origin.is_empty() {
            &self.origin
        } else {
            &self.signon_realm
        };
        if src.starts_with("http://") || src.starts_with("https://") {
            src.clone()
        } else if src.starts_with("android://") {
            String::new()
        } else if !src.is_empty() {
            format!("https://{}", strip_scheme(src))
        } else {
            String::new()
        }
    }
}

fn strip_scheme(s: &str) -> &str {
    s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s)
}

/// A 0-100 password strength score with a coarse label.
pub fn password_strength(pw: &str) -> (i32, &'static str) {
    if pw.is_empty() {
        return (0, "None");
    }
    let len = pw.chars().count();
    let has_lower = pw.chars().any(|c| c.is_lowercase());
    let has_upper = pw.chars().any(|c| c.is_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_alphanumeric());
    let classes =
        has_lower as i32 + has_upper as i32 + has_digit as i32 + has_symbol as i32;

    let mut score = 0i32;
    score += (len as i32 * 4).min(40);
    score += classes * 12;
    if len >= 12 {
        score += 12;
    }
    if len >= 16 {
        score += 8;
    }
    let score = score.clamp(0, 100);
    let label = match score {
        0..=39 => "Weak",
        40..=69 => "Fair",
        70..=89 => "Good",
        _ => "Strong",
    };
    (score, label)
}
