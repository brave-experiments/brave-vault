//! Building password commit entities (write-back to the sync server).
//!
//! Mirrors Chromium's password_sync_bridge.cc (ComputeClientTag) and
//! client_tag_hash.cc (FromUnhashed).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use prost::Message;
use sha1::{Digest, Sha1};

use crate::crypto::keybag::KeyBag;
use crate::sync::client::PASSWORDS_DATA_TYPE_ID;
use crate::sync::proto;

/// Percent-encode like Chromium's base::EscapePath: everything that isn't an
/// unreserved char or one of a small safe set gets %XX-encoded. Chromium's
/// EscapePath leaves unreserved chars plus "-_.!~*'()" and "/:" ... but to be
/// safe and match, we replicate net::EscapePath's "component" behavior: encode
/// everything except ALPHA / DIGIT / "-_.!~*'()".
fn escape_path(s: &str) -> String {
    // base::EscapePath keeps: a-zA-Z0-9 and - _ . ! ~ * ' ( ) — encodes the rest
    // (including '/', ':', '|', space) as %XX uppercase.
    const KEEP: &[u8] = b"-_.!~*'()";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || KEEP.contains(&b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// ComputeClientTag: EscapePath(origin)|EscapePath(username_element)|
/// EscapePath(username_value)|EscapePath(password_element)|EscapePath(signon_realm)
pub fn client_tag(d: &proto::PasswordSpecificsData) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        escape_path(d.origin()),
        escape_path(d.username_element()),
        escape_path(d.username_value()),
        escape_path(d.password_element()),
        escape_path(d.signon_realm()),
    )
}

/// client_tag_hash = Base64(SHA1( EntitySpecifics{empty password field} || client_tag )).
///
/// The "default field value" is an EntitySpecifics with just the password field
/// present (empty) — its serialization is the field tag + length 0.
pub fn client_tag_hash(tag: &str) -> String {
    let specifics = proto::EntitySpecifics {
        password: Some(proto::PasswordSpecifics::default()),
        ..Default::default()
    };
    let mut input = specifics.encode_to_vec();
    input.extend_from_slice(tag.as_bytes());
    let digest = Sha1::digest(&input);
    B64.encode(digest)
}

/// Build a commit-ready SyncEntity for an edited password.
///
/// `original` is the entity as fetched (so we preserve id_string, version, and
/// any specifics fields we don't touch). `new_data` is the full, modified
/// PasswordSpecificsData. `orig_blob` is the original encrypted blob, used to
/// pick the same encryption key.
pub fn build_password_entity(
    original: &proto::SyncEntity,
    new_data: &proto::PasswordSpecificsData,
    orig_blob: &str,
    keybag: &KeyBag,
) -> Option<proto::SyncEntity> {
    let plaintext = new_data.encode_to_vec();
    let (key_name, blob) = keybag.reencrypt_matching(orig_blob, &plaintext)?;

    let tag = client_tag(new_data);
    let hash = client_tag_hash(&tag);

    let mut entity = original.clone();
    entity.specifics = Some(proto::EntitySpecifics {
        password: Some(proto::PasswordSpecifics {
            encrypted: Some(proto::EncryptedData {
                key_name: Some(key_name),
                blob: Some(blob),
            }),
            // Preserve unencrypted metadata / notes backup if the original had
            // them so we don't strip data the server/other clients expect.
            unencrypted_metadata: original
                .specifics
                .as_ref()
                .and_then(|s| s.password.as_ref())
                .and_then(|p| p.unencrypted_metadata.clone()),
            ..Default::default()
        }),
        ..Default::default()
    });
    entity.client_tag_hash = Some(hash);
    entity.deleted = Some(false);
    entity.mtime = Some(now_ms());
    // name/non_unique_name are required-ish; use the client tag as Chromium does.
    entity.name = Some(tag.clone());
    entity.non_unique_name = Some(tag);
    Some(entity)
}

/// Build a commit entity for a brand-new password (no original entity).
///
/// Matches Chromium's initial-commit shape (commit_contribution_impl.cc):
/// version=0, a fresh random UUID id_string, client_tag_hash, ctime/mtime set.
pub fn build_new_password_entity(
    new_data: &proto::PasswordSpecificsData,
    keybag: &KeyBag,
) -> Option<proto::SyncEntity> {
    let plaintext = new_data.encode_to_vec();
    let (key_name, blob) = keybag.encrypt_default(&plaintext)?;
    let tag = client_tag(new_data);
    let hash = client_tag_hash(&tag);
    let _ = PASSWORDS_DATA_TYPE_ID;
    let now_ms = crate::sync::commit::now_ms();
    Some(proto::SyncEntity {
        id_string: Some(random_uuid()),
        version: Some(0),
        client_tag_hash: Some(hash),
        name: Some(tag.clone()),
        non_unique_name: Some(tag),
        deleted: Some(false),
        ctime: Some(now_ms),
        mtime: Some(now_ms),
        specifics: Some(proto::EntitySpecifics {
            password: Some(proto::PasswordSpecifics {
                encrypted: Some(proto::EncryptedData {
                    key_name: Some(key_name),
                    blob: Some(blob),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Milliseconds since the Unix epoch (Chromium's TimeToProtoTime).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// client_tag_hash for a datatype whose "default field value" is `default_es`
/// (an EntitySpecifics with just that type's field present, empty).
fn client_tag_hash_with(default_es: &proto::EntitySpecifics, tag: &str) -> String {
    let mut input = default_es.encode_to_vec();
    input.extend_from_slice(tag.as_bytes());
    B64.encode(Sha1::digest(&input))
}

/// Build a new bookmark (URL) commit entity. Bookmarks encrypt the WHOLE
/// EntitySpecifics into specifics.encrypted (generic path); client_tag = guid.
pub fn build_new_bookmark_entity(
    title: &str,
    url: &str,
    parent_guid: &str,
    keybag: &KeyBag,
) -> Option<proto::SyncEntity> {
    let guid = random_uuid();
    let bm = proto::BookmarkSpecifics {
        guid: Some(guid.clone()),
        full_title: Some(title.to_string()),
        legacy_canonicalized_title: Some(title.to_string()),
        url: Some(url.to_string()),
        parent_guid: Some(parent_guid.to_string()),
        r#type: Some(proto::bookmark_specifics::Type::Url as i32),
        creation_time_us: Some(now_ms() * 1000),
        ..Default::default()
    };
    let inner = proto::EntitySpecifics {
        bookmark: Some(bm),
        ..Default::default()
    };
    let (key_name, blob) = keybag.encrypt_default(&inner.encode_to_vec())?;
    let default_es = proto::EntitySpecifics {
        bookmark: Some(proto::BookmarkSpecifics::default()),
        ..Default::default()
    };
    let hash = client_tag_hash_with(&default_es, &guid);
    let now = now_ms();
    Some(proto::SyncEntity {
        id_string: Some(random_uuid()),
        version: Some(0),
        client_tag_hash: Some(hash),
        name: Some(title.to_string()),
        non_unique_name: Some(title.to_string()),
        deleted: Some(false),
        folder: Some(false),
        ctime: Some(now),
        mtime: Some(now),
        specifics: Some(proto::EntitySpecifics {
            encrypted: Some(proto::EncryptedData {
                key_name: Some(key_name),
                blob: Some(blob),
            }),
            // Type marker so the server can route the opaque encrypted blob
            // (Chromium's AddDefaultFieldValue). Empty bookmark field present.
            bookmark: Some(proto::BookmarkSpecifics::default()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Build a new identity (autofill profile) commit entity. Generic-encrypted;
/// client_tag = guid.
pub fn build_new_identity_entity(
    profile: proto::AutofillProfileSpecifics,
    keybag: &KeyBag,
) -> Option<proto::SyncEntity> {
    let guid = profile.guid().to_string();
    let inner = proto::EntitySpecifics {
        autofill_profile: Some(profile),
        ..Default::default()
    };
    let (key_name, blob) = keybag.encrypt_default(&inner.encode_to_vec())?;
    let default_es = proto::EntitySpecifics {
        autofill_profile: Some(proto::AutofillProfileSpecifics::default()),
        ..Default::default()
    };
    let hash = client_tag_hash_with(&default_es, &guid);
    let now = now_ms();
    Some(proto::SyncEntity {
        id_string: Some(random_uuid()),
        version: Some(0),
        client_tag_hash: Some(hash),
        name: Some(guid.clone()),
        non_unique_name: Some(guid),
        deleted: Some(false),
        ctime: Some(now),
        mtime: Some(now),
        specifics: Some(proto::EntitySpecifics {
            encrypted: Some(proto::EncryptedData {
                key_name: Some(key_name),
                blob: Some(blob),
            }),
            // Type marker so the server can route the opaque encrypted blob.
            autofill_profile: Some(proto::AutofillProfileSpecifics::default()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// A lowercase random UUIDv4 string, without pulling in the uuid crate.
pub fn random_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_tag_format() {
        let mut d = proto::PasswordSpecificsData::default();
        d.origin = Some("https://example.com/".into());
        d.username_value = Some("user@example.com".into());
        d.signon_realm = Some("https://example.com/".into());
        let tag = client_tag(&d);
        // spaces/colons/slashes escaped; pipes are literal separators
        assert!(tag.contains("https%3A%2F%2Fexample.com%2F"));
        assert_eq!(tag.split('|').count(), 5);
    }

    #[test]
    fn hash_is_stable_base64_sha1() {
        let h = client_tag_hash("a|b|c|d|e");
        // base64 of a 20-byte SHA1 is 28 chars ending in '='
        assert_eq!(h.len(), 28);
        assert!(h.ends_with('='));
    }
}
