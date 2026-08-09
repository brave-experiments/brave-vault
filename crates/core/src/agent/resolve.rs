//! Resolve a human item string (e.g. "example.com", "alice@example.com") to
//! concrete vault item ids, using the same id scheme the app uses:
//! `pw:<signon_realm>|<username>`, `bm:<guid>`, `id:<guid>`.
//!
//! Resolution is intentionally conservative: if a query matches more than one
//! item the broker should force a user prompt to disambiguate rather than guess.

use crate::model::{BookmarkItem, IdentityItem, PasswordItem};

/// A candidate item a query matched, with a stable id and a short label for the
/// approval popup / audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub id: String,
    pub kind: &'static str, // "password" | "identity" | "bookmark"
    pub label: String,
}

/// The id an app/broker uses for a password item.
pub fn password_id(it: &PasswordItem) -> String {
    format!("pw:{}", it.key())
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// The origin (`scheme://host[:port]`) of a URL, lower-cased, for origin-binding
/// checks. Returns "" if there's no host. Deliberately strict: a credential
/// stored for `https://admin.example.com` must not match `https://api-admin.
/// example.com` — the host comparison is exact, so lookalike domains differ.
pub fn origin_of(url: &str) -> String {
    let url = url.trim();
    // Split scheme.
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => return String::new(),
    };
    // Authority ends at the first '/', '?' or '#'.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    // Drop any userinfo ("user:pass@host").
    let hostport = authority.rsplit('@').next().unwrap_or("");
    if hostport.is_empty() {
        return String::new();
    }
    format!("{scheme}://{hostport}")
}

/// Whether two URLs share the same origin. Used to bind an injection to the
/// credential's own site.
pub fn same_origin(a: &str, b: &str) -> bool {
    let oa = origin_of(a);
    !oa.is_empty() && oa == origin_of(b)
}

/// Find all items matching `query` across the given collections. A password
/// matches on realm/origin/username/title; an identity on name/email; a
/// bookmark on title/url. Case-insensitive substring match.
pub fn resolve(
    query: &str,
    passwords: &[PasswordItem],
    identities: &[IdentityItem],
    bookmarks: &[BookmarkItem],
) -> Vec<Match> {
    let q = query.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();

    for it in passwords {
        if contains_ci(&it.signon_realm, q)
            || contains_ci(&it.origin, q)
            || contains_ci(&it.username, q)
            || contains_ci(&it.title(), q)
        {
            let label = if it.username.is_empty() {
                it.title()
            } else {
                format!("{} ({})", it.title(), it.username)
            };
            out.push(Match {
                id: password_id(it),
                kind: "password",
                label,
            });
        }
    }

    for it in identities {
        if contains_ci(&it.name, q) || contains_ci(&it.email, q) {
            out.push(Match {
                id: format!("id:{}", it.guid),
                kind: "identity",
                label: it.title(),
            });
        }
    }

    for b in bookmarks {
        if b.is_folder {
            continue;
        }
        if contains_ci(&b.title, q) || contains_ci(&b.url, q) {
            out.push(Match {
                id: format!("bm:{}", b.guid),
                kind: "bookmark",
                label: if b.title.is_empty() {
                    b.url.clone()
                } else {
                    b.title.clone()
                },
            });
        }
    }

    out
}

/// Exact-id lookup: does one of these collections contain the given item id?
/// Used when a grant already names a concrete id (e.g. pre-created grants).
pub fn find_by_id<'a>(
    id: &str,
    passwords: &'a [PasswordItem],
    identities: &'a [IdentityItem],
    bookmarks: &'a [BookmarkItem],
) -> Option<Match> {
    if let Some(_key) = id.strip_prefix("pw:") {
        return passwords
            .iter()
            .find(|it| password_id(it) == id)
            .map(|it| Match {
                id: id.to_string(),
                kind: "password",
                label: it.title(),
            });
    }
    if let Some(guid) = id.strip_prefix("id:") {
        return identities
            .iter()
            .find(|it| it.guid == guid)
            .map(|it| Match {
                id: id.to_string(),
                kind: "identity",
                label: it.title(),
            });
    }
    if let Some(guid) = id.strip_prefix("bm:") {
        return bookmarks.iter().find(|b| b.guid == guid).map(|b| Match {
            id: id.to_string(),
            kind: "bookmark",
            label: b.title.clone(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(realm: &str, user: &str) -> PasswordItem {
        PasswordItem {
            signon_realm: realm.into(),
            origin: realm.into(),
            username: user.into(),
            password: "secret".into(),
            ..Default::default()
        }
    }

    #[test]
    fn resolves_password_by_host_and_user() {
        let pws = vec![
            pw("https://example.com/", "alice"),
            pw("https://other.com/", "bob"),
        ];
        let m = resolve("example.com", &pws, &[], &[]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "pw:https://example.com/|alice");
        assert_eq!(m[0].kind, "password");

        let m2 = resolve("alice", &pws, &[], &[]);
        assert_eq!(m2.len(), 1);
    }

    #[test]
    fn ambiguous_query_returns_many() {
        let pws = vec![
            pw("https://example.com/", "alice"),
            pw("https://example.com/", "bob"),
        ];
        let m = resolve("example.com", &pws, &[], &[]);
        assert_eq!(m.len(), 2); // broker must disambiguate
    }

    #[test]
    fn find_by_id_exact() {
        let pws = vec![pw("https://example.com/", "alice")];
        let hit = find_by_id("pw:https://example.com/|alice", &pws, &[], &[]);
        assert!(hit.is_some());
        assert!(find_by_id("pw:nope|x", &pws, &[], &[]).is_none());
    }

    #[test]
    fn empty_query_matches_nothing() {
        let pws = vec![pw("https://example.com/", "alice")];
        assert!(resolve("  ", &pws, &[], &[]).is_empty());
    }

    #[test]
    fn origin_extracts_scheme_host_port() {
        assert_eq!(
            origin_of("https://example.com/login"),
            "https://example.com"
        );
        assert_eq!(
            origin_of("https://example.com:8443/x"),
            "https://example.com:8443"
        );
        assert_eq!(origin_of("http://a.b.com/p?q=1#f"), "http://a.b.com");
        assert_eq!(origin_of("https://user:pw@host.com/x"), "https://host.com");
        assert_eq!(origin_of("HTTPS://Example.COM/X"), "https://example.com");
        assert_eq!(origin_of("not a url"), "");
        assert_eq!(origin_of(""), "");
    }

    #[test]
    fn lookalike_hosts_are_different_origins() {
        // A lookalike-domain prefix (admin vs api-admin) must NOT match.
        assert!(!same_origin(
            "https://admin.example.com/login",
            "https://api-admin.example.com/login"
        ));
        assert!(same_origin(
            "https://admin.example.com/login",
            "https://admin.example.com/account"
        ));
        // Scheme mismatch is a different origin too.
        assert!(!same_origin("http://x.com/", "https://x.com/"));
    }
}
