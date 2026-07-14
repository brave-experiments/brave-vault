//! Favicon fetching with a local-only disk cache.
//!
//! Privacy: favicons are fetched DIRECTLY from each site (never via a
//! third-party favicon service), so we don't leak the list of saved sites.
//! Results are cached as 64x64 PNGs under ~/.brave_pw/favicons/, keyed by host.

use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use image::imageops::FilterType;

const ICON_SIZE: u32 = 64;

/// Version of the favicon/title fetching + parsing rules. Bump this whenever the
/// parsing logic changes so stale caches (esp. `.miss` and `.title`) are ignored
/// and re-fetched. The cache dir records the version it was built with.
pub const RULES_VERSION: u32 = 3;

fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".brave_vault").join("favicons")
}

fn version_path() -> PathBuf {
    cache_dir().join(".rules_version")
}

/// True if the on-disk cache was built with the current rules version.
pub fn cache_is_current() -> bool {
    std::fs::read_to_string(version_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v == RULES_VERSION)
        .unwrap_or(false)
}

/// Mark the cache as built with the current rules version.
pub fn mark_cache_current() {
    let _ = std::fs::create_dir_all(cache_dir());
    let _ = std::fs::write(version_path(), RULES_VERSION.to_string());
}

/// A filesystem-safe cache key for a host. Empty hosts are rejected upstream.
fn cache_key(host: &str) -> String {
    let safe: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    safe
}

fn cache_path(host: &str) -> PathBuf {
    cache_dir().join(format!("{}.png", cache_key(host)))
}

/// A negative-cache marker so we don't re-hammer sites with no favicon.
fn miss_path(host: &str) -> PathBuf {
    cache_dir().join(format!("{}.miss", cache_key(host)))
}

/// Extract the host from a website URL or realm.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Skip android:// and other non-web schemes.
    if url.starts_with("android://") || rest.contains("://") {
        return None;
    }
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split('@').last().unwrap_or(host); // strip userinfo
    let host = host.split(':').next().unwrap_or(host); // strip port
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host.to_lowercase())
}

/// Best-effort registrable (apex) domain: last two labels, or three for common
/// two-part TLDs (co.uk, com.au). "accounts.binance.com" -> "binance.com".
fn apex_domain(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let two_part = ["co", "com", "org", "net", "gov", "ac", "edu"];
    let take = if labels.len() >= 3 && two_part.contains(&labels[labels.len() - 2]) {
        3
    } else {
        2
    };
    Some(labels[labels.len() - take..].join("."))
}

/// Whether a favicon PNG is cached for this host.
pub fn is_cached(host: &str) -> bool {
    cache_path(host).exists()
}

/// Return the cached favicon as a `data:image/png;base64,...` URI, if present.
/// This is what the web UI consumes directly in an <img src>.
pub fn cached_data_uri(host: &str) -> Option<String> {
    let bytes = std::fs::read(cache_path(host)).ok()?;
    Some(format!("data:image/png;base64,{}", B64.encode(bytes)))
}

/// Whether we've already tried and failed to find a favicon for this host.
pub fn is_known_miss(host: &str) -> bool {
    miss_path(host).exists()
}

fn title_path(host: &str) -> PathBuf {
    cache_dir().join(format!("{}.title", cache_key(host)))
}

/// Return a cached friendly site title for the host, if present and meaningful.
/// Rejects junk (empty, punctuation-only like "/") so callers fall back to a
/// prettified domain instead.
pub fn load_cached_title(host: &str) -> Option<String> {
    let s = std::fs::read_to_string(title_path(host)).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() || !s.chars().any(|c| c.is_alphanumeric()) {
        return None;
    }
    Some(s)
}

/// Fetch + cache a favicon AND friendly title for `host`. Fetches the homepage
/// once for both. Returns the decoded PNG bytes on success (title is cached as
/// a side effect). Runs on a worker thread (blocking HTTP).
pub fn fetch_and_cache(host: &str) -> Option<Vec<u8>> {
    let _ = std::fs::create_dir_all(cache_dir());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(6))
        // Real browser UA — some sites (e.g. Binance) bot-block generic agents.
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        .build()
        .ok()?;

    // Fetch homepage once: extract icon candidates + friendly title.
    let home = format!("https://{host}/");
    let mut icon_urls: Vec<String> = Vec::new();
    if let Ok(resp) = client.get(&home).send() {
        if resp.status().is_success() {
            if let Ok(html) = resp.text() {
                if let Some(title) = parse_site_title(&html, host) {
                    let _ = std::fs::write(title_path(host), title);
                }
                icon_urls = parse_icon_hrefs(&html)
                    .into_iter()
                    .map(|href| resolve_url(&home, host, &href))
                    .collect();
            }
        }
    }
    // Fallbacks: this host's /favicon.ico, then the apex domain's (auth
    // subdomains like accounts.binance.com often block bots while binance.com
    // serves a normal icon).
    let mut push = |u: String| {
        if !icon_urls.contains(&u) {
            icon_urls.push(u);
        }
    };
    push(format!("https://{host}/favicon.ico"));
    if let Some(apex) = apex_domain(host) {
        if apex != host {
            push(format!("https://{apex}/favicon.ico"));
            push(format!("https://www.{apex}/favicon.ico"));
        }
    }

    // If we already have a cached favicon, don't overwrite/miss it — we may be
    // here only to fetch a missing title.
    let already_have_icon = cache_path(host).exists();

    // Try each candidate URL until one downloads AND decodes to an image.
    for url in icon_urls {
        if let Some(b) = get_bytes(&client, &url) {
            if let Some(png) = decode_and_resize(&b) {
                let _ = std::fs::write(cache_path(host), &png);
                let _ = std::fs::remove_file(miss_path(host));
                return Some(png);
            }
        }
    }
    // Only record a miss if we truly have no favicon for this host.
    if !already_have_icon {
        let _ = std::fs::write(miss_path(host), b"");
    }
    None
}

fn get_bytes(client: &reqwest::blocking::Client, url: &str) -> Option<Vec<u8>> {
    let resp = client.get(url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Cap download size to avoid pathological responses.
    let bytes = resp.bytes().ok()?;
    if bytes.len() > 2_000_000 {
        return None;
    }
    Some(bytes.to_vec())
}

/// Extract a friendly site name from homepage HTML. Prefers the page <title>
/// (most page-specific, e.g. "Grafana"), then og:site_name / application-name.
fn parse_site_title(html: &str, host: &str) -> Option<String> {
    if let Some(v) = html_title(html) {
        if let Some(t) = clean_title(&v, host) {
            return Some(t);
        }
    }
    if let Some(v) = meta_content(html, "og:site_name") {
        if let Some(t) = clean_title(&v, host) {
            return Some(t);
        }
    }
    if let Some(v) = meta_content(html, "application-name") {
        if let Some(t) = clean_title(&v, host) {
            return Some(t);
        }
    }
    None
}

/// Find `<meta property|name="key" content="...">` (order-independent).
fn meta_content(html: &str, key: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<meta") {
        let start = from + rel;
        let end = lower[start..].find('>').map(|e| start + e).unwrap_or(lower.len());
        let tag = &html[start..end];
        let tag_lower = &lower[start..end];
        from = end;
        let has_key = tag_lower.contains(&format!("\"{key}\""))
            || tag_lower.contains(&format!("'{key}'"))
            || tag_lower.contains(&format!("={key} "))
            || tag_lower.contains(&format!("={key}>"));
        if has_key {
            if let Some(c) = extract_attr(tag, "content") {
                let c = decode_entities(c.trim());
                if !c.is_empty() {
                    return Some(c);
                }
            }
        }
    }
    None
}

fn html_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let open_end = lower[start..].find('>')? + start + 1;
    let close = lower[open_end..].find("</title>")? + open_end;
    let raw = html.get(open_end..close)?.trim();
    let decoded = decode_entities(raw);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// True if a title segment is a generic login/action phrase (no brand value).
fn is_generic_segment(s: &str) -> bool {
    let pl = s.to_lowercase();
    let pl = pl.trim();
    const GENERIC: &[&str] = &[
        "login", "log in", "sign in", "signin", "sign-in", "log on", "logon",
        "home", "welcome", "account", "my account", "sign up", "signup",
        "register", "authentication", "auth", "dashboard", "loading",
        "please wait", "redirecting", "index", "untitled",
    ];
    GENERIC.iter().any(|g| pl == *g)
}

/// Clean a raw title into a brand-ish name, or None to fall back to the domain.
/// Handles "Log in · Transifex" -> "Transifex", "| Clif Bar" -> "Clif Bar",
/// rejects bare "Sign in", and preserves names like "Disney+".
fn clean_title(raw: &str, host: &str) -> Option<String> {
    // Split on common brand/section separators (NOT '+', which is part of names
    // like "Disney+"). Note '-' is included but many brands use it internally;
    // we only split when it's clearly a separator (surrounded by spaces).
    let normalized = raw
        .replace(" - ", "\u{1}")
        .replace(" — ", "\u{1}")
        .replace(" – ", "\u{1}");
    let seps = ['|', '·', '»', '«', ':', '\u{1}'];
    let parts: Vec<&str> = normalized
        .split(|c| seps.contains(&c))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let candidate = if parts.len() >= 2 {
        // Prefer non-generic segments; among those, the longest is usually the
        // brand ("Clif Bar" over a fragment). If all are generic, bail.
        let branded: Vec<&&str> = parts.iter().filter(|p| !is_generic_segment(p)).collect();
        if branded.is_empty() {
            return None;
        }
        **branded.iter().max_by_key(|p| p.len()).unwrap()
    } else {
        let only = parts.first().copied().unwrap_or(raw.trim());
        if is_generic_segment(only) {
            return None; // bare "Sign in" etc -> use the domain instead
        }
        only
    };
    let candidate = candidate.trim();
    // Reject empty, too-long, or punctuation-only titles (e.g. "/").
    if candidate.is_empty()
        || candidate.chars().count() > 40
        || !candidate.chars().any(|c| c.is_alphanumeric())
    {
        return None;
    }
    let host_base = host.trim_start_matches("www.");
    // If the title matches the host case-insensitively:
    //  - keep it if it has intentional mixed casing (e.g. "myVETstore.ca"),
    //    since that's better branding than our fallback;
    //  - reject a plain lowercase host repeat (no signal beyond the domain).
    if candidate.eq_ignore_ascii_case(host) || candidate.eq_ignore_ascii_case(host_base) {
        let has_mixed_case = candidate.chars().any(|c| c.is_uppercase())
            && candidate.chars().any(|c| c.is_lowercase());
        if has_mixed_case {
            // Strip a trailing .tld for a cleaner name (myVETstore.ca -> myVETstore).
            let trimmed = candidate
                .rsplit_once('.')
                .map(|(head, _)| head)
                .unwrap_or(candidate);
            return Some(trimmed.to_string());
        }
        return None;
    }
    Some(candidate.to_string())
}

/// HTML entity decode for titles: named entities plus numeric (&#183; / &#xB7;).
fn decode_entities(s: &str) -> String {
    // Named first.
    let mut out = s
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
        .replace("&middot;", "·");
    // Numeric entities: &#NNN; and &#xHH;.
    while let Some(start) = out.find("&#") {
        let rest = &out[start + 2..];
        let Some(semi) = rest.find(';') else { break };
        let body = &rest[..semi];
        let code = if let Some(hex) = body.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            body.parse::<u32>().ok()
        };
        let replacement = code.and_then(char::from_u32).map(|c| c.to_string());
        match replacement {
            Some(ch) => out.replace_range(start..start + 2 + semi + 1, &ch),
            None => break, // avoid infinite loop on malformed entity
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Scan the HTML for rel=icon link hrefs. Returns candidates ordered by
/// preference (apple-touch-icon first, then others). Skips SVGs, which the
/// image crate can't decode.
fn parse_icon_hrefs(html: &str) -> Vec<String> {
    let lower = html.to_lowercase();
    let mut search_from = 0;
    let mut preferred: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    while let Some(rel) = lower[search_from..].find("<link") {
        let start = search_from + rel;
        let end = lower[start..].find('>').map(|e| start + e).unwrap_or(lower.len());
        let tag = &html[start..end];
        let tag_lower = &lower[start..end];
        search_from = end;
        if !tag_lower.contains("rel=") {
            continue;
        }
        // "mask-icon" is always SVG; skip it. Match the real icon rels.
        let is_icon = (tag_lower.contains("\"icon\"")
            || tag_lower.contains("'icon'")
            || tag_lower.contains("shortcut icon")
            || tag_lower.contains("apple-touch-icon"))
            && !tag_lower.contains("mask-icon");
        if !is_icon {
            continue;
        }
        if let Some(href) = extract_attr(tag, "href") {
            if href.to_lowercase().ends_with(".svg") {
                continue; // can't decode SVG
            }
            if tag_lower.contains("apple-touch-icon") {
                preferred.push(href);
            } else {
                others.push(href);
            }
        }
    }
    preferred.extend(others);
    preferred
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let key = format!("{attr}=");
    let pos = lower.find(&key)? + key.len();
    let rest = &tag[pos..];
    let bytes = rest.as_bytes();
    let (quote, start) = match bytes.first() {
        Some(b'"') => ('"', 1),
        Some(b'\'') => ('\'', 1),
        _ => (' ', 0),
    };
    let rest = &rest[start..];
    let endc = if quote == ' ' { ' ' } else { quote };
    let val = rest.split(endc).next().unwrap_or("").trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Resolve a possibly-relative href against the homepage URL.
fn resolve_url(home: &str, host: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if let Some(rest) = href.strip_prefix("//") {
        format!("https://{rest}")
    } else if let Some(rest) = href.strip_prefix('/') {
        format!("https://{host}/{rest}")
    } else {
        format!("{home}{href}")
    }
}

/// Decode any supported image and re-encode as a square ICON_SIZE PNG.
fn decode_and_resize(bytes: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(bytes).ok()?;
    let resized = img.resize_exact(ICON_SIZE, ICON_SIZE, FilterType::Lanczos3);
    let mut out = Cursor::new(Vec::new());
    resized.write_to(&mut out, image::ImageFormat::Png).ok()?;
    Some(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://discord.com/").as_deref(), Some("discord.com"));
        assert_eq!(host_of("https://accounts.google.com/signin").as_deref(), Some("accounts.google.com"));
        assert_eq!(host_of("android://hash@com.foo/").as_deref(), None);
        assert_eq!(host_of("").as_deref(), None);
    }
    #[test]
    fn cache_key_matches() {
        assert_eq!(cache_key("discord.com"), "discord.com");
        assert_eq!(cache_path("discord.com").file_name().unwrap().to_str().unwrap(), "discord.com.png");
    }
}

#[cfg(test)]
mod display_path_tests {
    use super::*;
    #[test]
    fn cached_discord_loads() {
        // Requires ~/.brave_pw/favicons/discord.com.png to exist (run `favicon discord.com`).
        let host = host_of("https://discord.com/").unwrap();
        assert_eq!(host, "discord.com");
        if cache_path(&host).exists() {
            assert!(cached_data_uri(&host).is_some(), "cached png failed to load");
        } else {
            eprintln!("skip: no cached discord.com.png");
        }
    }
}
