//! Brave "time-limited words" — the 25-word sync code format.
//!
//! Reimplements time_limited_words.cc. A Brave v2 sync code is 24 BIP39 words
//! (the actual 32-byte seed) plus a 25th word that encodes an expiry:
//!
//!   last_word = BIP39_word[ round_days(v2_epoch -> not_after) % 2048 ]
//!
//! On parse, the first 24 words are the seed; the 25th is checked against the
//! current date and must be within ±1 day (matching Brave's strict Parse).

use std::time::{SystemTime, UNIX_EPOCH};

use bip39::Language;

use super::seed;

/// Tue, 10 May 2022 00:00:00 GMT, in unix seconds (kWordsv2Epoch).
const V2_EPOCH_SECS: i64 = 1_652_140_800;
const MS_PER_DAY: f64 = 86_400_000.0;
const WORDLIST_LEN: i64 = 2048;
const PURE_WORDS: usize = 24;
const V2_WORDS: usize = 25;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TimeWordsError {
    #[error("wrong number of words (expected 24 or 25)")]
    WrongWordCount,
    #[error("the 24 seed words are not a valid BIP39 phrase")]
    InvalidPureWords,
    #[error("unknown 25th (time) word")]
    UnknownTimeWord,
    #[error("sync code has expired — generate a fresh one in Brave")]
    Expired,
    #[error("sync code is valid too far in the future (clock mismatch?)")]
    ValidForTooLong,
}

fn word_list() -> &'static [&'static str; 2048] {
    Language::English.word_list()
}

fn word_by_index(index: i64) -> String {
    let i = index.rem_euclid(WORDLIST_LEN) as usize;
    word_list()[i].to_string()
}

fn index_by_word(word: &str) -> Option<i64> {
    let w = word.to_lowercase();
    word_list().iter().position(|x| *x == w).map(|p| p as i64)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(V2_EPOCH_SECS)
}

/// Rounded whole-day difference between the v2 epoch and `secs`.
fn days_since_epoch(secs: i64) -> i64 {
    let delta_ms = (secs - V2_EPOCH_SECS) as f64 * 1000.0;
    (delta_ms / MS_PER_DAY).round() as i64
}

/// Split on whitespace, dropping empties.
fn split(words: &str) -> Vec<String> {
    words.split_whitespace().map(|s| s.to_string()).collect()
}

/// Parse a 24- or 25-word Brave sync code into the pure 24-word seed phrase.
/// A 25-word code has its trailing time word validated against today's date.
pub fn parse(input: &str) -> Result<String, TimeWordsError> {
    let words = split(input);
    match words.len() {
        PURE_WORDS => {
            let pure = words.join(" ");
            if seed::is_valid(&pure) {
                Ok(pure)
            } else {
                Err(TimeWordsError::InvalidPureWords)
            }
        }
        V2_WORDS => {
            let pure = words[..PURE_WORDS].join(" ");
            if !seed::is_valid(&pure) {
                return Err(TimeWordsError::InvalidPureWords);
            }
            let days_actual = days_since_epoch(now_secs()).rem_euclid(WORDLIST_LEN);
            let days_encoded =
                index_by_word(&words[PURE_WORDS]).ok_or(TimeWordsError::UnknownTimeWord)?;
            let diff = (days_actual - days_encoded).abs();
            if diff <= 1 {
                Ok(pure)
            } else if days_actual > days_encoded {
                Err(TimeWordsError::Expired)
            } else {
                Err(TimeWordsError::ValidForTooLong)
            }
        }
        _ => Err(TimeWordsError::WrongWordCount),
    }
}

/// Append today's time word to a pure 24-word phrase, producing a 25-word
/// Brave-compatible sync code (matches GenerateForNow).
pub fn generate_for_now(pure_words: &str) -> String {
    let days = days_since_epoch(now_secs()).max(0);
    let last = word_by_index(days);
    format!("{pure_words} {last}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_generate_then_parse() {
        let (_bytes, pure) = seed::generate();
        let code = generate_for_now(&pure);
        assert_eq!(code.split_whitespace().count(), 25);
        // Freshly generated code parses back to the same pure words.
        assert_eq!(parse(&code).unwrap(), pure);
    }

    #[test]
    fn plain_24_words_still_accepted() {
        let (_b, pure) = seed::generate();
        assert_eq!(parse(&pure).unwrap(), pure);
    }

    #[test]
    fn expired_code_rejected() {
        let (_b, pure) = seed::generate();
        // A time word encoding "day 0" (epoch) is far in the past -> expired.
        let code = format!("{pure} {}", word_by_index(0));
        assert_eq!(parse(&code), Err(TimeWordsError::Expired));
    }

    #[test]
    fn wrong_count_rejected() {
        assert_eq!(parse("one two three"), Err(TimeWordsError::WrongWordCount));
    }
}
