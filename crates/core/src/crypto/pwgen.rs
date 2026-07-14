//! Password generator.

use rand::seq::SliceRandom;
use rand::Rng;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

// Lookalike characters excluded when `avoid_ambiguous` is on.
const AMBIGUOUS: &[u8] = b"0O1lI";

fn filter_ambiguous(set: &[u8], avoid: bool) -> Vec<u8> {
    if avoid {
        set.iter().copied().filter(|c| !AMBIGUOUS.contains(c)).collect()
    } else {
        set.to_vec()
    }
}

/// Generate a random password of `len` chars. Always includes lowercase and
/// uppercase; optionally digits and symbols. Guarantees at least one of each
/// enabled class. When `avoid_ambiguous` is set, lookalike chars (0 O 1 l I)
/// are excluded.
pub fn generate(len: usize, digits: bool, symbols: bool, avoid_ambiguous: bool) -> String {
    let len = len.clamp(4, 128);
    let mut rng = rand::thread_rng();

    let lower = filter_ambiguous(LOWER, avoid_ambiguous);
    let upper = filter_ambiguous(UPPER, avoid_ambiguous);
    let digit_set = filter_ambiguous(DIGITS, avoid_ambiguous);

    let mut classes: Vec<&[u8]> = vec![&lower, &upper];
    if digits {
        classes.push(&digit_set);
    }
    if symbols {
        classes.push(SYMBOLS);
    }
    let pool: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut out: Vec<u8> = Vec::with_capacity(len);
    // Guarantee one from each enabled class.
    for class in &classes {
        out.push(*class.choose(&mut rng).unwrap());
    }
    while out.len() < len {
        out.push(*pool.choose(&mut rng).unwrap());
    }
    // Shuffle so the guaranteed chars aren't front-loaded.
    out.shuffle(&mut rng);
    // Drop extras if classes exceeded len (only possible for very short len).
    out.truncate(len);
    let _ = rng.gen::<u8>();
    String::from_utf8(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_classes() {
        let p = generate(20, true, true, false);
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| c.is_lowercase()));
        assert!(p.chars().any(|c| c.is_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn no_symbols_when_disabled() {
        let p = generate(30, true, false, false);
        assert!(p.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn avoid_ambiguous_excludes_lookalikes() {
        let p = generate(120, true, false, true);
        assert!(!p.contains('0'));
        assert!(!p.contains('1'));
        assert!(!p.contains('l'));
        assert!(!p.contains('I'));
        assert!(!p.contains('O'));
    }
}
