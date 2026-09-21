//! Escaping of untrusted text that ends up in error and warning messages.
//!
//! Zip entry names and PE product names are attacker-controlled. Before one is embedded in a message it goes
//! through [`quote`]: a double-quoted string in which every control and format character (including bidi
//! overrides) is escaped, cut to a fixed length. The CLI still applies its own `safe()` when printing.

/// Longest quoted string, in characters of the escaped output (excluding the two quotes and the `...`).
pub const MAX_QUOTED: usize = 120;

/// `"..."` with `char::escape_debug` applied to every character, at most [`MAX_QUOTED`] output characters, and a
/// `...` before the closing quote when cut. Never longer than `MAX_QUOTED + 5` characters.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    let mut shown = 0;
    for c in s.chars() {
        let escaped: String = c.escape_debug().collect();
        shown += escaped.chars().count();
        if shown > MAX_QUOTED {
            out.push_str("...");
            break;
        }
        out.push_str(&escaped);
    }
    out.push('"');
    out
}

/// Removes control characters and bidi/format overrides, trims, and cuts to at most `max_bytes` bytes (on a
/// character boundary). For values that are stored (names, versions) rather than quoted.
pub fn clean(s: &str, max_bytes: usize) -> String {
    let filtered: String = s
        .chars()
        .filter(|&c| {
            !(c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'))
        })
        .collect();
    let mut out = filtered.trim().to_owned();
    if out.len() > max_bytes {
        let mut end = max_bytes;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.truncate(out.trim_end().len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_terminal_and_bidi_characters() {
        let q = quote("a\x1b]0;x\x07\u{9b}[31m\n\r\u{202e}b\"\\");
        for bad in ['\x1b', '\x07', '\u{9b}', '\n', '\r', '\u{202e}'] {
            assert!(!q.contains(bad), "{bad:?} survived in {q:?}");
        }
        assert!(q.starts_with('"') && q.ends_with('"'));
        assert!(q.contains("\\u{202e}"), "{q}");
    }

    #[test]
    fn quote_is_bounded_even_for_all_escaping_input() {
        let q = quote(&"\u{1b}".repeat(10_000));
        assert!(q.chars().count() <= MAX_QUOTED + 5, "{} chars", q.chars().count());
        assert!(q.contains("..."));
        assert_eq!(quote("plain.exe"), "\"plain.exe\"");
    }

    #[test]
    fn clean_strips_controls_bidi_and_caps_on_a_char_boundary() {
        assert_eq!(clean("  A\x1b[31m\u{202e}B\n ", 256), "A[31mB");
        assert_eq!(clean("\x01\x02", 10), "");
        let s = "\u{e9}".repeat(200); // 400 bytes
        let c = clean(&s, 255);
        assert!(c.len() <= 255 && c.chars().all(|ch| ch == '\u{e9}'));
        assert_eq!(c.len(), 254);
    }
}
