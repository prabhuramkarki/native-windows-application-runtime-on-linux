//! Escaping of untrusted text that ends up in error and warning messages.
//!
//! Zip entry names and PE product names are attacker-controlled. Before one is embedded in a message it goes
//! through [`quote`]: a double-quoted string in which every control and format character (including bidi
//! overrides) is escaped, cut to a fixed length. The CLI still applies its own `safe()` when printing.

/// Longest quoted string, in characters of the escaped output (excluding the two quotes and the `...`).
pub const MAX_QUOTED: usize = 120;

/// THE table of characters that draw nothing or change how surrounding text is laid out or read; the CLI's
/// `safe()` uses it too (`rt_core::is_format`), so there is exactly one list to keep. Bidi controls (U+061C,
/// U+200E/F, U+202A-E, U+2066-9), zero-width and joiner characters (U+200B-D), line/paragraph separators
/// (U+2028/9), word joiner and invisible operators (U+2060-4), the soft hyphen (U+00AD), the combining grapheme
/// joiner (U+034F), the Hangul fillers (U+115F, U+1160, U+3164), the Mongolian vowel separator (U+180E), variation
/// selectors (U+FE00-FE0F), the BOM (U+FEFF), the object replacement character (U+FFFC), interlinear annotation
/// (U+FFF9-B) and the tag characters (U+E0000-E007F). Control characters (`char::is_control`) are handled
/// separately.
///
/// Consequences accepted on purpose: U+200D (zero-width joiner) is in the table, so an emoji ZWJ sequence is
/// shown as its parts, and U+FE0F (emoji presentation) is escaped or removed from names. Everything else
/// printable (CJK, Hangul, Arabic, precomposed and combining accents other than U+034F, plain emoji) is untouched.
pub fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffc}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// [`escape`] between double quotes: `"..."`, at most [`MAX_QUOTED`] escaped characters. Never longer than
/// `MAX_QUOTED + 5` characters.
pub fn quote(s: &str) -> String {
    quote_max(s, MAX_QUOTED)
}

/// [`quote`] with the cut at `max` escaped characters instead (for lists of names: at most `max + 5` characters).
pub fn quote_max(s: &str, max: usize) -> String {
    format!("\"{}\"", escape(s, max))
}

/// `char::escape_debug` applied to every character (format characters as `\u{..}`), at most `max` output
/// characters, and `...` appended when cut. Reads no more than `max + 1` characters of `s`.
pub fn escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut shown = 0;
    for c in s.chars() {
        let escaped: String = if is_format(c) {
            format!("\\u{{{:x}}}", c as u32)
        } else {
            c.escape_debug().collect()
        };
        shown += escaped.chars().count();
        if shown > max {
            out.push_str("...");
            break;
        }
        out.push_str(&escaped);
    }
    out
}

/// Removes control characters and bidi/format overrides, trims, and cuts to at most `max_bytes` bytes (on a
/// character boundary). For values that are stored (names, versions) rather than quoted.
pub fn clean(s: &str, max_bytes: usize) -> String {
    let filtered: String = s.chars().filter(|&c| !(c.is_control() || is_format(c))).collect();
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
    fn escape_and_quote_max_cut_at_the_given_width() {
        assert_eq!(escape("abcdef", 4), "abcd...");
        assert_eq!(escape("abcd", 4), "abcd");
        assert_eq!(quote_max("abcdef", 4), "\"abcd...\"");
        let q = quote_max(&"\u{202e}".repeat(1000), 40);
        assert!(q.chars().count() <= 40 + 5, "{q}");
        assert!(!q.contains('\u{202e}'));
        assert_eq!(escape("a\x1bb", 20), "a\\u{1b}b");
    }

    #[test]
    fn quote_is_bounded_even_for_all_escaping_input() {
        let q = quote(&"\u{1b}".repeat(10_000));
        assert!(q.chars().count() <= MAX_QUOTED + 5, "{} chars", q.chars().count());
        assert!(q.contains("..."));
        assert_eq!(quote("plain.exe"), "\"plain.exe\"");
    }

    /// Every character `is_format` names, one representative per range end.
    const INVISIBLE: &[char] = &[
        '\u{ad}',
        '\u{61c}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{200e}',
        '\u{200f}',
        '\u{2028}',
        '\u{2029}',
        '\u{202a}',
        '\u{202b}',
        '\u{202c}',
        '\u{202d}',
        '\u{202e}',
        '\u{2060}',
        '\u{2061}',
        '\u{2064}',
        '\u{2066}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{feff}',
        '\u{fff9}',
        '\u{fffa}',
        '\u{fffb}',
        '\u{e0000}',
        '\u{e0001}',
        '\u{e0020}',
        '\u{e007f}',
        // added by the final review: invisible fillers, joiner and selectors, object replacement
        '\u{34f}',
        '\u{115f}',
        '\u{1160}',
        '\u{180e}',
        '\u{3164}',
        '\u{fe00}',
        '\u{fe0f}',
        '\u{fffc}',
    ];

    #[test]
    fn is_format_is_public_and_matches_the_table_and_nothing_printable() {
        for &c in INVISIBLE {
            assert!(is_format(c), "U+{:04X}", c as u32);
        }
        // Neighbours of every added range end, and ordinary printable text of many scripts, are NOT format
        // characters (U+200D is in the table on purpose: an emoji ZWJ sequence is shown as its parts).
        for c in [
            '\u{34e}', '\u{350}', '\u{301}', '\u{115e}', '\u{1161}', '\u{180d}', '\u{180f}', '\u{3163}', '\u{3165}',
            '\u{fdff}', '\u{fe10}', '\u{fffd}',
        ] {
            assert!(!is_format(c), "U+{:04X}", c as u32);
        }
        let plain = "Gr\u{f6}\u{df}e e\u{301} \u{65e5}\u{672c}\u{8a9e} \u{d55c}\u{ae00} \u{3b5}\u{3bb} \u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629} \u{1f600} \u{fdfa} \u{a4}";
        assert_eq!(clean(plain, 256), plain);
        assert!(plain.chars().all(|c| !is_format(c) && !c.is_control()));
    }

    #[test]
    fn clean_strips_every_invisible_formatting_character() {
        for &c in INVISIBLE {
            let s = format!("a{c}b");
            assert_eq!(clean(&s, 256), "ab", "U+{:04X} survived clean", c as u32);
        }
        assert_eq!(
            clean("ok \u{e9}\u{4e2d}", 256),
            "ok \u{e9}\u{4e2d}",
            "ordinary text is untouched"
        );
    }

    #[test]
    fn quote_escapes_every_invisible_formatting_character() {
        for &c in INVISIBLE {
            let q = quote(&format!("a{c}b"));
            assert!(!q.contains(c), "U+{:04X} survived quote: {q:?}", c as u32);
            assert!(q.contains(&format!("\\u{{{:x}}}", c as u32)), "{q}");
        }
        // The soft hyphen and the tag characters are not escaped by `escape_debug` alone.
        assert_eq!(quote("\u{ad}"), "\"\\u{ad}\"");
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
