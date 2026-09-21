//! Terminal safety for text that came from a file, the file system or the user: what could drive a terminal
//! (control characters, C1 controls, bidi overrides, invisible formatting characters) is escaped. EVERY command
//! prints untrusted text through this module; do not write another sanitiser.
use std::fmt::Write;

/// Characters that draw nothing or reorder text besides the control characters: soft hyphen, bidi controls
/// (U+061C, U+200E/F, U+202A-E, U+2066-9), zero-width characters (U+200B-D), line/paragraph separators, word
/// joiner and invisible operators (U+2060-4), BOM, interlinear annotation and the tag characters.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

fn is_dangerous(c: char) -> bool {
    c.is_control() || is_invisible(c)
}

/// Escapes what could drive a terminal from text taken out of an untrusted source (`\x1b` becomes the
/// printable `\u{1b}`, a newline `\n`, ...). Everything else, non-ASCII text included, is kept.
pub(crate) fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if is_dangerous(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// [`safe`] for text with several lines: each line is escaped, the line breaks (`\n`) are kept. Text that is
/// mostly untrusted but has a trusted layout (clap's usage errors, log files).
pub(crate) fn safe_lines(s: &str) -> String {
    s.split('\n').map(safe).collect::<Vec<_>>().join("\n")
}

/// At most `max` characters of `s`, then `...`: keeps an untrusted argument echoed in an error short.
pub(crate) fn shorten(s: &str, max: usize) -> String {
    let mut it = s.chars();
    let head: String = it.by_ref().take(max).collect();
    if it.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

/// `warning: <safe text>` on stderr.
pub(crate) fn warn(msg: &str) {
    eprintln!("warning: {}", safe(msg));
}

/// Makes serialised JSON safe to show on a terminal without changing what it means: `serde_json` already
/// escapes U+0000-U+001F; this also writes DEL, C1 controls (U+009B is a one-character CSI) and the invisible
/// and bidi characters as `\uXXXX` escapes (surrogate pairs above U+FFFF), which any JSON parser reads back to
/// the original text. Structural JSON characters are ASCII, so only string contents are touched.
pub(crate) fn json_safe(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if is_dangerous(c) && c as u32 >= 0x7f {
            for unit in c.encode_utf16(&mut [0; 2]) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_escapes_control_characters() {
        // ESC character (U+001B)
        assert!(!safe("\x1b]0;pwned\x07").contains('\x1b'));
        // Newline
        assert!(!safe("line1\nline2").contains('\n'));
        // Carriage return
        assert!(!safe("text\roverwrite").contains('\r'));
        // 8-bit CSI (U+009B)
        assert!(!safe("\u{9b}[31m").contains('\u{9b}'));
    }

    #[test]
    fn safe_escapes_bidi_overrides() {
        // Cover range boundaries and all directions
        for c in [
            '\u{202a}', // LRE: Left-to-right embedding
            '\u{202b}', // RLE: Right-to-left embedding
            '\u{202c}', // PDF: Pop directional formatting
            '\u{202d}', // LRO: Left-to-right override (classic RLO pair)
            '\u{202e}', // RLO: Right-to-left override (classic RLO)
            '\u{2066}', // LRI: Left-to-right isolate
            '\u{2067}', // RLI: Right-to-left isolate (range edge)
            '\u{2068}', // FSI: First strong isolate
            '\u{2069}', // PDI: Pop directional isolate (range edge)
        ] {
            let s = format!("{}text", c);
            assert!(
                !safe(&s).contains(c),
                "Bidi character U+{:04X} not escaped in safe()",
                c as u32
            );
        }
    }

    #[test]
    fn safe_preserves_unicode() {
        assert_eq!(safe("Größe 日本語"), "Größe 日本語");
    }

    /// One character from each invisible range end.
    const INVISIBLE: &[char] = &[
        '\u{ad}',
        '\u{61c}',
        '\u{200b}',
        '\u{200d}',
        '\u{200e}',
        '\u{200f}',
        '\u{2028}',
        '\u{2029}',
        '\u{2060}',
        '\u{2064}',
        '\u{feff}',
        '\u{fff9}',
        '\u{fffb}',
        '\u{e0000}',
        '\u{e0041}',
        '\u{e007f}',
    ];

    #[test]
    fn safe_escapes_invisible_formatting_characters_and_del() {
        for &c in INVISIBLE.iter().chain(&['\x7f']) {
            let out = safe(&format!("a{c}b"));
            assert!(!out.contains(c), "U+{:04X} survived: {out:?}", c as u32);
            assert!(out.starts_with('a') && out.ends_with('b') && out.len() > 3);
        }
        assert_eq!(safe("\x1b"), "\\u{1b}");
    }

    #[test]
    fn safe_lines_keeps_line_breaks_and_escapes_the_rest() {
        assert_eq!(safe_lines("a\x1b[0m\nb\r\n\nc"), "a\\u{1b}[0m\nb\\r\n\nc");
        assert_eq!(safe_lines(""), "");
        assert_eq!(safe_lines("\n"), "\n");
    }

    #[test]
    fn shorten_cuts_on_characters() {
        assert_eq!(shorten("abcdef", 3), "abc...");
        assert_eq!(shorten("abc", 3), "abc");
        assert_eq!(shorten("äöüß", 2), "äö...");
        assert_eq!(shorten("", 3), "");
    }

    #[test]
    fn json_safe_is_lossless_and_leaves_no_raw_control_or_bidi_characters() {
        let nasty = format!(
            "x\x1b]0;t\x07\u{9b}[2J\x7f\u{202e}\u{2067}\r\n\u{1f600}\u{e0041}{}",
            INVISIBLE.iter().collect::<String>()
        );
        let value = serde_json::json!({ "k\u{9b}": [nasty.clone(), 5, null] });
        let text = json_safe(&serde_json::to_string_pretty(&value).unwrap());
        for c in text.chars() {
            assert!(!(is_dangerous(c) && c != '\n'), "raw U+{:04X} in {text:?}", c as u32);
        }
        assert!(
            text.contains("\\ud83d\\ude00") || text.contains('\u{1f600}'),
            "an emoji is fine either way"
        );
        assert!(
            text.contains("\\udb40\\udc41"),
            "tag characters use surrogate pairs: {text}"
        );
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back, value, "escaping is lossless");
    }
}
