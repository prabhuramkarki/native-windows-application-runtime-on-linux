//! Application ids. An [`AppId`] becomes a directory name under the data dir, so validation is a security
//! boundary: anything that could escape a directory, be read as an option (`-x`), or be ambiguous is rejected.
//!
//! Rules: 1..=64 bytes (ASCII only, so bytes == chars), regex `^[a-z0-9][a-z0-9._-]*$`, no `..` substring, not
//! ending with `.` or `-`. Uppercase and non-ASCII are rejected outright, never folded (no look-alike collisions).
//!
//! Names that are reserved on Windows (`con`, `nul`, `com1`, ...) are deliberately ALLOWED: ids only ever name a
//! directory on the Linux host. Anything that becomes a path *inside* a prefix is validated separately (`winpath`).
use serde::{Deserialize, Serialize};
use std::fmt;

/// Longest accepted id, in bytes.
pub const MAX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("app id is empty")]
    Empty,
    #[error("app id is too long ({len} bytes, max {MAX_LEN})")]
    TooLong { len: usize },
    #[error("app id must start with a lowercase letter or digit, found {0:?}")]
    BadStart(char),
    #[error("app id contains invalid character {0:?} (allowed: a-z 0-9 . _ -)")]
    BadChar(char),
    #[error("app id must not contain \"..\"")]
    DotDot,
    #[error("app id must not end with '.' or '-'")]
    BadEnd,
}

fn is_start(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn is_body(c: char) -> bool {
    is_start(c) || matches!(c, '.' | '_' | '-')
}

/// A validated application id. The field is private: the only ways to get one are [`AppId::parse`],
/// [`AppId::slug`] and deserialisation (which calls `parse`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppId(String);

impl AppId {
    pub fn parse(s: &str) -> Result<AppId, IdError> {
        // Length first (O(1)) so a hostile 1 GiB string is never scanned.
        if s.len() > MAX_LEN {
            return Err(IdError::TooLong { len: s.len() });
        }
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(IdError::Empty);
        };
        if !is_start(first) {
            return Err(IdError::BadStart(first));
        }
        if let Some(bad) = chars.find(|&c| !is_body(c)) {
            return Err(IdError::BadChar(bad));
        }
        if s.contains("..") {
            return Err(IdError::DotDot);
        }
        if s.ends_with(['.', '-']) {
            return Err(IdError::BadEnd);
        }
        Ok(AppId(s.to_owned()))
    }

    /// Turns any display name into a valid id: ASCII letters/digits lowercased, every other run of characters
    /// becomes one `-`, trimmed, at most [`MAX_LEN`] bytes, `app` when nothing is left. Never fails; work is
    /// linear in the input and stops early once the output is full.
    pub fn slug(name: &str) -> AppId {
        let mut out = String::new();
        let mut gap = false;
        for c in name.chars() {
            if out.len() >= MAX_LEN {
                break;
            }
            if c.is_ascii_alphanumeric() {
                if gap && !out.is_empty() {
                    out.push('-');
                }
                gap = false;
                out.push(c.to_ascii_lowercase());
            } else {
                gap = true;
            }
        }
        // At most MAX_LEN + 1 bytes so far. Cutting can leave a trailing '-'; the first byte is alphanumeric, so
        // trimming never empties a non-empty result.
        out.truncate(MAX_LEN);
        out.truncate(out.trim_end_matches('-').len());
        if out.is_empty() {
            out.push_str("app");
        }
        debug_assert!(AppId::parse(&out).is_ok());
        AppId(out)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AppId {
    type Error = IdError;
    fn try_from(s: String) -> Result<Self, IdError> {
        AppId::parse(&s)
    }
}

impl From<AppId> for String {
    fn from(id: AppId) -> String {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> AppId {
        AppId::parse(s).unwrap_or_else(|e| panic!("{s:?} should be accepted: {e}"))
    }

    #[test]
    fn parse_accepts_valid_ids() {
        let long = "a".repeat(MAX_LEN);
        for s in [
            "a",
            "0",
            "app",
            "my-app",
            "my_app",
            "my.app",
            "7zip",
            "a1.b2-c3_d4",
            "a-.b",
            "a.-b",
            "a__b",
            "notepad.exe",
            // Reserved on Windows, fine on Linux (documented in the module docs).
            "con",
            "nul",
            "aux",
            "com1",
            "lpt9",
            long.as_str(),
        ] {
            assert_eq!(ok(s).as_str(), s);
        }
    }

    #[test]
    fn parse_rejects_with_specific_error() {
        let long65 = "a".repeat(MAX_LEN + 1);
        let huge = "a".repeat(10_000);
        let cases: Vec<(&str, IdError)> = vec![
            ("", IdError::Empty),
            (long65.as_str(), IdError::TooLong { len: 65 }),
            (huge.as_str(), IdError::TooLong { len: 10_000 }),
            // Uppercase, at the start and inside.
            ("App", IdError::BadStart('A')),
            ("aPp", IdError::BadChar('P')),
            ("APP", IdError::BadStart('A')),
            // Traversal and separators.
            ("../x", IdError::BadStart('.')),
            ("..", IdError::BadStart('.')),
            (".", IdError::BadStart('.')),
            ("a/b", IdError::BadChar('/')),
            ("a\\b", IdError::BadChar('\\')),
            ("/abs", IdError::BadStart('/')),
            ("a/../b", IdError::BadChar('/')),
            ("a..b", IdError::DotDot),
            ("a...b", IdError::DotDot),
            ("x..", IdError::DotDot),
            // Leading chars that hide files or look like options.
            (".hidden", IdError::BadStart('.')),
            ("-x", IdError::BadStart('-')),
            ("--help", IdError::BadStart('-')),
            ("_x", IdError::BadStart('_')),
            // Trailing dot/dash (Windows strips trailing dots: ambiguous).
            ("x.", IdError::BadEnd),
            ("x-", IdError::BadEnd),
            ("a.b.", IdError::BadEnd),
            // NUL, whitespace, control characters.
            ("a\0b", IdError::BadChar('\0')),
            ("\0", IdError::BadStart('\0')),
            ("a b", IdError::BadChar(' ')),
            (" a", IdError::BadStart(' ')),
            ("a ", IdError::BadChar(' ')),
            ("a\n", IdError::BadChar('\n')),
            ("a\tb", IdError::BadChar('\t')),
            ("a\rb", IdError::BadChar('\r')),
            ("a\x1bb", IdError::BadChar('\x1b')),
            // Unicode: never accepted, never folded.
            ("é", IdError::BadStart('é')),
            ("café", IdError::BadChar('é')),
            ("日本", IdError::BadStart('日')),
            ("ａｂｃ", IdError::BadStart('ａ')),
            ("a\u{212a}", IdError::BadChar('\u{212a}')), // Kelvin sign, lowercases to 'k'
            ("a\u{131}", IdError::BadChar('\u{131}')),   // dotless i
            ("a\u{200b}b", IdError::BadChar('\u{200b}')), // zero-width space
            ("a\u{202e}b", IdError::BadChar('\u{202e}')), // bidi override
            ("😀", IdError::BadStart('😀')),
            // Other shell/URL/Windows-special ASCII.
            ("a:b", IdError::BadChar(':')),
            ("a;b", IdError::BadChar(';')),
            ("a$b", IdError::BadChar('$')),
            ("a*b", IdError::BadChar('*')),
            ("a%2fb", IdError::BadChar('%')),
            ("~", IdError::BadStart('~')),
            ("a~1", IdError::BadChar('~')),
        ];
        for (input, want) in cases {
            let shown: String = input.chars().take(20).collect();
            assert_eq!(AppId::parse(input), Err(want), "input {shown:?}");
        }
    }

    #[test]
    fn length_boundary_is_exact() {
        assert!(AppId::parse(&"a".repeat(64)).is_ok());
        assert!(AppId::parse(&"a".repeat(65)).is_err());
        // A multi-byte string of 33 chars is 66 bytes: rejected (as too long, before any char scan).
        assert!(matches!(AppId::parse(&"é".repeat(33)), Err(IdError::TooLong { .. })));
    }

    #[test]
    fn error_messages_escape_untrusted_characters() {
        let msg = AppId::parse("a\u{1b}[31mb").unwrap_err().to_string();
        assert!(!msg.contains('\u{1b}'), "raw escape leaked into {msg:?}");
        let msg = AppId::parse("a\0b").unwrap_err().to_string();
        assert!(!msg.contains('\0'), "raw NUL leaked into {msg:?}");
    }

    #[test]
    fn display_and_as_str() {
        let id = ok("my-app");
        assert_eq!(id.as_str(), "my-app");
        assert_eq!(id.to_string(), "my-app");
        assert_eq!(String::from(id), "my-app");
    }

    #[test]
    fn slug_known_outputs() {
        let cases = [
            ("My App 2.0", "my-app-2-0"),
            ("  Hello,   World!! ", "hello-world"),
            ("Notepad++", "notepad"),
            ("already-ok", "already-ok"),
            ("UPPER", "upper"),
            ("a_b.c", "a-b-c"),
            ("---x---", "x"),
            ("Ünïcode", "n-code"),
            ("", "app"),
            ("   ", "app"),
            ("!!!", "app"),
            ("😀😀", "app"),
            ("日本語アプリ", "app"),
            ("../..", "app"),
            ("..", "app"),
            ("../evil", "evil"),
            ("a\0b", "a-b"),
            ("-rf", "rf"),
        ];
        for (input, want) in cases {
            assert_eq!(AppId::slug(input).as_str(), want, "input {input:?}");
        }
    }

    #[test]
    fn slug_truncates_to_the_cap_and_trims() {
        let ten_k = "a".repeat(10_000);
        assert_eq!(AppId::slug(&ten_k).as_str(), "a".repeat(MAX_LEN));
        // Truncation must not leave a trailing dash: 63 a, a separator, then b.
        let name = format!("{} b", "a".repeat(63));
        assert_eq!(AppId::slug(&name).as_str(), "a".repeat(63));
        // 64 a, then anything: exactly 64.
        let name = format!("{} tail", "a".repeat(64));
        assert_eq!(AppId::slug(&name).as_str(), "a".repeat(64));
        // A 10 kB run of separators and emoji is the fallback, not a huge id.
        assert_eq!(AppId::slug(&"-😀 ".repeat(3000)).as_str(), "app");
    }

    #[test]
    fn slug_is_always_a_valid_id() {
        let alphabet: Vec<char> = "aZ09 .-_/\\:\0\n\t\u{1b}éß日😀\u{212a}\u{202e}%~;$*".chars().collect();
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5_000 {
            let len = (next() % 200) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let id = AppId::slug(&s);
            assert_eq!(AppId::parse(id.as_str()), Ok(id.clone()), "slug of {s:?} was {id}");
        }
    }

    #[test]
    fn serde_round_trip() {
        let id = ok("my-app.1");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"my-app.1\"");
        assert_eq!(serde_json::from_str::<AppId>(&json).unwrap(), id);
    }

    #[test]
    fn serde_rejects_invalid_ids() {
        let long = format!("\"{}\"", "a".repeat(65));
        let huge = format!("\"{}\"", "a".repeat(10_000));
        for json in [
            "\"\"",
            "\"../x\"",
            "\"a/b\"",
            "\"App\"",
            "\"-x\"",
            "\"x.\"",
            "\"a..b\"",
            "\"a\\u0000b\"",
            "\"caf\\u00e9\"",
            "123",
            "null",
            "[]",
            "{}",
            long.as_str(),
            huge.as_str(),
        ] {
            assert!(serde_json::from_str::<AppId>(json).is_err(), "accepted {json:.40}");
        }
    }

    #[test]
    fn serde_validates_inside_a_struct() {
        #[derive(Debug, Deserialize)]
        struct M {
            id: AppId,
        }
        assert_eq!(serde_json::from_str::<M>(r#"{"id":"ok"}"#).unwrap().id.as_str(), "ok");
        assert!(serde_json::from_str::<M>(r#"{"id":"../ok"}"#).is_err());
    }
}
