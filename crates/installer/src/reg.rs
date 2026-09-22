//! A parser for Wine's `.reg` text format (`system.reg`/`user.reg`), NOT the real Windows binary registry
//! hive format. Verified against a real prefix on this machine (`WINEPREFIX=<tmp> WINEARCH=win64 WINEDEBUG=-all
//! wineboot -u`, Wine 10.0 on Ubuntu; the tempdir was deleted right after inspection):
//!
//! ```text
//! WINE REGISTRY Version 2
//! ;; All keys relative to REGISTRY\\Machine
//!
//! #arch=win64
//!
//! [Control Panel\\Desktop] 1790095421
//! #time=1dd4ab1864fafa4
//! "DragWidth"="4"
//! "CaretWidth"=dword:00000001
//!
//! [Software\\Classes\\exefile\\shell\\open\\command] 1790095421
//! #time=1dd4ab18626f88e
//! @="\"C:\\windows\\system32\\notepad.exe\" \"%1\""
//! ```
//!
//! Grammar: a header line, `;;`-comment lines, `#arch=...`/`#time=...` directive lines (recognised and skipped,
//! not modelled, never a warning), blank lines separating blocks, and repeated blocks of `[Key\\Path] <unix
//! timestamp>` followed by `"Name"="string value"` / `"Name"=dword:XXXXXXXX` / `@="default value"` lines. Also
//! seen for real (a fresh prefix has ~17,000 keys in `system.reg` alone, many using it): `"Name"=hex:xx,xx,...`
//! (REG_BINARY, and its `hex(2):`/`hex(7):` siblings for REG_EXPAND_SZ/REG_MULTI_SZ), whose value may continue
//! onto following physical lines ending in a trailing `\`. These are recognised (so a real prefix never produces
//! a spurious warning) but not modelled: [`RegValue`] only has variants for the three shapes this crate's
//! callers need.
//!
//! String escaping, confirmed against the real files above: `\\` -> `\` and `\"` -> `"` (seen directly, e.g.
//! `@="\"C:\\windows\\system32\\notepad.exe\" \"%1\""` decodes to `"C:\windows\system32\notepad.exe" "%1"`).
//! `\r` -> CR and `\n` -> LF were not directly observed in the sample (no value happened to contain either) but
//! are implemented per the project's design notes; nothing in the real files contradicts them. One escape WAS
//! found by inspection that the design notes do not mention: every non-ASCII byte is written as `\xHHHH`, one
//! UTF-16 code unit per escape (astral characters as a surrogate pair) — a real `user.reg` had a
//! `Control Panel\\International\\<flag emoji>` key spelled
//! `[Control Panel\\International\\\xd83c\xdf0e\xd83c\xdf0f\xd83c\xdf0d]`, which decodes (three UTF-16 surrogate
//! pairs) to three astral code points. Confirmed: the whole 3.3 MB `system.reg` had zero raw bytes >= 0x80, i.e.
//! Wine really does escape everything non-ASCII this way rather than writing UTF-8 directly. Both forms are
//! decoded here; an unknown `\<char>` escape is malformed (the line is skipped and counted).
//!
//! **Everything here is attacker-controlled**: a hostile installer running under Wine can write any bytes to
//! these files. Every string this module produces ([`RegKey`]'s value names/strings, [`WineReg::warnings`]) MUST
//! be escaped by the caller's sanitiser (`rt_core`/`cli`'s) before being shown to a person; nothing here does
//! that itself.
//!
//! **Bounds**: [`MAX_REG_BYTES`] on the whole input (the same 4 GiB ceiling as `rt_core::install::INPUT_CAP`;
//! duplicated here rather than depended on, since `rt_core::install` is a service module, not a shared-constants
//! one — a future cleanup could hoist both into one place and note as much), [`MAX_LINE_BYTES`] on one physical
//! line (an oversized line is skipped WITHOUT being copied into a `String` first, so one hostile huge line inside
//! an otherwise ordinary file cannot force one huge allocation), [`MAX_KEY_DEPTH`] `\`-separated segments per key
//! path, [`MAX_KEYS`] total keys kept (further keys are counted in [`WineReg::truncated`], never silently dropped
//! without a trace). No malformed byte sequence can panic: an unpaired `[`, a value line with no `=`, an
//! unterminated quoted string, invalid `dword:` hex, a truncated or invalid `\x` escape, and non-UTF-8 bytes
//! (decoded lossily, never rejected outright) are all skipped lines, counted, and folded into ONE aggregate
//! warning at the end — never one warning per bad line, so a hostile file that is nothing but bad lines cannot
//! make `warnings` grow without bound.
use std::collections::BTreeMap;

/// The whole input, in bytes. Matches `rt_core::install::INPUT_CAP`.
pub const MAX_REG_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// One physical line, in bytes. A hostile registry value must not be able to force one unbounded allocation.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// `\`-separated segments in one key path.
pub const MAX_KEY_DEPTH: usize = 64;
/// Keys kept in [`WineReg::keys`]; further keys are dropped and [`WineReg::truncated`] is set.
pub const MAX_KEYS: usize = 200_000;
/// Distinct kinds of malformed line quoted in the aggregate warning (the rest are just counted).
const MAX_WARNING_EXAMPLES: usize = 4;

/// One registry value. Only the three shapes this crate's callers need; `hex:`/`hex(2):`/`hex(7):` (REG_BINARY,
/// REG_EXPAND_SZ, REG_MULTI_SZ) are real but deliberately unmodelled (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// `"Name"="a string"`.
    Str(String),
    /// `"Name"=dword:XXXXXXXX`.
    Dword(u32),
    /// `@="a string"`: the key's own unnamed (default) value. Stored in [`RegKey::values`] under the empty name.
    Default(String),
}

/// One `[Key\Path]` block: its values (by name; the default value's name is `""`) and the timestamp the block
/// header carried, when one was present and parsed cleanly. A missing or unparseable timestamp is not an error
/// on its own — it is optional metadata, not modelled data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegKey {
    pub values: BTreeMap<String, RegValue>,
    pub timestamp: Option<i64>,
}

/// A parsed `.reg` text file (or, in [`crate::snapshot::Snapshot`], several merged together).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WineReg {
    /// Full decoded key paths (`\`-separated, no surrounding brackets) to their contents.
    pub keys: BTreeMap<String, RegKey>,
    /// At most one aggregate line describing every malformed line skipped during the parse (see the module
    /// docs). Empty when nothing was skipped.
    pub warnings: Vec<String>,
    /// `true` when [`MAX_KEYS`] was reached: real keys past the cap were not added to [`WineReg::keys`].
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegError {
    /// Defence in depth only: the byte slice itself is already bigger than [`MAX_REG_BYTES`]. The real guard
    /// against ever reading this much into memory belongs where the file is opened
    /// ([`crate::snapshot::Snapshot::capture`]), not here — this is a second, redundant check for whoever calls
    /// [`WineReg::parse`] directly with an in-memory buffer.
    #[error("registry text is larger than the {MAX_REG_BYTES} byte cap")]
    TooLarge,
}

impl WineReg {
    /// Parses Wine's `.reg` text format. See the module docs for the grammar, the escaping, and every bound.
    /// Never panics: any byte sequence produces a `WineReg` (possibly with `warnings` and/or `truncated` set).
    pub fn parse(bytes: &[u8]) -> Result<WineReg, RegError> {
        if bytes.len() as u64 > MAX_REG_BYTES {
            return Err(RegError::TooLarge);
        }
        let mut p = Parser::default();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let (line, next_pos) = take_line(bytes, pos);
            pos = next_pos;
            p.line(line);
        }
        Ok(p.finish())
    }
}

/// One physical line at `bytes[pos..]`, capped at [`MAX_LINE_BYTES`] (an oversized line is reported as `None`
/// and its bytes are never copied into a `String`), and the offset of the following line. Wine itself writes
/// bare `\n`; a stray `\r` right before it is stripped so a foreign-edited file still parses.
fn take_line(bytes: &[u8], pos: usize) -> (Option<String>, usize) {
    let rest = &bytes[pos..];
    let (raw, next_pos) = match rest.iter().position(|&b| b == b'\n') {
        Some(i) => (&rest[..i], pos + i + 1),
        None => (rest, bytes.len()),
    };
    if raw.len() > MAX_LINE_BYTES {
        return (None, next_pos);
    }
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    (Some(String::from_utf8_lossy(raw).into_owned()), next_pos)
}

/// The end (byte index right after the closing `"`) of a `"`-quoted string starting at `s` (which must NOT
/// include the opening quote), honouring `\"` inside it. `None`: no unescaped closing quote (unterminated).
fn quoted_end(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// Decodes Wine's escaping (`\\`, `\"`, `\r`, `\n`, `\xHHHH`) over the WHOLE of `s` (no surrounding quotes, no
/// terminator search: used for key paths and for the inside of an already-delimited quoted string alike).
/// `None` on any malformed escape: an unknown `\<char>`, a `\` with nothing after it, or a `\x` not followed by
/// exactly 4 hex digits. Never panics.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut pending_u16: Vec<u16> = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            flush_u16(&mut pending_u16, &mut out);
            out.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => {
                flush_u16(&mut pending_u16, &mut out);
                out.push('\\');
            }
            '"' => {
                flush_u16(&mut pending_u16, &mut out);
                out.push('"');
            }
            'r' => {
                flush_u16(&mut pending_u16, &mut out);
                out.push('\r');
            }
            'n' => {
                flush_u16(&mut pending_u16, &mut out);
                out.push('\n');
            }
            'x' => {
                let hex: String = (&mut chars).take(4).collect();
                if hex.chars().count() != 4 {
                    return None; // truncated \x escape
                }
                pending_u16.push(u16::from_str_radix(&hex, 16).ok()?);
            }
            _ => return None, // unknown escape
        }
    }
    flush_u16(&mut pending_u16, &mut out);
    Some(out)
}

/// Flushes buffered UTF-16 code units (accumulated across consecutive `\xHHHH` escapes, so a surrogate pair
/// combines correctly) into `out`. An unpaired surrogate decodes to U+FFFD rather than being dropped or panicking.
fn flush_u16(pending: &mut Vec<u16>, out: &mut String) {
    if pending.is_empty() {
        return;
    }
    for c in char::decode_utf16(pending.drain(..)) {
        out.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
}

/// Parses the decoded content and remaining tail of a quoted string starting at `s[..]` = `"..."<tail>`, i.e.
/// `s` is everything from (and including) the opening quote.
fn parse_quoted(s: &str) -> Option<(String, &str)> {
    parse_quoted_body(s.strip_prefix('"')?)
}

/// As [`parse_quoted`], but `body` is already past the opening quote.
fn parse_quoted_body(body: &str) -> Option<(String, &str)> {
    let end = quoted_end(body)?;
    let decoded = unescape(&body[..end - 1])?;
    Some((decoded, &body[end..]))
}

#[derive(Default)]
struct Parser {
    keys: BTreeMap<String, RegKey>,
    current: Option<(String, RegKey)>,
    /// The previous line was `"Name"=hex:...\` (or a continuation of one) ending in `\`: this line is another
    /// continuation, whatever it looks like.
    hex_continues: bool,
    truncated: bool,
    malformed: usize,
    examples: Vec<String>,
}

impl Parser {
    fn note_malformed(&mut self, why: &str) {
        self.malformed += 1;
        if self.examples.len() < MAX_WARNING_EXAMPLES && !self.examples.iter().any(|e| e == why) {
            self.examples.push(why.to_owned());
        }
    }

    fn flush_current(&mut self) {
        if let Some((path, key)) = self.current.take() {
            if self.keys.len() >= MAX_KEYS {
                self.truncated = true;
            } else {
                self.keys.insert(path, key);
            }
        }
    }

    fn line(&mut self, line: Option<String>) {
        let Some(line) = line else {
            self.hex_continues = false;
            self.note_malformed("line too long");
            return;
        };
        let line = line.as_str();
        if self.hex_continues {
            // A continuation of a `hex:`/`hex(N):` value: recognised, not modelled, never a warning, whatever
            // it looks like (committing to "still a continuation" avoids a hostile line trying to smuggle a
            // fake `[Key]`/value line past the parser mid-continuation).
            self.hex_continues = line.trim_end().ends_with('\\');
            return;
        }
        if line.is_empty() {
            self.flush_current(); // a blank line ends the current block
            return;
        }
        if line.starts_with(";;") || line.starts_with('#') || line.starts_with("WINE REGISTRY") {
            return; // comment / directive / header: recognised, not modelled, never a warning
        }
        if let Some(rest) = line.strip_prefix('[') {
            self.flush_current();
            self.key_line(rest);
            return;
        }
        if let Some(rest) = line.strip_prefix("@=") {
            self.value_line(String::new(), rest);
            return;
        }
        if line.starts_with('"') {
            match parse_quoted(line) {
                Some((name, tail)) => match tail.strip_prefix('=') {
                    Some(rest) => self.value_line(name, rest),
                    None => self.note_malformed("value line with no '='"),
                },
                None => self.note_malformed("unterminated quoted name"),
            }
            return;
        }
        self.note_malformed("unrecognised line");
    }

    /// `rest` is everything after the `[` of a key line: `Key\\Path] <timestamp>`.
    fn key_line(&mut self, rest: &str) {
        let Some(close) = rest.rfind(']') else {
            self.note_malformed("'[' with no closing ']'");
            return;
        };
        let Some(path) = unescape(&rest[..close]) else {
            self.note_malformed("malformed escape in key path");
            return;
        };
        if path.split('\\').count() > MAX_KEY_DEPTH {
            self.note_malformed("key path deeper than the cap");
            return;
        }
        let timestamp = rest[close + 1..].trim().parse::<i64>().ok();
        self.current = Some((
            path,
            RegKey {
                values: BTreeMap::new(),
                timestamp,
            },
        ));
    }

    /// `name` is the already-decoded value name (`""` for `@=`); `rest` is everything after the `=`.
    fn value_line(&mut self, name: String, rest: &str) {
        let Some((_, key)) = self.current.as_mut() else {
            self.note_malformed("value line outside any key");
            return;
        };
        if let Some(quoted) = rest.strip_prefix('"') {
            let Some((s, tail)) = parse_quoted_body(quoted) else {
                self.note_malformed("unterminated quoted value");
                return;
            };
            if !tail.is_empty() {
                self.note_malformed("trailing bytes after quoted value");
                return;
            }
            let value = if name.is_empty() {
                RegValue::Default(s)
            } else {
                RegValue::Str(s)
            };
            key.values.insert(name, value);
        } else if let Some(hex) = rest.strip_prefix("dword:") {
            match (hex.len() == 8, u32::from_str_radix(hex, 16)) {
                (true, Ok(n)) => {
                    key.values.insert(name, RegValue::Dword(n));
                }
                _ => self.note_malformed("invalid dword"),
            }
        } else if rest.starts_with("hex") {
            // REG_BINARY/REG_EXPAND_SZ/REG_MULTI_SZ (`hex:`, `hex(2):`, `hex(7):`, ...): real, common,
            // deliberately unmodelled — see the module docs. Not validated further; a line merely starting with
            // "hex" that is not really one of these types is accepted the same way (a documented simplification,
            // not a security gap: nothing this crate's callers read comes from an unmodelled value).
            self.hex_continues = rest.trim_end().ends_with('\\');
        } else {
            self.note_malformed("unrecognised value type");
        }
    }

    fn finish(mut self) -> WineReg {
        self.flush_current();
        let mut warnings = Vec::new();
        if self.malformed > 0 {
            let mut msg = format!("{} malformed registry line(s) skipped", self.malformed);
            if !self.examples.is_empty() {
                msg.push_str(" (");
                msg.push_str(&self.examples.join("; "));
                msg.push(')');
            }
            warnings.push(msg);
        }
        WineReg {
            keys: self.keys,
            warnings,
            truncated: self.truncated,
        }
    }
}

#[cfg(test)]
mod tests;
