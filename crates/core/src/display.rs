//! The Wine graphics driver setting (`HKCU\Software\Wine\Drivers`, value `Graphics`), read from `user.reg`.
//!
//! `rt_core` cannot depend on `rt_installer` (the dependency runs the other way), so this does not use
//! `WineReg::parse`. It scans the raw bytes for the one section and value it needs, mirroring that parser's
//! rules (Wine's `.reg` text format: doubled backslashes in key paths, `\\`/`\"`/`\r`/`\n`/`\xHHHH` escapes in
//! strings, non-UTF-8 decoded lossily) and its bounds: [`MAX_REG_BYTES`] on the whole input and
//! [`MAX_LINE_BYTES`] per line (a longer line is skipped, never copied). Only the matching value line is
//! ever copied. The file is attacker-controlled: whatever is read is passed through `text::clean`.
use crate::text::clean;

/// The whole input, in bytes. Same 4 GiB ceiling as `rt_installer::reg::MAX_REG_BYTES`.
const MAX_REG_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// One physical line, in bytes. Same as `rt_installer::reg::MAX_LINE_BYTES`.
const MAX_LINE_BYTES: usize = 1024 * 1024;
/// The section header as `user.reg` spells it (doubled backslashes). Registry names are case-insensitive.
const DRIVERS_SECTION: &str = r"Software\\Wine\\Drivers";
/// The key as `reg.exe` takes it.
pub const DRIVERS_KEY: &str = r"HKCU\Software\Wine\Drivers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsDriver {
    Auto,
    X11,
    Wayland,
    /// Anything else Wine holds (`x11,wayland`, an empty string, a driver we do not know); `clean(value, 60)`.
    Custom(String),
}

impl GraphicsDriver {
    /// Only the three words we offer, exactly as written (lowercase, no surrounding space).
    pub fn parse_choice(s: &str) -> Option<GraphicsDriver> {
        match s {
            "auto" => Some(GraphicsDriver::Auto),
            "x11" => Some(GraphicsDriver::X11),
            "wayland" => Some(GraphicsDriver::Wayland),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            GraphicsDriver::Auto => "auto",
            GraphicsDriver::X11 => "x11",
            GraphicsDriver::Wayland => "wayland",
            GraphicsDriver::Custom(s) => s,
        }
    }
}

/// The driver a `user.reg` selects. A missing section or value is `Auto` (Wine picks itself). A duplicate
/// `Graphics` line: the last one wins, as when Wine loads the hive. `Err` only for input over the size cap.
/// Never panics on any bytes.
pub fn read_graphics_driver(user_reg: &[u8]) -> Result<GraphicsDriver, String> {
    if user_reg.len() as u64 > MAX_REG_BYTES {
        return Err(clean("user.reg is larger than the size cap", 120));
    }
    let mut in_section = false;
    let mut found: Option<String> = None;
    for raw in user_reg.split(|&b| b == b'\n') {
        if raw.len() > MAX_LINE_BYTES {
            in_section = false; // cannot tell what it was; never carry a section over an unread line
            continue;
        }
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.first() == Some(&b'[') {
            // `[Key\\Path] <timestamp>`: the path is up to the last `]`.
            in_section = raw.iter().rposition(|&b| b == b']').is_some_and(|end| {
                raw.get(1..end)
                    .is_some_and(|p| p.eq_ignore_ascii_case(DRIVERS_SECTION.as_bytes()))
            });
        } else if raw.is_empty() {
            in_section = false; // a blank line ends the block
        } else if in_section
            && raw.first() == Some(&b'"')
            && let Some(v) = graphics_value(&String::from_utf8_lossy(raw))
        {
            found = Some(v);
        }
    }
    Ok(match found.as_deref() {
        None => GraphicsDriver::Auto,
        Some("x11") => GraphicsDriver::X11,
        Some("wayland") => GraphicsDriver::Wayland,
        Some(v) => GraphicsDriver::Custom(clean(v, 60)),
    })
}

/// The decoded string of a `"Graphics"="..."` line (name matched case-insensitively), else `None`. A string
/// with a malformed escape is kept undecoded rather than dropped, so it still shows up as `Custom`.
fn graphics_value(line: &str) -> Option<String> {
    let rest = line.strip_prefix('"')?;
    let (name, rest) = rest.split_once('"')?;
    if !name.eq_ignore_ascii_case("Graphics") {
        return None;
    }
    let body = rest.strip_prefix("=\"")?.strip_suffix('"')?;
    Some(unescape(body).unwrap_or_else(|| body.to_owned()))
}

/// Wine's string escapes (`\\`, `\"`, `\r`, `\n`, `\xHHHH` as UTF-16 units). `None` on a malformed one.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut units: Vec<u16> = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend(char::decode_utf16(units.drain(..)).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)));
            out.push(c);
            continue;
        }
        match chars.next()? {
            'x' => {
                let hex: String = (&mut chars).take(4).collect();
                units.push(u16::from_str_radix(&hex, 16).ok().filter(|_| hex.len() == 4)?);
            }
            e @ ('\\' | '"' | 'r' | 'n') => {
                out.extend(char::decode_utf16(units.drain(..)).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)));
                out.push(match e {
                    'r' => '\r',
                    'n' => '\n',
                    other => other,
                });
            }
            _ => return None,
        }
    }
    out.extend(char::decode_utf16(units.drain(..)).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(section_body: &str) -> Vec<u8> {
        format!(
            "WINE REGISTRY Version 2\n;; All keys relative to \\\\User\\\\S-1-5-21\n\n#arch=win64\n\n\
             [Control Panel\\\\Desktop] 1790095421\n#time=1dd4ab1864fafa4\n\"DragWidth\"=\"4\"\n\n{section_body}"
        )
        .into_bytes()
    }
    fn drivers(lines: &str) -> Vec<u8> {
        reg(&format!(
            "[Software\\\\Wine\\\\Drivers] 1790095421\n#time=1dd\n{lines}\n\n"
        ))
    }
    fn read(b: &[u8]) -> GraphicsDriver {
        read_graphics_driver(b).unwrap()
    }

    #[test]
    fn missing_key_or_value_is_auto() {
        assert_eq!(read(&reg("")), GraphicsDriver::Auto);
        assert_eq!(read(&drivers("\"Other\"=\"x11\"")), GraphicsDriver::Auto);
        assert_eq!(read(b""), GraphicsDriver::Auto);
    }

    #[test]
    fn known_values() {
        assert_eq!(read(&drivers("\"Graphics\"=\"x11\"")), GraphicsDriver::X11);
        assert_eq!(read(&drivers("\"Graphics\"=\"wayland\"")), GraphicsDriver::Wayland);
        // name and section case-insensitive; CRLF tolerated
        let b = b"[software\\\\WINE\\\\drivers] 1\r\n\"GRAPHICS\"=\"x11\"\r\n";
        assert_eq!(read(b), GraphicsDriver::X11);
    }

    #[test]
    fn other_values_are_custom() {
        let c = |s: &str| GraphicsDriver::Custom(s.into());
        assert_eq!(read(&drivers("\"Graphics\"=\"x11,wayland\"")), c("x11,wayland"));
        assert_eq!(read(&drivers("\"Graphics\"=\"\"")), c(""));
        assert_eq!(read(&drivers("\"Graphics\"=\"X11\"")), c("X11"));
        assert_eq!(read(&drivers("\"Graphics\"=\"caf\\x00e9\"")), c("caf\u{e9}"));
        assert_eq!(read(&drivers("\"Graphics\"=\"a\\qb\"")), c("a\\qb")); // malformed escape kept raw
        assert_eq!(read(&drivers("\"Graphics\"=\"a\\\"b\\\\\"")), c("a\"b\\"));
    }

    #[test]
    fn long_and_control_values_are_cleaned() {
        let long = format!("\"Graphics\"=\"{}\"", "a".repeat(10_000));
        match read(&drivers(&long)) {
            GraphicsDriver::Custom(s) => assert!(!s.is_empty() && s.len() <= 60),
            other => panic!("{other:?}"),
        }
        let ctl = read(&drivers("\"Graphics\"=\"x\\n\x1b[31m\u{202e}y\""));
        assert_eq!(ctl, GraphicsDriver::Custom("x[31my".into()));
    }

    #[test]
    fn other_keys_are_not_picked_up() {
        for k in [
            "Software\\\\Wine\\\\Drivers\\\\Sub",
            "Software\\\\Wine\\\\X11 Driver",
            "Software\\\\Wine\\\\Drivers2",
        ] {
            let b = reg(&format!("[{k}] 1\n\"Graphics\"=\"wayland\"\n\n"));
            assert_eq!(read(&b), GraphicsDriver::Auto, "{k}");
        }
        // a value after the blank line that ends the block is not in the section
        let b = reg("[Software\\\\Wine\\\\Drivers] 1\n\n\"Graphics\"=\"wayland\"\n");
        assert_eq!(read(&b), GraphicsDriver::Auto);
    }

    #[test]
    fn last_duplicate_wins() {
        let b = drivers("\"Graphics\"=\"x11\"\n\"Graphics\"=\"wayland\"");
        assert_eq!(read(&b), GraphicsDriver::Wayland);
    }

    #[test]
    fn oversized_line_is_skipped_and_hostile_bytes_do_not_panic() {
        let mut b = drivers("\"Graphics\"=\"wayland\"");
        b.extend(b"[Software\\\\Wine\\\\Drivers] 1\n");
        b.extend(format!("\"Graphics\"=\"{}\"\n", "a".repeat(MAX_LINE_BYTES)).bytes());
        assert_eq!(read(&b), GraphicsDriver::Wayland);
        let good = drivers("\"Graphics\"=\"x11\"");
        for i in (0..good.len()).step_by(7) {
            for flip in [0xff, 0x22, 0x5c, b'\n', b'[', 0x00] {
                let mut m = good.clone();
                m[i] = flip;
                let _ = read_graphics_driver(&m);
            }
        }
        let _ = read_graphics_driver(&[0xff, 0xfe, b'[', b'"', b'\\', b'x']);
    }

    #[test]
    fn parse_choice_is_exact() {
        assert_eq!(GraphicsDriver::parse_choice("auto"), Some(GraphicsDriver::Auto));
        assert_eq!(GraphicsDriver::parse_choice("x11"), Some(GraphicsDriver::X11));
        assert_eq!(GraphicsDriver::parse_choice("wayland"), Some(GraphicsDriver::Wayland));
        for s in ["X11", " x11", "auto\n", "", "x11,wayland"] {
            assert_eq!(GraphicsDriver::parse_choice(s), None, "{s:?}");
        }
        assert_eq!(GraphicsDriver::X11.as_str(), "x11");
        assert_eq!(GraphicsDriver::Custom("q".into()).as_str(), "q");
        assert_eq!(DRIVERS_KEY, r"HKCU\Software\Wine\Drivers");
    }
}
