//! The Wine graphics driver a prefix's `user.reg` selects.
//!
//! Parsing is `rt_installer::WineReg::parse` and nothing else, so what is read here is exactly what the rest of
//! the runtime reads: hex continuations, `str(2):` values, escapes, over-long lines, non-UTF-8 bytes and a
//! duplicated line are all as that parser defines them. Everything is attacker-controlled; `driver_from_value`
//! cleans what is returned.
//!
//! The CALLER bounds the read: pass bytes that came from a bounded reader (`rt_installer::read_reg_file` reads a
//! path with a size cap, metadata before open). `WineReg::parse` itself only refuses input over 4 GiB.
use rt_core::{GraphicsDriver, driver_from_value};
use rt_installer::{RegValue, WineReg};

const DRIVERS_KEY: &str = r"Software\Wine\Drivers";

/// The `Graphics` value of `HKCU\Software\Wine\Drivers` in `user_reg`. A missing key or value is `Auto`; a
/// string (`REG_SZ` or `str(2)`) goes through [`driver_from_value`]; a dword is `Custom("non-string value")`.
/// Key and value names match case-insensitively; if several spellings of the key or value exist, the last in
/// the parser's (sorted) order wins. `Err`: the parser refused the input (its text is fixed, never file content).
pub fn read_graphics_driver(user_reg: &[u8]) -> Result<GraphicsDriver, String> {
    let reg = WineReg::parse(user_reg).map_err(|e| e.to_string())?;
    let value = reg
        .keys
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(DRIVERS_KEY))
        .flat_map(|(_, key)| key.values.iter())
        .rfind(|(n, _)| n.eq_ignore_ascii_case("Graphics"))
        .map(|(_, v)| v);
    Ok(match value {
        None => GraphicsDriver::Auto,
        Some(RegValue::Str(s) | RegValue::Default(s)) => driver_from_value(Some(s)),
        Some(RegValue::Dword(_)) => GraphicsDriver::Custom("non-string value".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(body: &str) -> Vec<u8> {
        format!("WINE REGISTRY Version 2\n;; All keys relative to \\\\User\\\\S-1\n\n#arch=win64\n\n{body}")
            .into_bytes()
    }
    fn drivers(lines: &str) -> Vec<u8> {
        file(&format!(
            "[Software\\\\Wine\\\\Drivers] 1790095421\n#time=1dd\n{lines}\n\n"
        ))
    }
    fn read(b: &[u8]) -> GraphicsDriver {
        read_graphics_driver(b).unwrap()
    }
    fn custom(s: &str) -> GraphicsDriver {
        GraphicsDriver::Custom(s.into())
    }

    #[test]
    fn missing_is_auto() {
        assert_eq!(read(b""), GraphicsDriver::Auto);
        assert_eq!(read(&file("")), GraphicsDriver::Auto);
        assert_eq!(read(&drivers("\"Other\"=\"x11\"")), GraphicsDriver::Auto);
    }

    #[test]
    fn known_and_custom_values() {
        assert_eq!(read(&drivers("\"Graphics\"=\"x11\"")), GraphicsDriver::X11);
        assert_eq!(read(&drivers("\"Graphics\"=\"wayland\"")), GraphicsDriver::Wayland);
        assert_eq!(read(&drivers("\"Graphics\"=str(2):\"x11\"")), GraphicsDriver::X11);
        assert_eq!(read(&drivers("\"Graphics\"=\"x11,wayland\"")), custom("x11,wayland"));
        assert_eq!(read(&drivers("\"Graphics\"=\"\"")), custom(""));
        assert_eq!(read(&drivers("\"Graphics\"=\"caf\\x00e9\"")), custom("caf\u{e9}"));
        assert_eq!(
            read(&drivers("\"Graphics\"=dword:00000001")),
            custom("non-string value")
        );
    }

    #[test]
    fn case_and_crlf() {
        let b = b"[software\\\\WINE\\\\drivers] 1\r\n\"GRAPHICS\"=\"wayland\"\r\n";
        assert_eq!(read(b), GraphicsDriver::Wayland);
    }

    #[test]
    fn other_keys_are_not_picked_up() {
        for k in [
            "Software\\\\Wine\\\\Drivers\\\\Sub",
            "Software\\\\Wine\\\\X11 Driver",
            "Software\\\\Wine\\\\Drivers2",
        ] {
            let b = file(&format!("[{k}] 1\n\"Graphics\"=\"wayland\"\n\n"));
            assert_eq!(read(&b), GraphicsDriver::Auto, "{k}");
        }
        // after the blank line ending the block there is no key: WineReg drops the value line
        let b = file("[Software\\\\Wine\\\\Drivers] 1\n\n\"Graphics\"=\"wayland\"\n");
        assert_eq!(read(&b), GraphicsDriver::Auto);
    }

    #[test]
    fn duplicates_last_wins_and_later_non_string_wins() {
        let b = drivers("\"Graphics\"=\"x11\"\n\"Graphics\"=\"wayland\"");
        assert_eq!(read(&b), GraphicsDriver::Wayland);
        let b = drivers("\"Graphics\"=\"x11\"\n\"Graphics\"=dword:00000001");
        assert_eq!(read(&b), custom("non-string value"));
    }

    #[test]
    fn a_hex_continuation_swallows_the_following_line() {
        // WineReg: a `hex:` value ending in `\` makes the next line a continuation, so the Graphics line is data
        let b = drivers("\"Blob\"=hex:01,02,\\\n\"Graphics\"=\"wayland\"");
        assert_eq!(read(&b), GraphicsDriver::Auto);
    }

    #[test]
    fn malformed_lines_are_skipped_by_the_parser() {
        // trailing junk after the closing quote, and an unterminated string: WineReg skips both lines
        assert_eq!(read(&drivers("\"Graphics\"=\"a\"b\"")), GraphicsDriver::Auto);
        assert_eq!(read(&drivers("\"Graphics\"=\"x11\\\"")), GraphicsDriver::Auto);
        // a skipped bad line does not hide an earlier good one
        assert_eq!(
            read(&drivers("\"Graphics\"=\"x11\"\n\"Graphics\"=\"a\"b\"")),
            GraphicsDriver::X11
        );
    }

    #[test]
    fn oversized_line_is_skipped_by_the_parser() {
        let long = format!("\"Graphics\"=\"{}\"", "a".repeat(1024 * 1024 + 1));
        assert_eq!(
            read(&drivers(&format!("\"Graphics\"=\"x11\"\n{long}"))),
            GraphicsDriver::X11
        );
    }

    #[test]
    fn long_control_and_non_utf8_values_are_cleaned() {
        match read(&drivers(&format!("\"Graphics\"=\"{}\"", "a".repeat(10_000)))) {
            GraphicsDriver::Custom(s) => assert!(!s.is_empty() && s.len() <= 60),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            read(&drivers("\"Graphics\"=\"x\\n\x1b[31m\u{202e}y\"")),
            custom("x[31my")
        );
        let mut b = drivers("\"Graphics\"=\"xAy\"");
        let at = b.iter().rposition(|&c| c == b'A').unwrap();
        b[at] = 0xff;
        assert_eq!(read(&b), custom("x\u{fffd}y")); // lossy U+FFFD is not a control/format char, so it stays
    }

    #[test]
    fn mutations_and_truncations_never_panic() {
        let good = drivers("\"Graphics\"=\"x11\"");
        for i in (0..good.len()).step_by(7) {
            for flip in [0xff, 0x22, 0x5c, b'\n', b'[', 0x00] {
                let mut m = good.clone();
                m[i] = flip;
                let _ = read_graphics_driver(&m);
            }
        }
        for n in 0..good.len() {
            let _ = read_graphics_driver(&good[..n]);
        }
    }
}
