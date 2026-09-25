//! The Wine graphics driver a prefix's `user.reg` selects.
//!
//! Parsing is `rt_installer::WineReg::parse` and nothing else, so what is read here is exactly what the rest of
//! the runtime reads: hex continuations, `str(2):` values, escapes, over-long lines, non-UTF-8 bytes and a
//! duplicated line are all as that parser defines them. Everything is attacker-controlled; `driver_from_value`
//! cleans what is returned.
//!
//! The CALLER bounds the read: pass bytes that came from a bounded reader (`rt_installer::read_reg_file` reads a
//! path with a size cap, metadata before open). `WineReg::parse` itself only refuses input over 4 GiB.
use crate::install_archive::{ArchiveError, reg};
use crate::install_installer::read_hive;
use rt_core::{AppEnv, CompatBackend, DRIVERS_KEY, GraphicsDriver, Launcher, driver_from_value};
use rt_installer::{RegValue, WineReg};

/// The key as it is spelled in `user.reg` (no hive prefix).
const HIVE_KEY: &str = r"Software\Wine\Drivers";

#[derive(Debug, thiserror::Error)]
pub enum WineConfigError {
    #[error("{0:?} is not a driver this runtime sets (only auto, x11 and wayland)")]
    NotSettable(String),
    #[error("setting the Wine graphics driver failed: {0}")]
    Registry(String),
}

/// The `Graphics` value of `HKCU\Software\Wine\Drivers` in `user_reg`. A missing key or value is `Auto`; a
/// string (`REG_SZ` or `str(2)`) goes through [`driver_from_value`]; a dword is `Custom("non-string value")`.
/// Key and value names match case-insensitively; if several spellings of the key or value exist, the last in
/// the parser's (sorted) order wins. `Err`: the parser refused the input (its text is fixed, never file content).
pub fn read_graphics_driver(user_reg: &[u8]) -> Result<GraphicsDriver, String> {
    Ok(driver_in(&WineReg::parse(user_reg).map_err(|e| e.to_string())?))
}

/// The graphics driver of the prefix's `user.reg`, read with the no-follow, regular-file-only, size-capped hive
/// reader. A missing `user.reg` is `Auto`; a symlink, an oversized or an unparsable file is `Err` (fixed text).
pub fn read_graphics_driver_from_prefix(env: &AppEnv) -> Result<GraphicsDriver, String> {
    match read_hive(&env.prefix(), "user.reg").map_err(|e| e.to_string())? {
        Some(reg) => Ok(driver_in(&reg)),
        None => Ok(GraphicsDriver::Auto),
    }
}

fn driver_in(reg: &WineReg) -> GraphicsDriver {
    let value = reg
        .keys
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(HIVE_KEY))
        .flat_map(|(_, key)| key.values.iter())
        .rfind(|(n, _)| n.eq_ignore_ascii_case("Graphics"))
        .map(|(_, v)| v);
    match value {
        None => GraphicsDriver::Auto,
        Some(RegValue::Str(s) | RegValue::Default(s)) => driver_from_value(Some(s)),
        Some(RegValue::Dword(_)) => GraphicsDriver::Custom("non-string value".into()),
    }
}

/// Sets the app's graphics driver: `Auto` deletes the `Graphics` value (Wine then picks), `X11`/`Wayland` write
/// it. `Custom` is never written. A failed delete is fine if `reg query` then says the value is not there.
pub fn set_graphics_driver(
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    d: &GraphicsDriver,
) -> Result<(), WineConfigError> {
    let fail = |what: &str, detail: String| WineConfigError::Registry(format!("{what}: {detail}"));
    let run = |args: &[&str]| {
        reg(args, env, backend, launcher, None).map_err(|e| match e {
            ArchiveError::Registry(m) => WineConfigError::Registry(m),
            other => WineConfigError::Registry(other.to_string()),
        })
    };
    match d {
        GraphicsDriver::Custom(s) => Err(WineConfigError::NotSettable(s.clone())),
        GraphicsDriver::Auto => {
            let (ok, detail) = run(&["delete", DRIVERS_KEY, "/v", "Graphics", "/f"])?;
            if ok || !run(&["query", DRIVERS_KEY, "/v", "Graphics"])?.0 {
                Ok(())
            } else {
                Err(fail("reg delete Graphics", detail))
            }
        }
        GraphicsDriver::X11 | GraphicsDriver::Wayland => {
            let (ok, detail) = run(&["add", DRIVERS_KEY, "/v", "Graphics", "/d", d.as_str(), "/f"])?;
            if ok {
                Ok(())
            } else {
                Err(fail("reg add Graphics", detail))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::{AppId, Call, FakeBackend, Store};
    use std::fs;
    use std::os::unix::fs::symlink;

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

    fn app() -> (tempfile::TempDir, AppEnv) {
        let tmp = tempfile::tempdir().unwrap();
        let env = Store::new(tmp.path().join("apps"))
            .unwrap()
            .create(&AppId::parse("app").unwrap())
            .unwrap();
        fs::create_dir_all(env.drive_c().join("windows/system32")).unwrap();
        fs::write(env.drive_c().join("windows/system32/reg.exe"), b"MZ").unwrap();
        (tmp, env)
    }

    fn argv(b: &FakeBackend) -> Vec<Vec<String>> {
        b.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Command { args, .. } => Some(args.iter().map(|a| a.to_string_lossy().into_owned()).collect()),
                _ => None,
            })
            .collect()
    }

    fn launcher() -> Launcher {
        Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
    }

    fn set(b: &FakeBackend, env: &AppEnv, d: &GraphicsDriver) -> Result<(), WineConfigError> {
        set_graphics_driver(env, b, &launcher(), d)
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn set_builds_the_exact_reg_argv() {
        let (_t, env) = app();
        let b = FakeBackend::new();
        set(&b, &env, &GraphicsDriver::X11).unwrap();
        set(&b, &env, &GraphicsDriver::Wayland).unwrap();
        set(&b, &env, &GraphicsDriver::Auto).unwrap();
        let k = r"HKCU\Software\Wine\Drivers";
        assert_eq!(
            argv(&b),
            [
                v(&["add", k, "/v", "Graphics", "/d", "x11", "/f"]),
                v(&["add", k, "/v", "Graphics", "/d", "wayland", "/f"]),
                v(&["delete", k, "/v", "Graphics", "/f"]),
            ]
        );
    }

    #[test]
    fn custom_is_never_written() {
        let (_t, env) = app();
        let b = FakeBackend::new();
        let e = set(&b, &env, &custom("x11,wayland")).unwrap_err();
        assert!(matches!(e, WineConfigError::NotSettable(_)), "{e}");
        assert!(argv(&b).is_empty());
    }

    #[test]
    fn a_failing_reg_is_an_error_naming_the_value() {
        let (_t, env) = app();
        let b = FakeBackend::with_script("exit 5");
        let e = set(&b, &env, &GraphicsDriver::Wayland).unwrap_err().to_string();
        assert!(e.contains("Graphics") && e.contains("add"), "{e}");
        // delete fails and the query also says it is absent: fine; delete fails and it is still there: error
        set(&FakeBackend::with_script("exit 1"), &env, &GraphicsDriver::Auto).unwrap();
        let b = FakeBackend::with_script(r#"[ "$1" = delete ] && exit 1; exit 0"#);
        let e = set(&b, &env, &GraphicsDriver::Auto).unwrap_err().to_string();
        assert!(e.contains("Graphics"), "{e}");
    }

    #[test]
    fn prefix_read_missing_symlink_oversized_and_hostile() {
        let (_t, env) = app();
        let p = env.prefix();
        assert_eq!(read_graphics_driver_from_prefix(&env), Ok(GraphicsDriver::Auto));
        fs::write(p.join("user.reg"), drivers("\"Graphics\"=\"wayland\"")).unwrap();
        assert_eq!(read_graphics_driver_from_prefix(&env), Ok(GraphicsDriver::Wayland));
        fs::remove_file(p.join("user.reg")).unwrap();
        // a symlink is an error, never followed
        let target = p.join("elsewhere");
        fs::write(&target, drivers("\"Graphics\"=\"wayland\"")).unwrap();
        symlink(&target, p.join("user.reg")).unwrap();
        assert!(read_graphics_driver_from_prefix(&env).unwrap_err().contains("symlink"));
        fs::remove_file(p.join("user.reg")).unwrap();
        // a directory is not a hive; a sparse oversized file is refused unread
        fs::create_dir(p.join("user.reg")).unwrap();
        assert_eq!(read_graphics_driver_from_prefix(&env), Ok(GraphicsDriver::Auto));
        fs::remove_dir(p.join("user.reg")).unwrap();
        let f = fs::File::create(p.join("user.reg")).unwrap();
        f.set_len(crate::install_installer::MAX_MARKER_HIVE_BYTES + 1).unwrap();
        assert!(read_graphics_driver_from_prefix(&env).unwrap_err().contains("cap"));
        // hostile bytes: no panic, some answer
        fs::write(p.join("user.reg"), [0xffu8, b'[', b'\\', 0, b'\n', b'"'].repeat(500)).unwrap();
        let _ = read_graphics_driver_from_prefix(&env);
    }

    #[test]
    #[ignore = "needs Wine 10"]
    fn e2e_real_wine_display_driver() {
        let launcher = Launcher::new();
        let backend = crate::real_wine_backend(&launcher);
        let tmp = tempfile::tempdir().unwrap(); // never ~/.wine; and no stub reg.exe, Wine's own is used
        let env = Store::new(tmp.path().join("apps"))
            .unwrap()
            .create(&AppId::parse("e2e").unwrap())
            .unwrap();
        backend.prepare(&env).unwrap();
        for (want, expect) in [
            (GraphicsDriver::Wayland, GraphicsDriver::Wayland),
            (GraphicsDriver::Auto, GraphicsDriver::Auto),
            (GraphicsDriver::X11, GraphicsDriver::X11),
        ] {
            set_graphics_driver(&env, &backend, &launcher, &want).unwrap();
            backend.stop(&env).unwrap(); // the registry is flushed to user.reg when the server exits
            assert_eq!(read_graphics_driver_from_prefix(&env), Ok(expect));
        }
    }
}
