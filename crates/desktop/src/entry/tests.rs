use super::*;
use crate::testutil::require_tool;
use rt_core::{BackendInfo, Store, WinPath};
use std::collections::HashMap;
use std::path::PathBuf;

fn require_dfv() -> Option<PathBuf> {
    require_tool("desktop-file-validate", "RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE")
}

fn app_id(s: &str) -> AppId {
    AppId::parse(s).unwrap()
}

fn sample_meta(id: &str, name: &str) -> Metadata {
    let exe = WinPath::parse("C:\\Program Files\\App\\app.exe").unwrap();
    Metadata::new(
        app_id(id),
        name.to_owned(),
        None,
        "x86_64",
        &exe,
        BackendInfo {
            id: "fake".into(),
            version: "1".into(),
        },
        "gui",
    )
}

/// Runs a real `desktop-file-validate` on freshly written content; `None` when the tool is unavailable (the
/// caller should then skip, per this crate's loud-skip convention).
fn validate_content(dir: &Path, content: &str) -> Option<bool> {
    let tool = require_dfv()?;
    let path = dir.join("check.desktop");
    fs::write(&path, content).unwrap();
    let out = std::process::Command::new(tool).arg(&path).output().unwrap();
    Some(out.status.success())
}

// --------------------------------------------------------------------------------------- escape_value

#[test]
fn escape_value_is_the_identity_on_plain_text() {
    for s in ["My App", "7-Zip", "Ünïcode App", "日本語アプリ", "100% Orange Juice"] {
        assert_eq!(escape_value(s), s);
    }
}

#[test]
fn escape_value_doubles_every_backslash() {
    assert_eq!(escape_value("back\\slash"), "back\\\\slash");
    assert_eq!(escape_value("\\\\"), "\\\\\\\\");
}

#[test]
fn escape_value_drops_control_and_format_characters_never_encodes_them() {
    assert_eq!(escape_value("a\nb\tc\rd\x1be"), "abcde");
    assert_eq!(escape_value("a\0b"), "ab");
    assert_eq!(escape_value("a\u{200b}b"), "ab"); // zero-width space (format char)
    assert_eq!(escape_value("a\u{202e}b"), "ab"); // bidi override
    for c in ["\n", "\t", "\r", "\x1b", "\0", "\u{200b}", "\u{202e}"] {
        assert!(!escape_value(&format!("x{c}y")).contains(c));
    }
}

#[test]
fn escape_value_leaves_quotes_and_percent_untouched_outside_exec() {
    // Quoting and `%%`-doubling are Exec=-specific; a plain string value like Name= has neither rule.
    assert_eq!(escape_value("100% \"quoted\" 'App'"), "100% \"quoted\" 'App'");
}

// ------------------------------------------------------------------------------------ escape_exec_arg

#[test]
fn escape_exec_arg_is_the_identity_when_nothing_is_reserved() {
    for s in ["plain-id", "my.app_1", "notepad"] {
        assert_eq!(escape_exec_arg(s), s);
    }
}

#[test]
fn escape_exec_arg_quotes_only_when_a_reserved_character_is_present() {
    assert_eq!(escape_exec_arg("has space"), "\"has space\"");
    assert_eq!(escape_exec_arg("a\"b"), "\"a\\\"b\"");
    assert_eq!(escape_exec_arg("a$b"), "\"a\\$b\"");
    assert_eq!(escape_exec_arg("a`b"), "\"a\\`b\"");
    assert_eq!(escape_exec_arg("<a>"), "\"<a>\"");
    assert_eq!(escape_exec_arg("a|b&c;d*e?f#g(h)i~j"), "\"a|b&c;d*e?f#g(h)i~j\"");
}

#[test]
fn escape_exec_arg_doubles_a_literal_percent_regardless_of_quoting() {
    assert_eq!(escape_exec_arg("100%"), "100%%");
    assert_eq!(escape_exec_arg("100% off"), "\"100%% off\"");
}

#[test]
fn escape_exec_arg_doubles_backslash_twice_when_the_argument_is_quoted() {
    // One literal backslash: general string escape (`\\`) then the quoting escape doubles that again (`\\\\`),
    // per the spec's own worked example.
    let got = escape_exec_arg("back\\slash");
    let expected = format!("\"back{}slash\"", "\\".repeat(4));
    assert_eq!(got, expected);
}

#[test]
fn escape_exec_arg_drops_control_and_format_characters() {
    assert_eq!(escape_exec_arg("a\nb\tc\x1bd"), "abcd");
    assert_eq!(escape_exec_arg("a\u{200b}b"), "ab");
}

#[test]
fn escape_exec_arg_output_passes_real_desktop_file_validate_for_hostile_inputs() {
    let Some(tool) = require_dfv() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let hostile = [
        "has space",
        "100%",
        "has\"quote",
        "$(injection)",
        "back\\slash",
        "a'b",
        "<>|&;*?#()`~",
        "a\nb\tc", // control chars: dropped before quoting is even decided
        "",
    ];
    for raw in hostile {
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=X\nExec=runtime run {}\nTerminal=false\nCategories=Utility;\n",
            escape_exec_arg(raw)
        );
        let path = tmp.path().join("check.desktop");
        fs::write(&path, &content).unwrap();
        let out = std::process::Command::new(&tool).arg(&path).output().unwrap();
        assert!(
            out.status.success(),
            "{raw:?} -> {content:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ------------------------------------------------------------------------------------------- render

#[test]
fn render_exact_content_plain_name_with_icon() {
    let got = render(&app_id("my-app"), "My App", true);
    assert_eq!(
        got,
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=My App\n\
         Exec=runtime run my-app\n\
         Icon=runtime-my-app\n\
         Terminal=false\n\
         Categories=Utility;\n"
    );
}

#[test]
fn render_omits_icon_line_when_there_is_no_icon() {
    let got = render(&app_id("my-app"), "My App", false);
    assert!(!got.contains("Icon="), "{got}");
    assert_eq!(
        got,
        "[Desktop Entry]\nType=Application\nName=My App\nExec=runtime run my-app\nTerminal=false\nCategories=Utility;\n"
    );
}

#[test]
fn render_exact_content_for_hostile_names_and_each_passes_real_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let cases: &[(&str, &str)] = &[
        ("with-spaces", "App With Spaces"),
        ("with-quotes", "Quote\"d 'App'"),
        ("with-percent", "100% Orange Juice"),
        ("with-backslash", "back\\slash App"),
        ("with-control", "line1\nline2\ttabbed"),
        ("with-bidi", "a\u{202e}b"),
        ("with-unicode", "日本語アプリ Ünïcode"),
    ];
    for (id, name) in cases {
        let content = render(&app_id(id), name, false);
        // Exactly 6 lines (no icon): a raw control/format character in `name` never grows the line count.
        assert_eq!(content.lines().count(), 6, "{id}: {content:?}");
        let name_line = content.lines().find(|l| l.starts_with("Name=")).unwrap();
        for bad in ['\n', '\r', '\x1b', '\u{202e}'] {
            assert!(!name_line.contains(bad), "{id}: {name_line:?}");
        }
        if let Some(ok) = validate_content(tmp.path(), &content) {
            assert!(ok, "{id} ({name:?}) produced invalid content:\n{content}");
        }
    }
}

#[test]
fn render_truncates_a_very_long_name_to_the_documented_cap() {
    let long = "a".repeat(1000);
    let got = render(&app_id("app"), &long, false);
    let name_line = got.lines().find(|l| l.starts_with("Name=")).unwrap();
    let value = &name_line["Name=".len()..];
    assert!(value.len() <= MAX_DISPLAY_NAME_LEN, "{}", value.len());
    assert_eq!(value, "a".repeat(MAX_DISPLAY_NAME_LEN));
    if let Some(tool) = require_dfv() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("check.desktop");
        fs::write(&path, &got).unwrap();
        let out = std::process::Command::new(tool).arg(&path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn render_truncation_is_on_a_char_boundary() {
    // 100 two-byte characters = 200 bytes = exactly the cap; one more character must still cut cleanly.
    let s = "\u{e9}".repeat(101);
    let got = render(&app_id("app"), &s, false);
    let name_line = got.lines().find(|l| l.starts_with("Name=")).unwrap();
    let value = &name_line["Name=".len()..];
    assert!(value.len() <= MAX_DISPLAY_NAME_LEN);
    assert!(std::str::from_utf8(value.as_bytes()).is_ok());
}

// -------------------------------------------------------------------------------------- write/remove fixture

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
    move |k| map.get(k).cloned()
}

struct Fx {
    _tmp: tempfile::TempDir,
    xdg: PathBuf,
    store: Store,
}

impl Fx {
    fn new() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let xdg = tmp.path().join("xdg");
        fs::create_dir_all(&xdg).unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        Fx { _tmp: tmp, xdg, store }
    }

    fn env(&self) -> impl Fn(&str) -> Option<OsString> + use<> {
        env(&[("XDG_DATA_HOME", self.xdg.to_str().unwrap())])
    }

    fn app(&self, id: &str) -> AppEnv {
        self.store.create(&app_id(id)).unwrap()
    }

    fn applications_dir(&self) -> PathBuf {
        self.xdg.join("applications")
    }

    fn icon_path(&self, id: &str, size: u32) -> PathBuf {
        self.xdg
            .join(format!("icons/hicolor/{size}x{size}/apps/runtime-{id}.png"))
    }
}

fn png(byte: u8) -> Vec<u8> {
    vec![0x89, b'P', b'N', b'G', byte]
}

// ------------------------------------------------------------------------------------------- write

#[test]
fn write_places_the_desktop_file_and_icons_at_the_documented_xdg_paths() {
    let fx = Fx::new();
    let app = fx.app("my-app");
    let meta = sample_meta("my-app", "My App");
    let icons = vec![(16u32, png(1)), (48u32, png(2))];
    write_with_env(&app, &meta, &icons, &fx.env()).unwrap();

    let desktop_path = fx.applications_dir().join("runtime-my-app.desktop");
    assert!(desktop_path.is_file());
    let content = fs::read_to_string(&desktop_path).unwrap();
    assert!(content.contains("Name=My App"));
    assert!(content.contains("Exec=runtime run my-app"));
    assert!(content.contains("Icon=runtime-my-app"));

    assert_eq!(fs::read(fx.icon_path("my-app", 16)).unwrap(), png(1));
    assert_eq!(fs::read(fx.icon_path("my-app", 48)).unwrap(), png(2));
    assert!(
        !fx.icon_path("my-app", 32).exists(),
        "a size never given must not appear"
    );
}

#[test]
fn write_with_no_icons_writes_no_icon_files_and_omits_icon_key() {
    let fx = Fx::new();
    let app = fx.app("bare");
    let meta = sample_meta("bare", "Bare App");
    write_with_env(&app, &meta, &[], &fx.env()).unwrap();
    let content = fs::read_to_string(fx.applications_dir().join("runtime-bare.desktop")).unwrap();
    assert!(!content.contains("Icon="));
    for size in HICOLOR_SIZES {
        assert!(!fx.icon_path("bare", size).exists());
    }
}

#[test]
fn write_result_is_a_real_installed_desktop_file_that_passes_real_validation() {
    let Some(_) = require_dfv() else { return };
    let fx = Fx::new();
    let app = fx.app("e2e-app");
    let meta = sample_meta("e2e-app", "End To End App");
    write_with_env(&app, &meta, &[(16, png(9))], &fx.env()).unwrap();

    let path = fx.applications_dir().join("runtime-e2e-app.desktop");
    assert!(path.is_file(), "not present in the scratch XDG_DATA_HOME");
    let tool = require_dfv().unwrap();
    let out = std::process::Command::new(tool).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn write_surfaces_xdg_resolution_failures() {
    let app = Store::new(tempfile::tempdir().unwrap().path().join("apps").to_owned())
        .unwrap()
        .create(&app_id("x"))
        .unwrap();
    // Neither XDG_DATA_HOME nor HOME set: unresolvable.
    let err = write_with_env(&app, &sample_meta("x", "X"), &[], &env(&[])).unwrap_err();
    assert!(matches!(err, DesktopError::Xdg(XdgError::Unresolvable)), "{err:?}");
}

#[test]
fn write_is_idempotent_when_run_twice() {
    let fx = Fx::new();
    let app = fx.app("again");
    write_with_env(&app, &sample_meta("again", "First"), &[(16, png(1))], &fx.env()).unwrap();
    write_with_env(&app, &sample_meta("again", "Second"), &[(16, png(2))], &fx.env()).unwrap();
    let content = fs::read_to_string(fx.applications_dir().join("runtime-again.desktop")).unwrap();
    assert!(content.contains("Name=Second"), "{content}");
    assert_eq!(fs::read(fx.icon_path("again", 16)).unwrap(), png(2));
}

// ------------------------------------------------------------------------------------------ remove

#[test]
fn remove_deletes_exactly_the_tracked_files_and_nothing_else() {
    let fx = Fx::new();
    let app = fx.app("doomed");
    let icons = vec![(16u32, png(1)), (48u32, png(2))];
    write_with_env(&app, &sample_meta("doomed", "Doomed"), &icons, &fx.env()).unwrap();

    // An unrelated app's files (canaries) in the very same directories.
    let survivor = fx.app("survivor");
    write_with_env(&survivor, &sample_meta("survivor", "Survivor"), &icons, &fx.env()).unwrap();
    // A genuinely unrelated file dropped straight into the applications dir (not one this crate ever wrote).
    let canary = fx.applications_dir().join("canary.txt");
    fs::write(&canary, "not ours").unwrap();
    let icon_canary = fx.icon_path("doomed", 16).parent().unwrap().join("canary.png");
    fs::write(&icon_canary, "not ours either").unwrap();

    remove_with_env(&app_id("doomed"), &fx.env()).unwrap();

    assert!(!fx.applications_dir().join("runtime-doomed.desktop").exists());
    assert!(!fx.icon_path("doomed", 16).exists());
    assert!(!fx.icon_path("doomed", 48).exists());

    // Survivor's own files, and both canaries, are untouched.
    assert!(fx.applications_dir().join("runtime-survivor.desktop").exists());
    assert!(fx.icon_path("survivor", 16).exists());
    assert!(fx.icon_path("survivor", 48).exists());
    assert_eq!(fs::read_to_string(&canary).unwrap(), "not ours");
    assert_eq!(fs::read_to_string(&icon_canary).unwrap(), "not ours either");
}

#[test]
fn remove_of_an_id_that_was_never_written_is_not_an_error() {
    let fx = Fx::new();
    remove_with_env(&app_id("ghost"), &fx.env()).unwrap();
}

#[test]
fn remove_is_safe_to_call_twice() {
    let fx = Fx::new();
    let app = fx.app("twice");
    write_with_env(&app, &sample_meta("twice", "Twice"), &[(16, png(1))], &fx.env()).unwrap();
    remove_with_env(&app_id("twice"), &fx.env()).unwrap();
    remove_with_env(&app_id("twice"), &fx.env()).unwrap();
}

// ----------------------------------------------------------------------------------- misc small helpers

#[test]
fn truncate_cuts_on_a_char_boundary() {
    assert_eq!(truncate("hello", 3), "hel");
    assert_eq!(truncate("hello", 10), "hello");
    let s = "\u{e9}\u{e9}\u{e9}"; // 2 bytes each
    assert_eq!(truncate(s, 3), "\u{e9}"); // cannot include a partial 2nd char
}

#[test]
fn clean_message_strips_control_characters_and_caps_length() {
    let msg = clean_message(&format!("bad\x1b[31m{}", "x".repeat(1000)));
    assert!(!msg.contains('\x1b'));
    assert!(msg.len() <= 500);
}

#[test]
fn desktop_and_icon_file_names_are_derived_only_from_the_id() {
    let id = app_id("my-app.1");
    assert_eq!(desktop_file_name(&id), "runtime-my-app.1.desktop");
    assert_eq!(icon_file_name(&id), "runtime-my-app.1.png");
    assert_eq!(icon_name(&id), "runtime-my-app.1");
}
