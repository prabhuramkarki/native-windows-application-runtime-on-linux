use super::*;
use crate::reg::RegKey;
use rt_core::{AppId, Store};
use std::io::Write as _;
use std::time::{Duration, Instant};

fn key(values: &[(&str, RegValue)]) -> RegKey {
    RegKey {
        values: values.iter().map(|(n, v)| (n.to_string(), v.clone())).collect(),
        timestamp: None,
    }
}

fn reg(entries: &[(&str, RegKey)]) -> WineReg {
    WineReg {
        keys: entries.iter().map(|(p, k)| (p.to_string(), k.clone())).collect(),
        ..Default::default()
    }
}

#[test]
fn new_files_are_those_in_after_but_not_before() {
    let before = Snapshot {
        files: vec!["a.exe".into(), "keep.dll".into()],
        ..Default::default()
    };
    let after = Snapshot {
        files: vec!["keep.dll".into(), "new.exe".into()],
        ..Default::default()
    };
    let diff = Snapshot::diff(&before, &after);
    assert_eq!(diff.new_files, vec!["new.exe".to_string()]);
}

#[test]
fn a_removed_file_is_not_reported_as_new() {
    let before = Snapshot {
        files: vec!["gone.exe".into()],
        ..Default::default()
    };
    let after = Snapshot {
        files: vec![],
        ..Default::default()
    };
    let diff = Snapshot::diff(&before, &after);
    assert!(diff.new_files.is_empty(), "{:?}", diff.new_files);
}

#[test]
fn a_brand_new_key_reports_all_of_its_value_names() {
    let before = reg(&[]);
    let after = reg(&[("HKLM\\Software\\NewApp", key(&[("Ver", RegValue::Str("1.0".into()))]))]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: before,
            ..Default::default()
        },
        &Snapshot {
            registry: after,
            ..Default::default()
        },
    );
    assert_eq!(
        diff.new_registry_keys,
        vec![("HKLM\\Software\\NewApp".to_string(), vec!["Ver".to_string()])]
    );
}

#[test]
fn a_new_value_in_an_already_existing_key_is_reported_alone() {
    let before = reg(&[("HKLM\\Software\\App", key(&[("Old", RegValue::Str("x".into()))]))]);
    let after = reg(&[(
        "HKLM\\Software\\App",
        key(&[("Old", RegValue::Str("x".into())), ("New", RegValue::Str("y".into()))]),
    )]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: before,
            ..Default::default()
        },
        &Snapshot {
            registry: after,
            ..Default::default()
        },
    );
    assert_eq!(
        diff.new_registry_keys,
        vec![("HKLM\\Software\\App".to_string(), vec!["New".to_string()])]
    );
}

#[test]
fn a_removed_key_and_a_removed_value_are_never_reported_as_new() {
    let before = reg(&[
        ("HKLM\\Software\\GoneKey", key(&[("A", RegValue::Str("1".into()))])),
        (
            "HKLM\\Software\\Kept",
            key(&[
                ("Stays", RegValue::Str("1".into())),
                ("Removed", RegValue::Str("2".into())),
            ]),
        ),
    ]);
    let after = reg(&[("HKLM\\Software\\Kept", key(&[("Stays", RegValue::Str("1".into()))]))]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: before,
            ..Default::default()
        },
        &Snapshot {
            registry: after,
            ..Default::default()
        },
    );
    assert!(diff.new_registry_keys.is_empty(), "{:?}", diff.new_registry_keys);
}

#[test]
fn uninstall_entries_come_only_from_brand_new_uninstall_subkeys() {
    let uninstall_key = |vals: &[(&str, RegValue)]| key(vals);
    let before = reg(&[]);
    let after = reg(&[
        (
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{FULL-GUID}",
            uninstall_key(&[
                ("DisplayName", RegValue::Str("Full App".into())),
                (
                    "UninstallString",
                    RegValue::Str(r"C:\Program Files\Full\uninst.exe".into()),
                ),
                ("DisplayIcon", RegValue::Str(r"C:\Program Files\Full\app.exe".into())),
            ]),
        ),
        (
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{PARTIAL-GUID}",
            uninstall_key(&[
                ("DisplayName", RegValue::Str("Partial App".into())),
                (
                    "UninstallString",
                    RegValue::Str(r"C:\Program Files\Partial\uninst.exe".into()),
                ),
                // no DisplayIcon: a hostile/incomplete installer left it out.
            ]),
        ),
        // A sibling key under Uninstall that is not itself a direct subkey: must not be mistaken for an entry.
        (
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            uninstall_key(&[]),
        ),
    ]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: before,
            ..Default::default()
        },
        &Snapshot {
            registry: after,
            ..Default::default()
        },
    );
    assert_eq!(diff.uninstall_entries.len(), 2, "{:?}", diff.uninstall_entries);
    let full = diff
        .uninstall_entries
        .iter()
        .find(|e| e.display_name.as_deref() == Some("Full App"))
        .unwrap();
    assert_eq!(
        full.uninstall_string.as_deref(),
        Some(r"C:\Program Files\Full\uninst.exe")
    );
    assert_eq!(full.icon_path.as_deref(), Some(r"C:\Program Files\Full\app.exe"));
    let partial = diff
        .uninstall_entries
        .iter()
        .find(|e| e.display_name.as_deref() == Some("Partial App"))
        .unwrap();
    assert_eq!(
        partial.icon_path, None,
        "a missing DisplayIcon must be None, never a panic or a guess"
    );
}

/// I1: a real 64-bit Wine prefix's Wow6432Node mirror (where a 32-bit installer's Uninstall entry actually
/// lands, confirmed for real against `hello-nsis.exe`) must be captured exactly like the non-Wow path, not
/// silently dropped.
#[test]
fn a_wow6432node_uninstall_subkey_is_captured_like_the_regular_one() {
    let before = reg(&[]);
    let after = reg(&[(
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\RuntimeFixtureNsis",
        key(&[
            ("DisplayName", RegValue::Str("Runtime Fixture NSIS".into())),
            (
                "UninstallString",
                RegValue::Str(r"C:\Program Files\RuntimeFixtureNsis\uninstall.exe".into()),
            ),
        ]),
    )]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: before,
            ..Default::default()
        },
        &Snapshot {
            registry: after,
            ..Default::default()
        },
    );
    assert_eq!(diff.uninstall_entries.len(), 1, "{:?}", diff.uninstall_entries);
    assert_eq!(
        diff.uninstall_entries[0].display_name.as_deref(),
        Some("Runtime Fixture NSIS")
    );
    assert_eq!(
        diff.uninstall_entries[0].uninstall_string.as_deref(),
        Some(r"C:\Program Files\RuntimeFixtureNsis\uninstall.exe")
    );
}

#[test]
fn an_uninstall_subkey_that_already_existed_is_not_reported_as_a_new_entry() {
    let existing = reg(&[(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{OLD}",
        key(&[("DisplayName", RegValue::Str("Already there".into()))]),
    )]);
    let diff = Snapshot::diff(
        &Snapshot {
            registry: existing.clone(),
            ..Default::default()
        },
        &Snapshot {
            registry: existing,
            ..Default::default()
        },
    );
    assert!(diff.uninstall_entries.is_empty());
}

/// Builds a real `AppEnv` (via `Store`) in a fresh tempdir: `Snapshot::capture` needs a real `AppEnv`, not a
/// hand-built struct (its fields are private to `rt_core`).
fn fake_env(tmp: &std::path::Path) -> rt_core::AppEnv {
    let store = Store::new(tmp).unwrap();
    store.create(&AppId::slug("capture-test")).unwrap()
}

#[test]
fn capture_on_a_fresh_env_with_no_prefix_yet_is_empty_not_a_panic_or_error() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fake_env(tmp.path());
    let snap = Snapshot::capture(&env);
    assert!(snap.files.is_empty());
    assert!(!snap.files_truncated);
    assert!(snap.registry.keys.is_empty());
    assert!(snap.registry.warnings.is_empty());
}

#[test]
fn capture_wires_the_reg_parser_and_the_drive_c_listing_together() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fake_env(tmp.path());
    fs::create_dir_all(env.prefix()).unwrap();
    fs::write(
        env.prefix().join("system.reg"),
        "WINE REGISTRY Version 2\n\n#arch=win64\n\n[Software\\\\Vendor] 1\n\"Ver\"=\"1.0\"\n",
    )
    .unwrap();
    fs::write(
        env.prefix().join("user.reg"),
        "WINE REGISTRY Version 2\n\n[Software\\\\Vendor] 1\n\"UserOnly\"=\"yes\"\n",
    )
    .unwrap();
    fs::create_dir_all(env.drive_c().join("Program Files/App")).unwrap();
    fs::write(env.drive_c().join("Program Files/App/app.exe"), b"x").unwrap();

    let snap = Snapshot::capture(&env);
    assert_eq!(snap.files, vec!["Program Files/App/app.exe".to_string()]);
    assert!(!snap.files_truncated);
    assert_eq!(
        snap.registry.keys["HKLM\\Software\\Vendor"].values["Ver"],
        RegValue::Str("1.0".into())
    );
    assert_eq!(
        snap.registry.keys["HKCU\\Software\\Vendor"].values["UserOnly"],
        RegValue::Str("yes".into())
    );
    assert!(snap.registry.warnings.is_empty(), "{:?}", snap.registry.warnings);
}

/// `read_capped` is `fn`-private to this module; called directly (not through `Snapshot::capture`) so this test
/// is not rescued by `WineReg::parse`'s OWN redundant size guard (`crate::reg::RegError::TooLarge`) — on a fast
/// tmpfs, reading a many-GiB hole-filled sparse file is (surprisingly) near-instant, so a wall-clock bound alone
/// cannot reliably tell "the guard rejected this unread" from "the guard is gone and a fast disk read it anyway,
/// then something else caught it downstream". Asserting `Err` (not just "eventually produced a warning") is the
/// deterministic, environment-independent check.
#[test]
fn a_5_gib_sparse_registry_file_is_refused_by_read_capped_without_reading_it() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("system.reg");
    let file = File::create(&path).unwrap();
    file.set_len(5 << 30).unwrap();
    // It starts like a valid file so a reader that did not check the size first would start reading/decoding.
    (&file).write_all(b"WINE REGISTRY Version 2\n").unwrap();
    drop(file);

    let started = Instant::now();
    let err = read_capped(&path).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "took {:?} (a correct guard never reads the file at all)",
        started.elapsed()
    );
    assert!(err.contains("without reading it"), "{err}");
}

#[test]
fn capture_reports_an_oversized_registry_file_as_one_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fake_env(tmp.path());
    fs::create_dir_all(env.prefix()).unwrap();
    let path = env.prefix().join("system.reg");
    let file = File::create(&path).unwrap();
    file.set_len(5 << 30).unwrap();
    (&file).write_all(b"WINE REGISTRY Version 2\n").unwrap();
    drop(file);

    let snap = Snapshot::capture(&env);
    assert!(snap.registry.keys.is_empty());
    assert_eq!(snap.registry.warnings.len(), 1, "{:?}", snap.registry.warnings);
    assert!(
        snap.registry.warnings[0].contains("without reading it"),
        "{}",
        snap.registry.warnings[0]
    );
}

#[test]
fn a_symlink_under_drive_c_is_recorded_but_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let env = fake_env(tmp.path());
    fs::create_dir_all(env.drive_c()).unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"nope").unwrap();
    std::os::unix::fs::symlink(&outside, env.drive_c().join("escape")).unwrap();

    let snap = Snapshot::capture(&env);
    assert_eq!(
        snap.files,
        vec!["escape".to_string()],
        "the symlink itself is one entry, never descended into"
    );
}
