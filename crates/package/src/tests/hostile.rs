//! One test per container (spec 3.1) and manifest (spec 3.2) rule: each asserts the error kind and, where anything
//! could be written, that nothing was.
use super::*;
use crate::manifest::parse_manifest;
use crate::{Entry, PackageError as E, Requests};
use rt_core::ZipError as Z;
use rt_core::unzip::Layout;

fn manifest_err(text: &str) -> String {
    match parse_manifest(text.as_bytes()) {
        Ok(_) => panic!("accepted:\n{text}"),
        Err(E::Manifest(m)) => m,
        Err(e) => panic!("not a manifest error: {e}"),
    }
}

/// The valid package plus one entry called `name` (written under a same-length placeholder, then renamed).
fn with_extra_entry(name: &str) -> Vec<u8> {
    let placeholder = "q".repeat(name.len());
    let mut files = payload();
    files.push((Box::leak(placeholder.clone().into_boxed_str()), b"x".to_vec()));
    rename_everywhere(
        package_of(&valid_manifest(), &files),
        placeholder.as_bytes(),
        name.as_bytes(),
    )
}

#[test]
fn the_valid_package_opens_verifies_and_reports_its_manifest() {
    let (_t, mut p) = open_bytes(&valid_package()).unwrap();
    p.verify().unwrap();
    let m = &p.manifest;
    assert_eq!(m.id.as_str(), "example-app");
    assert_eq!(m.arch, pe::Arch::X86_64);
    assert_eq!(m.dependencies, ["vcrun2022"]);
    assert_eq!(
        m.entry,
        Entry::Portable {
            exe: "payload/App/app.exe".into()
        }
    );
    assert_eq!(m.permissions.exprs(), ["network=allow", "gpu=on"]);
    assert_eq!(p.digest, sha256(valid_manifest().as_bytes()));
    assert_eq!(p.digests().len(), 3);
    assert_eq!(p.digests()["payload/App/data.bin"], sha256(&[7u8; 3000]));
}

// ---------------------------------------------------------------- container

#[test]
fn traversal_and_absolute_names_are_refused_by_the_planner() {
    for name in ["payload/../x", "../x", "/abs", "C:x", "payload/C:x", "payload/a\u{1b}b"] {
        let e = open_err(&with_extra_entry(name));
        assert!(matches!(e, E::Zip(Z::BadName { .. })), "{name:?}: {e}");
        assert!(!e.to_string().contains('\u{1b}'));
    }
}

#[test]
fn a_backslash_in_a_name_is_refused() {
    let e = open_err(&with_extra_entry("payload\\x"));
    assert!(matches!(&e, E::Layout(m) if m.contains('\\')), "{e}");
}

#[test]
fn non_canonical_names_are_refused() {
    // The planner reads `payload/./x` as `payload\x`: the manifest could not name it exactly.
    let e = open_err(&with_extra_entry("payload/./x"));
    assert!(matches!(e, E::Layout(_)), "{e}");
}

#[test]
fn symlink_device_and_fifo_entries_are_refused_not_skipped() {
    for mode in [S_IFLNK | 0o777, S_IFIFO | 0o644, S_IFCHR | 0o666, 0o140_666, 0o060_666] {
        let zip = set_mode(with_extra_entry("payload/link"), "payload/link", mode);
        let e = open_err(&zip);
        assert!(matches!(&e, E::Layout(m) if m.contains("special")), "{mode:o}: {e}");
    }
    // A symlink written as one by the zip writer.
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("wrun.toml", stored()).unwrap();
    w.write_all(valid_manifest().as_bytes()).unwrap();
    for (p, d) in payload() {
        w.start_file(p, stored()).unwrap();
        w.write_all(&d).unwrap();
    }
    w.add_symlink("payload/etc", "/etc", stored()).unwrap();
    let e = open_err(&w.finish().unwrap().into_inner());
    assert!(matches!(e, E::Layout(_)), "{e}");
}

#[test]
fn case_collisions_duplicates_and_file_dir_conflicts_are_refused() {
    let e = open_err(&with_extra_entry("payload/APP.png"));
    assert!(matches!(e, E::Zip(Z::CaseCollision { .. })), "{e}");
    let e = open_err(&with_extra_entry("payload/app.png"));
    assert!(
        matches!(e, E::Zip(Z::DuplicateNames { .. } | Z::Duplicate { .. })),
        "{e}"
    );
    let e = open_err(&with_extra_entry("payload/app.png/x"));
    assert!(matches!(e, E::Zip(Z::TypeConflict { .. })), "{e}");
}

#[test]
fn zip_bombs_are_refused_from_the_central_directory() {
    // 2 MiB declared from 10 stored bytes: over the 1000:1 ratio.
    let zip = set_declared_size(valid_package(), "payload/app.png", 2 << 20);
    let e = open_err(&zip);
    assert!(matches!(e, E::Zip(Z::Ratio { .. })), "{e}");
    // Declared sizes over the caps (lowered here; the production caps are the planner's own tests).
    let tight = Limits {
        max_entry_bytes: 1000,
        ..Limits::default()
    };
    let t = tempfile::tempdir().unwrap();
    let e = open_in(t.path(), &valid_package(), tight).err().unwrap();
    assert!(matches!(e, E::Zip(Z::EntryTooLarge { .. })), "{e}");
    let tight = Limits {
        max_total_bytes: 2000,
        ..Limits::default()
    };
    let e = open_in(t.path(), &valid_package(), tight).err().unwrap();
    assert!(matches!(e, E::Zip(Z::TotalTooLarge { .. })), "{e}");
}

#[test]
fn truncated_archives_and_trailing_garbage_are_refused() {
    let zip = valid_package();
    for cut in [0, 10, zip.len() / 2, zip.len() - 1] {
        let e = open_err(&zip[..cut]);
        assert!(matches!(e, E::Zip(_)), "cut at {cut}: {e}");
    }
    let mut trailing = zip.clone();
    trailing.extend_from_slice(b"garbage");
    let e = open_err(&trailing);
    assert!(matches!(e, E::Zip(Z::Layout(Layout::EndNotAtEof))), "{e}");
}

#[test]
fn the_manifest_must_exist_and_be_the_first_entry() {
    let e = open_err(&zip_of(&[("payload/a", b"a")]));
    assert!(matches!(&e, E::Layout(m) if m.contains("first entry")), "{e}");
    let manifest = format!("{HEAD}{}", files_toml(&payload()));
    let mut entries: Vec<(&str, &[u8])> = payload().iter().map(|(p, d)| (*p, &*d.clone().leak())).collect();
    entries.push(("wrun.toml", manifest.as_bytes()));
    let e = open_err(&zip_of(&entries));
    assert!(matches!(&e, E::Layout(m) if m.contains("first entry")), "{e}");
    // A directory called wrun.toml.
    let e = open_err(&zip_of(&[("wrun.toml/", b"")]));
    assert!(matches!(e, E::Layout(_)), "{e}");
}

#[test]
fn a_manifest_over_64_kib_or_not_utf8_is_refused() {
    let big = format!("{}\n# {}\n", valid_manifest(), "x".repeat(64 * 1024));
    let e = open_err(&package_of(&big, &payload()));
    assert!(matches!(&e, E::Manifest(m) if m.contains("larger")), "{e}");
    let mut bad = valid_manifest().into_bytes();
    bad.extend_from_slice(b"# \xff\xfe\n");
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("wrun.toml", stored()).unwrap();
    w.write_all(&bad).unwrap();
    for (p, d) in payload() {
        w.start_file(p, stored()).unwrap();
        w.write_all(&d).unwrap();
    }
    let e = open_err(&w.finish().unwrap().into_inner());
    assert!(matches!(&e, E::Manifest(m) if m.contains("UTF-8")), "{e}");
}

#[test]
fn a_signature_entry_is_refused_as_signed_wherever_it_is() {
    let e = open_err(&with_extra_entry("wrun.sig"));
    assert!(matches!(e, E::Signed), "{e}");
    let first = zip_of(&[("wrun.sig", b"sig"), ("wrun.toml", valid_manifest().as_bytes())]);
    assert!(matches!(open_err(&first), E::Signed));
    assert!(E::Signed.to_string().contains("newer runtime"));
}

#[test]
fn another_top_level_entry_is_refused() {
    // (`Payload/a` collides with `payload` by case first: the planner's error.)
    for name in ["README.txt", "payloadx/a", "wrun.toml2", "wrun.tom/"] {
        let e = open_err(&with_extra_entry(name));
        assert!(
            matches!(&e, E::Layout(m) if m.contains("outside payload/")),
            "{name}: {e}"
        );
    }
}

#[test]
fn the_files_table_must_equal_the_payload_exactly() {
    // A listed file missing from the archive.
    let mut files = payload();
    let missing = files.pop().unwrap();
    let text = format!("{HEAD}{}", files_toml(&[files.clone(), vec![missing]].concat()))
        .replace("icon = \"payload/app.png\"\n", "");
    let e = open_err(&package_of(&text, &files));
    assert!(matches!(&e, E::Layout(m) if m.contains("not in the archive")), "{e}");
    // An unlisted file.
    let e = open_err(&with_extra_entry("payload/extra.dll"));
    assert!(matches!(&e, E::Layout(m) if m.contains("not listed")), "{e}");
    // A size that differs from the declared one.
    let text = valid_manifest().replace("size = 3000", "size = 2999");
    let e = open_err(&package_of(&text, &payload()));
    assert!(matches!(e, E::Integrity { .. }), "{e}");
}

#[test]
fn a_sha_mismatch_is_found_while_streaming_and_unpack_leaves_nothing() {
    let mut tampered = payload();
    tampered[1].1[100] = 8; // same size, different bytes
    let zip = package_of(&valid_manifest(), &tampered);
    let (t, mut p) = open_bytes(&zip).unwrap(); // sizes agree: open reads no payload
    let e = p.verify().unwrap_err();
    assert!(matches!(&e, E::Integrity { path } if path.contains("data.bin")), "{e}");
    let dest = t.path().join("out");
    let e = p.unpack(&dest).unwrap_err();
    assert!(matches!(e, E::Integrity { .. }), "{e}");
    assert!(!dest.exists(), "unpack left its directory behind");
    let one = t.path().join("one");
    let e = p.extract_one("payload/App/data.bin", &one).unwrap_err();
    assert!(matches!(e, E::Integrity { .. }), "{e}");
    assert!(!one.exists());
}

#[test]
fn unpack_writes_the_manifest_and_the_tree_into_a_new_directory_only() {
    let (t, mut p) = open_bytes(&valid_package()).unwrap();
    let dest = t.path().join("out");
    p.unpack(&dest).unwrap();
    assert_eq!(
        std::fs::read(dest.join("wrun.toml")).unwrap(),
        valid_manifest().as_bytes()
    );
    assert_eq!(
        std::fs::read(dest.join("payload/App/data.bin")).unwrap(),
        vec![7u8; 3000]
    );
    // An existing destination is refused and untouched.
    std::fs::remove_file(dest.join("payload/app.png")).unwrap();
    let e = p.unpack(&dest).unwrap_err();
    assert!(matches!(e, E::Io { .. }), "{e}");
    assert!(dest.join("wrun.toml").exists(), "an existing directory was removed");
}

#[test]
fn extract_one_writes_one_verified_file_0600_and_only_listed_ones() {
    use std::os::unix::fs::PermissionsExt;
    let (t, mut p) = open_bytes(&valid_package()).unwrap();
    let dest = t.path().join("app.exe");
    p.extract_one("payload/App/app.exe", &dest).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"MZ not really a program");
    assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(matches!(p.extract_one("payload/App/app.exe", &dest), Err(E::Io { .. })));
    for path in ["wrun.toml", "payload/App", "payload/nope", "payload/app.exe"] {
        let e = p.extract_one(path, &t.path().join("x")).unwrap_err();
        assert!(matches!(e, E::Layout(_)), "{path}: {e}");
    }
    assert!(!t.path().join("x").exists());
}

// ---------------------------------------------------------------- manifest

#[test]
fn format_2_and_missing_format_are_refused() {
    let m = manifest_err(&valid_manifest().replace("format = 1", "format = 2"));
    assert!(m.contains("format 2"), "{m}");
    let m = manifest_err(&valid_manifest().replace("format = 1\n", ""));
    assert!(m.contains("format"), "{m}");
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    let base = valid_manifest();
    let cases = [
        (format!("scripts = [\"x\"]\n{base}"), "scripts"),
        (format!("{base}\n[signature]\nkey = \"x\"\n"), "signature"),
        (
            base.replace("[permissions]\n", "[permissions]\nfilesystem = \"/\"\n"),
            "filesystem",
        ),
        (base.replace("[entry]\n", "[entry]\nrun = \"x\"\n"), "run"),
        (base.replacen("size = ", "mode = 493\nsize = ", 1), "mode"),
    ];
    for (text, key) in cases {
        let m = manifest_err(&text);
        assert!(m.contains(key), "{key}: {m}");
    }
}

#[test]
fn control_and_format_characters_in_the_name_are_refused_and_never_echoed() {
    for bad in ["\\u001b[31m", "\\u202e", "\\u0000", "\\n", "\\u200b"] {
        let m = manifest_err(&valid_manifest().replace("Example App", &format!("Evil{bad}App")));
        assert!(m.contains("name"), "{m}");
        for c in ['\u{1b}', '\u{202e}', '\0', '\n', '\u{200b}'] {
            assert!(!m.contains(c), "{c:?} echoed in {m:?}");
        }
    }
}

#[test]
fn overlong_and_malformed_fields_are_refused() {
    let v = valid_manifest();
    let deps: Vec<String> = (0..17).map(|i| format!("\"d{i}\"")).collect();
    let cases = [
        v.replace("Example App", &"n".repeat(257)),
        v.replace("\"Example App\"", "\"\""),
        v.replace("1.2.0", &"1".repeat(65)),
        v.replace("1.2.0", "1.2 beta"),
        v.replace("example-app", &"a".repeat(65)),
        v.replace("example-app", "Example"),
        v.replace("example-app", "../x"),
        v.replace("\"x86_64\"", "\"arm64\""),
        v.replace("[\"vcrun2022\"]", &format!("[{}]", deps.join(", "))),
        v.replace("[\"vcrun2022\"]", "[\"a\", \"a\"]"),
        v.replace("[\"vcrun2022\"]", "[\"Bad Id\"]"),
        v.replace("\"allow\"", "\"yes\""),
        v.replace("gpu = \"on\"", "gpu = \"allow\""),
        v.replace("kind = \"portable\"", "kind = \"script\""),
    ];
    for text in cases {
        manifest_err(&text);
    }
    // Text in errors is bounded.
    let m = manifest_err(&v.replace("example-app", &"\u{1b}".repeat(100_000)));
    assert!(m.len() < 1024, "{} bytes", m.len());
}

#[test]
fn bad_hex_is_refused() {
    let v = valid_manifest();
    let sha = hex(&sha256(&[7u8; 3000]));
    for bad in [
        sha.to_uppercase(),
        sha[1..].to_owned(),
        format!("{}g", &sha[1..]),
        String::new(),
    ] {
        let m = manifest_err(&v.replace(&sha, &bad));
        assert!(m.contains("sha256"), "{m}");
    }
}

#[test]
fn entry_paths_must_be_listed_files_below_payload() {
    let v = valid_manifest();
    for exe in [
        "payload/App",
        "payload/App/other.exe",
        "wrun.toml",
        "other/app.exe",
        "payload\\\\App\\\\app.exe",
    ] {
        let m = manifest_err(&v.replace("exe = \"payload/App/app.exe\"", &format!("exe = \"{exe}\"")));
        assert!(m.contains("entry.exe"), "{exe}: {m}");
    }
    for path in [
        "payload/../x",
        "payload/./x",
        "payload//x",
        "payload",
        "x/y",
        "payload/a\\\\b",
    ] {
        let m = manifest_err(
            &format!("{HEAD}{}", files_toml(&payload()))
                .replace("\"payload/app.png\"\nsize", &format!("\"{path}\"\nsize")),
        );
        assert!(m.contains("canonical"), "{path}: {m}");
    }
    let m = manifest_err(&v.replace("icon = \"payload/app.png\"", "icon = \"payload/App/data.bin\""));
    assert!(m.contains(".png"), "{m}");
    let m = manifest_err(&format!("{v}{}", files_toml(&[("payload/app.png", vec![1])])));
    assert!(m.contains("twice"), "{m}");
    let m = manifest_err(HEAD);
    assert!(m.contains("[[files]]"), "{m}");
}

#[test]
fn portable_and_installer_entries_have_their_own_keys() {
    let v = valid_manifest();
    manifest_err(&v.replace("[entry]\n", "[entry]\ninstaller = \"payload/App/app.exe\"\n"));
    manifest_err(&v.replace("[entry]\n", "[entry]\ninstalledExe = \"a.exe\"\n"));
    let setup = vec![("payload/setup.exe", b"MZ setup".to_vec())];
    let head = |entry: &str| {
        format!(
            "format = 1\nid = \"x\"\nname = \"X\"\nversion = \"1\"\narch = \"x86\"\n\n[entry]\nkind = \"installer\"\n{entry}"
        )
    };
    let ok = format!(
        "{}{}",
        head("installer = \"payload/setup.exe\"\ninstalledExe = \"Program Files/X/x.exe\"\n"),
        files_toml(&setup)
    );
    let (_t, mut p) = open_bytes(&package_of(&ok, &setup)).unwrap();
    p.verify().unwrap();
    assert_eq!(
        p.manifest.entry,
        Entry::Installer {
            installer: "payload/setup.exe".into(),
            installed_exe: Some("Program Files/X/x.exe".into())
        }
    );
    // Two payload files.
    let two = [setup.clone(), vec![("payload/readme.txt", b"r".to_vec())]].concat();
    let m = manifest_err(&format!(
        "{}{}",
        head("installer = \"payload/setup.exe\"\n"),
        files_toml(&two)
    ));
    assert!(m.contains("exactly one"), "{m}");
    // An installer entry with `exe`, and an invalid installedExe.
    manifest_err(&format!(
        "{}{}",
        head("installer = \"payload/setup.exe\"\nexe = \"payload/setup.exe\"\n"),
        files_toml(&setup)
    ));
    for bad in ["../x.exe", "C:\\\\x.exe", "a\\u001bb.exe", "con.exe"] {
        let m = manifest_err(&format!(
            "{}{}",
            head(&format!(
                "installer = \"payload/setup.exe\"\ninstalledExe = \"{bad}\"\n"
            )),
            files_toml(&setup)
        ));
        assert!(m.contains("installedExe"), "{bad}: {m}");
    }
}

#[test]
fn requests_exprs_are_canonical_strings_from_the_enums_only() {
    let all = Requests {
        network: Some(false),
        display: Some(true),
        audio: Some(false),
        gpu: Some(true),
    };
    assert_eq!(all.exprs(), ["network=deny", "display=on", "audio=off", "gpu=on"]);
    let all = Requests {
        network: Some(true),
        display: Some(false),
        audio: Some(true),
        gpu: Some(false),
    };
    assert_eq!(all.exprs(), ["network=allow", "display=off", "audio=on", "gpu=off"]);
    assert!(Requests::default().exprs().is_empty());
}

// ---------------------------------------------------------------- name encoding (review M5)

/// The valid package plus one entry whose raw name bytes are `raw` (written under an ASCII placeholder, so the
/// UTF-8 flag is NOT set, then patched in both headers).
fn with_raw_name(raw: &[u8]) -> Vec<u8> {
    let placeholder = format!("payload/{}", "q".repeat(raw.len() - "payload/".len()));
    let mut files = payload();
    files.push((Box::leak(placeholder.clone().into_boxed_str()), b"x".to_vec()));
    rename_everywhere(package_of(&valid_manifest(), &files), placeholder.as_bytes(), raw)
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let e = open_err(&with_raw_name(b"payload/\xff\xfe"));
    assert!(matches!(&e, E::Layout(m) if m.contains("not UTF-8")), "{e}");
}

#[test]
fn utf8_bytes_without_the_utf8_flag_are_an_ambiguous_name() {
    // Read as UTF-8 this is `payload/é`; without the flag the zip crate decodes it as CP437 (`payload/├⌐`).
    let e = open_err(&with_raw_name("payload/é".as_bytes()));
    assert!(
        matches!(&e, E::Layout(m) if m.contains("ambiguous name encoding")),
        "{e}"
    );
    // The same name written WITH the flag (the writer sets it for non-ASCII) is a plain unlisted file.
    let mut files = payload();
    files.push(("payload/é", b"x".to_vec()));
    let e = open_err(&package_of(&valid_manifest(), &files));
    assert!(!e.to_string().contains("ambiguous"), "{e}");
}

#[test]
fn a_unicode_path_extra_field_renames_consistently_or_is_refused() {
    // Info-ZIP 0x7075: the crate replaces BOTH the raw and the decoded name, so the package rules and the planner
    // see one name (`payload/zz`), never two. Here it names a file the manifest does not list: refused.
    let mut crc = flate2::Crc::new();
    crc.update(b"payload/qq");
    let mut field = vec![1u8];
    field.extend_from_slice(&crc.sum().to_le_bytes());
    field.extend_from_slice(b"payload/zz");
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("wrun.toml", stored()).unwrap();
    w.write_all(valid_manifest().as_bytes()).unwrap();
    for (p, d) in payload() {
        w.start_file(p, stored()).unwrap();
        w.write_all(&d).unwrap();
    }
    let mut opts = zip::write::FullFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    // The writer validates a 0x7075 field against the name it does not know yet: write it under an unused id,
    // then patch the id in both headers.
    opts.add_extra_data(0x6666, field, false).unwrap();
    w.start_file("payload/qq", opts).unwrap();
    w.write_all(b"x").unwrap();
    let zip = rename_everywhere(
        w.finish().unwrap().into_inner(),
        b"\x66\x66\x0f\x00",
        b"\x75\x70\x0f\x00",
    );
    let e = open_err(&zip);
    assert!(
        matches!(&e, E::Layout(m) if m.contains("\"payload/zz\" is not listed")),
        "{e}"
    );
}
