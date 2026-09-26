use super::*;
use std::time::{Duration, Instant};

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One archive package with the given id, `requires` and `provides`, as TOML.
fn archive(id: &str, requires: &[&str], provides: &[&str]) -> String {
    format!(
        r#"
[[package]]
id = "{id}"
version = "1.0"
sha256 = "{HASH}"
size = 1024
licence = "Zlib"
url = "https://example.org/{id}.zip"
kind = "archive"
requires_consent = false
requires = {requires:?}
provides = {provides:?}
[package.install]
format = "zip"
extract = [{{ from = "x64/{id}.dll", to = "windows/system32/{id}.dll" }}]
dll_overrides = []
"#
    )
}

/// A valid archive + installer pair with one dependency edge.
fn valid() -> String {
    archive("base", &[], &["base"])
        + &format!(
            r#"
[[package]]
id = "vcrun"
version = "14.40"
sha256 = "{HASH}"
size = 25000000
licence = "proprietary-redistributable"
url = "https://download.example.com/vc_redist.x64.exe"
kind = "installer"
requires_consent = true
requires = ["base"]
provides = ["vcruntime140.dll"]
[package.install]
silent_args = ["/install", "/quiet", "/norestart"]
marker = {{ file = "windows/system32/vcruntime140.dll" }}
"#
        )
}

fn err(text: &str) -> ManifestError {
    Manifest::parse(text).expect_err("manifest should be rejected")
}

/// `valid()` with the first occurrence of `from` replaced by `to`.
fn valid_with(from: &str, to: &str) -> String {
    let v = valid();
    assert!(v.contains(from), "fixture lacks {from:?}");
    v.replacen(from, to, 1)
}

#[test]
fn valid_manifest_parses() {
    let m = Manifest::parse(&valid()).unwrap();
    assert_eq!(m.packages.len(), 2);
    let base = m.get("base").unwrap();
    assert_eq!(base.kind, Kind::Archive);
    assert_eq!(
        base.install,
        Install::Archive {
            format: ArchiveFormat::Zip,
            extract: vec![Extract {
                from: "x64/base.dll".into(),
                to: "windows/system32/base.dll".into()
            }],
            dll_overrides: vec![],
        }
    );
    let vc = m.get("vcrun").unwrap();
    assert_eq!(vc.kind, Kind::Installer);
    assert_eq!(vc.requires, ["base"]);
    assert!(vc.requires_consent);
    assert_eq!(vc.size, 25_000_000);
    assert_eq!(
        vc.install,
        Install::Installer {
            silent_args: vec!["/install".into(), "/quiet".into(), "/norestart".into()],
            marker: Marker::File("windows/system32/vcruntime140.dll".into()),
            dll_overrides: vec![],
        }
    );
    assert!(m.get("missing").is_none());
}

#[test]
fn registry_marker_parses() {
    let text = valid_with(
        r#"marker = { file = "windows/system32/vcruntime140.dll" }"#,
        r#"marker = { registry_value = { key = 'HKLM\Software\Vendor', name = "Version" } }"#,
    );
    let m = Manifest::parse(&text).unwrap();
    let Install::Installer { marker, .. } = &m.get("vcrun").unwrap().install else {
        panic!("installer expected")
    };
    assert_eq!(
        *marker,
        Marker::RegistryValue {
            key: r"HKLM\Software\Vendor".into(),
            name: "Version".into(),
            min_dword: None,
        }
    );
}

#[test]
fn a_registry_marker_may_carry_a_min_dword() {
    let from = r#"marker = { file = "windows/system32/vcruntime140.dll" }"#;
    let m = Manifest::parse(&valid_with(
        from,
        r#"marker = { registry_value = { key = 'HKLM\Software\Vendor', name = "Bld", min_dword = 35211 } }"#,
    ))
    .unwrap();
    let Install::Installer { marker, .. } = &m.get("vcrun").unwrap().install else {
        panic!("installer expected")
    };
    assert_eq!(
        *marker,
        Marker::RegistryValue {
            key: r"HKLM\Software\Vendor".into(),
            name: "Bld".into(),
            min_dword: Some(35211),
        }
    );
    // Not for the default (unnamed) value, which the hive parser only knows as a string.
    let e = err(&valid_with(
        from,
        r#"marker = { registry_value = { key = 'HKLM\Software\Vendor', name = "", min_dword = 1 } }"#,
    ));
    assert!(matches!(e, ManifestError::BadMarker { .. }), "{e:?}");
    // Not negative, not over u32, not on a file marker.
    for bad in [
        r#"marker = { registry_value = { key = 'HKLM\Software\Vendor', name = "Bld", min_dword = -1 } }"#,
        r#"marker = { registry_value = { key = 'HKLM\Software\Vendor', name = "Bld", min_dword = 4294967296 } }"#,
        r#"marker = { file = "a.dll", min_dword = 1 }"#,
    ] {
        assert!(Manifest::parse(&valid_with(from, bad)).is_err(), "{bad}");
    }
}

#[test]
fn empty_manifest_is_valid() {
    assert!(Manifest::parse("").unwrap().packages.is_empty());
}

#[test]
fn unknown_field_rejected() {
    let e = err(&valid_with(
        "requires_consent = false",
        "requires_consent = false\nextra = 1",
    ));
    assert!(matches!(e, ManifestError::UnknownField(_)), "{e:?}");
    let e = err(&format!("schema = 1\n{}", valid()));
    assert!(matches!(e, ManifestError::UnknownField(_)), "{e:?}");
    let e = err(&valid_with("dll_overrides = []", "dll_overrides = []\nsilent = true"));
    assert!(matches!(e, ManifestError::UnknownField(_)), "{e:?}");
    let e = err(&valid_with(
        "to = \"windows/system32/base.dll\" }",
        "to = \"windows/system32/base.dll\", mode = 1 }",
    ));
    assert!(matches!(e, ManifestError::UnknownField(_)), "{e:?}");
    let e = err(&valid_with(
        r#"marker = { file = "windows/system32/vcruntime140.dll" }"#,
        r#"marker = { registry_value = { key = "k", name = "n", kind = "dword" } }"#,
    ));
    assert!(matches!(e, ManifestError::UnknownField(_)), "{e:?}");
}

#[test]
fn malformed_toml_rejected() {
    assert!(matches!(err("[[package]\n"), ManifestError::Toml(_)));
    let e = err(&valid_with("size = 1024", "size = -1"));
    assert!(matches!(e, ManifestError::Toml(_)), "{e:?}");
}

#[test]
fn duplicate_id_rejected() {
    let text = archive("a", &[], &["a1"]) + &archive("a", &[], &["a2"]);
    assert!(matches!(err(&text), ManifestError::DuplicateId(id) if id == "a"));
}

#[test]
fn bad_id_rejected() {
    for id in ["", "A", "-a", ".a", "a b", "a/b", &"a".repeat(65)] {
        let text = archive(id, &[], &["x"]);
        assert!(matches!(err(&text), ManifestError::BadId(_)), "{id:?}");
    }
    Manifest::parse(&archive(&"a".repeat(64), &[], &["x"])).unwrap();
    Manifest::parse(&archive("a0._-z", &[], &["x"])).unwrap();
}

#[test]
fn cycle_rejected() {
    let text = archive("a", &["b"], &["a"]) + &archive("b", &["a"], &["b"]);
    assert!(matches!(err(&text), ManifestError::Cycle(_)));
    let text = archive("a", &["b"], &["a"])
        + &archive("b", &["c"], &["b"])
        + &archive("c", &["a"], &["c"])
        + &archive("d", &[], &["d"]);
    assert!(matches!(err(&text), ManifestError::Cycle(_)));
}

#[test]
fn self_requirement_rejected() {
    let text = archive("a", &["a"], &["a"]);
    assert!(matches!(err(&text), ManifestError::SelfRequire(id) if id == "a"));
}

#[test]
fn diamond_dependency_is_valid() {
    let text = archive("top", &["l", "r"], &["top"])
        + &archive("l", &["bottom"], &["l"])
        + &archive("r", &["bottom"], &["r"])
        + &archive("bottom", &[], &["bottom"]);
    assert_eq!(Manifest::parse(&text).unwrap().packages.len(), 4);
}

#[test]
fn duplicate_require_rejected() {
    let text = archive("a", &["b", "b"], &["a"]) + &archive("b", &[], &["b"]);
    assert!(matches!(err(&text), ManifestError::DuplicateRef { .. }));
}

#[test]
fn unknown_require_rejected() {
    let text = archive("a", &["nope"], &["a"]);
    assert!(matches!(err(&text), ManifestError::UnknownRef { .. }));
}

#[test]
fn http_url_rejected() {
    let e = err(&valid_with(
        "https://example.org/base.zip",
        "http://example.org/base.zip",
    ));
    assert!(matches!(e, ManifestError::BadUrl { .. }), "{e:?}");
}

#[test]
fn malformed_urls_rejected() {
    for url in [
        "https://",
        "https:///path",
        "HTTPS://example.org/a",
        "https://user@example.org/a",
        "https://user:pw@example.org/a",
        "https://exa mple.org/a",
        "https://example.org/a b",
        "https://example.org/a\\tb",
        "https://example.org/\\u0000",
        "https://example.org\\\\evil/a",
        "https://:443/a",
        "https://example.org:/a",
        "https://example.org:44x/a",
        "https://example.org:123456/a",
        "https://example.org/a\\\\b",
        "ftp://example.org/a",
        "file:///etc/passwd",
    ] {
        let e = err(&valid_with("https://example.org/base.zip", url));
        assert!(matches!(e, ManifestError::BadUrl { .. }), "{url:?}: {e:?}");
    }
    let long = format!("https://example.org/{}", "a".repeat(MAX_URL_LEN));
    let e = err(&valid_with("https://example.org/base.zip", &long));
    assert!(matches!(e, ManifestError::BadUrl { .. }), "{e:?}");
    for url in [
        "https://example.org",
        "https://example.org:8443/a?b=c#d",
        "https://a.example.org/x/y.zip",
    ] {
        // On the installer, which has no archive-extension rule.
        Manifest::parse(&valid_with("https://download.example.com/vc_redist.x64.exe", url)).unwrap();
    }
}

#[test]
fn bad_hash_rejected() {
    for bad in [
        &HASH[1..],
        &format!("{HASH}0"),
        &HASH.to_uppercase(),
        &HASH.replacen('0', "g", 1),
        "",
    ] {
        let e = err(&valid_with(HASH, bad));
        assert!(matches!(e, ManifestError::BadHash { .. }), "{bad:?}: {e:?}");
    }
}

#[test]
fn bad_size_rejected() {
    for bad in ["0", &(MAX_PACKAGE_SIZE + 1).to_string()] {
        let e = err(&valid_with("size = 1024", &format!("size = {bad}")));
        assert!(matches!(e, ManifestError::BadSize { .. }), "{bad}: {e:?}");
    }
    Manifest::parse(&valid_with("size = 1024", &format!("size = {MAX_PACKAGE_SIZE}"))).unwrap();
}

#[test]
fn bad_version_and_licence_rejected() {
    for v in ["", "1 0", "1\\n0", &"1".repeat(65)] {
        let e = err(&valid_with("version = \"1.0\"", &format!("version = \"{v}\"")));
        assert!(matches!(e, ManifestError::BadVersion { .. }), "{v:?}: {e:?}");
    }
    for l in ["", "MIT\\u0007", &"M".repeat(65)] {
        let e = err(&valid_with("licence = \"Zlib\"", &format!("licence = \"{l}\"")));
        assert!(matches!(e, ManifestError::BadLicence { .. }), "{l:?}: {e:?}");
    }
}

#[test]
fn extract_to_unsafe_paths_rejected() {
    for to in [
        "/etc/passwd",
        "../x",
        "a/../../x",
        "",
        "a//b",
        "a/",
        "./a",
        "a/.",
        "a/.. /b",
        "a/b.",
        "C:/windows",
        "c:x",
        "a\\\\..\\\\..\\\\x",
        "\\\\\\\\server\\\\share",
        "a\\u0000b",
        &"a".repeat(MAX_PATH_LEN + 1),
    ] {
        let e = err(&valid_with(
            "to = \"windows/system32/base.dll\"",
            &format!("to = \"{to}\""),
        ));
        assert!(matches!(e, ManifestError::BadPath { .. }), "{to:?}: {e:?}");
    }
}

#[test]
fn extract_from_unsafe_paths_rejected() {
    for from in [
        "/x64/base.dll",
        "../base.dll",
        "x64/../../base.dll",
        "",
        "/",
        "x64//",
        "../",
        "x64/./",
    ] {
        let e = err(&valid_with("from = \"x64/base.dll\"", &format!("from = \"{from}\"")));
        assert!(matches!(e, ManifestError::BadPath { .. }), "{from:?}: {e:?}");
    }
}

#[test]
fn extract_from_may_name_a_directory_prefix_with_one_trailing_slash() {
    let m = Manifest::parse(&valid_with("from = \"x64/base.dll\"", "from = \"x64/\"")).unwrap();
    let Install::Archive { extract, .. } = &m.packages[0].install else {
        panic!("not an archive")
    };
    assert_eq!(extract[0].from, "x64/");
}

#[test]
fn marker_file_unsafe_paths_rejected() {
    for p in ["/windows/x.dll", "../x.dll", "C:/x.dll", ""] {
        let e = err(&valid_with(
            "file = \"windows/system32/vcruntime140.dll\"",
            &format!("file = \"{p}\""),
        ));
        assert!(matches!(e, ManifestError::BadPath { .. }), "{p:?}: {e:?}");
    }
}

#[test]
fn bad_registry_marker_rejected() {
    for (key, name) in [
        ("", "Version"),
        ("HKLM\\\\a\\u0000", "Version"),
        ("HKLM\\\\a", "V\\n"),
        (&"k".repeat(MAX_TEXT_LEN + 1), "Version"),
        ("HKLM\\\\a", &"n".repeat(MAX_TEXT_LEN + 1)),
    ] {
        let e = err(&valid_with(
            r#"marker = { file = "windows/system32/vcruntime140.dll" }"#,
            &format!(r#"marker = {{ registry_value = {{ key = "{key}", name = "{name}" }} }}"#),
        ));
        assert!(matches!(e, ManifestError::BadMarker { .. }), "{key:?}: {e:?}");
    }
}

#[test]
fn empty_extract_rejected() {
    let text = valid_with(
        "extract = [{ from = \"x64/base.dll\", to = \"windows/system32/base.dll\" }]",
        "extract = []",
    );
    assert!(matches!(err(&text), ManifestError::BadInstall { .. }));
    let many = vec!["{ from = \"a\", to = \"b\" }"; MAX_LIST_LEN + 1].join(",");
    let text = valid_with(
        "extract = [{ from = \"x64/base.dll\", to = \"windows/system32/base.dll\" }]",
        &format!("extract = [{many}]"),
    );
    assert!(matches!(err(&text), ManifestError::BadInstall { .. }));
}

#[test]
fn kind_install_mismatch_rejected() {
    let marker = r#"marker = { file = "windows/system32/vcruntime140.dll" }"#;
    for (from, to) in [
        // Archive with a marker, or without dll_overrides.
        ("dll_overrides = []", format!("dll_overrides = []\n{marker}")),
        ("dll_overrides = []", String::new()),
        // Installer with archive fields (dll_overrides is shared, see installer_dll_overrides_are_optional...).
        (marker, format!("{marker}\nextract = [{{ from = \"a\", to = \"b\" }}]")),
        // Archive without format, installer with one.
        ("format = \"zip\"\n", String::new()),
        (marker, format!("{marker}\nformat = \"zip\"")),
    ] {
        let e = err(&valid_with(from, &to));
        assert!(matches!(e, ManifestError::BadInstall { .. }), "{to:?}: {e:?}");
    }
    // An archive carrying installer fields.
    let e = err(&valid_with(
        "dll_overrides = []",
        "dll_overrides = []\nsilent_args = []",
    ));
    assert!(matches!(e, ManifestError::BadInstall { .. }), "{e:?}");
    // An installer without its marker.
    let e = err(&valid_with(
        r#"marker = { file = "windows/system32/vcruntime140.dll" }"#,
        "",
    ));
    assert!(matches!(e, ManifestError::BadInstall { .. }), "{e:?}");
    // An archive declared as installer.
    let e = err(&valid_with("kind = \"archive\"", "kind = \"installer\""));
    assert!(matches!(e, ManifestError::BadInstall { .. }), "{e:?}");
    // Unknown kind is a TOML/serde error.
    let e = err(&valid_with("kind = \"archive\"", "kind = \"script\""));
    assert!(matches!(e, ManifestError::Toml(_)), "{e:?}");
}

#[test]
fn bad_silent_args_rejected() {
    for a in ["", "/q\\n", &"q".repeat(MAX_TEXT_LEN + 1)] {
        let e = err(&valid_with("\"/norestart\"", &format!("\"{a}\"")));
        assert!(matches!(e, ManifestError::BadInstall { .. }), "{a:?}: {e:?}");
    }
    let many = vec!["\"/q\""; MAX_LIST_LEN + 1].join(",");
    let e = err(&valid_with(
        r#"silent_args = ["/install", "/quiet", "/norestart"]"#,
        &format!("silent_args = [{many}]"),
    ));
    assert!(matches!(e, ManifestError::BadInstall { .. }), "{e:?}");
}

#[test]
fn duplicate_provides_rejected() {
    let text = archive("a", &[], &["d3d11"]) + &archive("b", &[], &["d3d11"]);
    assert!(matches!(err(&text), ManifestError::DuplicateProvides { .. }));
    let text = archive("a", &[], &["x", "x"]);
    assert!(matches!(err(&text), ManifestError::DuplicateProvides { .. }));
}

#[test]
fn bad_provides_rejected() {
    for name in ["", "D3D11", "a b", "a/b", &"a".repeat(65)] {
        let e = err(&archive("a", &[], &[name]));
        assert!(matches!(e, ManifestError::BadProvides { .. }), "{name:?}: {e:?}");
    }
    let many: Vec<String> = (0..=MAX_LIST_LEN).map(|i| format!("p{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let e = err(&archive("a", &[], &many));
    assert!(matches!(e, ManifestError::BadProvides { .. }), "{e:?}");
}

#[test]
fn dll_override_must_be_provided() {
    let text = valid_with("dll_overrides = []", "dll_overrides = [\"d3d11\"]");
    assert!(matches!(err(&text), ManifestError::BadDllOverride { .. }));
    let ok = valid_with("dll_overrides = []", "dll_overrides = [\"base\"]");
    Manifest::parse(&ok).unwrap();
}

#[test]
fn a_url_naming_a_sha256_must_name_the_packages() {
    let upper = HASH.to_ascii_uppercase();
    let url = |seg: &str| format!(r#"url = "https://download.example.com/pr/{seg}/vc_redist.x64.exe""#);
    let from = r#"url = "https://download.example.com/vc_redist.x64.exe""#;
    // The same hash, in either case, is fine.
    for seg in [HASH, upper.as_str()] {
        Manifest::parse(&valid_with(from, &url(seg))).unwrap();
    }
    // Any other 64-hex segment is not.
    let other = "de".repeat(32);
    let e = err(&valid_with(from, &url(&other)));
    assert!(
        matches!(&e, ManifestError::BadUrl { id, reason, .. } if id == "vcrun" && reason.contains("sha256")),
        "{e:?}"
    );
    // Not 64 hex characters: not a hash, not checked.
    for seg in [&other[..63], &format!("{}x", &other[..63]), &format!("{other}0")] {
        Manifest::parse(&valid_with(from, &url(seg))).unwrap();
    }
}

#[test]
fn installer_dll_overrides_are_optional_and_must_be_provided() {
    let marker = r#"marker = { file = "windows/system32/vcruntime140.dll" }"#;
    let ok = valid_with(marker, &format!("{marker}\ndll_overrides = [\"vcruntime140.dll\"]"));
    let m = Manifest::parse(&ok).unwrap();
    let Install::Installer { dll_overrides, .. } = &m.get("vcrun").unwrap().install else {
        panic!("installer expected")
    };
    assert_eq!(dll_overrides, &["vcruntime140.dll"]);
    let empty = valid_with(marker, &format!("{marker}\ndll_overrides = []"));
    Manifest::parse(&empty).unwrap();
    for name in ["msvcp140", "base"] {
        let bad = valid_with(marker, &format!("{marker}\ndll_overrides = [\"{name}\"]"));
        let e = err(&bad);
        assert!(
            matches!(&e, ManifestError::BadDllOverride { id, .. } if id == "vcrun"),
            "{name}: {e:?}"
        );
    }
}

#[test]
fn oversized_input_rejected() {
    let mut text = valid();
    text.push('#');
    text.push_str(&"x".repeat(MAX_MANIFEST_BYTES - text.len() + 1));
    assert_eq!(text.len(), MAX_MANIFEST_BYTES + 1);
    assert!(matches!(err(&text), ManifestError::TooLarge { .. }));
    // Exactly at the cap is still parsed.
    text.pop();
    Manifest::parse(&text).unwrap();
}

#[test]
fn deeply_nested_input_is_an_error_not_a_crash() {
    let depth = 200_000;
    let text = format!("x = {}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(text.len() <= MAX_MANIFEST_BYTES);
    assert!(matches!(err(&text), ManifestError::Toml(_)));
    let text = format!("x = {}", "{ a = ".repeat(100_000));
    assert!(matches!(err(&text), ManifestError::Toml(_)));
}

#[test]
fn error_messages_are_bounded() {
    let long = "a".repeat(100_000);
    let msgs = [
        err(&archive(&long, &[], &["x"])).to_string(),
        err(&valid_with("requires_consent = false", &format!("{long} = 1"))).to_string(),
        err(&archive("a", &[&long], &["a"])).to_string(),
        err(&valid_with("https://example.org/base.zip", &format!("http://{long}"))).to_string(),
        err(&format!("{long} = ")).to_string(),
    ];
    for m in msgs {
        assert!(m.len() < 512, "{} bytes: {}", m.len(), &m[..200]);
    }
}

#[test]
fn ten_thousand_packages_in_bounded_time() {
    // 10k full packages are ~3 MiB of TOML, above the input cap, so the capped `parse` cannot take them; this
    // exercises the uncapped parse + validate path with a long dependency chain plus fan-in.
    let mut text = String::new();
    for i in 0..10_000 {
        let requires: Vec<String> = match i {
            0 => vec![],
            1 => vec!["p0".into()],
            _ => vec![format!("p{}", i - 1), "p0".into()],
        };
        let requires: Vec<&str> = requires.iter().map(String::as_str).collect();
        text += &archive(&format!("p{i}"), &requires, &[&format!("cap{i}")]);
    }
    let start = Instant::now();
    let m = parse_uncapped(&text).unwrap();
    assert_eq!(m.packages.len(), 10_000);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());

    // A 10k-long cycle is found without recursion.
    let closed = text.replacen("requires = []", "requires = [\"p9999\"]", 1);
    let start = Instant::now();
    assert!(matches!(parse_uncapped(&closed), Err(ManifestError::Cycle(_))));
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
}

#[test]
fn bundled_manifest_invariants() {
    let m = Manifest::bundled();
    assert!(!m.packages.is_empty());
    assert!(std::ptr::eq(m, Manifest::bundled()), "parsed once");
    assert_eq!(*m, Manifest::parse(include_str!("../../packages.toml")).unwrap());
    for p in &m.packages {
        assert!(p.url.starts_with("https://"), "{}", p.id);
        assert!(!p.url["https://".len()..].starts_with('/'), "{}", p.id);
        assert_eq!(p.sha256.len(), 64, "{}", p.id);
        assert!(
            p.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{}",
            p.id
        );
        assert!(p.size > 0 && p.size <= MAX_PACKAGE_SIZE, "{}", p.id);
        assert!(!p.provides.is_empty(), "{}", p.id);
        assert_eq!(
            p.kind,
            match p.install {
                Install::Archive { .. } => Kind::Archive,
                Install::Installer { .. } => Kind::Installer,
            }
        );
        for r in &p.requires {
            assert!(m.get(r).is_some(), "{} requires unknown {r}", p.id);
        }
        if let Install::Archive { format, .. } = p.install {
            let ext = match format {
                ArchiveFormat::Zip => ".zip",
                ArchiveFormat::TarGz => ".tar.gz",
                ArchiveFormat::TarZst => ".tar.zst",
            };
            assert!(p.url.ends_with(ext), "{}", p.id);
        }
        if p.licence == PROPRIETARY {
            assert!(p.requires_consent, "{}", p.id);
        }
    }
}

/// Phase 4F: Wine Mono is the `dotnet` provider, a plain MSI installer confirmed by a file the MSI lays down.
#[test]
fn bundled_wine_mono_entry() {
    let p = Manifest::bundled().get("wine-mono").expect("wine-mono is bundled");
    assert_eq!((p.version.as_str(), p.kind), ("9.4.0", Kind::Installer));
    assert_eq!(p.provides, ["dotnet"]);
    assert!(p.requires.is_empty() && !p.requires_consent && p.min_vulkan.is_none());
    assert!(p.url.ends_with("/wine-mono-9.4.0-x86.msi"), "{}", p.url);
    let Install::Installer {
        silent_args,
        marker,
        dll_overrides,
    } = &p.install
    else {
        panic!("not an installer")
    };
    assert_eq!(silent_args, &["/qn"]);
    assert_eq!(
        marker,
        &Marker::File("windows/mono/mono-2.0/bin/libmono-2.0-x86_64.dll".into())
    );
    assert!(dll_overrides.is_empty());
}

/// Task 8: only verified pins ship. A placeholder (size 1, a hash made of one repeated digit or zeros plus a short
/// counter, a PLACEHOLDER comment, an unversioned aka.ms redirect) fails this.
#[test]
fn bundled_manifest_has_no_placeholder_pins() {
    let text = include_str!("../../packages.toml");
    assert!(!text.contains("PLACEHOLDER"), "placeholder comment in packages.toml");
    for p in &Manifest::bundled().packages {
        assert!(p.size > 1024, "{}: size {} looks like a placeholder", p.id, p.size);
        let distinct: HashSet<u8> = p.sha256.bytes().collect();
        assert!(distinct.len() > 4, "{}: sha256 {} looks synthetic", p.id, p.sha256);
        assert!(
            !p.sha256.starts_with("00000000"),
            "{}: sha256 {} looks synthetic",
            p.id,
            p.sha256
        );
        assert!(
            !repeats_short_unit(&p.sha256),
            "{}: sha256 {} is a repeated pattern",
            p.id,
            p.sha256
        );
        assert!(
            !p.url.contains("aka.ms/"),
            "{}: pin the final url, not a redirect",
            p.id
        );
    }
}

/// `s` is one unit of at most 8 characters repeated (`deadbeef` x 8, `ab` x 32, ...), possibly cut short.
fn repeats_short_unit(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=8).any(|n| b.iter().enumerate().all(|(i, c)| *c == b[i % n]))
}

#[test]
fn repeated_short_units_are_recognised() {
    for yes in [
        "deadbeef".repeat(8),
        "ab".repeat(32),
        "0".repeat(64),
        "abcdefg".repeat(10)[..64].to_owned(),
    ] {
        assert!(repeats_short_unit(&yes), "{yes}");
    }
    assert!(!repeats_short_unit(
        "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b"
    ));
    assert!(!repeats_short_unit(&("abcdefgh".repeat(7) + "abcdefg0")));
    assert!(!repeats_short_unit(&"abcdefghi".repeat(8)[..64]));
}

/// Deterministic xorshift64 so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn mutated_manifests_never_panic() {
    let seed = valid().into_bytes();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0;
    for i in 0..10_000 {
        let mut b = seed.clone();
        for _ in 0..1 + rng.below(8) {
            match rng.below(5) {
                0 => {
                    let at = rng.below(b.len());
                    b[at] ^= 1 << rng.below(8);
                }
                1 => {
                    let at = rng.below(b.len());
                    b[at] = rng.next() as u8;
                }
                2 => b.truncate(rng.below(b.len() + 1)),
                3 => {
                    let start = rng.below(b.len());
                    let end = (start + rng.below(64)).min(b.len());
                    let chunk = b[start..end].to_vec();
                    let at = rng.below(b.len() + 1);
                    b.splice(at..at, chunk);
                }
                _ => {
                    if !b.is_empty() {
                        b.remove(rng.below(b.len()));
                    }
                }
            }
            if b.is_empty() {
                break;
            }
        }
        let text = String::from_utf8_lossy(&b).into_owned();
        let r = std::panic::catch_unwind(|| Manifest::parse(&text));
        assert!(r.is_ok(), "iteration {i} panicked on {text:?}");
        if let Ok(Ok(_)) = r {
            accepted += 1;
        }
    }
    // Some mutations (inside comments or benign value changes) must still pass, others must fail.
    assert!(accepted > 0 && accepted < 10_000, "accepted {accepted}");
}

#[test]
fn proprietary_licence_needs_consent() {
    // `valid()`'s installer is proprietary with consent: accepted.
    Manifest::parse(&valid()).unwrap();
    // Permissive without consent: accepted (the archive in `valid()`).
    assert!(!Manifest::parse(&valid()).unwrap().get("base").unwrap().requires_consent);
    let text = valid_with("requires_consent = true", "requires_consent = false");
    assert!(matches!(err(&text), ManifestError::BadConsent(id) if id == "vcrun"));
}

#[test]
fn licence_charset_restricted() {
    for l in ["MIT OR Apache-2.0", "(MIT OR Apache-2.0)", "LGPL-2.1+", "Zlib"] {
        Manifest::parse(&valid_with("licence = \"Zlib\"", &format!("licence = \"{l}\""))).unwrap();
    }
    for l in ["MIT; rm", "MIT/BSD", "<b>MIT</b>", "MIT\\u00e9", "MIT_1", "'MIT'"] {
        let e = err(&valid_with("licence = \"Zlib\"", &format!("licence = \"{l}\"")));
        assert!(matches!(e, ManifestError::BadLicence { .. }), "{l:?}: {e:?}");
    }
}

#[test]
fn archive_format_parsed_and_checked() {
    let text = valid_with("format = \"zip\"", "format = \"tar.gz\"").replacen(
        "example.org/base.zip",
        "example.org/base.tar.gz",
        1,
    );
    let m = Manifest::parse(&text).unwrap();
    assert!(matches!(
        m.get("base").unwrap().install,
        Install::Archive {
            format: ArchiveFormat::TarGz,
            ..
        }
    ));
    let tgz = text.replacen("base.tar.gz", "base.TGZ?x=1#y", 1);
    Manifest::parse(&tgz).unwrap();
    Manifest::parse(&valid_with("base.zip", "base.zip?v=1")).unwrap();
    let zst = valid_with("format = \"zip\"", "format = \"tar.zst\"").replacen(
        "example.org/base.zip",
        "example.org/base.tar.zst",
        1,
    );
    assert!(matches!(
        Manifest::parse(&zst).unwrap().get("base").unwrap().install,
        Install::Archive {
            format: ArchiveFormat::TarZst,
            ..
        }
    ));

    for f in ["tar.zstd", "tzst", "TAR.ZST", "ZIP", "tar", "", "7z"] {
        let e = err(&valid_with("format = \"zip\"", &format!("format = \"{f}\"")));
        assert!(matches!(e, ManifestError::UnsupportedFormat { .. }), "{f:?}: {e:?}");
    }
    // Url extension disagreeing with the format.
    for (fmt, url) in [
        ("zip", "https://example.org/base.tar.gz"),
        ("zip", "https://example.org/base"),
        ("zip", "https://example.org/base.zip.exe"),
        ("zip", "https://example.org/x?f=base.zip"),
        ("tar.gz", "https://example.org/base.zip"),
        ("tar.gz", "https://example.org/base.tar.zst"),
        ("tar.gz", "https://example.org/base.gz"),
        ("tar.zst", "https://example.org/base.tar.gz"),
        ("tar.zst", "https://example.org/base.zst"),
        ("zip", "https://example.org/base.tar.zst"),
    ] {
        let text = valid_with("format = \"zip\"", &format!("format = \"{fmt}\"")).replacen(
            "https://example.org/base.zip",
            url,
            1,
        );
        let e = err(&text);
        assert!(matches!(e, ManifestError::FormatMismatch { .. }), "{fmt} {url}: {e:?}");
    }
}

/// An archive package extracting to each of `to`.
fn archive_to(id: &str, to: &[&str]) -> String {
    let extract: Vec<String> = to.iter().map(|t| format!("{{ from = \"f\", to = \"{t}\" }}")).collect();
    archive(id, &[], &[&format!("{id}-cap")]).replacen(
        &format!("extract = [{{ from = \"x64/{id}.dll\", to = \"windows/system32/{id}.dll\" }}]"),
        &format!("extract = [{}]", extract.join(",")),
        1,
    )
}

#[test]
fn duplicate_destinations_rejected() {
    let dup = |text: &str| matches!(err(text), ManifestError::DuplicateDestination { .. });
    assert!(dup(&archive_to("a", &["w/x.dll", "w/x.dll"])), "same package");
    assert!(
        dup(&(archive_to("a", &["w/x.dll"]) + &archive_to("b", &["w/x.dll"]))),
        "cross package"
    );
    assert!(
        dup(&(archive_to("a", &["Windows/X.dll"]) + &archive_to("b", &["windows/x.DLL"]))),
        "case only"
    );
    // Extract target vs installer marker (valid()'s marker is windows/system32/vcruntime140.dll).
    let text = valid() + &archive_to("c", &["WINDOWS/system32/vcruntime140.dll"]);
    assert!(dup(&text), "extract vs marker");
}

#[test]
fn overlapping_destinations_rejected() {
    let overlap = |text: &str| matches!(err(text), ManifestError::OverlappingDestination { .. });
    assert!(overlap(&archive_to("a", &["w", "w/x.dll"])), "file then child");
    assert!(
        overlap(&archive_to("a", &["w/x.dll", "W"])),
        "child then ancestor, case-folded"
    );
    assert!(
        overlap(&(archive_to("a", &["w/s/x.dll"]) + &archive_to("b", &["w/s"]))),
        "cross package"
    );
    assert!(
        overlap(&(archive_to("a", &["w/s"]) + &archive_to("b", &["w/S/x.dll"]))),
        "cross package, reversed"
    );
}

#[test]
fn distinct_destinations_accepted() {
    let text = archive_to("a", &["w/s/x.dll", "w/s/y.dll", "w/sx", "w/s.dll"])
        + &archive_to("b", &["w/s/xy.dll", "w/x.dll", "ws/x.dll"]);
    assert_eq!(Manifest::parse(&text).unwrap().packages.len(), 2);
}

/// One archive package `p` whose `min_vulkan` line is `line` (none if empty).
fn with_min_vulkan(line: &str) -> String {
    archive("p", &[], &["p"]).replacen(
        "requires_consent = false",
        &format!("requires_consent = false\n{line}"),
        1,
    )
}

#[test]
fn min_vulkan_parses_major_dot_minor() {
    let m = Manifest::parse(&with_min_vulkan("min_vulkan = \"1.3\"")).unwrap();
    assert_eq!(m.get("p").unwrap().min_vulkan, Some((1, 3)));
    assert_eq!(m.max_min_vulkan(), Some((1, 3)));
}

#[test]
fn min_vulkan_rejects_junk() {
    for v in [
        "1",
        "1.3.0",
        "a.b",
        "",
        "1.99999999999",
        "-1.3",
        "1. 3",
        "+1.3",
        "1.",
        ".3",
        "12345.1",
        "1.3\n",
        "1.3\t",
    ] {
        let e = err(&with_min_vulkan(&format!("min_vulkan = {v:?}")));
        assert!(matches!(e, ManifestError::BadMinVulkan { .. }), "{v}: {e:?}");
    }
}

#[test]
fn min_vulkan_is_optional() {
    let m = Manifest::parse(&with_min_vulkan("")).unwrap();
    assert_eq!(m.get("p").unwrap().min_vulkan, None);
    assert_eq!(m.max_min_vulkan(), None);
}
