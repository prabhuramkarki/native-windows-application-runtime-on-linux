use super::*;
use crate::testutil::*;
use std::os::unix::fs::{MetadataExt, symlink};

struct Opened {
    _tmp: tempfile::TempDir,
    archive: Archive,
    plan: Plan,
}

fn open_with(bytes: &[u8], limits: &Limits) -> Result<Opened, ZipError> {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_file(tmp.path(), "in.zip", bytes);
    let (archive, plan) = open(File::open(path).unwrap(), limits)?;
    Ok(Opened {
        _tmp: tmp,
        archive,
        plan,
    })
}

fn open_default(bytes: &[u8]) -> Result<Opened, ZipError> {
    open_with(bytes, &Limits::default())
}

fn expect_err(bytes: &[u8]) -> ZipError {
    match open_default(bytes) {
        Ok(_) => panic!("archive was accepted"),
        Err(e) => e,
    }
}

fn dest() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("dest");
    fs::create_dir(&dest).unwrap();
    (tmp, dest)
}

use std::fs;

// ---------------------------------------------------------------- names

#[test]
fn entry_names_are_normalised_the_windows_way() {
    let table: [(&str, &[&str]); 9] = [
        ("a/b.txt", &["a", "b.txt"]),
        ("a\\b.txt", &["a", "b.txt"]),
        ("a/./b", &["a", "b"]),
        ("dir/", &["dir"]),
        ("dir\\", &["dir"]),
        ("A/B", &["A", "B"]),
        ("caf\u{e9}/\u{4e2d}\u{6587}.txt", &["caf\u{e9}", "\u{4e2d}\u{6587}.txt"]),
        ("a b/c d.exe", &["a b", "c d.exe"]),
        ("./a", &["a"]),
    ];
    for (name, want) in table {
        assert_eq!(entry_path(name).unwrap(), want, "{name:?}");
    }
}

fn hostile_names() -> Vec<String> {
    let mut v: Vec<String> = [
        "../evil",
        "/abs",
        "/etc/passwd",
        "C:\\x",
        "C:/x",
        "C:foo",
        "a/../../b",
        "..\\..\\x",
        "..",
        "../",
        "a/..",
        "a/b/..",
        ".",
        "./",
        "",
        "/",
        "\\",
        "a\0b",
        "\0",
        "\\\\srv\\x",
        "//srv/x",
        "\\\\?\\unix\\etc\\x",
        "\\\\.\\pipe\\x",
        "\\??\\C:\\x",
        "a:b",
        "a/b:stream",
        "con.txt",
        "CON",
        "a/nul",
        "com1",
        "x/LPT9.log",
        "aux.tar.gz",
        "trail.",
        "trail ",
        "a/trail./b",
        "a// b",
        "a//b",
        "a//",
        "...",
        "a/ /b",
        "a\x1bb",
        "a\nb",
        "a<b",
        "a>b",
        "a|b",
        "a?b",
        "a*b",
        "a\"b",
        "\u{9b}x",
    ]
    .map(String::from)
    .to_vec();
    v.push(["x/"; 129].concat()); // 129 components
    v.push("a".repeat(256)); // component too long
    v
}

#[test]
fn empty_and_root_names_have_their_own_errors() {
    for name in ["", "/", "\\"] {
        assert_eq!(entry_path(name), Err(NameError::Empty), "{name:?}");
    }
    for name in [".", "./", ".\\", "././"] {
        assert_eq!(entry_path(name), Err(NameError::Root), "{name:?}");
    }
}

#[test]
fn every_hostile_entry_name_is_refused_by_entry_path() {
    for name in hostile_names() {
        let shown: String = name.chars().take(30).collect();
        assert!(entry_path(&name).is_err(), "accepted {shown:?}");
    }
    assert!(
        entry_path(["d/"; 128].concat().trim_end_matches('/')).is_ok(),
        "128 components is the limit"
    );
}

#[test]
fn every_hostile_entry_name_is_refused_when_opening_an_archive() {
    for name in hostile_names() {
        let zip = raw_zip(&[Raw::file("ok.txt", b"x"), Raw::file(&name, b"evil")]);
        let shown: String = name.chars().take(30).collect();
        match open_default(&zip) {
            Err(ZipError::BadName { name: q, .. }) => {
                assert!(q.chars().count() <= 130, "quoted name is {} chars", q.chars().count());
                assert!(
                    !q.contains(['\0', '\n', '\x1b']),
                    "unescaped control character in {q:?}"
                );
            }
            Err(other) => panic!("{shown:?}: unexpected error {other}"),
            Ok(_) => panic!("{shown:?} was accepted"),
        }
    }
}

// ---------------------------------------------------------------- planning

#[test]
fn plan_lists_files_and_implied_directories_parents_first() {
    let zip = raw_zip(&[
        Raw::dir("explicit/"),
        Raw::file("explicit/a.txt", b"a"),
        Raw::file("implied/deep/b.txt", b"b"),
        Raw::file("top.txt", b"t"),
    ]);
    let o = open_default(&zip).unwrap();
    let dirs: Vec<String> = o.plan.dirs.iter().map(|d| d.join("/")).collect();
    assert_eq!(dirs, ["explicit", "implied", "implied/deep"]);
    let files: Vec<String> = o.plan.files.iter().map(|f| f.path.join("/")).collect();
    assert_eq!(files, ["explicit/a.txt", "implied/deep/b.txt", "top.txt"]);
    assert_eq!(o.plan.skipped, 0);
}

#[test]
fn a_dir_entry_after_its_children_is_fine_but_twice_is_a_duplicate() {
    open_default(&raw_zip(&[Raw::file("a/b", b"x"), Raw::dir("a/")])).unwrap();
    let err = expect_err(&raw_zip(&[Raw::dir("a/"), Raw::dir("./a/")]));
    assert!(matches!(err, ZipError::Duplicate { .. }), "{err}");
}

#[test]
fn extraction_writes_the_planned_tree_with_fixed_permissions() {
    let zip = raw_zip(&[
        Raw::dir("d/").mode(S_IFDIR | 0o777),
        Raw::file("d/a.txt", b"hello").mode(S_IFREG | 0o4755),
        Raw::deflated("d/e/b.bin", &[7u8; 5000]).mode(S_IFREG | 0o2777),
        Raw::file("plain.txt", b"").mode(0o7777), // no file type bits at all
    ]);
    let mut o = open_default(&zip).unwrap();
    let (_t, dest) = dest();
    let n = extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap();
    assert_eq!(n, 5 + 5000);
    assert_eq!(fs::read(dest.join("d/a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(dest.join("d/e/b.bin")).unwrap(), vec![7u8; 5000]);
    for f in ["d/a.txt", "d/e/b.bin", "plain.txt"] {
        let m = fs::metadata(dest.join(f)).unwrap().mode();
        assert_eq!(m & 0o7000, 0, "{f}: setuid/setgid/sticky bit preserved ({m:o})");
        assert_eq!(m & 0o111, 0, "{f}: exec bit preserved ({m:o})");
        assert_eq!(m & !0o644 & 0o7777, 0, "{f}: more than 0644 ({m:o})");
    }
    for d in ["d", "d/e"] {
        let m = fs::metadata(dest.join(d)).unwrap().mode();
        assert_eq!(m & 0o7777 & !0o755, 0, "{d}: more than 0755 ({m:o})");
    }
}

#[test]
fn symlink_device_fifo_and_socket_entries_are_skipped_and_counted() {
    let zip = raw_zip(&[
        Raw::file("real.txt", b"r"),
        Raw::special("link", S_IFLNK | 0o777, b"/etc/passwd"),
        Raw::special("dir/link", S_IFLNK | 0o777, b"../../x"),
        Raw::special("fifo", S_IFIFO | 0o644, b""),
        Raw::special("chr", S_IFCHR | 0o666, b""),
        Raw::special("blk", 0o060_666, b""),
        Raw::special("sock", 0o140_666, b""),
    ]);
    let mut o = open_default(&zip).unwrap();
    assert_eq!(o.plan.skipped, 6);
    assert_eq!(o.plan.files.len(), 1);
    assert!(
        o.plan.dirs.is_empty(),
        "a skipped entry must not create its parent directory"
    );
    let (_t, dest) = dest();
    extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap();
    assert_eq!(tree(&dest), ["real.txt"]);
}

#[test]
fn a_skipped_symlink_entry_does_not_hide_a_hostile_name() {
    let zip = raw_zip(&[Raw::special("../evil", S_IFLNK | 0o777, b"/etc")]);
    assert!(matches!(expect_err(&zip), ZipError::BadName { .. }));
}

#[test]
fn encrypted_entries_are_refused() {
    for flags in [1u16, 1 | 0x40, 1 | 8] {
        let zip = raw_zip(&[Raw::file("secret.txt", b"xxxxxxxxxxxx").flags(flags)]);
        assert!(
            matches!(expect_err(&zip), ZipError::Encrypted { .. }),
            "flags {flags:#x}"
        );
    }
}

#[test]
fn unsupported_compression_methods_are_refused() {
    for method in [1u16, 6, 9, 12, 14, 93, 95, 98] {
        let zip = raw_zip(&[Raw::file("a.txt", b"data").method(method)]);
        assert!(
            matches!(expect_err(&zip), ZipError::Unsupported { .. }),
            "method {method}"
        );
    }
    // Method 99 is AES: the crate itself refuses it (no AES extra field) with a format error.
    let zip = raw_zip(&[Raw::file("a.txt", b"data").method(99)]);
    assert!(matches!(expect_err(&zip), ZipError::Format(m) if m.contains("AES")));
}

#[test]
fn names_that_differ_only_by_case_collide() {
    let cases = [
        vec![Raw::file("A.exe", b"1"), Raw::file("a.exe", b"2")],
        vec![Raw::file("A/x", b"1"), Raw::file("a/y", b"2")],
        vec![Raw::dir("Data/"), Raw::file("data/x", b"2")],
        vec![Raw::file("a/B", b"1"), Raw::file("A/c", b"2")],
        vec![Raw::file("\u{c9}.txt", b"1"), Raw::file("\u{e9}.txt", b"2")],
    ];
    for entries in cases {
        let err = expect_err(&raw_zip(&entries));
        assert!(matches!(err, ZipError::CaseCollision { .. }), "{err}");
    }
}

#[test]
fn a_name_that_is_both_a_file_and_a_directory_is_refused() {
    let cases = [
        vec![Raw::file("a", b"1"), Raw::file("a/b", b"2")],
        vec![Raw::file("a/b", b"2"), Raw::file("a", b"1")],
        vec![Raw::dir("a/"), Raw::file("a", b"1")],
        vec![Raw::file("a", b"1"), Raw::dir("a/")],
        vec![Raw::file("x/a", b"1"), Raw::file("x/a/b/c", b"2")],
    ];
    for entries in cases {
        let err = expect_err(&raw_zip(&entries));
        assert!(matches!(err, ZipError::TypeConflict { .. }), "{err}");
    }
}

/// `replace` for a same-length replacement everywhere in the archive (local header and central directory).
fn rename_everywhere(mut zip: Vec<u8>, from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let mut i = 0;
    while i + from.len() <= zip.len() {
        if &zip[i..i + from.len()] == from {
            zip[i..i + to.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
    zip
}

#[test]
fn identical_names_are_refused_not_silently_collapsed() {
    // The `zip` crate would keep only the last of two identical names; the end record still says 2.
    let zip = raw_zip(&[Raw::file("aaaaaa.exe", b"one"), Raw::file("bbbbbb.exe", b"two")]);
    let zip = rename_everywhere(zip, b"bbbbbb.exe", b"aaaaaa.exe");
    let err = expect_err(&zip);
    assert!(
        matches!(
            err,
            ZipError::DuplicateNames {
                declared: 2,
                distinct: 1
            }
        ),
        "{err}"
    );
    // Same canonical name through two spellings.
    let err = expect_err(&raw_zip(&[Raw::file("a/x", b"1"), Raw::file("./a/x", b"2")]));
    assert!(matches!(err, ZipError::Duplicate { .. }), "{err}");
    let err = expect_err(&raw_zip(&[Raw::file("a/x", b"1"), Raw::file("a\\x", b"2")]));
    assert!(matches!(err, ZipError::Duplicate { .. }), "{err}");
}

// ---------------------------------------------------------------- caps

#[test]
fn a_central_directory_declaring_huge_sizes_is_refused_without_reading_data() {
    // 10 bytes stored, but both headers claim 3.75 GiB (just under the per-entry cap): a bomb by ratio.
    let bomb = Raw::file("big.bin", b"0123456789").declared(0xF000_0000);
    let err = expect_err(&raw_zip(&[bomb]));
    assert!(
        matches!(
            err,
            ZipError::Ratio {
                size: 0xF000_0000,
                compressed: 10,
                ..
            }
        ),
        "{err}"
    );
    // Same with a deflated entry claiming 2 GiB from a few bytes.
    let bomb = Raw::deflated("big.bin", b"abc").declared(0x8000_0000);
    let err = expect_err(&raw_zip(&[bomb]));
    assert!(matches!(err, ZipError::Ratio { .. }), "{err}");
}

#[test]
fn the_declared_size_caps_are_per_entry_and_in_total() {
    let two = raw_zip(&[Raw::file("a", &[1u8; 600]), Raw::file("b", &[2u8; 600])]);
    let tight = Limits {
        max_total_bytes: 1000,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(&two, &tight),
        Err(ZipError::TotalTooLarge { max: 1000 })
    ));
    let ok = Limits {
        max_total_bytes: 1200,
        ..Limits::default()
    };
    open_with(&two, &ok).unwrap();
    let per_entry = Limits {
        max_entry_bytes: 500,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(&two, &per_entry),
        Err(ZipError::EntryTooLarge {
            size: 600,
            max: 500,
            ..
        })
    ));
    // Directories declare nothing that counts.
    open_with(&raw_zip(&[Raw::dir("d/").declared(u32::MAX as u64 - 1)]), &tight).unwrap();
}

#[test]
fn the_ratio_guard_applies_above_the_floor_only() {
    let zeros = Raw::deflated("z.bin", &[0u8; 2000]); // about 2000:1
    let guarded = Limits {
        ratio_floor: 1000,
        max_ratio: 10,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(&raw_zip(&[zeros]), &guarded),
        Err(ZipError::Ratio { max: 10, .. })
    ));
    let small = Raw::deflated("z.bin", &[0u8; 1000]); // not over the floor
    open_with(&raw_zip(&[small]), &guarded).unwrap();
    // Just at the ratio is accepted, over it is not.
    let e = Raw::file("s", &[9u8; 1500]).declared(1500);
    let compressed = e.data.len() as u64;
    let at = Limits {
        ratio_floor: 0,
        max_ratio: 1500 / compressed,
        ..Limits::default()
    };
    open_with(&raw_zip(&[e]), &at).unwrap();
}

#[test]
fn a_real_300_mib_zero_entry_is_a_bomb_by_the_ratio_guard() {
    let data = deflated_zeros(300 << 20);
    let ratio = (300u64 << 20) / data.len() as u64;
    assert!(
        ratio > 1000,
        "test data compresses only {ratio}:1, cannot exercise the guard"
    );
    let entry = Raw {
        method: 8,
        data,
        declared_size: 300 << 20,
        crc: 0,
        ..Raw::file("zeros.bin", b"")
    };
    let err = expect_err(&raw_zip(&[entry]));
    assert!(matches!(err, ZipError::Ratio { max: 1000, .. }), "{err}");
}

#[test]
fn a_real_300_mib_zero_entry_is_bounded_by_the_byte_cap_when_the_ratio_guard_is_off() {
    let data = deflated_zeros(300 << 20);
    let entry = Raw {
        method: 8,
        data,
        declared_size: 300 << 20,
        crc: 0,
        ..Raw::file("zeros.bin", b"")
    };
    let zip = raw_zip(&[entry]);
    let no_ratio = Limits {
        max_ratio: u64::MAX,
        ..Limits::default()
    };
    let mut o = open_with(&zip, &no_ratio).unwrap();
    let (_t, dest) = dest();
    let cap = 16 << 20;
    let tight = Limits {
        max_total_bytes: cap,
        ..no_ratio
    };
    let err = extract(&mut o.archive, &o.plan, &dest, &tight).unwrap_err();
    assert!(matches!(err, ZipError::ExtractedTooMuch { .. }), "{err}");
    let on_disk = fs::metadata(dest.join("zeros.bin")).unwrap().len();
    assert!(on_disk <= cap, "{on_disk} bytes written, cap {cap}");
}

#[test]
fn the_entry_count_cap_is_20_000() {
    let many = |n: usize| -> Vec<u8> {
        let entries: Vec<Raw> = (0..n).map(|i| Raw::file(&format!("f{i}"), b"")).collect();
        raw_zip(&entries)
    };
    let o = open_default(&many(20_000)).unwrap();
    assert_eq!(o.plan.files.len(), 20_000);
    let err = expect_err(&many(20_001));
    assert!(matches!(err, ZipError::TooManyEntries { max: 20_000 }), "{err}");
}

#[test]
fn the_entry_count_is_checked_from_the_end_record_before_the_directory_is_parsed() {
    let mut zip = raw_zip(&[Raw::file("a", b"1")]);
    let end = zip.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
    for at in [end + 8, end + 10] {
        zip[at..at + 2].copy_from_slice(&60_000u16.to_le_bytes());
    }
    let err = expect_err(&zip);
    assert!(matches!(err, ZipError::TooManyEntries { .. }), "{err}");
}

#[test]
fn zip64_end_records_are_read_for_the_entry_count() {
    let base = raw_zip(&[Raw::file("a", b"1"), Raw::file("b", b"2"), Raw::file("c", b"3")]);
    // A zip64 archive whose record states the real count is accepted.
    let o = open_default(&to_zip64(base.clone(), 3)).unwrap();
    assert_eq!(o.plan.files.len(), 3);
    // One that states a huge count is refused from the record, before the directory is parsed.
    for lie in [20_001u64, 1 << 40, u64::MAX] {
        let err = expect_err(&to_zip64(base.clone(), lie));
        assert!(matches!(err, ZipError::TooManyEntries { max: 20_000 }), "{lie}: {err}");
    }
    // A sentinel without the zip64 record behind it is refused by the strict pre-validation (this assertion said
    // `Format(_)` when the end record was only read for its count).
    let mut broken = base;
    let end = broken.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
    for at in [end + 8, end + 10] {
        broken[at..at + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    }
    assert!(matches!(expect_err(&broken), ZipError::Layout(Layout::Zip64)));
}

#[test]
fn the_directory_count_and_depth_are_capped() {
    let deep = raw_zip(&[Raw::file("a/b/c/d/x", b"1")]);
    let few = Limits {
        max_dirs: 3,
        ..Limits::default()
    };
    assert!(matches!(open_with(&deep, &few), Err(ZipError::TooManyDirs { max: 3 })));
    let name = |n: usize| (0..n).map(|_| "d").collect::<Vec<_>>().join("/");
    open_default(&raw_zip(&[Raw::file(&name(128), b"1")])).unwrap();
    assert!(matches!(
        expect_err(&raw_zip(&[Raw::file(&name(129), b"1")])),
        ZipError::BadName { .. }
    ));
}

// ---------------------------------------------------------------- streaming guards

#[test]
fn an_entry_that_holds_more_than_its_declared_size_is_stopped() {
    // Declared 1000 bytes, 5000 stored: the central directory lies.
    let zip = raw_zip(&[Raw::file("liar.bin", &[3u8; 5000]).declared(1000)]);
    let mut o = open_default(&zip).unwrap();
    let (_t, dest) = dest();
    let err = extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap_err();
    assert!(matches!(err, ZipError::LiesAboutSize { .. }), "{err}");
    let on_disk = fs::metadata(dest.join("liar.bin")).unwrap().len();
    assert!(on_disk <= 1000, "{on_disk} bytes written for a 1000 byte declaration");
}

#[test]
fn a_deflated_entry_that_inflates_past_its_declaration_is_stopped() {
    let plain = vec![0u8; 200_000];
    let entry = Raw {
        method: 8,
        data: deflate(&plain, flate2::Compression::best()),
        declared_size: 1024,
        crc: crc32(&plain),
        ..Raw::file("liar.bin", b"")
    };
    let mut o = open_default(&raw_zip(&[entry])).unwrap();
    let (_t, dest) = dest();
    let err = extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap_err();
    // Either our take(declared + 1) guard or the crate's own size check stops it: never 200 000 bytes on disk.
    let on_disk = fs::metadata(dest.join("liar.bin")).unwrap().len();
    assert!(
        on_disk <= 1024,
        "{on_disk} bytes written for a 1024 byte declaration ({err})"
    );
}

#[test]
fn an_entry_shorter_than_declared_is_an_error() {
    let zip = raw_zip(&[Raw::file("short.bin", &[3u8; 100]).declared(5000)]);
    let mut o = open_default(&zip).unwrap();
    let (_t, dest) = dest();
    assert!(extract(&mut o.archive, &o.plan, &dest, &Limits::default()).is_err());
}

#[test]
fn the_bytes_actually_written_are_counted_against_the_total_cap() {
    // The plan passed under the default limits; extraction is run with a tighter total: the streaming check trips.
    let zip = raw_zip(&[Raw::file("a", &[1u8; 700]), Raw::file("b", &[2u8; 700])]);
    let mut o = open_default(&zip).unwrap();
    let (_t, dest) = dest();
    let tight = Limits {
        max_total_bytes: 1000,
        ..Limits::default()
    };
    let err = extract(&mut o.archive, &o.plan, &dest, &tight).unwrap_err();
    assert!(matches!(err, ZipError::ExtractedTooMuch { max: 1000 }), "{err}");
    let on_disk: u64 = ["a", "b"]
        .iter()
        .map(|f| fs::metadata(dest.join(f)).unwrap().len())
        .sum();
    assert_eq!(fs::metadata(dest.join("a")).unwrap().len(), 700);
    assert!(on_disk <= 1000, "{on_disk} bytes on disk with a cap of 1000");
}

#[test]
fn a_bad_checksum_is_an_error() {
    let mut e = Raw::file("a.bin", b"payload");
    e.crc ^= 1;
    let mut o = open_default(&raw_zip(&[e])).unwrap();
    let (_t, dest) = dest();
    assert!(extract(&mut o.archive, &o.plan, &dest, &Limits::default()).is_err());
}

#[test]
fn extraction_never_overwrites_or_follows_what_is_already_there() {
    let zip = raw_zip(&[Raw::file("a.txt", b"NEW"), Raw::file("b.txt", b"NEW"), Raw::dir("sub/")]);
    let (t, dest) = dest();
    let outside = t.path().join("outside-canary");
    fs::write(&outside, "canary").unwrap();
    fs::write(dest.join("a.txt"), "old").unwrap();
    symlink(&outside, dest.join("b.txt")).unwrap();
    let mut o = open_default(&zip).unwrap();
    let err = extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, ZipError::Io { ref source, .. } if source.kind() == io::ErrorKind::AlreadyExists),
        "{err}"
    );
    assert_eq!(fs::read_to_string(dest.join("a.txt")).unwrap(), "old");
    assert_eq!(fs::read_to_string(&outside).unwrap(), "canary");

    // A symlink where a file is planned: refused, target untouched.
    fs::remove_file(dest.join("a.txt")).unwrap();
    fs::remove_dir(dest.join("sub")).ok();
    let zip = raw_zip(&[Raw::file("b.txt", b"NEW")]);
    let mut o = open_default(&zip).unwrap();
    let err = extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap_err();
    assert!(matches!(err, ZipError::Io { .. }), "{err}");
    assert_eq!(fs::read_to_string(&outside).unwrap(), "canary");

    // An existing directory where a directory is planned is an error too (nothing is merged).
    let (_t2, dest2) = self::dest();
    fs::create_dir(dest2.join("sub")).unwrap();
    let mut o = open_default(&raw_zip(&[Raw::dir("sub/")])).unwrap();
    assert!(extract(&mut o.archive, &o.plan, &dest2, &Limits::default()).is_err());
}

#[test]
fn a_directory_symlink_planted_in_the_destination_is_never_written_through() {
    let (t, dest) = dest();
    let outside = t.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, dest.join("d")).unwrap(); // the plan wants a directory `d`
    let mut o = open_default(&raw_zip(&[Raw::file("d/evil.txt", b"x")])).unwrap();
    assert!(extract(&mut o.archive, &o.plan, &dest, &Limits::default()).is_err());
    assert!(
        fs::read_dir(&outside).unwrap().next().is_none(),
        "wrote through a symlink"
    );
}

#[test]
fn candidate_reads_are_bounded_by_the_declaration_and_the_budget() {
    let zip = raw_zip(&[
        Raw::file("a.bin", &[5u8; 300]),
        Raw::file("liar.bin", &[6u8; 900]).declared(100),
    ]);
    let mut o = open_default(&zip).unwrap();
    let limits = Limits::default();
    let mut budget = 1000;
    let bytes = read_entry(&mut o.archive, &o.plan.files[0], &mut budget, &limits).unwrap();
    assert_eq!(bytes, vec![5u8; 300]);
    assert_eq!(budget, 700);
    let err = read_entry(&mut o.archive, &o.plan.files[1], &mut budget, &limits).unwrap_err();
    assert!(matches!(err, ZipError::LiesAboutSize { .. }), "{err}");
    let mut small = 50;
    let err = read_entry(&mut o.archive, &o.plan.files[0], &mut small, &limits).unwrap_err();
    assert!(matches!(err, ZipError::AnalysisBudget { .. }), "{err}");
}

#[test]
fn read_capped_never_hands_out_more_than_declared_plus_one() {
    /// Serves zeros, but fails the read once more than `limit` bytes were handed out.
    struct Endless {
        given: u64,
        limit: u64,
    }
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.given >= self.limit {
                return Err(io::Error::other("read past the cap"));
            }
            let n = buf.len().min((self.limit - self.given) as usize);
            buf[..n].fill(0);
            self.given += n as u64;
            Ok(n)
        }
    }
    // An endless source is cut at declared + 1 bytes (the extra byte is how a lie is noticed).
    let bytes = read_capped(
        Endless {
            given: 0,
            limit: u64::MAX,
        },
        1000,
    )
    .unwrap();
    assert_eq!(bytes.len(), 1001);
    assert_eq!(read_capped(io::repeat(1).take(10), 10).unwrap().len(), 10);
    assert_eq!(read_capped(io::empty(), 0).unwrap().len(), 0);
}

#[test]
fn crate_error_texts_are_cut_on_a_character_boundary() {
    // 300 bytes of two-byte characters: a byte cut at 200 would be fine, one at 201 would split a character.
    let e = zip::result::ZipError::InvalidArchive("\u{e9}".repeat(150).into());
    let ZipError::Format(m) = format_err(&e) else { panic!() };
    assert!(m.len() <= 200 && m.is_char_boundary(m.len()));
    let e = zip::result::ZipError::InvalidArchive(format!("x{}", "\u{1f600}".repeat(60)).into());
    let ZipError::Format(m) = format_err(&e) else { panic!() };
    assert!(m.len() <= 200, "{}", m.len());
}

#[test]
fn garbage_is_a_format_error_not_a_panic() {
    for bytes in [
        &b""[..],
        b"PK",
        b"PK\x03\x04",
        b"not a zip at all",
        &[0u8; 100],
        &[0xffu8; 70_000],
    ] {
        assert!(
            matches!(open_default(bytes), Err(ZipError::Format(_))),
            "{:?}",
            &bytes[..bytes.len().min(8)]
        );
    }
}

// ---------------------------------------------------------------- strict pre-validation (before the crate)

mod prevalidate_tests {
    use super::*;
    use std::io::Cursor;

    fn pv_with(bytes: &[u8], limits: &Limits) -> Result<DirInfo, ZipError> {
        prevalidate(&mut Cursor::new(bytes), bytes.len() as u64, limits)
    }

    fn pv(bytes: &[u8]) -> Result<DirInfo, ZipError> {
        pv_with(bytes, &Limits::default())
    }

    /// The exact layout reason `prevalidate` refuses `bytes` for (the zip crate is never involved: this takes a
    /// byte slice).
    fn layout(bytes: &[u8]) -> Layout {
        match pv(bytes) {
            Err(ZipError::Layout(l)) => l,
            other => panic!("expected a layout error, got {other:?}"),
        }
    }

    /// `open` must give the same answer (and so never reaches the crate for these).
    fn open_layout(bytes: &[u8]) -> Layout {
        match expect_err(bytes) {
            ZipError::Layout(l) => l,
            other => panic!("expected a layout error from open, got {other}"),
        }
    }

    fn base3() -> Vec<u8> {
        raw_zip(&[
            Raw::file("a.txt", b"aaa"),
            Raw::file("b/c.txt", b"bbbb"),
            Raw::file("d", b""),
        ])
    }

    /// Offset of the `n`th central directory header.
    fn header(zip: &[u8], n: usize) -> usize {
        zip.windows(4)
            .enumerate()
            .filter(|(_, w)| *w == b"PK\x01\x02")
            .nth(n)
            .unwrap()
            .0
    }

    fn decoy_eocd(entries: u16) -> Vec<u8> {
        let mut d = b"PK\x05\x06\0\0\0\0".to_vec();
        d.extend_from_slice(&entries.to_le_bytes());
        d.extend_from_slice(&entries.to_le_bytes());
        d.extend_from_slice(&[0u8; 10]);
        d
    }

    #[test]
    fn a_plain_archive_validates_and_reports_what_it_found() {
        let zip = base3();
        let info = pv(&zip).unwrap();
        assert_eq!(info.entries, 3);
        assert_eq!(info.cd_offset + info.cd_size, eocd_at(&zip) as u64);
        assert_eq!(info.cd_offset as usize, header(&zip, 0));
        assert_eq!(pv(&raw_zip(&[])).unwrap().entries, 0);
    }

    #[test]
    fn entry_counts_that_disagree_on_disk_and_total_are_refused() {
        for (disk, total) in [(3u16, 1u16), (1, 3), (0, 3), (3, 0)] {
            let mut zip = base3();
            let end = eocd_at(&zip);
            put16(&mut zip, end + 8, disk);
            put16(&mut zip, end + 10, total);
            assert_eq!(layout(&zip), Layout::CountMismatch, "disk {disk} total {total}");
            assert_eq!(open_layout(&zip), Layout::CountMismatch);
        }
    }

    #[test]
    fn disk_numbers_must_be_zero() {
        for at in [4, 6] {
            let mut zip = base3();
            let end = eocd_at(&zip);
            put16(&mut zip, end + at, 1);
            assert_eq!(layout(&zip), Layout::MultiDisk, "offset {at}");
        }
    }

    #[test]
    fn a_decoy_end_record_inside_the_comment_is_ambiguous() {
        let zip = with_comment(base3(), &decoy_eocd(1));
        assert_eq!(layout(&zip), Layout::AmbiguousEnd);
        assert_eq!(open_layout(&zip), Layout::AmbiguousEnd);
        // The reviewer's shape: 60 000 real entries, a maximal comment with a decoy that says 1 entry.
        let many: Vec<Raw> = (0..60_000).map(|i| Raw::file(&format!("f{i}"), b"")).collect();
        let mut comment = decoy_eocd(1);
        comment.resize(0xFFFF, 0);
        let zip = with_comment(raw_zip(&many), &comment);
        assert_eq!(layout(&zip), Layout::AmbiguousEnd);
        assert_eq!(open_layout(&zip), Layout::AmbiguousEnd);
    }

    #[test]
    fn two_end_records_in_the_tail_window_are_ambiguous() {
        let zip = base3();
        let end = eocd_at(&zip);
        let twice = [zip.clone(), zip[end..].to_vec()].concat();
        assert_eq!(layout(&twice), Layout::AmbiguousEnd);
        // Also when the earlier signature is nowhere near a record (a bare signature in the window).
        let mut sig_in_data = base3();
        let at = header(&sig_in_data, 0) - 8;
        sig_in_data[at..at + 4].copy_from_slice(b"PK\x05\x06");
        assert_eq!(layout(&sig_in_data), Layout::AmbiguousEnd);
    }

    #[test]
    fn the_end_record_must_end_exactly_at_the_end_of_the_file() {
        let trailing = [base3(), b"garbage".to_vec()].concat();
        assert_eq!(layout(&trailing), Layout::EndNotAtEof);
        let mut short_comment = base3();
        let end = eocd_at(&short_comment);
        put16(&mut short_comment, end + 20, 10); // says 10, only 0 follow
        assert_eq!(layout(&short_comment), Layout::EndNotAtEof);
        let mut long_comment = with_comment(base3(), b"0123456789");
        let end = eocd_at(&long_comment);
        put16(&mut long_comment, end + 20, 3); // says 3, 10 follow
        assert_eq!(layout(&long_comment), Layout::EndNotAtEof);
        assert_eq!(open_layout(&trailing), Layout::EndNotAtEof);
    }

    #[test]
    fn a_comment_is_fine_when_it_is_honest() {
        for n in [1usize, 100, 0xFFFF] {
            let zip = with_comment(base3(), &vec![b'c'; n]);
            assert_eq!(pv(&zip).unwrap().entries, 3, "{n}-byte comment");
            assert_eq!(open_default(&zip).unwrap().plan.files.len(), 3);
        }
        let with_local_sig = with_comment(base3(), b"PK\x03\x04 and PK\x01\x02 are not end records");
        assert_eq!(pv(&with_local_sig).unwrap().entries, 3);
    }

    #[test]
    fn a_zip64_sentinel_without_a_zip64_record_is_refused() {
        for which in ["count", "size", "offset"] {
            let mut zip = base3();
            let end = eocd_at(&zip);
            match which {
                "count" => {
                    put16(&mut zip, end + 8, 0xFFFF);
                    put16(&mut zip, end + 10, 0xFFFF);
                }
                "size" => put32(&mut zip, end + 12, 0xFFFF_FFFF),
                _ => put32(&mut zip, end + 16, 0xFFFF_FFFF),
            }
            assert_eq!(layout(&zip), Layout::Zip64, "{which}");
        }
    }

    #[test]
    fn a_small_honest_zip64_archive_is_accepted_whichever_field_carries_the_sentinel() {
        for (count, size, offset) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let honest = base3();
            let z = Z64 {
                sentinel_count: count,
                sentinel_size: size,
                sentinel_offset: offset,
                ..Z64::honest(&honest)
            };
            let zip = to_zip64_with(honest, &z);
            let info = pv(&zip).unwrap();
            assert_eq!(info.entries, 3, "sentinels {count} {size} {offset}");
            let o =
                open_default(&zip).unwrap_or_else(|e| panic!("open failed for sentinels {count} {size} {offset}: {e}"));
            assert_eq!(o.plan.files.len(), 3);
        }
    }

    #[test]
    fn the_reviewers_zip64_memory_attack_shape_is_refused_by_its_count() {
        // Classic count 3 and cd_offset = 0xFFFFFFFF, so the crate would go zip64 and trust a record that claims
        // 30 million entries (and allocate for them). A few hundred bytes are enough to build it.
        let honest = base3();
        let z = Z64 {
            entries_disk: 30_000_000,
            total: 30_000_000,
            sentinel_count: false,
            sentinel_offset: true,
            ..Z64::honest(&honest)
        };
        let zip = to_zip64_with(honest, &z);
        assert!(zip.len() < 1000);
        assert!(matches!(pv(&zip), Err(ZipError::TooManyEntries { max: 20_000 })));
        assert!(matches!(expect_err(&zip), ZipError::TooManyEntries { max: 20_000 }));
        // The same with a bogus (large) directory offset in the zip64 record, as in the 1.44 GB sparse-file probe:
        // the crate only sizes its `Vec` for a count that does not exceed the directory offset.
        let honest = base3();
        let z = Z64 {
            entries_disk: 30_000_000,
            total: 30_000_000,
            cd_offset: 40_000_000,
            sentinel_count: false,
            sentinel_offset: true,
            ..Z64::honest(&honest)
        };
        let zip = to_zip64_with(honest, &z);
        assert!(zip.len() < 1000);
        assert!(matches!(pv(&zip), Err(ZipError::TooManyEntries { max: 20_000 })));
        assert!(matches!(expect_err(&zip), ZipError::TooManyEntries { max: 20_000 }));
    }

    #[test]
    fn the_zip64_allocation_attack_on_a_file_of_realistic_size_is_refused_before_the_crate_allocates() {
        // The reviewer's probe (a ~1 GB sparse file, classic count 3, `cd_offset` = 0xFFFFFFFF, a zip64 record
        // claiming millions of entries). The crate accepts such a record when the count does not exceed the directory
        // offset and the record lies at least 46 x count bytes after it, and then does
        // `Vec::with_capacity(count x ~232 bytes)`: 21 million entries are ~4.9 GB, an ABORT under
        // `ulimit -v 4000000`. Only the file's tail is real; the rest is a hole.
        const N: u64 = 21_000_000;
        let record_at = 46 * N + N + 1000;
        let honest = base3();
        let end = eocd_at(&honest);
        let z = Z64 {
            entries_disk: N,
            total: N,
            cd_size: 0,
            cd_offset: N,
            locator_target: Some(record_at),
            sentinel_count: false,
            sentinel_offset: true,
            ..Z64::honest(&honest)
        };
        let tail = to_zip64_with(honest, &z)[end..].to_vec();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("attack.zip");
        {
            let mut f = File::create(&path).unwrap();
            f.set_len(record_at).unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            io::Write::write_all(&mut f, &tail).unwrap();
        }
        let err = match open(File::open(&path).unwrap(), &Limits::default()) {
            Ok(_) => panic!("the attack archive was accepted"),
            Err(e) => e,
        };
        assert!(matches!(err, ZipError::TooManyEntries { max: 20_000 }), "{err}");
    }

    #[test]
    fn zip64_limits_and_consistency_are_enforced_on_the_64_bit_values() {
        type Tweak = Box<dyn Fn(&mut Z64)>;
        let cases: Vec<(&str, Tweak, Layout)> = vec![
            ("disk", Box::new(|z| z.disk = 1), Layout::MultiDisk),
            ("disk_cd", Box::new(|z| z.disk_cd = 2), Layout::MultiDisk),
            ("locator disk", Box::new(|z| z.locator_disk = 1), Layout::MultiDisk),
            (
                "locator total disks",
                Box::new(|z| z.locator_disks = 2),
                Layout::MultiDisk,
            ),
            (
                "entries_disk != total",
                Box::new(|z| z.entries_disk = 2),
                Layout::CountMismatch,
            ),
            ("cd_size", Box::new(|z| z.cd_size = 70 << 20), Layout::DirectoryTooLarge),
            (
                "cd_offset past the record",
                Box::new(|z| z.cd_offset += 1),
                Layout::DirectoryOutOfBounds,
            ),
            (
                "cd_size past the record",
                Box::new(|z| z.cd_size += 1),
                Layout::DirectoryOutOfBounds,
            ),
            ("record size field", Box::new(|z| z.size_field = 45), Layout::Zip64),
            (
                "record size field too small",
                Box::new(|z| z.size_field = 10),
                Layout::Zip64,
            ),
            (
                "locator points elsewhere",
                Box::new(|z| z.locator_target = Some(0)),
                Layout::Zip64,
            ),
            (
                "locator points after itself",
                Box::new(|z| z.locator_target = Some(1 << 40)),
                Layout::Zip64,
            ),
        ];
        for (what, tweak, want) in cases {
            let honest = base3();
            let mut z = Z64::honest(&honest);
            tweak(&mut z);
            let zip = to_zip64_with(honest, &z);
            assert_eq!(layout(&zip), want, "{what}");
        }
        // A record whose signature is not `PK\x06\x06`, though its size and position are right.
        let honest = base3();
        let mut zip = to_zip64_with(honest.clone(), &Z64::honest(&honest));
        let at = zip.windows(4).position(|w| w == b"PK\x06\x06").unwrap();
        zip[at + 3] = 0x09;
        assert_eq!(layout(&zip), Layout::Zip64);
        // A zip64 record with more entries than the cap.
        let honest = base3();
        let z = Z64 {
            entries_disk: 20_001,
            total: 20_001,
            ..Z64::honest(&honest)
        };
        assert!(matches!(
            pv(&to_zip64_with(honest, &z)),
            Err(ZipError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn a_zip64_locator_the_end_record_does_not_point_to_is_ambiguous() {
        let honest = base3();
        let z = Z64 {
            sentinel_count: false,
            ..Z64::honest(&honest)
        };
        assert_eq!(layout(&to_zip64_with(honest, &z)), Layout::StrayZip64Locator);
    }

    #[test]
    fn an_end_record_signature_hidden_in_the_directory_or_the_zip64_data_is_ambiguous() {
        // In an entry name inside the central directory.
        let zip = raw_zip(&[Raw::file("a.txt", b"1"), Raw::file("xPK\x05\x06y", b"2")]);
        assert_eq!(layout(&zip), Layout::AmbiguousEnd);
        assert_eq!(open_layout(&zip), Layout::AmbiguousEnd);
        // In the zip64 extensible data sector (an honest size field, so only the signature is wrong).
        let honest = base3();
        let sector = b"....PK\x05\x06....".to_vec();
        let z = Z64 {
            size_field: 44 + sector.len() as u64,
            extensible: sector,
            ..Z64::honest(&honest)
        };
        assert_eq!(layout(&to_zip64_with(honest, &z)), Layout::AmbiguousEnd);
        // Far from the end (outside the 64 KiB tail window) it is still found: a big sector, signature first.
        let honest = base3();
        let mut sector = vec![0u8; 65_535];
        sector[..4].copy_from_slice(b"PK\x05\x06");
        let z = Z64 {
            size_field: 44 + sector.len() as u64,
            extensible: sector,
            ..Z64::honest(&honest)
        };
        assert_eq!(layout(&to_zip64_with(honest, &z)), Layout::AmbiguousEnd);
        // The same for a poisoned name at the start of a big central directory.
        let mut entries = vec![Raw::file("xPK\x05\x06y", b"")];
        entries.extend((0..3000).map(|i| Raw::file(&format!("filler-{i:05}-{}", "z".repeat(40)), b"")));
        let big = raw_zip(&entries);
        assert!(
            big.len() - header(&big, 0) > 70_000,
            "the signature must lie outside the tail window"
        );
        assert_eq!(layout(&big), Layout::AmbiguousEnd);
        // The same sector without the signature is fine.
        let honest = base3();
        let sector = b"....PK\x03\x04....".to_vec();
        let z = Z64 {
            size_field: 44 + sector.len() as u64,
            extensible: sector,
            ..Z64::honest(&honest)
        };
        assert_eq!(pv(&to_zip64_with(honest, &z)).unwrap().entries, 3);
    }

    #[test]
    fn the_central_directory_size_is_capped_at_64_mib() {
        let mut zip = base3();
        let end = eocd_at(&zip);
        put32(&mut zip, end + 12, (64 << 20) + 1);
        assert_eq!(layout(&zip), Layout::DirectoryTooLarge);
        assert_eq!(open_layout(&zip), Layout::DirectoryTooLarge);
    }

    #[test]
    fn the_central_directory_must_lie_inside_the_archive_and_end_at_the_end_record() {
        let mut past = base3();
        let end = eocd_at(&past);
        put32(&mut past, end + 16, end as u32); // cd_offset + cd_size > eocd_pos
        assert_eq!(layout(&past), Layout::DirectoryOutOfBounds);
        let mut huge = base3();
        put32(&mut huge, end + 16, 0xFFFF_FFF0);
        assert_eq!(layout(&huge), Layout::DirectoryOutOfBounds);
        // Junk between the directory and the end record.
        let mut gap = base3();
        gap.splice(end..end, [7u8; 10]);
        assert_eq!(layout(&gap), Layout::DirectoryGap);
    }

    #[test]
    fn a_missing_or_wrong_central_header_signature_is_refused() {
        let mut first = base3();
        let at = header(&first, 0);
        first[at + 2] = 9;
        assert_eq!(layout(&first), Layout::PrependedData);
        let mut second = base3();
        let at = header(&second, 1);
        second[at + 3] = 9;
        assert_eq!(layout(&second), Layout::InconsistentDirectory);
        assert_eq!(open_layout(&second), Layout::InconsistentDirectory);
    }

    #[test]
    fn a_directory_walk_that_overruns_or_leaves_bytes_is_refused() {
        // A name length that runs past the directory.
        let mut overrun = base3();
        let at = header(&overrun, 2);
        put16(&mut overrun, at + 28, 3000);
        assert_eq!(layout(&overrun), Layout::InconsistentDirectory);
        // Extra and comment lengths count too.
        for field in [30, 32] {
            let mut z = base3();
            let at = header(&z, 2);
            put16(&mut z, at + field, 500);
            assert_eq!(layout(&z), Layout::InconsistentDirectory, "field {field}");
        }
        // Fewer entries than headers: bytes are left over.
        let mut fewer = base3();
        let end = eocd_at(&fewer);
        put16(&mut fewer, end + 8, 2);
        put16(&mut fewer, end + 10, 2);
        assert_eq!(layout(&fewer), Layout::InconsistentDirectory);
        // More entries than headers: the walk runs out.
        let mut more = base3();
        put16(&mut more, end + 8, 5);
        put16(&mut more, end + 10, 5);
        assert_eq!(layout(&more), Layout::InconsistentDirectory);
        // Even a directory of nothing but its declared size.
        let mut empty_count = base3();
        put16(&mut empty_count, end + 8, 0);
        put16(&mut empty_count, end + 10, 0);
        assert_eq!(layout(&empty_count), Layout::InconsistentDirectory);
    }

    #[test]
    fn entry_names_are_bounded_per_entry_and_in_total() {
        let long = raw_zip(&[Raw::file(&"n".repeat(4097), b"")]);
        assert_eq!(layout(&long), Layout::NamesTooLong);
        let at_cap = raw_zip(&[Raw::file(&"n".repeat(4096), b"")]);
        assert_eq!(pv(&at_cap).unwrap().entries, 1);
        // 4200 names of 4096 bytes: 17 MB, over the 16 MiB total.
        let entries: Vec<Raw> = (0..4200)
            .map(|i| Raw::file(&format!("{i:05}{}", "x".repeat(4091)), b""))
            .collect();
        assert_eq!(layout(&raw_zip(&entries)), Layout::NamesTooLong);
    }

    #[test]
    fn prepended_data_is_not_supported() {
        for junk in [&b"JUNK"[..], b"#!/bin/sh\nexit 0\n", &[0u8; 5000]] {
            let zip = [junk, &base3()].concat();
            assert_eq!(layout(&zip), Layout::PrependedData, "{} junk bytes", junk.len());
            assert_eq!(open_layout(&zip), Layout::PrependedData);
        }
        let msg = ZipError::Layout(Layout::PrependedData).to_string();
        assert!(msg.contains("data before the first entry"), "{msg}");
    }

    #[test]
    fn the_entry_count_cap_holds_in_prevalidate() {
        let many = |n: usize| raw_zip(&(0..n).map(|i| Raw::file(&format!("f{i}"), b"")).collect::<Vec<_>>());
        assert_eq!(pv(&many(20_000)).unwrap().entries, 20_000);
        assert!(matches!(
            pv(&many(20_001)),
            Err(ZipError::TooManyEntries { max: 20_000 })
        ));
        let tight = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        assert!(matches!(
            pv_with(&base3(), &tight),
            Err(ZipError::TooManyEntries { max: 2 })
        ));
    }

    #[test]
    fn not_a_zip_at_all_is_a_format_error() {
        for bytes in [&b""[..], b"PK", &[0u8; 21], &[0u8; 100_000]] {
            assert!(matches!(pv(bytes), Err(ZipError::Format(_))), "{} bytes", bytes.len());
        }
    }

    #[test]
    fn an_archive_written_by_the_zip_crate_is_accepted() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.add_directory("d/", o).unwrap();
        for i in 0..50 {
            w.start_file(format!("d/f{i}.txt"), o).unwrap();
            io::Write::write_all(&mut w, format!("file {i}").as_bytes()).unwrap();
        }
        w.set_raw_comment(b"made by the zip crate".to_vec().into()).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        assert_eq!(pv(&bytes).unwrap().entries, 51);
        assert_eq!(open_default(&bytes).unwrap().plan.files.len(), 50);
    }

    #[test]
    fn an_archive_written_by_the_zip_tool_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub/deeper")).unwrap();
        fs::write(src.join("a.txt"), "alpha").unwrap();
        fs::write(src.join("sub/b.bin"), vec![7u8; 100_000]).unwrap();
        fs::write(src.join("sub/deeper/c.txt"), "gamma").unwrap();
        let out = tmp.path().join("out.zip");
        let status = std::process::Command::new("zip")
            .args(["-q", "-r"])
            .arg(&out)
            .arg(".")
            .current_dir(&src)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("zip failed: {s}"),
            Err(e) => {
                eprintln!("SKIPPED: the `zip` tool is not available ({e}); only the zip-crate archive was tested");
                return;
            }
        }
        let bytes = fs::read(&out).unwrap();
        assert_eq!(pv(&bytes).unwrap().entries, 5, "3 files + 2 directories");
        let mut o = open_default(&bytes).unwrap();
        assert_eq!(o.plan.files.len(), 3);
        let (_t, dest) = dest();
        extract(&mut o.archive, &o.plan, &dest, &Limits::default()).unwrap();
        assert_eq!(fs::read(dest.join("sub/b.bin")).unwrap(), vec![7u8; 100_000]);
    }

    #[test]
    fn the_crate_cannot_fall_back_to_another_end_record_hidden_in_the_data() {
        // Outer archive: a STORED nested zip (with its own end record, well before the tail window), padding, and
        // an entry the crate refuses (AES method without its extra field). Without the mask the crate would fail on
        // our record and walk back to the nested one; with it there is no other record to find.
        let nested = raw_zip(&[Raw::file("x", b"1"), Raw::file("y", b"2")]);
        let zip = raw_zip(&[
            Raw::file("nested.zip", &nested),
            Raw::file("pad.bin", &vec![0u8; 70_000]),
            Raw::file("aes.bin", b"data").method(99),
        ]);
        assert_eq!(pv(&zip).unwrap().entries, 3, "prevalidate accepts the outer archive");
        match expect_err(&zip) {
            ZipError::Format(m) => assert!(m.contains("AES"), "{m}"),
            other => panic!("expected the crate's own refusal of the AES entry, got: {other}"),
        }
    }

    #[test]
    fn after_parsing_the_crate_must_have_used_exactly_the_validated_record() {
        // The archive validates; the crate accepts it; its view matches ours.
        let o = open_default(&base3()).unwrap();
        assert_eq!(o.archive.len(), 3);
        assert_eq!(o.archive.offset(), 0);
        assert_eq!(o.archive.central_directory_start(), pv(&base3()).unwrap().cd_offset);
    }
}

#[test]
fn the_guarded_reader_masks_from_the_files_real_cursor_not_from_zero() {
    // 100 bytes of 0xAA, directory at 20, cursor at 10: the first read shows 10 zero bytes (10..20) and then the
    // real data. A reader that assumed position 0 would blank 20 bytes.
    let tmp = tempfile::tempdir().unwrap();
    let path = write_file(tmp.path(), "f", &[0xAA; 100]);
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();
    let mut g = Guarded::new(file, 20, Arc::new(AtomicBool::new(true))).unwrap();
    let mut buf = [0xFF; 30];
    g.read_exact(&mut buf).unwrap();
    assert_eq!(buf[..10], [0; 10]);
    assert_eq!(buf[10..], [0xAA; 20]);
    // and once the mask is off, or past the directory start, nothing is touched
    let mut file = File::open(tmp.path().join("f")).unwrap();
    file.seek(SeekFrom::Start(40)).unwrap();
    let mut g = Guarded::new(file, 20, Arc::new(AtomicBool::new(true))).unwrap();
    let mut buf = [0xFF; 8];
    g.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xAA; 8]);
}
