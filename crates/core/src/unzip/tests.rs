use super::*;
use crate::testutil::*;
use std::os::unix::fs::{MetadataExt, symlink};

struct Opened {
    _tmp: tempfile::TempDir,
    archive: ZipArchive<File>,
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
    // A sentinel without the zip64 record behind it is not a usable archive.
    let mut broken = base;
    let end = broken.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
    for at in [end + 8, end + 10] {
        broken[at..at + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    }
    assert!(matches!(expect_err(&broken), ZipError::Format(_)));
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
