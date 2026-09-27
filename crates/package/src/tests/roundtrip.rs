//! The writer: reproducible output the reader accepts, and every refusal of spec 6 "Writer".
use super::*;
use crate::write::pack_with;
use crate::{PackageError as E, open, pack};
use std::fs;
use std::path::PathBuf;

const INPUT: &str = r#"format = 1
id = "example-app"
name = "Example \"App\" \\ 例"
version = "1.2.0"
arch = "x86_64"
dependencies = ["vcrun2022"]
icon = "payload/app.png"

[permissions]
gpu = "on"
network = "allow"

[entry]
kind = "portable"
exe = "payload/App/app.exe"
"#;

/// A package directory holding [`INPUT`] and [`payload`], plus a data file with a non-ASCII name.
fn source(root: &Path) -> PathBuf {
    let dir = root.join("src");
    fs::create_dir_all(dir.join("payload/App/sub")).unwrap();
    fs::write(dir.join("wrun.toml"), INPUT).unwrap();
    for (p, d) in payload() {
        fs::write(dir.join(p), d).unwrap();
    }
    fs::write(dir.join("payload/App/sub/caf\u{e9}.txt"), vec![0u8; 5 << 20]).unwrap();
    dir
}

#[test]
fn pack_open_unpack_pack_is_byte_identical() {
    let t = tempfile::tempdir().unwrap();
    let src = source(t.path());
    let first = t.path().join("a.wrun");
    let digest = pack(&src, &first).unwrap();

    let mut p = open(fs::File::open(&first).unwrap()).unwrap();
    assert_eq!(p.digest, digest);
    p.verify().unwrap();
    let paths: Vec<&str> = p.manifest.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "payload/App/app.exe",
            "payload/App/data.bin",
            "payload/App/sub/caf\u{e9}.txt",
            "payload/app.png"
        ],
        "sorted by path bytes"
    );
    assert_eq!(p.manifest.name, "Example \"App\" \\ 例");

    let out = t.path().join("unpacked");
    p.unpack(&out).unwrap();
    // The unpacked manifest carries [[files]]: pack refuses it as input, so repack from a copy without them.
    let text = fs::read_to_string(out.join("wrun.toml")).unwrap();
    assert_eq!(sha256(text.as_bytes()), digest);
    let head = &text[..text.find("\n[[files]]").unwrap() + 1];
    fs::write(out.join("wrun.toml"), head).unwrap();
    let second = t.path().join("b.wrun");
    assert_eq!(pack(&out, &second).unwrap(), digest);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    // Every entry: 1980-01-01, 0644, no directory entries, wrun.toml first, deflate unless it would be a "bomb".
    let mut z = zip::ZipArchive::new(fs::File::open(&first).unwrap()).unwrap();
    assert_eq!(z.len(), 5);
    for i in 0..z.len() {
        let e = z.by_index_raw(i).unwrap();
        assert_eq!(e.unix_mode().unwrap() & 0o7777, 0o644, "{}", e.name());
        assert_eq!(e.last_modified(), Some(zip::DateTime::default()));
        // 5 MiB of zeros deflates past the reader's ratio guard: stored instead.
        let want = if e.name().ends_with("caf\u{e9}.txt") {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        };
        assert_eq!(e.compression(), want, "{}", e.name());
        assert!(!e.is_dir());
    }
    assert_eq!(z.by_index_raw(0).unwrap().name(), "wrun.toml");
}

#[test]
fn pack_refuses_links_special_files_and_names_the_reader_would_refuse() {
    type Plant = fn(&Path);
    let cases: [(&str, Plant); 5] = [
        ("symlink", |d| {
            std::os::unix::fs::symlink("/etc/passwd", d.join("payload/link")).unwrap()
        }),
        ("fifo", |d| {
            let c = std::ffi::CString::new(d.join("payload/fifo").into_os_string().into_encoded_bytes()).unwrap();
            // SAFETY: a valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }),
        ("backslash", |d| fs::write(d.join("payload/a\\b"), b"x").unwrap()),
        ("reserved", |d| fs::write(d.join("payload/con.txt"), b"x").unwrap()),
        ("top-level", |d| fs::write(d.join("README"), b"x").unwrap()),
    ];
    for (what, plant) in cases {
        let t = tempfile::tempdir().unwrap();
        let src = source(t.path());
        plant(&src);
        let out = t.path().join("o.wrun");
        let e = pack(&src, &out).unwrap_err();
        assert!(matches!(e, E::Layout(_)), "{what}: {e}");
        assert!(!out.exists(), "{what}: the output was left behind");
    }
}

#[test]
fn pack_refuses_an_existing_files_table_and_an_existing_output() {
    let t = tempfile::tempdir().unwrap();
    let src = source(t.path());
    let out = t.path().join("o.wrun");
    fs::write(&out, b"precious").unwrap();
    assert!(matches!(pack(&src, &out), Err(E::Io { .. })));
    assert_eq!(fs::read(&out).unwrap(), b"precious", "an existing output was touched");

    fs::write(src.join("wrun.toml"), format!("{INPUT}{}", files_toml(&payload()))).unwrap();
    let out = t.path().join("p.wrun");
    let e = pack(&src, &out).unwrap_err();
    assert!(matches!(&e, E::Manifest(m) if m.contains("[[files]]")), "{e}");
    assert!(!out.exists());

    // An invalid manifest (the manifest rules apply to pack's input too).
    fs::write(
        src.join("wrun.toml"),
        INPUT.replace("payload/App/app.exe", "payload/App/none.exe"),
    )
    .unwrap();
    assert!(matches!(pack(&src, &out), Err(E::Manifest(_))));
    assert!(!out.exists());
}

#[test]
fn pack_refuses_inputs_over_the_readers_caps() {
    let t = tempfile::tempdir().unwrap();
    let src = source(t.path());
    let cases = [
        Limits {
            max_entries: 4, // wrun.toml + 3 < 5 payload files
            ..Limits::default()
        },
        Limits {
            max_entry_bytes: 4 << 20,
            ..Limits::default()
        },
        Limits {
            max_total_bytes: 4 << 20,
            ..Limits::default()
        },
    ];
    for (i, limits) in cases.iter().enumerate() {
        let out = t.path().join(format!("{i}.wrun"));
        let e = pack_with(&src, &out, limits).unwrap_err();
        assert!(matches!(e, E::Layout(_)), "{i}: {e}");
        assert!(!out.exists());
    }
}
