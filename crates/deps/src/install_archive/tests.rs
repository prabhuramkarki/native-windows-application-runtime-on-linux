use super::*;
use crate::manifest::{ArchiveFormat, Extract, Install, Kind, Package};
use rt_core::{AppId, Call, FakeBackend, Store};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::Mutex;

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
const FORMATS: [ArchiveFormat; 2] = [ArchiveFormat::Zip, ArchiveFormat::TarGz];

// ------------------------------------------------------------------------------------------------ archive builders

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// One zip entry, stored (method 0) unless `deflate` is set; `mode` is the Unix mode in the external attributes.
#[derive(Clone)]
struct Z {
    name: Vec<u8>,
    data: Vec<u8>,
    size: u32,
    crc: u32,
    mode: u32,
    method: u16,
}

impl Z {
    fn file(name: &str, data: &[u8]) -> Z {
        Z {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            size: data.len() as u32,
            crc: crc32(data),
            mode: S_IFREG | 0o644,
            method: 0,
        }
    }
    fn dir(name: &str) -> Z {
        Z {
            mode: S_IFDIR | 0o755,
            ..Z::file(name, b"")
        }
    }
    fn mode(mut self, mode: u32) -> Z {
        self.mode = mode;
        self
    }
    fn deflated(name: &str, plain: &[u8]) -> Z {
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(plain).unwrap();
        Z {
            data: enc.finish().unwrap(),
            method: 8,
            ..Z::file(name, plain)
        }
    }
}

/// A plain zip (no zip64, no extra fields) exactly as described.
fn zip_of(entries: &[Z]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for e in entries {
        let offset = out.len() as u32;
        let flags: u16 = if e.name.is_ascii() { 0 } else { 0x800 };
        let mut common = Vec::new();
        common.extend_from_slice(&flags.to_le_bytes());
        common.extend_from_slice(&e.method.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes());
        common.extend_from_slice(&33u16.to_le_bytes());
        common.extend_from_slice(&e.crc.to_le_bytes());
        common.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        common.extend_from_slice(&e.size.to_le_bytes());
        common.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&common);
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&common);
        central.extend_from_slice(&[0u8; 6]);
        central.extend_from_slice(&(e.mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(&e.name);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// One tar entry: `typeflag` `b'0'` file, `b'5'` directory, anything else as given.
#[derive(Clone)]
struct T {
    name: Vec<u8>,
    data: Vec<u8>,
    flag: u8,
    mode: u32,
}

impl T {
    fn file(name: &str, data: &[u8]) -> T {
        T {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            flag: b'0',
            mode: 0o644,
        }
    }
    fn dir(name: &str) -> T {
        T {
            flag: b'5',
            mode: 0o755,
            ..T::file(name, b"")
        }
    }
    fn special(name: &str, flag: u8) -> T {
        T {
            flag,
            ..T::file(name, b"")
        }
    }
    fn mode(mut self, mode: u32) -> T {
        self.mode = mode;
        self
    }
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{v:0w$o}\0", w = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

fn tar_header(name: &[u8], size: u64, flag: u8, mode: u32) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[148..156].fill(b' ');
    h[156] = flag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// The uncompressed ustar stream. Names over 100 bytes get a GNU `L` long-name entry.
fn tar_of(entries: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    let pad = |out: &mut Vec<u8>| out.resize(out.len().div_ceil(512) * 512, 0);
    for e in entries {
        let mut name = e.name.clone();
        if name.len() > 100 {
            let mut long = name.clone();
            long.push(0);
            out.extend_from_slice(&tar_header(b"././@LongLink", long.len() as u64, b'L', 0o644));
            out.extend_from_slice(&long);
            pad(&mut out);
            name.truncate(100);
        }
        out.extend_from_slice(&tar_header(&name, e.data.len() as u64, e.flag, e.mode));
        out.extend_from_slice(&e.data);
        pad(&mut out);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn targz_of(entries: &[T]) -> Vec<u8> {
    gzip(&tar_of(entries))
}

/// Regular files `(name, data)` in the given format.
fn files_in(format: ArchiveFormat, files: &[(&str, &[u8])]) -> Vec<u8> {
    match format {
        ArchiveFormat::Zip => zip_of(&files.iter().map(|(n, d)| Z::file(n, d)).collect::<Vec<_>>()),
        ArchiveFormat::TarGz => targz_of(&files.iter().map(|(n, d)| T::file(n, d)).collect::<Vec<_>>()),
    }
}

// ------------------------------------------------------------------------------------------------ environment

struct Env {
    tmp: tempfile::TempDir,
    env: AppEnv,
}

impl Env {
    fn new() -> Env {
        Env::named("app")
    }

    /// A fresh app environment with `drive_c/windows/system32/reg.exe` (a stand-in; the fake backend never runs it).
    fn named(id: &str) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let env = Store::new(tmp.path().join("apps"))
            .unwrap()
            .create(&AppId::parse(id).unwrap())
            .unwrap();
        fs::create_dir_all(env.drive_c().join("windows/system32")).unwrap();
        fs::write(env.drive_c().join("windows/system32/reg.exe"), b"MZ fake").unwrap();
        Env { tmp, env }
    }

    fn c(&self, rel: &str) -> PathBuf {
        self.env.drive_c().join(rel)
    }

    /// Writes an archive to `<tmp>/cache/<name>` and returns its path.
    fn archive(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let dir = self.tmp.path().join("cache");
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    fn backup(&self, id: &str, rel: &str) -> PathBuf {
        self.env.root().join(BACKUP_DIR).join(id).join("c").join(rel)
    }

    fn journal(&self) -> PathBuf {
        self.env.root().join(BACKUP_DIR).join("dxvk").join("journal")
    }

    fn snapshot(&self) -> BTreeMap<String, String> {
        snapshot(self.tmp.path())
    }
}

/// Every entry under `root` (symlinks not followed) with its type, permission bits and content.
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            let key = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let perm = m.mode() & 0o7777;
            if m.file_type().is_symlink() {
                out.insert(key, format!("link {:?}", fs::read_link(&p).unwrap()));
            } else if m.is_dir() {
                out.insert(key, format!("dir {perm:o}"));
                walk(&p, root, out);
            } else {
                out.insert(key, format!("file {perm:o} {:?}", fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn pkg_with(format: ArchiveFormat, extract: &[(&str, &str)], overrides: &[&str], provides: &[&str]) -> Package {
    Package {
        id: "dxvk".into(),
        version: "2.4".into(),
        sha256: HASH.into(),
        size: 1,
        licence: "Zlib".into(),
        url: "https://example.org/dxvk.tar.gz".into(),
        kind: Kind::Archive,
        requires_consent: false,
        requires: vec![],
        provides: provides.iter().map(|s| (*s).to_owned()).collect(),
        install: Install::Archive {
            format,
            extract: extract
                .iter()
                .map(|(f, t)| Extract {
                    from: (*f).into(),
                    to: (*t).into(),
                })
                .collect(),
            dll_overrides: overrides.iter().map(|s| (*s).to_owned()).collect(),
        },
    }
}

fn pkg(format: ArchiveFormat, extract: &[(&str, &str)]) -> Package {
    pkg_with(format, extract, &[], &["d3d11", "dxgi"])
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

/// `install_archive` with the package size set to the archive's real size.
fn install_with(
    e: &Env,
    mut p: Package,
    file: &Path,
    backend: &dyn CompatBackend,
) -> Result<ArchiveInstalled, ArchiveError> {
    p.size = fs::metadata(file).unwrap().len();
    install_archive(&p, file, &e.env, backend, &launcher())
}

fn install(e: &Env, p: Package, file: &Path) -> Result<ArchiveInstalled, ArchiveError> {
    install_with(e, p, file, &FakeBackend::new())
}

fn remove(e: &Env, done: &ArchiveInstalled) -> Result<(), ArchiveError> {
    remove_archive(done, "dxvk", &e.env, &FakeBackend::new(), &launcher())
}

fn paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

/// Writes `bytes` with mode 0644 whatever the umask (restored originals are 0644).
fn put(p: &Path, bytes: &[u8]) {
    fs::write(p, bytes).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

// ------------------------------------------------------------------------------------------------ happy paths

#[test]
fn declared_files_are_extracted_and_exactly_recorded() {
    for format in FORMATS {
        let e = Env::new();
        let bytes = files_in(
            format,
            &[
                ("dxvk-2.4/x64/d3d11.dll", b"D3D11"),
                ("dxvk-2.4/x64/dxgi.dll", b"DXGI"),
                ("dxvk-2.4/README.md", b"readme"),
            ],
        );
        let file = e.archive("a", &bytes);
        let p = pkg(
            format,
            &[
                ("dxvk-2.4/x64/d3d11.dll", "windows/system32/d3d11.dll"),
                ("dxvk-2.4/x64/dxgi.dll", "Program Files/dxvk/bin/dxgi.dll"),
            ],
        );
        let done = install(&e, p, &file).unwrap();
        assert_eq!(
            fs::read(e.c("windows/system32/d3d11.dll")).unwrap(),
            b"D3D11",
            "{format:?}"
        );
        assert_eq!(fs::read(e.c("Program Files/dxvk/bin/dxgi.dll")).unwrap(), b"DXGI");
        assert_eq!(
            done,
            ArchiveInstalled {
                files: paths(&["windows/system32/d3d11.dll", "Program Files/dxvk/bin/dxgi.dll"]),
                replaced: vec![],
                created_dirs: paths(&["Program Files", "Program Files/dxvk", "Program Files/dxvk/bin"]),
                overrides: vec![],
            }
        );
        // Nothing else appeared anywhere under drive_c (the README was not selected).
        let mut all: Vec<String> = snapshot(&e.env.drive_c()).into_keys().collect();
        all.sort();
        assert_eq!(
            all,
            [
                "Program Files",
                "Program Files/dxvk",
                "Program Files/dxvk/bin",
                "Program Files/dxvk/bin/dxgi.dll",
                "windows",
                "windows/system32",
                "windows/system32/d3d11.dll",
                "windows/system32/reg.exe"
            ]
        );
        assert!(
            !e.env.root().join(BACKUP_DIR).join("dxvk/c").exists(),
            "no backup without a replaced file"
        );
        assert!(e.journal().is_file(), "the journal stays until the package is removed");
    }
}

#[test]
fn existing_directories_are_reused_case_insensitively() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive("a", &files_in(format, &[("x/a.dll", b"A")]));
        let done = install(&e, pkg(format, &[("x/a.dll", "WINDOWS/System32/a.dll")]), &file).unwrap();
        assert_eq!(fs::read(e.c("windows/system32/a.dll")).unwrap(), b"A");
        assert_eq!(
            done.files,
            paths(&["windows/system32/a.dll"]),
            "real on-disk names are recorded"
        );
        assert!(done.created_dirs.is_empty());
    }
}

#[test]
fn a_trailing_slash_selects_every_file_below_a_directory() {
    for format in FORMATS {
        let e = Env::new();
        let bytes = match format {
            ArchiveFormat::Zip => zip_of(&[
                Z::dir("dxvk/"),
                Z::dir("dxvk/x64/"),
                Z::file("dxvk/x64/d3d11.dll", b"64"),
                Z::file("dxvk/x64/sub/deep.dll", b"deep"),
                Z::file("dxvk/x32/d3d11.dll", b"32"),
                Z::file("dxvk/x64.txt", b"not below x64/"),
            ]),
            ArchiveFormat::TarGz => targz_of(&[
                T::dir("dxvk"),
                T::dir("dxvk/x64"),
                T::file("dxvk/x64/d3d11.dll", b"64"),
                T::dir("dxvk/x64/sub"),
                T::file("dxvk/x64/sub/deep.dll", b"deep"),
                T::file("dxvk/x32/d3d11.dll", b"32"),
                T::file("dxvk/x64.txt", b"not below x64/"),
            ]),
        };
        let file = e.archive("a", &bytes);
        let done = install(&e, pkg(format, &[("dxvk/x64/", "windows/system32")]), &file).unwrap();
        assert_eq!(
            fs::read(e.c("windows/system32/d3d11.dll")).unwrap(),
            b"64",
            "{format:?}"
        );
        assert_eq!(fs::read(e.c("windows/system32/sub/deep.dll")).unwrap(), b"deep");
        assert_eq!(
            done.files,
            paths(&["windows/system32/d3d11.dll", "windows/system32/sub/deep.dll"])
        );
        assert_eq!(done.created_dirs, paths(&["windows/system32/sub"]));
        assert!(!e.c("windows/system32/x64.txt").exists());
    }
}

#[test]
fn the_full_archive_path_is_required_no_wrapper_directory_is_stripped() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive("a", &files_in(format, &[("dxvk-2.4/x64/d3d11.dll", b"D")]));
        let before = e.snapshot();
        for from in ["x64/d3d11.dll", "x64/", "d3d11.dll", "DXVK-2.4/x64/d3d11.dll"] {
            let err = install(&e, pkg(format, &[(from, "windows/system32/d3d11.dll")]), &file).unwrap_err();
            assert!(
                matches!(&err, ArchiveError::NoMatch(f) if f == from),
                "{format:?} {from}: {err:?}"
            );
        }
        assert_eq!(e.snapshot(), before);
    }
}

// ------------------------------------------------------------------------------------------------ selection errors

#[test]
fn an_extract_entry_matching_nothing_is_no_match_and_nothing_is_written() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive("a", &files_in(format, &[("x/a.dll", b"A"), ("x/dir/b.dll", b"B")]));
        let before = e.snapshot();
        for missing in ["x/missing.dll", "x/dir", "x/none/", "x/a.dll/"] {
            let p = pkg(format, &[("x/a.dll", "windows/a.dll"), (missing, "windows/m.dll")]);
            let err = install(&e, p, &file).unwrap_err();
            assert!(
                matches!(&err, ArchiveError::NoMatch(f) if f == missing),
                "{missing}: {err:?}"
            );
            assert_eq!(e.snapshot(), before, "{format:?} {missing}");
        }
    }
}

#[test]
fn two_files_mapping_to_one_destination_are_refused() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive(
            "a",
            &files_in(format, &[("a/x.dll", b"1"), ("b/x.dll", b"2"), ("c/X.DLL", b"3")]),
        );
        let before = e.snapshot();
        let cases: [&[(&str, &str)]; 3] = [
            &[("a/x.dll", "windows/x.dll"), ("b/x.dll", "windows/x.dll")],
            &[("a/x.dll", "windows/x.dll"), ("b/x.dll", "Windows/X.dll")],
            &[("a/", "windows"), ("c/", "WINDOWS")],
        ];
        for extract in cases {
            let err = install(&e, pkg(format, extract), &file).unwrap_err();
            assert!(matches!(err, ArchiveError::Destination(_)), "{extract:?}: {err:?}");
            assert_eq!(e.snapshot(), before);
        }
    }
}

#[test]
fn a_file_selected_by_two_extract_entries_is_refused() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive("a", &files_in(format, &[("a/x.dll", b"1")]));
        let before = e.snapshot();
        let err = install(
            &e,
            pkg(format, &[("a/x.dll", "windows/x.dll"), ("a/", "windows/other")]),
            &file,
        )
        .unwrap_err();
        assert!(matches!(err, ArchiveError::Destination(_)), "{err:?}");
        assert_eq!(e.snapshot(), before);
    }
}

#[test]
fn a_selected_path_that_appears_twice_in_the_archive_is_refused() {
    let e = Env::new();
    let before = e.snapshot();
    // tar: the reader reports both copies; the installer refuses instead of picking one.
    let tar = e.archive(
        "t",
        &targz_of(&[T::file("a/x.dll", b"first"), T::file("a/x.dll", b"second")]),
    );
    let err = install(&e, pkg(ArchiveFormat::TarGz, &[("a/x.dll", "windows/x.dll")]), &tar).unwrap_err();
    assert!(matches!(err, ArchiveError::Destination(_)), "{err:?}");
    let err = install(&e, pkg(ArchiveFormat::TarGz, &[("a/", "windows")]), &tar).unwrap_err();
    assert!(matches!(err, ArchiveError::Destination(_)), "{err:?}");
    // zip: the planner already refuses duplicate names.
    let zip = e.archive(
        "z",
        &zip_of(&[Z::file("a/x.dll", b"first"), Z::file("a/x.dll", b"second")]),
    );
    let err = install(&e, pkg(ArchiveFormat::Zip, &[("a/x.dll", "windows/x.dll")]), &zip).unwrap_err();
    assert!(matches!(err, ArchiveError::Zip(_)), "{err:?}");
    let mut after = e.snapshot();
    after.retain(|k, _| !k.starts_with("cache"));
    let mut before = before;
    before.retain(|k, _| !k.starts_with("cache"));
    assert_eq!(after, before);
}

#[test]
fn unselected_entries_are_never_written() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive(
            "a",
            &files_in(
                format,
                &[
                    ("keep.dll", b"K"),
                    ("skip/evil.dll", b"E"),
                    ("windows/system32/x.dll", b"X"),
                ],
            ),
        );
        let done = install(&e, pkg(format, &[("keep.dll", "keep.dll")]), &file).unwrap();
        assert_eq!(done.files, paths(&["keep.dll"]));
        assert!(!e.c("skip").exists() && !e.c("windows/system32/x.dll").exists());
    }
}

// ------------------------------------------------------------------------------------------------ hostile archives

/// Everything outside `cache/` (where the archives sit) is unchanged.
fn assert_untouched(e: &Env, before: &BTreeMap<String, String>, what: &str) {
    let strip = |m: &BTreeMap<String, String>| {
        let mut m = m.clone();
        m.retain(|k, _| !k.starts_with("cache"));
        m
    };
    assert_eq!(strip(&e.snapshot()), strip(before), "{what}");
}

#[test]
fn hostile_zip_names_never_write_anything() {
    let long = "a".repeat(300);
    let names: Vec<String> = [
        "../evil.dll",
        "a/../../evil.dll",
        "/abs/evil.dll",
        "\\abs\\evil.dll",
        "a\\..\\..\\evil.dll",
        "C:/evil.dll",
        "C:\\evil.dll",
        "c:evil.dll",
        "\\\\server\\share\\evil.dll",
        "a/evil.dll\0.txt",
        "a/con.dll",
        "a/evil.dll:stream",
        "a/evil.",
        "a/evil ",
        long.as_str(),
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let e = Env::new();
    let before = e.snapshot();
    for (i, n) in names.iter().enumerate() {
        let file = e.archive(
            &format!("z{i}"),
            &zip_of(&[Z::file("good.dll", b"G"), Z::file(n, b"EVIL")]),
        );
        // Both a plain selection of the good file and a prefix selection that would reach the hostile one.
        for extract in [&[("good.dll", "good.dll")][..], &[("a/", "x")][..]] {
            let err = install(&e, pkg(ArchiveFormat::Zip, extract), &file).unwrap_err();
            assert!(
                matches!(err, ArchiveError::Zip(_) | ArchiveError::NoMatch(_)),
                "{n:?}: {err:?}"
            );
        }
        assert_untouched(&e, &before, n);
    }
}

#[test]
fn hostile_tar_names_never_write_anything() {
    let names: Vec<Vec<u8>> = [
        "../evil.dll",
        "a/../../evil.dll",
        "/abs/evil.dll",
        "a\\..\\evil.dll",
        "C:/evil.dll",
        "c:evil.dll",
        "a/./evil.dll",
        "a//evil.dll",
        "a/evil.",
        "a/evil ",
        "a/\u{202e}lld.exe",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .chain([b"a/\xff.dll".to_vec(), vec![b'a'; 600]])
    .collect();
    let e = Env::new();
    let before = e.snapshot();
    for (i, n) in names.iter().enumerate() {
        let hostile = T {
            name: n.clone(),
            ..T::file("x", b"EVIL")
        };
        let file = e.archive(&format!("t{i}"), &targz_of(&[T::file("good.dll", b"G"), hostile]));
        let err = install(&e, pkg(ArchiveFormat::TarGz, &[("good.dll", "good.dll")]), &file)
            .expect_err(&String::from_utf8_lossy(n));
        assert!(matches!(err, ArchiveError::Tar(_)), "{n:?}: {err:?}");
        assert_untouched(&e, &before, &String::from_utf8_lossy(n));
    }
    // A ustar name field ends at its first NUL; a PAX `path` record can carry one.
    let pax = T {
        name: b"pax".to_vec(),
        data: b"24 path=a/evil.dll\0.txt\n".to_vec(),
        flag: b'x',
        mode: 0o644,
    };
    let file = e.archive(
        "pax",
        &targz_of(&[T::file("good.dll", b"G"), pax, T::file("x", b"EVIL")]),
    );
    let err = install(&e, pkg(ArchiveFormat::TarGz, &[("good.dll", "good.dll")]), &file).unwrap_err();
    assert!(matches!(err, ArchiveError::Tar(TarError::UnsafeName(_))), "{err:?}");
    assert_untouched(&e, &before, "NUL in a PAX path");
}

#[test]
fn names_the_tar_reader_accepts_but_windows_cannot_hold_are_refused_before_writing() {
    // A reserved device name and an over-long component pass the tar layer; mapping them onto drive_c fails.
    let e = Env::new();
    let before = e.snapshot();
    let long = format!("a/{}", "b".repeat(300));
    for (i, n) in ["a/con.dll", "a/NUL", long.as_str()].iter().enumerate() {
        let file = e.archive(
            &format!("t{i}"),
            &targz_of(&[T::file("a/good.dll", b"G"), T::file(n, b"EVIL")]),
        );
        let err = install(&e, pkg(ArchiveFormat::TarGz, &[("a/", "x")]), &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Destination(_)), "{n}: {err:?}");
        assert_untouched(&e, &before, n);
    }
}

#[test]
fn link_and_device_entries_are_refused() {
    let e = Env::new();
    let before = e.snapshot();
    for (i, mode) in [S_IFLNK | 0o777, S_IFCHR | 0o666, S_IFIFO | 0o644, 0o060_666, 0o140_666]
        .iter()
        .enumerate()
    {
        let file = e.archive(
            &format!("z{i}"),
            &zip_of(&[Z::file("good.dll", b"G"), Z::file("link", b"/etc/passwd").mode(*mode)]),
        );
        let err = install(&e, pkg(ArchiveFormat::Zip, &[("good.dll", "good.dll")]), &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Zip(_)), "{mode:o}: {err:?}");
    }
    for flag in *b"123467" {
        let file = e.archive(
            &format!("t{flag}"),
            &targz_of(&[T::file("good.dll", b"G"), T::special("link", flag)]),
        );
        let err = install(&e, pkg(ArchiveFormat::TarGz, &[("good.dll", "good.dll")]), &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Tar(_)), "{}: {err:?}", flag as char);
    }
    assert_untouched(&e, &before, "special entries");
}

#[test]
fn zip_and_gzip_bombs_are_refused_with_nothing_left() {
    let e = Env::new();
    let before = e.snapshot();
    let zeros = vec![0u8; 16 << 20];
    let zip = e.archive(
        "z",
        &zip_of(&[Z::file("good.dll", b"G"), Z::deflated("bomb.dll", &zeros)]),
    );
    let err = install(
        &e,
        pkg(
            ArchiveFormat::Zip,
            &[("good.dll", "good.dll"), ("bomb.dll", "bomb.dll")],
        ),
        &zip,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::Zip(_)), "{err:?}");
    let tar = e.archive(
        "t",
        &targz_of(&[T::file("good.dll", b"G"), T::file("bomb.dll", &zeros)]),
    );
    let err = install(
        &e,
        pkg(
            ArchiveFormat::TarGz,
            &[("good.dll", "good.dll"), ("bomb.dll", "bomb.dll")],
        ),
        &tar,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::Tar(_)), "{err:?}");
    assert_untouched(&e, &before, "bombs");
}

#[test]
fn the_zip_expansion_cap_and_ratio_guard_each_hold_on_their_own() {
    let e = Env::new();
    let before = e.snapshot();
    // Twenty 1 MiB zero entries: each is under the ratio floor, together they exceed 200 x the archive size.
    let mut many: Vec<Z> = (0..20)
        .map(|i| Z::deflated(&format!("z{i}.dll"), &[0u8; 1 << 20]))
        .collect();
    many.push(Z::file("good.dll", b"G"));
    let file = e.archive("many", &zip_of(&many));
    let err = install(&e, pkg(ArchiveFormat::Zip, &[("good.dll", "good.dll")]), &file).unwrap_err();
    assert!(
        matches!(&err, ArchiveError::Zip(m) if m.contains("in total")),
        "{err:?}"
    );
    // One 16 MiB zero entry padded with 200 KiB of incompressible data: within 200 x the archive size, but the
    // entry itself expands more than 200:1.
    let mut rng = Rng(7);
    let noise: Vec<u8> = (0..200 << 10).map(|_| rng.next() as u8).collect();
    let padded = zip_of(&[
        Z::file("noise.bin", &noise),
        Z::deflated("bomb.dll", &vec![0u8; 16 << 20]),
    ]);
    let file = e.archive("padded", &padded);
    let err = install(&e, pkg(ArchiveFormat::Zip, &[("noise.bin", "noise.bin")]), &file).unwrap_err();
    assert!(
        matches!(&err, ArchiveError::Zip(m) if m.contains("zip bomb")),
        "{err:?}"
    );
    assert_untouched(&e, &before, "zip caps");
}

#[test]
fn a_zip_with_more_than_4096_entries_is_refused() {
    let e = Env::new();
    let before = e.snapshot();
    let entries: Vec<Z> = (0..=4096).map(|i| Z::file(&format!("f{i}"), b"")).collect();
    let file = e.archive("many", &zip_of(&entries));
    let err = install(&e, pkg(ArchiveFormat::Zip, &[("f0", "f0")]), &file).unwrap_err();
    assert!(matches!(&err, ArchiveError::Zip(m) if m.contains("4096")), "{err:?}");
    assert_untouched(&e, &before, "entry cap");
}

#[test]
fn a_symlinked_backup_directory_is_refused() {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
    let outside = e.tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, e.env.root().join(BACKUP_DIR)).unwrap();
    let before = e.snapshot();
    let file = e.archive(
        "a",
        &files_in(ArchiveFormat::Zip, &[("a.dll", b"A"), ("d3d11.dll", b"D")]),
    );
    let p = pkg(
        ArchiveFormat::Zip,
        &[("a.dll", "new/a.dll"), ("d3d11.dll", "windows/system32/d3d11.dll")],
    );
    let err = install(&e, p, &file).unwrap_err();
    assert!(matches!(err, ArchiveError::Destination(_)), "{err:?}");
    assert_untouched(&e, &before, "symlinked deps-backup");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn remove_takes_recorded_directories_children_first_whatever_their_order() {
    let e = Env::new();
    fs::create_dir_all(e.c("x/y/z")).unwrap();
    let done = ArchiveInstalled {
        created_dirs: paths(&["x/y/z", "x", "x/y"]),
        ..ArchiveInstalled::default()
    };
    remove(&e, &done).unwrap();
    assert!(!e.c("x").exists());
}

#[test]
fn a_zip_entry_holding_less_or_more_than_it_declares_leaves_nothing() {
    let e = Env::new();
    let before = e.snapshot();
    for size in [1u32, 100] {
        let mut lie = Z::file("b.dll", b"0123456789");
        lie.size = size;
        let file = e.archive(&format!("z{size}"), &zip_of(&[Z::file("a.dll", b"A"), lie]));
        let err = install(
            &e,
            pkg(ArchiveFormat::Zip, &[("a.dll", "a.dll"), ("b.dll", "b.dll")]),
            &file,
        )
        .unwrap_err();
        assert!(
            matches!(err, ArchiveError::Zip(_) | ArchiveError::Io(_)),
            "{size}: {err:?}"
        );
        assert_untouched(&e, &before, "size lie");
    }
}

// ------------------------------------------------------------------------------------------------ destinations

#[test]
fn a_symlink_or_directory_at_a_destination_is_refused_and_nothing_else_is_written() {
    for format in FORMATS {
        let bytes = files_in(format, &[("a.dll", b"A"), ("b.dll", b"B")]);
        // (what, destination of b.dll); the first file goes to dst/a.dll and must be rolled back.
        for (what, to_b) in [
            ("symlink file", "dst/b.dll"),
            ("dangling symlink", "dst/b.dll"),
            ("directory", "dst/b.dll"),
            ("symlinked parent", "dst/sub/b.dll"),
        ] {
            let e = Env::new();
            let outside = e.tmp.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("target.dll"), b"OUTSIDE").unwrap();
            fs::create_dir(e.c("dst")).unwrap();
            match what {
                "symlink file" => symlink(outside.join("target.dll"), e.c("dst/b.dll")).unwrap(),
                "dangling symlink" => symlink("/nonexistent/x", e.c("dst/b.dll")).unwrap(),
                "directory" => fs::create_dir(e.c("dst/b.dll")).unwrap(),
                _ => symlink(&outside, e.c("dst/sub")).unwrap(),
            }
            let file = e.archive("a", &bytes);
            let before = e.snapshot();
            let err = install(&e, pkg(format, &[("a.dll", "dst/a.dll"), ("b.dll", to_b)]), &file).unwrap_err();
            assert!(
                matches!(err, ArchiveError::Destination(_)),
                "{format:?} {what}: {err:?}"
            );
            assert_untouched(&e, &before, what);
        }
    }
}

#[test]
fn an_existing_file_is_replaced_backed_up_and_restored_by_remove() {
    for format in FORMATS {
        let e = Env::new();
        put(&e.c("windows/system32/d3d11.dll"), b"WINE BUILTIN");
        let file = e.archive("a", &files_in(format, &[("x/d3d11.dll", b"DXVK")]));
        let done = install(&e, pkg(format, &[("x/d3d11.dll", "windows/system32/d3d11.dll")]), &file).unwrap();
        assert_eq!(fs::read(e.c("windows/system32/d3d11.dll")).unwrap(), b"DXVK");
        assert_eq!(done.replaced, paths(&["windows/system32/d3d11.dll"]));
        assert_eq!(done.files, paths(&["windows/system32/d3d11.dll"]));
        let backup = e.backup("dxvk", "windows/system32/d3d11.dll");
        assert_eq!(fs::read(&backup).unwrap(), b"WINE BUILTIN");
        assert_eq!(mode_of(&backup), 0o600);
        for d in ["", "/dxvk", "/dxvk/c", "/dxvk/c/windows", "/dxvk/c/windows/system32"] {
            let dir = PathBuf::from(format!("{}{d}", e.env.root().join(BACKUP_DIR).display()));
            assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
        }
        remove(&e, &done).unwrap();
        assert_eq!(fs::read(e.c("windows/system32/d3d11.dll")).unwrap(), b"WINE BUILTIN");
        assert!(!backup.exists());
        assert!(
            !e.env.root().join(BACKUP_DIR).join("dxvk").exists(),
            "empty backup dirs are pruned"
        );
    }
}

#[test]
fn a_backup_left_by_an_interrupted_install_is_kept_not_overwritten() {
    let e = Env::new();
    fs::write(e.c("windows/system32/d3d11.dll"), b"DXVK FROM A KILLED RUN").unwrap();
    let backup = e.backup("dxvk", "windows/system32/d3d11.dll");
    fs::create_dir_all(backup.parent().unwrap()).unwrap();
    fs::write(&backup, b"TRUE ORIGINAL").unwrap();
    let file = e.archive("a", &files_in(ArchiveFormat::Zip, &[("d3d11.dll", b"DXVK")]));
    let done = install(
        &e,
        pkg(ArchiveFormat::Zip, &[("d3d11.dll", "windows/system32/d3d11.dll")]),
        &file,
    )
    .unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"TRUE ORIGINAL");
    remove(&e, &done).unwrap();
    assert_eq!(fs::read(e.c("windows/system32/d3d11.dll")).unwrap(), b"TRUE ORIGINAL");
}

#[test]
fn remove_deletes_exactly_the_recorded_files_and_only_empty_created_dirs() {
    for format in FORMATS {
        let e = Env::new();
        fs::write(e.c("windows/system32/canary.dll"), b"C").unwrap();
        let file = e.archive(
            "a",
            &files_in(format, &[("a.dll", b"A"), ("b.dll", b"B"), ("c.dll", b"C")]),
        );
        let p = pkg(
            format,
            &[
                ("a.dll", "windows/system32/a.dll"),
                ("b.dll", "new1/x/b.dll"),
                ("c.dll", "new2/y/c.dll"),
            ],
        );
        let done = install(&e, p, &file).unwrap();
        assert_eq!(done.created_dirs, paths(&["new1", "new1/x", "new2", "new2/y"]));
        // Someone else puts a file in one of the created directories.
        fs::write(e.c("new2/y/user.txt"), b"U").unwrap();
        fs::write(e.c("new1/sibling.txt"), b"S").unwrap();
        remove(&e, &done).unwrap();
        let left: Vec<String> = snapshot(&e.env.drive_c()).into_keys().collect();
        assert_eq!(
            left,
            [
                "new1",
                "new1/sibling.txt",
                "new2",
                "new2/y",
                "new2/y/user.txt",
                "windows",
                "windows/system32",
                "windows/system32/canary.dll",
                "windows/system32/reg.exe"
            ],
            "{format:?}"
        );
        // Removing again is harmless (idempotent for files and directories).
        remove(&e, &done).unwrap();
    }
}

#[test]
fn file_and_directory_modes_are_fixed_whatever_the_archive_says() {
    for format in FORMATS {
        let e = Env::new();
        let bytes = match format {
            ArchiveFormat::Zip => zip_of(&[
                Z::dir("d/").mode(S_IFDIR | 0o7777),
                Z::file("d/suid.dll", b"S").mode(S_IFREG | 0o4755),
                Z::file("d/all.dll", b"A").mode(S_IFREG | 0o7777),
                Z::file("d/none.dll", b"N").mode(S_IFREG),
            ]),
            ArchiveFormat::TarGz => targz_of(&[
                T::dir("d").mode(0o7777),
                T::file("d/suid.dll", b"S").mode(0o4755),
                T::file("d/all.dll", b"A").mode(0o7777),
                T::file("d/none.dll", b"N").mode(0),
            ]),
        };
        let file = e.archive("a", &bytes);
        let done = install(&e, pkg(format, &[("d/", "new/sub")]), &file).unwrap();
        for f in &done.files {
            assert_eq!(mode_of(&e.env.drive_c().join(f)), 0o644, "{format:?} {}", f.display());
        }
        for d in &done.created_dirs {
            assert_eq!(mode_of(&e.env.drive_c().join(d)), 0o755, "{format:?} {}", d.display());
        }
        assert_eq!(done.files.len(), 3);
    }
}

#[test]
fn two_prefixes_sharing_one_archive_are_independent() {
    for format in FORMATS {
        let (a, b) = (Env::named("one"), Env::named("two"));
        let file = a.archive("shared", &files_in(format, &[("x.dll", b"X")]));
        let p = pkg(format, &[("x.dll", "windows/system32/x.dll")]);
        let da = install(&a, p.clone(), &file).unwrap();
        let db = install(&b, p, &file).unwrap();
        assert_eq!(da, db);
        remove(&a, &da).unwrap();
        assert!(!a.c("windows/system32/x.dll").exists());
        assert_eq!(fs::read(b.c("windows/system32/x.dll")).unwrap(), b"X");
    }
}

#[test]
fn the_archive_file_is_opened_read_only_and_never_changed() {
    for format in FORMATS {
        let e = Env::new();
        let bytes = files_in(format, &[("x.dll", b"X")]);
        let file = e.archive("a", &bytes);
        // Read-only on disk: opening it for writing would fail (the tests do not run as root).
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        let mtime = fs::metadata(&file).unwrap().modified().unwrap();
        install(&e, pkg(format, &[("x.dll", "x.dll")]), &file).unwrap();
        assert_eq!(fs::read(&file).unwrap(), bytes);
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), mtime);
        assert_eq!(mode_of(&file), 0o444);
    }
}

// ------------------------------------------------------------------------------------------------ bad input

#[test]
fn unusable_packages_and_archive_paths_are_refused() {
    let e = Env::new();
    let file = e.archive("a", &files_in(ArchiveFormat::Zip, &[("x.dll", b"X")]));
    let size = fs::metadata(&file).unwrap().len();
    let good = || {
        let mut p = pkg(ArchiveFormat::Zip, &[("x.dll", "x.dll")]);
        p.size = size;
        p
    };
    let run = |p: &Package, f: &Path| install_archive(p, f, &e.env, &FakeBackend::new(), &launcher());
    let mut cases: Vec<(&str, Package)> = Vec::new();
    let mut p = good();
    p.kind = Kind::Installer;
    cases.push(("kind", p));
    let mut p = good();
    p.install = Install::Installer {
        silent_args: vec![],
        marker: crate::manifest::Marker::File("x".into()),
        dll_overrides: vec![],
    };
    p.kind = Kind::Installer;
    cases.push(("install", p));
    for sha in ["", "../../x", &HASH.to_uppercase()] {
        let mut p = good();
        p.sha256 = sha.into();
        cases.push(("sha256", p));
    }
    for s in [0, size + 1, size - 1, crate::manifest::MAX_PACKAGE_SIZE + 1] {
        let mut p = good();
        p.size = s;
        cases.push(("size", p));
    }
    for id in ["", "../x", "A", "a/b"] {
        let mut p = good();
        p.id = id.into();
        cases.push(("id", p));
    }
    for (from, to) in [
        ("../x.dll", "x.dll"),
        ("x.dll", "../x.dll"),
        ("x.dll", "/etc/x"),
        ("x.dll", "C:/x"),
        ("x.dll", "a/"),
    ] {
        let mut p = good();
        p.install = pkg(ArchiveFormat::Zip, &[(from, to)]).install;
        cases.push(("path", p));
    }
    let mut p = good();
    p.install = pkg(ArchiveFormat::Zip, &[]).install;
    cases.push(("empty extract", p));
    let link = e.tmp.path().join("link.zip");
    symlink(&file, &link).unwrap();
    let before = e.snapshot();
    for (what, p) in &cases {
        let err = run(p, &file).unwrap_err();
        assert!(matches!(err, ArchiveError::BadPackage(_)), "{what} {p:?}: {err:?}");
    }
    // The archive itself: a symlink to it, a directory, a missing file.
    for f in [link.as_path(), e.tmp.path()] {
        let err = run(&good(), f).unwrap_err();
        assert!(matches!(err, ArchiveError::BadPackage(_)), "{}: {err:?}", f.display());
    }
    let err = run(&good(), &e.tmp.path().join("missing.zip")).unwrap_err();
    assert!(matches!(err, ArchiveError::Io(_)), "{err:?}");
    // An empty archive with a declared size of 0 is refused as a package, before the archive is read.
    let empty = e.tmp.path().join("empty.zip");
    File::create(&empty).unwrap();
    let mut p = good();
    p.size = 0;
    let err = run(&p, &empty).unwrap_err();
    assert!(matches!(err, ArchiveError::BadPackage(_)), "{err:?}");
    fs::remove_file(&empty).unwrap();
    assert_eq!(e.snapshot(), before);
    run(&good(), &file).unwrap();
}

// ------------------------------------------------------------------------------------------------ DLL overrides

/// A backend that records `settle` calls and otherwise delegates to a [`FakeBackend`].
struct Settling {
    inner: FakeBackend,
    settled: Mutex<Vec<Vec<OsString>>>,
}

impl Settling {
    fn new(script: &str) -> Settling {
        Settling {
            inner: FakeBackend::with_script(script),
            settled: Mutex::new(Vec::new()),
        }
    }
    /// The argv (after the program) of each `reg.exe` command, in order.
    fn reg_calls(&self) -> Vec<Vec<String>> {
        self.inner
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Command { exe, args, cwd, .. } => {
                    assert!(exe.ends_with("windows/system32/reg.exe"), "{}", exe.display());
                    assert!(cwd.ends_with("drive_c"), "{}", cwd.display());
                    Some(args.iter().map(|a| a.to_string_lossy().into_owned()).collect())
                }
                _ => None,
            })
            .collect()
    }
}

impl CompatBackend for Settling {
    fn id(&self) -> &'static str {
        "settling"
    }
    fn version(&self) -> Result<String, rt_core::BackendError> {
        self.inner.version()
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), rt_core::BackendError> {
        self.inner.prepare(env)
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<std::process::Command, rt_core::BackendError> {
        self.inner.command(env, exe, cwd, args, opts)
    }
    fn stop(&self, env: &AppEnv) -> Result<(), rt_core::BackendError> {
        self.inner.stop(env)
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn settle(&self, cmd: std::process::Command) -> std::process::Command {
        self.settled
            .lock()
            .unwrap()
            .push(cmd.get_args().map(OsStr::to_owned).collect());
        cmd
    }
}

fn add(name: &str) -> Vec<String> {
    [
        "add",
        r"HKCU\Software\Wine\DllOverrides",
        "/v",
        name,
        "/d",
        "native,builtin",
        "/f",
    ]
    .map(String::from)
    .to_vec()
}

fn del(name: &str) -> Vec<String> {
    ["delete", r"HKCU\Software\Wine\DllOverrides", "/v", name, "/f"]
        .map(String::from)
        .to_vec()
}

fn query(name: &str) -> Vec<String> {
    ["query", r"HKCU\Software\Wine\DllOverrides", "/v", name]
        .map(String::from)
        .to_vec()
}

#[test]
fn overrides_run_reg_add_with_the_exact_argv_through_settle() {
    let e = Env::new();
    let file = e.archive(
        "a",
        &files_in(ArchiveFormat::Zip, &[("d3d11.dll", b"D"), ("dxgi.dll", b"X")]),
    );
    let p = pkg_with(
        ArchiveFormat::Zip,
        &[
            ("d3d11.dll", "windows/system32/d3d11.dll"),
            ("dxgi.dll", "windows/system32/dxgi.dll"),
        ],
        &["d3d11", "dxgi"],
        &["d3d11", "dxgi", "d3d10core"],
    );
    let b = Settling::new("exit 0");
    let done = install_with(&e, p, &file, &b).unwrap();
    assert_eq!(done.overrides, ["d3d11", "dxgi"]);
    assert_eq!(b.reg_calls(), [add("d3d11"), add("dxgi")]);
    // Every reg command was wrapped by `settle` (so wineserver flushes the registry before the call returns).
    assert_eq!(b.settled.lock().unwrap().len(), 2);
    // remove deletes the overrides with the exact argv, again through settle.
    remove_archive(&done, "dxvk", &e.env, &b, &launcher()).unwrap();
    assert_eq!(b.reg_calls()[2..], [del("dxgi"), del("d3d11")], "newest first");
    assert_eq!(b.settled.lock().unwrap().len(), 4);
    assert!(!e.c("windows/system32/d3d11.dll").exists());
}

#[test]
fn a_failing_reg_add_rolls_back_files_backups_and_earlier_overrides() {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
    let before = e.snapshot();
    let file = e.archive(
        "a",
        &files_in(ArchiveFormat::TarGz, &[("d3d11.dll", b"D"), ("dxgi.dll", b"X")]),
    );
    let p = pkg_with(
        ArchiveFormat::TarGz,
        &[
            ("d3d11.dll", "windows/system32/d3d11.dll"),
            ("dxgi.dll", "new/dxgi.dll"),
        ],
        &["d3d11", "dxgi"],
        &["d3d11", "dxgi"],
    );
    // `$1` is the verb, `$4` the value name: adding dxgi fails, everything else succeeds.
    let b = Settling::new(r#"[ "$1" = add ] && [ "$4" = dxgi ] && exit 5; exit 0"#);
    let err = install_with(&e, p, &file, &b).unwrap_err();
    assert!(
        matches!(&err, ArchiveError::Registry(m) if m.contains("dxgi")),
        "{err:?}"
    );
    // The failed name is deleted too (reg may have written it before failing), newest first.
    assert_eq!(b.reg_calls(), [add("d3d11"), add("dxgi"), del("dxgi"), del("d3d11")]);
    assert_untouched(&e, &before, "registry rollback");
}

#[test]
fn a_reg_delete_failure_is_an_error_unless_the_value_is_already_gone() {
    let e = Env::new();
    let done = ArchiveInstalled {
        overrides: vec!["d3d11".into()],
        ..ArchiveInstalled::default()
    };
    // delete fails, query says the value is absent: already removed, fine.
    let b = Settling::new(r#"[ "$1" = add ] && exit 0; exit 1"#);
    remove_archive(&done, "dxvk", &e.env, &b, &launcher()).unwrap();
    assert_eq!(b.reg_calls(), [del("d3d11"), query("d3d11")]);
    // delete fails and the value is still there: an error.
    let b = Settling::new(r#"[ "$1" = delete ] && exit 1; exit 0"#);
    let err = remove_archive(&done, "dxvk", &e.env, &b, &launcher()).unwrap_err();
    assert!(matches!(err, ArchiveError::Registry(_)), "{err:?}");
}

#[test]
fn an_override_not_in_provides_is_refused_before_anything_runs() {
    for format in FORMATS {
        let e = Env::new();
        let file = e.archive("a", &files_in(format, &[("d3d11.dll", b"D")]));
        let before = e.snapshot();
        let p = pkg_with(format, &[("d3d11.dll", "d3d11.dll")], &["d3d11", "dxgi"], &["d3d11"]);
        let b = Settling::new("exit 0");
        let err = install_with(&e, p, &file, &b).unwrap_err();
        assert!(matches!(&err, ArchiveError::NotInProvides(n) if n == "dxgi"), "{err:?}");
        assert!(b.inner.calls().is_empty());
        assert_eq!(e.snapshot(), before);
    }
}

#[test]
fn bad_override_names_are_refused_even_when_provided() {
    let e = Env::new();
    let file = e.archive("a", &files_in(ArchiveFormat::Zip, &[("d3d11.dll", b"D")]));
    let long = "a".repeat(33);
    for name in [
        "d3d11;calc",
        "../x",
        "D3D11",
        "",
        long.as_str(),
        "d3d\0",
        "d3d11.dll",
        "a b",
        "-f",
        "d3d11-x",
        "é",
    ] {
        let p = pkg_with(ArchiveFormat::Zip, &[("d3d11.dll", "d3d11.dll")], &[name], &[name]);
        let b = Settling::new("exit 0");
        let err = install_with(&e, p, &file, &b).unwrap_err();
        assert!(matches!(err, ArchiveError::BadOverrideName(_)), "{name:?}: {err:?}");
        assert!(b.inner.calls().is_empty());
    }
    // The same name twice would be deleted twice on rollback: refused too.
    let p = pkg_with(
        ArchiveFormat::Zip,
        &[("d3d11.dll", "d3d11.dll")],
        &["d3d11", "d3d11"],
        &["d3d11"],
    );
    assert!(matches!(install(&e, p, &file), Err(ArchiveError::BadOverrideName(_))));
    // 32 characters of the allowed set are fine.
    let ok = "a_1".repeat(10) + "zz";
    let p = pkg_with(ArchiveFormat::Zip, &[("d3d11.dll", "d3d11.dll")], &[&ok], &[&ok]);
    assert_eq!(install(&e, p, &file).unwrap().overrides, [ok]);
}

// ------------------------------------------------------------------------------------------------ rollback

#[test]
fn a_failure_halfway_rolls_back_everything_this_call_wrote() {
    for format in FORMATS {
        let e = Env::new();
        put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
        // The third destination is blocked by a directory.
        fs::create_dir_all(e.c("blocked/c.dll")).unwrap();
        let before = e.snapshot();
        let file = e.archive(
            "a",
            &files_in(format, &[("a.dll", b"A"), ("b.dll", b"B"), ("c.dll", b"C")]),
        );
        let p = pkg(
            format,
            &[
                ("a.dll", "windows/system32/d3d11.dll"),
                ("b.dll", "new/deep/b.dll"),
                ("c.dll", "blocked/c.dll"),
            ],
        );
        let err = install(&e, p, &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Destination(_)), "{format:?}: {err:?}");
        assert_untouched(&e, &before, "blocked third file");
    }
}

#[test]
fn a_corrupt_third_zip_entry_rolls_back_the_first_two() {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
    let before = e.snapshot();
    let mut bad = Z::file("c.dll", b"CCCC");
    bad.crc ^= 1;
    let file = e.archive("a", &zip_of(&[Z::file("a.dll", b"A"), Z::file("b.dll", b"B"), bad]));
    let p = pkg(
        ArchiveFormat::Zip,
        &[
            ("a.dll", "windows/system32/d3d11.dll"),
            ("b.dll", "new/b.dll"),
            ("c.dll", "new/c.dll"),
        ],
    );
    let err = install(&e, p, &file).unwrap_err();
    assert!(matches!(err, ArchiveError::Zip(_) | ArchiveError::Io(_)), "{err:?}");
    assert_untouched(&e, &before, "corrupt zip entry");
}

#[test]
fn a_corrupt_third_tar_entry_writes_nothing() {
    let e = Env::new();
    let before = e.snapshot();
    let mut tar = tar_of(&[T::file("a.dll", b"A"), T::file("b.dll", b"B"), T::file("c.dll", b"C")]);
    tar[4 * 512 + 148] ^= 1; // the third header's checksum
    let file = e.archive("a", &gzip(&tar));
    let p = pkg(
        ArchiveFormat::TarGz,
        &[("a.dll", "a.dll"), ("b.dll", "b.dll"), ("c.dll", "c.dll")],
    );
    let err = install(&e, p, &file).unwrap_err();
    assert!(matches!(err, ArchiveError::Tar(_)), "{err:?}");
    assert_untouched(&e, &before, "corrupt tar entry");
}

#[test]
fn a_rollback_failure_is_reported_with_the_original_error() {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
    let file = e.archive("a", &files_in(ArchiveFormat::Zip, &[("a.dll", b"A")]));
    let p = pkg_with(
        ArchiveFormat::Zip,
        &[("a.dll", "windows/system32/d3d11.dll")],
        &["d3d11"],
        &["d3d11"],
    );
    // reg add fails; the script also deletes the backup, so restoring the original fails.
    let script = format!(
        r#"[ "$1" = add ] && rm -f '{}' && exit 3; exit 0"#,
        e.backup("dxvk", "windows/system32/d3d11.dll").display()
    );
    let err = install_with(&e, p, &file, &FakeBackend::with_script(&script)).unwrap_err();
    let ArchiveError::Rollback(msg) = &err else {
        panic!("{err:?}")
    };
    assert!(msg.contains("d3d11") && msg.contains("reg"), "{msg}");
}

// ------------------------------------------------------------------------------------------------ recorded state

#[test]
fn installed_records_round_trip_and_hostile_ones_are_refused_by_remove() {
    let done = ArchiveInstalled {
        files: paths(&["windows/system32/d3d11.dll"]),
        replaced: paths(&["windows/system32/d3d11.dll"]),
        created_dirs: paths(&["x"]),
        overrides: vec!["d3d11".into()],
    };
    let json = serde_json::to_string(&done).unwrap();
    assert_eq!(serde_json::from_str::<ArchiveInstalled>(&json).unwrap(), done);
    let e = Env::new();
    fs::write(e.tmp.path().join("victim"), b"V").unwrap();
    let before = e.snapshot();
    let bad = |f: ArchiveInstalled| {
        let err = remove(&e, &f).unwrap_err();
        assert!(matches!(err, ArchiveError::BadPackage(_)), "{f:?}: {err:?}");
    };
    for p in ["../../../../victim", "/etc/passwd", "a/../../x", "", "a\\..\\x", "con"] {
        bad(ArchiveInstalled {
            files: paths(&[p]),
            ..ArchiveInstalled::default()
        });
        bad(ArchiveInstalled {
            created_dirs: paths(&[p]),
            ..ArchiveInstalled::default()
        });
    }
    bad(ArchiveInstalled {
        files: paths(&["y"]),
        replaced: paths(&["x"]),
        ..ArchiveInstalled::default()
    });
    bad(ArchiveInstalled {
        overrides: vec!["d3d11;calc".into()],
        ..ArchiveInstalled::default()
    });
    bad(ArchiveInstalled {
        files: vec![PathBuf::from("x"); MAX_ENTRIES + 1],
        ..ArchiveInstalled::default()
    });
    let err = remove_archive(
        &ArchiveInstalled::default(),
        "../x",
        &e.env,
        &FakeBackend::new(),
        &launcher(),
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::BadPackage(_)), "{err:?}");
    assert_eq!(e.snapshot(), before);
}

// ------------------------------------------------------------------------------------------------ fuzz

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(rng: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    for _ in 0..=rng.below(4) {
        match rng.below(5) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0, 0xff, b'/', b'.', b'\\', b':', 0x7f][rng.below(7)];
            }
            2 => {
                let at = rng.below(b.len() + 1);
                b.truncate(at);
            }
            3 => {
                let at = rng.below(b.len() + 1);
                let n = rng.below(16);
                b.splice(at..at, (0..n).map(|_| rng.next() as u8));
            }
            _ if b.len() > 8 => {
                let (i, j) = (rng.below(b.len()), rng.below(b.len()));
                b.swap(i, j);
            }
            _ => {}
        }
    }
    b
}

/// Mutated archives (raw bytes, and for tar.gz also the tar stream before compression) never panic, never touch
/// anything outside drive_c and the backup directory, leave drive_c as it was on error and are fully removable
/// on success.
fn fuzz(format: ArchiveFormat, seed: u64) {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL");
    let tars = [
        T::file("dxvk/x64/d3d11.dll", b"D3D11"),
        T::file("dxvk/x64/dxgi.dll", b"DXGI"),
        T::dir("dxvk/x32"),
        T::file("dxvk/x32/d3d11.dll", b"32"),
    ];
    let zips = [
        Z::file("dxvk/x64/d3d11.dll", b"D3D11"),
        Z::deflated("dxvk/x64/dxgi.dll", b"DXGIDXGIDXGIDXGI"),
        Z::dir("dxvk/x32/"),
        Z::file("dxvk/x32/d3d11.dll", b"32"),
    ];
    let p = pkg(
        format,
        &[
            ("dxvk/x64/d3d11.dll", "windows/system32/d3d11.dll"),
            ("dxvk/x64/dxgi.dll", "new/x64/dxgi.dll"),
            ("dxvk/x32/", "new/x32"),
        ],
    );
    let base = e.snapshot();
    let drive_c = snapshot(&e.env.drive_c());
    let outside = |s: &BTreeMap<String, String>| {
        let mut s = s.clone();
        let c = e.env.drive_c();
        let c = c.strip_prefix(e.tmp.path()).unwrap().to_string_lossy().into_owned();
        s.retain(|k, _| !k.starts_with(&c) && !k.starts_with("cache") && !k.contains(BACKUP_DIR));
        s
    };
    let mut rng = Rng(seed);
    let (mut ok, mut failed) = (0, 0);
    for i in 0..5000 {
        let bytes = match (format, i % 2) {
            (ArchiveFormat::Zip, _) => mutate(&mut rng, zip_of(&zips)),
            (ArchiveFormat::TarGz, 0) => mutate(&mut rng, targz_of(&tars)),
            (ArchiveFormat::TarGz, _) => gzip(&mutate(&mut rng, tar_of(&tars))),
        };
        if bytes.is_empty() {
            continue;
        }
        let file = e.archive("fuzz", &bytes);
        match install(&e, p.clone(), &file) {
            Ok(done) => {
                ok += 1;
                remove(&e, &done).unwrap_or_else(|err| panic!("iteration {i}: remove failed: {err}"));
            }
            Err(_) => failed += 1,
        }
        assert_eq!(snapshot(&e.env.drive_c()), drive_c, "iteration {i}: drive_c changed");
        assert_eq!(
            outside(&e.snapshot()),
            outside(&base),
            "iteration {i}: something outside changed"
        );
    }
    assert!(ok > 50 && failed > 50, "{format:?}: ok {ok}, failed {failed}");
}

#[test]
fn fuzz_zip() {
    fuzz(ArchiveFormat::Zip, 0x5eed_0001);
}

#[test]
fn fuzz_tar_gz() {
    fuzz(ArchiveFormat::TarGz, 0x5eed_0002);
}

// ------------------------------------------------------------------------------------------------ real Wine

/// Real Wine 10.0: `sh tools/build-fixtures.sh` first, then
/// `cargo test -p runtime-deps --lib install_archive -- --ignored --nocapture`.
#[test]
#[ignore = "needs Wine and the mingw fixtures"]
fn e2e_real_wine_zip_and_tar_gz_with_a_dll_override() {
    use backend_wine::WineBackend;
    let dll = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build/exports64.dll");
    let dll = fs::read(&dll).expect("fixture missing: run sh tools/build-fixtures.sh");
    for format in FORMATS {
        let launcher = Launcher::new();
        let backend = WineBackend::discover_with(launcher.clone()).expect("Wine must be installed");
        let scratch = Path::new("/tmp/claude-1000");
        fs::create_dir_all(scratch).unwrap();
        let tmp = tempfile::tempdir_in(scratch).unwrap();
        let env = Store::new(tmp.path().join("apps"))
            .unwrap()
            .create(&AppId::parse("e2e").unwrap())
            .unwrap();
        backend.prepare(&env).unwrap();
        let bytes = files_in(format, &[("pkg-1.0/x64/exports64.dll", &dll), ("pkg-1.0/README", b"r")]);
        let file = tmp.path().join("pkg");
        fs::write(&file, &bytes).unwrap();
        let mut p = pkg_with(
            format,
            &[("pkg-1.0/x64/", "windows/system32")],
            &["exports64"],
            &["exports64"],
        );
        p.id = "exports".into();
        p.size = bytes.len() as u64;
        let started = std::time::Instant::now();
        let done = install_archive(&p, &file, &env, &backend, &launcher).unwrap();
        eprintln!("{format:?}: installed in {:?}: {done:?}", started.elapsed());
        let installed = env.drive_c().join("windows/system32/exports64.dll");
        assert_eq!(fs::read(&installed).unwrap(), dll, "byte-identical");
        let wait_no_server = |what: &str| {
            let t = std::time::Instant::now();
            while std::process::Command::new("pgrep")
                .args(["-f", "wineserver"])
                .output()
                .map(|o| {
                    // Only this prefix's server: its environment names our WINEPREFIX.
                    String::from_utf8_lossy(&o.stdout).lines().any(|pid| {
                        fs::read(format!("/proc/{}/environ", pid.trim())).is_ok_and(|env_b| {
                            let want = format!("WINEPREFIX={}", env.prefix().display());
                            env_b.split(|b| *b == 0).any(|v| v == want.as_bytes())
                        })
                    })
                })
                .unwrap_or(false)
            {
                assert!(
                    t.elapsed() < std::time::Duration::from_secs(15),
                    "wineserver still running after {what}"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            eprintln!(
                "{format:?}: no wineserver for the prefix {:?} after {what}",
                t.elapsed()
            );
        };
        wait_no_server("install");
        let user_reg = fs::read_to_string(env.prefix().join("user.reg")).unwrap();
        let section = user_reg
            .split("\n\n")
            .find(|s| s.starts_with("[Software\\\\Wine\\\\DllOverrides]"))
            .expect("DllOverrides section");
        eprintln!("{format:?}: user.reg after install:\n{section}");
        assert!(section.contains("\"exports64\"=\"native,builtin\""), "{section}");
        remove_archive(&done, &p.id, &env, &backend, &launcher).unwrap();
        wait_no_server("remove");
        assert!(!installed.exists());
        let user_reg = fs::read_to_string(env.prefix().join("user.reg")).unwrap();
        assert!(!user_reg.contains("\"exports64\""), "override still present");
        eprintln!("{format:?}: removed; exports64 absent from user.reg");
        backend.stop(&env).unwrap();
    }
}

/// The BUNDLED dxvk, downloaded for real and installed into a fresh real Wine 10.0 prefix: the real upstream
/// tarball passes the bounded tar reader, every declared DLL lands (replacing Wine's builtin placeholder) with its
/// override set, and removal restores the placeholders. Needs network, so CI's `e2e_real_wine` filter skips it:
/// `cargo test -p runtime-deps --lib real_net_wine -- --ignored --nocapture`.
#[test]
#[ignore = "needs network and Wine"]
fn real_net_wine_bundled_dxvk_installs_and_removes() {
    use backend_wine::WineBackend;
    let p = crate::Manifest::bundled().get("dxvk").expect("bundled dxvk");
    let Install::Archive { extract, .. } = &p.install else {
        panic!("dxvk is not an archive package")
    };
    let tmp = tempfile::tempdir().unwrap();
    let file = crate::fetch::fetch(p, &tmp.path().join("cache"), &crate::fetch::FetchOpts::default()).unwrap();
    let launcher = Launcher::new();
    let backend = WineBackend::discover_with(launcher.clone()).expect("Wine must be installed");
    let env = Store::new(tmp.path().join("apps"))
        .unwrap()
        .create(&AppId::parse("dxvk").unwrap())
        .unwrap();
    backend.prepare(&env).unwrap();
    backend.stop(&env).unwrap();
    let before: Vec<Vec<u8>> = extract
        .iter()
        .map(|e| fs::read(env.drive_c().join(&e.to)).unwrap())
        .collect();
    let done = install_archive(p, &file, &env, &backend, &launcher).unwrap();
    eprintln!("dxvk: {done:?}");
    assert_eq!(done.overrides, p.provides);
    assert_eq!(done.files.len(), extract.len());
    for (e, old) in extract.iter().zip(&before) {
        let now = fs::read(env.drive_c().join(&e.to)).unwrap();
        assert!(now != *old && now.starts_with(b"MZ"), "{} not replaced", e.to);
    }
    backend.stop(&env).unwrap();
    let user_reg = fs::read_to_string(env.prefix().join("user.reg")).unwrap();
    for name in &p.provides {
        assert!(user_reg.contains(&format!("\"{name}\"=\"native,builtin\"")), "{name}");
    }
    remove_archive(&done, &p.id, &env, &backend, &launcher).unwrap();
    for (e, old) in extract.iter().zip(&before) {
        assert_eq!(
            fs::read(env.drive_c().join(&e.to)).unwrap(),
            *old,
            "{} not restored",
            e.to
        );
    }
    backend.stop(&env).unwrap();
}

// ------------------------------------------------------------------------------------------------ interrupted installs

/// Runs `install` and simulates SIGKILL after `steps` steps (a panic that skips every rollback): 0 = right after the
/// journal was created, n = right after the n-th file was written.
fn crash_install(e: &Env, p: Package, file: &Path, steps: u32) {
    CRASH_AFTER.with(|c| c.set(Some(steps)));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| install(e, p, file)));
    CRASH_AFTER.with(|c| c.set(None));
    assert!(r.is_err(), "the simulated crash did not happen (step {steps})");
}

/// An original `d3d11.dll` (replaced first), two new files below a new directory tree, and an original `dxgi.dll`
/// that is replaced last.
fn interrupted_fixture(format: ArchiveFormat) -> (Env, Package, PathBuf, BTreeMap<String, String>) {
    let e = Env::new();
    put(&e.c("windows/system32/d3d11.dll"), b"ORIGINAL D3D11");
    put(&e.c("windows/system32/dxgi.dll"), b"ORIGINAL DXGI");
    let before = e.snapshot();
    let file = e.archive(
        "a",
        &files_in(
            format,
            &[
                ("x/d3d11.dll", b"PKG D3D11"),
                ("x/new/a.dll", b"PKG A"),
                ("x/new/sub/b.dll", b"PKG B"),
                ("x/zz/dxgi.dll", b"PKG DXGI"),
            ],
        ),
    );
    let p = pkg(
        format,
        &[
            ("x/d3d11.dll", "windows/system32/d3d11.dll"),
            ("x/new/", "newdir/deep"),
            ("x/zz/dxgi.dll", "windows/system32/dxgi.dll"),
        ],
    );
    (e, p, file, before)
}

#[test]
fn a_retry_after_a_killed_install_tracks_the_killed_runs_files_as_its_own() {
    for format in FORMATS {
        for steps in 0..=4 {
            let (e, p, file, before) = interrupted_fixture(format);
            crash_install(&e, p.clone(), &file, steps);
            assert!(
                e.journal().is_file(),
                "{format:?} {steps}: the journal is written before the first file"
            );
            let done = install(&e, p, &file).unwrap_or_else(|err| panic!("{format:?} {steps}: {err}"));
            let what = format!("{format:?} crash after {steps}");
            assert_eq!(
                done.replaced,
                paths(&["windows/system32/d3d11.dll", "windows/system32/dxgi.dll"]),
                "{what}: only the genuine originals are replaced"
            );
            let mut files = done.files.clone();
            files.sort();
            assert_eq!(
                files,
                paths(&[
                    "newdir/deep/a.dll",
                    "newdir/deep/sub/b.dll",
                    "windows/system32/d3d11.dll",
                    "windows/system32/dxgi.dll"
                ]),
                "{what}"
            );
            let mut dirs = done.created_dirs.clone();
            dirs.sort();
            assert_eq!(dirs, paths(&["newdir", "newdir/deep", "newdir/deep/sub"]), "{what}");
            assert_eq!(
                fs::read(e.backup("dxvk", "windows/system32/d3d11.dll")).unwrap(),
                b"ORIGINAL D3D11"
            );
            assert_eq!(
                fs::read(e.backup("dxvk", "windows/system32/dxgi.dll")).unwrap(),
                b"ORIGINAL DXGI"
            );
            remove(&e, &done).unwrap();
            // Everything the killed run and the retry did is gone: files, directories, backups and the journal.
            assert_untouched(&e, &before, &what);
        }
    }
}

#[test]
fn a_failed_retry_after_a_killed_install_rolls_back_the_killed_runs_work_too() {
    for format in FORMATS {
        for steps in [0, 2, 3] {
            let (e, mut p, file, before) = interrupted_fixture(format);
            crash_install(&e, p.clone(), &file, steps);
            if let Install::Archive { dll_overrides, .. } = &mut p.install {
                dll_overrides.push("d3d11".into());
            }
            let err = install_with(&e, p, &file, &FakeBackend::with_script("exit 1")).unwrap_err();
            assert!(matches!(err, ArchiveError::Registry(_)), "{err:?}");
            assert_untouched(&e, &before, &format!("{format:?} crash after {steps}, failed retry"));
        }
    }
    // A retry that fails BEFORE it rewrites the killed run's files (a truncated archive) still removes them.
    for format in FORMATS {
        let (e, p, file, before) = interrupted_fixture(format);
        crash_install(&e, p.clone(), &file, 3);
        let bytes = fs::read(&file).unwrap();
        let truncated = e.archive("truncated", &bytes[..bytes.len() - 20]);
        let err = install(&e, p, &truncated).unwrap_err();
        assert!(matches!(err, ArchiveError::Zip(_) | ArchiveError::Tar(_)), "{err:?}");
        assert_untouched(&e, &before, &format!("{format:?} truncated retry"));
    }
}

#[test]
fn a_file_that_existed_before_without_a_journal_entry_is_a_genuine_original() {
    // The reviewer's case without a journal: a file nobody recorded is backed up, restored and kept.
    let e = Env::new();
    put(&e.c("windows/system32/newdep.dll"), b"SOMEONE ELSE'S");
    let before = e.snapshot();
    let file = e.archive("a", &files_in(ArchiveFormat::TarGz, &[("newdep.dll", b"PKG")]));
    let done = install(
        &e,
        pkg(ArchiveFormat::TarGz, &[("newdep.dll", "windows/system32/newdep.dll")]),
        &file,
    )
    .unwrap();
    assert_eq!(done.replaced, paths(&["windows/system32/newdep.dll"]));
    remove(&e, &done).unwrap();
    assert_untouched(&e, &before, "genuine original");
}

#[test]
fn a_torn_last_journal_line_is_dropped() {
    let (e, p, file, _) = interrupted_fixture(ArchiveFormat::Zip);
    fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
    fs::write(e.journal(), format!("rt-deps-journal 1 {HASH}\nF newdir/deep/a.d")).unwrap();
    install(&e, p, &file).unwrap();
}

#[test]
fn a_bad_journal_is_a_typed_error_and_nothing_is_written() {
    let header = format!("rt-deps-journal 1 {HASH}\n");
    let other = format!("rt-deps-journal 1 {}\n", "f".repeat(64));
    let huge = header.clone() + &"F a\n".repeat(2 << 20);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"hello\n".to_vec()),
        ("empty", vec![]),
        ("torn header", header.trim_end().as_bytes().to_vec()),
        ("other archive", other.into_bytes()),
        ("unknown kind", format!("{header}X a.dll\n").into_bytes()),
        ("traversal", format!("{header}F ../../victim\n").into_bytes()),
        ("absolute", format!("{header}F /etc/passwd\n").into_bytes()),
        ("reserved", format!("{header}D con\n").into_bytes()),
        ("empty path", format!("{header}F \n").into_bytes()),
        ("not utf-8", [header.as_bytes(), b"F \xff\n"].concat()),
        ("oversized", huge.into_bytes()),
        (
            "oversized but otherwise valid",
            (header.clone() + &format!("F {}\n", "a".repeat(255)).repeat(16384)).into_bytes(),
        ),
        (
            "too many entries",
            (header.clone() + &"F a\n".repeat(16385)).into_bytes(),
        ),
    ];
    for (what, bytes) in cases {
        let (e, p, file, _) = interrupted_fixture(ArchiveFormat::Zip);
        fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
        fs::write(e.journal(), &bytes).unwrap();
        let before = e.snapshot();
        let err = install(&e, p, &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Journal(_)), "{what}: {err:?}");
        assert_untouched(&e, &before, what);
    }
    for what in ["symlink", "directory"] {
        let (e, p, file, _) = interrupted_fixture(ArchiveFormat::Zip);
        fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
        let real = e.tmp.path().join("real-journal");
        fs::write(&real, &header).unwrap();
        if what == "symlink" {
            symlink(&real, e.journal()).unwrap();
        } else {
            fs::create_dir(e.journal()).unwrap();
        }
        let before = e.snapshot();
        let err = install(&e, p, &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Journal(_)), "{what}: {err:?}");
        assert_untouched(&e, &before, what);
    }
}

#[test]
fn an_r_entry_whose_backup_was_never_made_is_skipped_by_rollback() {
    // Killed between the `R` line and the backup's rename: the original is still in place, nothing to restore.
    let (e, p, file, before) = interrupted_fixture(ArchiveFormat::Zip);
    fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
    fs::write(
        e.journal(),
        format!("rt-deps-journal 1 {HASH}\nR windows/system32/dxgi.dll\n"),
    )
    .unwrap();
    let bytes = fs::read(&file).unwrap();
    let truncated = e.archive("truncated", &bytes[..bytes.len() - 20]);
    let err = install(&e, p, &truncated).unwrap_err();
    assert!(matches!(err, ArchiveError::Zip(_)), "not a rollback failure: {err:?}");
    assert_untouched(&e, &before, "R without backup");
}

// ------------------------------------------------------------------------------------------------ fix round 2

#[test]
fn a_retry_with_a_different_extract_selection_still_owns_everything_the_killed_run_did() {
    for format in FORMATS {
        // Killed after all four files, retried with a SMALLER selection (same archive, same sha256).
        let (e, full, file, before) = interrupted_fixture(format);
        crash_install(&e, full.clone(), &file, 4);
        let small = pkg(format, &[("x/d3d11.dll", "windows/system32/d3d11.dll")]);
        let done = install(&e, small, &file).unwrap();
        assert!(
            done.replaced.contains(&PathBuf::from("windows/system32/dxgi.dll")),
            "{done:?}"
        );
        remove(&e, &done).unwrap();
        assert_untouched(&e, &before, &format!("{format:?} smaller retry"));

        // Killed after one file with the small selection, retried with the FULL one.
        let (e, full, file, before) = interrupted_fixture(format);
        let small = pkg(format, &[("x/d3d11.dll", "windows/system32/d3d11.dll")]);
        crash_install(&e, small, &file, 1);
        let done = install(&e, full, &file).unwrap();
        remove(&e, &done).unwrap();
        assert_untouched(&e, &before, &format!("{format:?} larger retry"));
    }
}

#[test]
fn a_torn_journal_tail_is_cut_before_appending() {
    for format in FORMATS {
        // Only the directory-prefix entry, so the first line appended after the torn tail is `D newdir`.
        let (e, _, file, before) = interrupted_fixture(format);
        let p = pkg(format, &[("x/new/", "newdir/deep")]);
        fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
        fs::write(e.journal(), format!("rt-deps-journal 1 {HASH}\nF zz/q.d")).unwrap();
        crash_install(&e, p.clone(), &file, 1);
        let done = install(&e, p, &file).unwrap();
        remove(&e, &done).unwrap();
        assert_untouched(&e, &before, &format!("{format:?} torn tail"));
    }
    // A torn header is not a journal: refused, and not discardable either (it is created atomically, so this is
    // damage, not a crash).
    let (e, p, file, _) = interrupted_fixture(ArchiveFormat::Zip);
    fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
    fs::write(e.journal(), format!("rt-deps-journal 1 {}", &HASH[..20])).unwrap();
    assert!(matches!(install(&e, p, &file), Err(ArchiveError::Journal(_))));
    assert!(matches!(
        discard_interrupted("dxvk", &e.env),
        Err(ArchiveError::Journal(_))
    ));
    // A complete header must still name a valid sha256, for discard too.
    fs::write(e.journal(), "rt-deps-journal 1 xyz\n").unwrap();
    assert!(matches!(
        discard_interrupted("dxvk", &e.env),
        Err(ArchiveError::Journal(_))
    ));
}

#[test]
fn a_journal_of_another_archive_blocks_install_until_discarded() {
    for format in FORMATS {
        let (e, p, file, before) = interrupted_fixture(format);
        crash_install(&e, p.clone(), &file, 3);
        let mut newer = p.clone();
        newer.sha256 = "f".repeat(64);
        let err = install(&e, newer.clone(), &file).unwrap_err();
        assert!(matches!(err, ArchiveError::Journal(_)), "{err:?}");
        // An empty record must not be used to "clean up": it would drop the journal and leak the killed run.
        let err = remove(&e, &ArchiveInstalled::default()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Journal(m) if m.contains("discard_interrupted")),
            "{err:?}"
        );
        let report = discard_interrupted("dxvk", &e.env).unwrap();
        assert!(
            !report.removed_files.is_empty() && !report.restored.is_empty(),
            "{report:?}"
        );
        assert_untouched(&e, &before, &format!("{format:?} discarded"));
        assert_eq!(discard_interrupted("dxvk", &e.env).unwrap(), DiscardReport::default());
        let done = install(&e, newer, &file).unwrap();
        remove(&e, &done).unwrap();
        assert_untouched(&e, &before, &format!("{format:?} newer archive"));
    }
}

#[test]
fn discarding_a_corrupt_journal_is_a_typed_error() {
    let e = Env::new();
    fs::create_dir_all(e.journal().parent().unwrap()).unwrap();
    fs::write(e.journal(), format!("rt-deps-journal 1 {HASH}\nF ../../victim\n")).unwrap();
    assert!(matches!(
        discard_interrupted("dxvk", &e.env),
        Err(ArchiveError::Journal(_))
    ));
    assert!(e.journal().is_file(), "a corrupt journal is kept for inspection");
    assert!(matches!(
        discard_interrupted("../x", &e.env),
        Err(ArchiveError::BadPackage(_))
    ));
}
