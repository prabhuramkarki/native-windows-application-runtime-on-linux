use super::*;
use crate::manifest::{ArchiveFormat, Kind};
use rt_core::{AppId, Call, FakeBackend, Store};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

/// The installer body used by most tests: any bytes; the fake backend never executes them.
const BODY: &[u8] = b"MZ pretend vendor installer";
/// OLE2 compound-file magic: what makes a staged file an MSI.
const OLE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MARKER: &str = "windows/system32/depmarker.dll";
/// Creates the file marker (cwd of the installer is `drive_c`).
const MAKE_MARKER: &str = "mkdir -p windows/system32 && echo ok > windows/system32/depmarker.dll";
/// Proves the installer ran.
const CANARY: &str = "ran";
/// A `bwrap` path for tests that must stop before anything runs: it does not exist, so reaching the sandbox fails.
const NO_RUN_BWRAP: &str = "/nonexistent/bwrap-must-not-run";

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

struct Fx {
    tmp: tempfile::TempDir,
    env: AppEnv,
    cache: PathBuf,
}

/// An app with an empty `drive_c` and `cache/<sha256>` (0400) holding `body`.
fn fx(body: &[u8]) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let env = Store::new(tmp.path().join("apps"))
        .unwrap()
        .create(&AppId::parse("t").unwrap())
        .unwrap();
    // A non-MSI installer is started by the prefix's explorer.exe; the fake backend runs it as the shell script.
    fs::create_dir_all(env.drive_c().join("windows")).unwrap();
    fs::write(env.drive_c().join(EXPLORER_RELATIVE), "fake explorer").unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    let cache = cache_dir.join(sha(body));
    fs::write(&cache, body).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o400)).unwrap();
    Fx { tmp, env, cache }
}

impl Fx {
    fn c(&self, rel: &str) -> PathBuf {
        self.env.drive_c().join(rel)
    }
    fn ran(&self) -> bool {
        self.c(CANARY).exists()
    }
    fn staging_left(&self) -> bool {
        // Wine's real casing is `windows/temp`; `join_new` reuses an existing `windows` and creates `Temp`.
        [
            "windows/Temp/rt-deps/testpkg",
            "windows/temp/rt-deps/testpkg",
            "Windows/Temp/rt-deps/testpkg",
        ]
        .iter()
        .any(|d| fs::read_dir(self.c(d)).is_ok_and(|mut r| r.next().is_some()))
    }
    /// Nothing was staged: no `windows/temp` (any case) was created.
    fn nothing_staged(&self) -> bool {
        !self.c("windows/Temp").exists() && !self.c("windows/temp").exists()
    }
    fn write_reg(&self, file: &str, text: &str) {
        fs::write(self.env.prefix().join(file), text).unwrap();
    }
}

fn pkg_for(body: &[u8], silent_args: &[&str], marker: Marker) -> Package {
    Package {
        id: "testpkg".into(),
        version: "1.0".into(),
        sha256: sha(body),
        size: body.len() as u64,
        licence: "MIT".into(),
        url: "https://example.com/setup.exe".into(),
        kind: Kind::Installer,
        requires_consent: false,
        requires: vec![],
        provides: vec![],
        install: Install::Installer {
            silent_args: silent_args.iter().map(|s| (*s).to_owned()).collect(),
            marker,
        },
    }
}

fn file_marker() -> Marker {
    Marker::File(MARKER.into())
}

fn reg_marker(key: &str, name: &str) -> Marker {
    Marker::RegistryValue {
        key: key.into(),
        name: name.into(),
    }
}

/// `FakeBackend` runs `/bin/sh`; `/bin` is bound into the sandbox through `dll_dirs` (as Phase 3's tests do).
fn backend(script: &str) -> FakeBackend {
    FakeBackend::with_script(&format!("touch {CANARY}; {script}")).with_dll_dirs(vec![PathBuf::from("/bin")])
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

/// Real `bwrap`, or a loud skip (`RUNTIME_REQUIRE_BWRAP=1` makes it a failure), as in Phase 3's tests.
fn require_real_bwrap() -> Option<PathBuf> {
    let require = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    match rt_installer::find_bwrap_on_path() {
        Some(p) => Some(p),
        None if require => panic!("bwrap not found on $PATH and RUNTIME_REQUIRE_BWRAP is set"),
        None => {
            eprintln!("SKIP: bwrap not found on $PATH; the real-sandbox tests need bubblewrap installed");
            None
        }
    }
}

fn run_with(f: &Fx, p: &Package, b: &FakeBackend, bwrap: &Path) -> Result<InstallerPkgInstalled, InstallerPkgError> {
    install_with(
        p,
        &f.cache,
        &f.env,
        b,
        &launcher(),
        Some(bwrap.to_path_buf()),
        Duration::from_secs(60),
    )
}

// ------------------------------------------------------------------------------------------------ outcomes

#[test]
fn a_file_marker_created_by_the_installer_is_success() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    let got = run_with(&f, &p, &backend(MAKE_MARKER), &bwrap).unwrap();
    assert!(got.marker_confirmed);
    assert!(got.staged_removed);
    assert!(got.warnings.is_empty(), "{:?}", got.warnings);
    assert!(f.ran());
    assert!(!f.staging_left());
}

#[test]
fn exit_zero_without_the_marker_is_marker_missing() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = run_with(&f, &p, &backend("exit 0"), &bwrap).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerMissing), "{err:?}");
    assert!(f.ran());
    assert!(!f.staging_left(), "the staged installer is removed on failure too");
}

#[test]
fn a_nonzero_exit_with_the_marker_is_success_with_a_warning() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    let got = run_with(&f, &p, &backend(&format!("{MAKE_MARKER}; exit 3")), &bwrap).unwrap();
    assert!(got.marker_confirmed);
    assert_eq!(got.warnings.len(), 1, "{:?}", got.warnings);
    assert!(got.warnings[0].contains('3'), "{:?}", got.warnings);
}

#[test]
fn a_nonzero_exit_without_the_marker_is_reported_with_the_code() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = run_with(&f, &p, &backend("exit 3"), &bwrap).unwrap_err();
    assert!(
        matches!(err, InstallerPkgError::NonZeroAndNoMarker { code: Some(3) }),
        "{err:?}"
    );
    assert!(!f.staging_left());
}

// ------------------------------------------------------------------------------------------------ marker absent first

#[test]
fn a_file_marker_already_present_refuses_without_running_anything() {
    let f = fx(BODY);
    fs::create_dir_all(f.c("windows/system32")).unwrap();
    fs::write(f.c(MARKER), "foreign").unwrap();
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerAlreadyPresent), "{err:?}");
    assert!(!f.ran(), "the installer ran although its marker was already there");
    assert!(!f.staging_left());
    assert_eq!(fs::read_to_string(f.c(MARKER)).unwrap(), "foreign");
}

#[test]
fn a_file_marker_is_found_case_insensitively_as_wine_does() {
    let f = fx(BODY);
    // `windows` itself exists already (fx puts explorer.exe there); the rest differs in case.
    fs::create_dir_all(f.c("windows/System32")).unwrap();
    fs::write(f.c("windows/System32/DepMarker.DLL"), "foreign").unwrap();
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerAlreadyPresent), "{err:?}");
    assert!(!f.ran());
}

#[test]
fn a_marker_that_names_the_staged_installer_itself_is_already_present() {
    // Staging happens before the marker check, so a marker that the staging copy itself would satisfy can never
    // be "confirmed" by the run.
    let f = fx(BODY);
    let p = pkg_for(
        BODY,
        &["/S"],
        Marker::File("windows/Temp/rt-deps/testpkg/testpkg.exe".into()),
    );
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerAlreadyPresent), "{err:?}");
    assert!(!f.ran());
    assert!(!f.staging_left());
}

#[test]
fn a_symlink_or_directory_at_the_marker_path_is_refused_without_running() {
    for kind in ["symlink", "dir", "symlinked parent"] {
        let f = fx(BODY);
        fs::create_dir_all(f.c("windows")).unwrap();
        let outside = f.tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("depmarker.dll"), "x").unwrap();
        match kind {
            "symlink" => {
                fs::create_dir_all(f.c("windows/system32")).unwrap();
                symlink(outside.join("depmarker.dll"), f.c(MARKER)).unwrap();
            }
            "dir" => fs::create_dir_all(f.c(MARKER)).unwrap(),
            _ => symlink(&outside, f.c("windows/system32")).unwrap(),
        }
        let p = pkg_for(BODY, &["/S"], file_marker());
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(matches!(err, InstallerPkgError::Marker(_)), "{kind}: {err:?}");
        assert!(!f.ran(), "{kind}");
        assert!(!f.staging_left(), "{kind}");
    }
}

#[test]
fn a_traversing_marker_path_in_a_hand_built_package_is_refused() {
    for bad in [
        "../escape.txt",
        "windows/../../escape.txt",
        "/etc/passwd",
        "a\\..\\..\\x",
        "C:/x",
        "",
    ] {
        let f = fx(BODY);
        let p = pkg_for(BODY, &["/S"], Marker::File(bad.into()));
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(matches!(err, InstallerPkgError::BadPackage(_)), "{bad:?}: {err:?}");
        assert!(!f.ran());
        assert!(!f.staging_left());
    }
}

// ------------------------------------------------------------------------------------------------ registry markers

const REG_HEAD: &str = "WINE REGISTRY Version 2\n;; All keys relative to REGISTRY\\\\Machine\n\n#arch=win64\n\n";

fn reg_with(key: &str, name: &str) -> String {
    format!("{REG_HEAD}[{key}] 1790095421\n#time=1dd4ab1864fafa4\n\"{name}\"=dword:00000001\n\n")
}

#[test]
fn a_registry_marker_already_present_refuses_without_running() {
    // (hive file, key as Wine writes it, the marker key as the manifest says it)
    let cases = [
        (
            "system.reg",
            "Software\\\\RuntimeDepFixture",
            "HKLM\\Software\\RuntimeDepFixture",
        ),
        (
            "system.reg",
            "Software\\\\Wow6432Node\\\\RuntimeDepFixture",
            "HKLM\\Software\\RuntimeDepFixture",
        ),
        (
            "system.reg",
            "Software\\\\RuntimeDepFixture",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\runtimedepfixture",
        ),
        (
            "user.reg",
            "Software\\\\RuntimeDepFixture",
            "HKCU\\Software\\RuntimeDepFixture",
        ),
        (
            "user.reg",
            "Software\\\\RuntimeDepFixture",
            "HKEY_CURRENT_USER\\Software\\RuntimeDepFixture",
        ),
    ];
    for (file, written, key) in cases {
        let f = fx(BODY);
        f.write_reg(file, &reg_with(written, "Installed"));
        let p = pkg_for(BODY, &["/S"], reg_marker(key, "installed"));
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(
            matches!(err, InstallerPkgError::MarkerAlreadyPresent),
            "{file} {written} {key}: {err:?}"
        );
        assert!(!f.ran());
        assert!(!f.staging_left());
    }
}

#[test]
fn registry_lookup_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tmp.path();
    let look = |key: &str, name: &str| registry_marker_present(prefix, key, name);
    fs::write(
        prefix.join("system.reg"),
        format!(
            "{}{}",
            reg_with("Software\\\\A", "V"),
            "[Software\\\\B] 1\n@=\"default\"\n\n[Software\\\\Wow6432Node\\\\C] 1\n\"W\"=\"s\"\n\n"
        ),
    )
    .unwrap();
    fs::write(prefix.join("user.reg"), reg_with("Software\\\\U", "X")).unwrap();
    assert!(look("HKLM\\Software\\A", "V").unwrap());
    assert!(
        look("hklm\\software\\a", "v").unwrap(),
        "keys and names compare case-insensitively"
    );
    assert!(
        !look("HKLM\\Software\\A", "Other").unwrap(),
        "another value of the same key"
    );
    assert!(look("HKLM\\Software\\B", "").unwrap(), "empty name = the default value");
    assert!(!look("HKLM\\Software\\A", "").unwrap(), "no default value there");
    assert!(
        look("HKLM\\Software\\C", "W").unwrap(),
        "Wow6432Node mirror of HKLM\\Software"
    );
    assert!(look("HKLM\\Software\\Wow6432Node\\C", "W").unwrap(), "named directly");
    assert!(!look("HKCU\\Software\\A", "V").unwrap(), "hives are separate");
    assert!(look("HKCU\\Software\\U", "X").unwrap());
    assert!(!look("HKLM\\Software\\U", "X").unwrap(), "hives are separate");
    assert!(
        !look("HKCU\\Software\\C", "W").unwrap(),
        "no Wow6432Node mirror for HKCU"
    );
    assert!(!look("HKLM\\Software", "V").unwrap(), "a parent key is not the key");
    assert!(
        !look("HKLM\\Software\\A\\Sub", "V").unwrap(),
        "a child key is not the key"
    );
    for bad in ["HKCR\\x", "HKLM", "HKLM\\", "Software\\A", "HKLM\\\\A", ""] {
        assert!(
            matches!(look(bad, "V"), Err(InstallerPkgError::BadPackage(_))),
            "{bad:?}"
        );
    }
    // No hive files at all (a fresh fake prefix): absent, not an error.
    let empty = tempfile::tempdir().unwrap();
    assert!(!registry_marker_present(empty.path(), "HKLM\\Software\\A", "V").unwrap());
}

#[test]
fn a_registry_marker_written_by_the_installer_is_success() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    // The installer (cwd drive_c) writes the 32-bit view, as a 32-bit NSIS installer on a win64 prefix does.
    let script = format!(
        "printf '%s' '{}' > ../system.reg",
        reg_with("Software\\\\Wow6432Node\\\\RuntimeDepFixture", "Installed")
    );
    let p = pkg_for(
        BODY,
        &["/S"],
        reg_marker("HKLM\\Software\\RuntimeDepFixture", "Installed"),
    );
    let got = run_with(&f, &p, &backend(&script), &bwrap).unwrap();
    assert!(got.marker_confirmed);
    // And an installer that writes nothing is not confirmed.
    let f = fx(BODY);
    let err = run_with(&f, &p, &backend("exit 0"), &bwrap).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerMissing), "{err:?}");
}

#[test]
fn a_truncated_or_unreadable_hive_is_an_error_not_absent() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("system.reg")).unwrap_or(()); // a directory is "does not exist": fine
    assert!(!registry_marker_present(tmp.path(), "HKLM\\Software\\A", "V").unwrap());
    fs::remove_dir(tmp.path().join("system.reg")).unwrap();
    fs::write(tmp.path().join("system.reg"), "x").unwrap();
    fs::set_permissions(tmp.path().join("system.reg"), fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(tmp.path().join("system.reg")).is_err() {
        // (root can read a 0000 file; the check only means something for an ordinary user)
        let err = registry_marker_present(tmp.path(), "HKLM\\Software\\A", "V").unwrap_err();
        assert!(matches!(err, InstallerPkgError::Registry(_)), "{err:?}");
    }
}

#[test]
fn hostile_registry_bytes_never_panic_and_echo_nothing_unbounded() {
    let tmp = tempfile::tempdir().unwrap();
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let alphabet: &[u8] = b"[]\\\"=@:#;\n\r xdword0123456789abcdefHKLMSoftwareWow6432Node\x00\xff\xc3";
    for _ in 0..2000 {
        let len = (next() % 400) as usize;
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        fs::write(tmp.path().join("system.reg"), &bytes).unwrap();
        fs::write(
            tmp.path().join("user.reg"),
            bytes.iter().rev().copied().collect::<Vec<u8>>(),
        )
        .unwrap();
        for (k, n) in [
            ("HKLM\\Software\\A", "V"),
            ("HKCU\\Software\\x", ""),
            ("HKLM\\Software\\Wow6432Node\\A", "\""),
        ] {
            match registry_marker_present(tmp.path(), k, n) {
                Ok(_) => {}
                Err(e) => assert!(e.to_string().len() < 400, "{e}"),
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ sandbox, staging, cache

/// Records what the installer saw: its own path, its args, its network namespace and a copy of its bytes.
const RECORD: &str =
    "printf '%s\\n' \"$0\" \"$@\" > argv.txt; cp \"$0\" staged-copy.bin; readlink /proc/self/ns/net > netns.txt";
/// The same for a non-MSI installer, where `$0` is explorer.exe: the staged copy is the file at the staging path.
const RECORD_STAGED: &str = "printf '%s\\n' \"$0\" \"$@\" > argv.txt; cp windows/*emp/rt-deps/testpkg/testpkg.exe \
     staged-copy.bin; readlink /proc/self/ns/net > netns.txt";

#[test]
fn the_installer_runs_offline_in_the_sandbox_from_a_verified_staged_copy() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let before = fs::metadata(&f.cache).unwrap();
    let p = pkg_for(BODY, &["/S", "/D=C:\\x y", "$(touch pwned)"], file_marker());
    let b = backend(&format!("{RECORD_STAGED}; {MAKE_MARKER}"));
    let got = run_with(&f, &p, &b, &bwrap).unwrap();
    assert!(got.staged_removed);

    // The network namespace inside is not the host's (`--unshare-net`).
    let inside = fs::read_to_string(f.c("netns.txt")).unwrap();
    let host = fs::read_link("/proc/self/ns/net").unwrap();
    assert!(inside.trim().starts_with("net:["), "{inside}");
    assert_ne!(
        inside.trim(),
        host.to_str().unwrap(),
        "the installer shared the host network"
    );

    // The prefix's explorer.exe started the staged copy inside drive_c (never the cache file) on the null
    // desktop, with each arg as one argv element.
    let argv = fs::read_to_string(f.c("argv.txt")).unwrap();
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(Path::new(lines[0]), f.c(EXPLORER_RELATIVE));
    let staged_win = "C:\\windows\\temp\\rt-deps\\testpkg\\testpkg.exe";
    assert_eq!(
        &lines[1..],
        [
            "/desktop=rt-deps,800x600,null",
            staged_win,
            "/S",
            "/D=C:\\x y",
            "$(touch pwned)"
        ]
    );
    assert!(!f.c("pwned").exists());
    let staged = resolve_under(&f.env.drive_c(), &WinPath::parse(staged_win).unwrap());
    assert!(matches!(staged, Err(ResolveError::NotFound)), "{staged:?}");
    let calls = b.calls();
    let Some(Call::Command { exe, cwd, args, .. }) = calls.iter().find(|c| matches!(c, Call::Command { .. })) else {
        panic!("{calls:?}")
    };
    assert_eq!(exe, &f.c(EXPLORER_RELATIVE));
    assert_eq!(args.len(), 5);
    assert_eq!(cwd, &f.env.drive_c());

    // The copy it ran is byte-identical to the verified package, and it is gone afterwards.
    assert_eq!(sha(&fs::read(f.c("staged-copy.bin")).unwrap()), p.sha256);
    assert!(!f.staging_left());

    // The cache file is untouched: bytes, mode and mtime.
    let after = fs::metadata(&f.cache).unwrap();
    assert_eq!(fs::read(&f.cache).unwrap(), BODY);
    assert_eq!(after.permissions().mode() & 0o777, 0o400);
    assert_eq!(
        (after.mtime(), after.mtime_nsec()),
        (before.mtime(), before.mtime_nsec())
    );
    assert_eq!(after.ino(), before.ino());
}

#[test]
fn a_cache_file_that_does_not_match_the_package_hash_is_never_run() {
    // `pkg.sha256` names other bytes than the file holds: only the staged-copy verification can notice.
    let f = fx(BODY);
    let mut p = pkg_for(BODY, &["/S"], file_marker());
    p.sha256 = sha(b"something else entirely....");
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(
        matches!(err, InstallerPkgError::Stage(ref m) if m.contains("sha256")),
        "{err:?}"
    );
    assert!(!f.ran());
    assert!(!f.staging_left());
}

#[test]
fn a_cache_file_of_the_wrong_size_or_a_symlink_is_refused() {
    let f = fx(BODY);
    let mut p = pkg_for(BODY, &["/S"], file_marker());
    p.size += 1;
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::Stage(_)), "{err:?}");
    let link = f.tmp.path().join("link");
    symlink(&f.cache, &link).unwrap();
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = install_with(
        &p,
        &link,
        &f.env,
        &backend(MAKE_MARKER),
        &launcher(),
        Some(NO_RUN_BWRAP.into()),
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(matches!(err, InstallerPkgError::Stage(_)), "{err:?}");
    assert!(!f.ran());
    assert!(!f.staging_left());
}

#[test]
fn a_staged_file_left_by_a_killed_run_is_replaced() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    fs::create_dir_all(f.c("windows/Temp/rt-deps/testpkg")).unwrap();
    fs::write(f.c("windows/Temp/rt-deps/testpkg/testpkg.exe"), "stale half copy").unwrap();
    let p = pkg_for(BODY, &["/S"], file_marker());
    let got = run_with(&f, &p, &backend(&format!("{RECORD_STAGED}; {MAKE_MARKER}")), &bwrap).unwrap();
    assert!(got.marker_confirmed);
    assert_eq!(fs::read(f.c("staged-copy.bin")).unwrap(), BODY);
    assert!(!f.staging_left());
}

#[test]
fn a_symlink_planted_at_the_staging_path_is_refused() {
    let f = fx(BODY);
    let outside = f.tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::create_dir_all(f.c("windows/Temp/rt-deps")).unwrap();
    symlink(&outside, f.c("windows/Temp/rt-deps/testpkg")).unwrap();
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::Stage(_)), "{err:?}");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "wrote through the symlink");
    assert!(!f.ran());
}

#[test]
fn bad_silent_args_are_refused_before_anything_happens() {
    let long = "x".repeat(513);
    let many: Vec<&str> = vec!["/S"; 65];
    let cases: Vec<Vec<&str>> = vec![
        vec!["/S", "a\0b"],
        vec!["a\nb"],
        vec!["\u{1b}[2J"],
        vec![""],
        vec![long.as_str()],
        many,
    ];
    for args in cases {
        let f = fx(BODY);
        let p = pkg_for(BODY, &args, file_marker());
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(
            matches!(err, InstallerPkgError::BadSilentArg(_)),
            "{:?}: {err:?}",
            args.len()
        );
        assert!(err.to_string().len() < 300, "{err}");
        assert!(!f.ran());
        assert!(!f.staging_left());
    }
    // The limits themselves are fine.
    let ok = "x".repeat(512);
    assert!(check_silent_args(&vec![ok; 64]).is_ok());
}

#[test]
fn no_bwrap_is_a_typed_error_before_anything_is_staged() {
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    let err = install_with(
        &p,
        &f.cache,
        &f.env,
        &backend(MAKE_MARKER),
        &launcher(),
        None,
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(matches!(err, InstallerPkgError::BwrapNotFound), "{err:?}");
    assert!(!f.ran());
    assert!(f.nothing_staged(), "something was staged");
}

#[test]
fn an_archive_package_is_not_installer_kind() {
    let f = fx(BODY);
    let mut p = pkg_for(BODY, &["/S"], file_marker());
    p.kind = Kind::Archive;
    p.install = Install::Archive {
        format: ArchiveFormat::Zip,
        extract: vec![],
        dll_overrides: vec![],
    };
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::NotInstallerKind), "{err:?}");
    // Mismatched kind and install section too.
    let mut p = pkg_for(BODY, &["/S"], file_marker());
    p.kind = Kind::Archive;
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::NotInstallerKind), "{err:?}");
}

#[test]
fn a_hand_built_package_with_a_bad_id_or_hash_is_refused() {
    let f = fx(BODY);
    for (id, hash) in [("../x", sha(BODY)), ("Bad", sha(BODY)), ("ok", "../../etc".to_owned())] {
        let mut p = pkg_for(BODY, &["/S"], file_marker());
        p.id = id.into();
        p.sha256 = hash;
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(matches!(err, InstallerPkgError::BadPackage(_)), "{id}: {err:?}");
    }
    assert!(!f.ran());
    assert!(f.nothing_staged());
}

// ------------------------------------------------------------------------------------------------ deadline

#[test]
fn a_hanging_installer_is_killed_at_the_deadline() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let p = pkg_for(BODY, &["/S"], file_marker());
    // A unique argument so the host process table can be searched for survivors.
    let token = format!("98{}", std::process::id());
    let b = backend(&format!("sleep {token} & sleep {token}; {MAKE_MARKER}"));
    let t0 = std::time::Instant::now();
    let err = install_with(
        &p,
        &f.cache,
        &f.env,
        &b,
        &launcher(),
        Some(bwrap),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(t0.elapsed() < Duration::from_secs(10), "took {:?}", t0.elapsed());
    assert!(matches!(err, InstallerPkgError::TimedOut { secs: 1 }), "{err:?}");
    assert!(!f.c(MARKER).exists());
    assert!(!f.staging_left());
    assert!(
        b.calls().iter().any(|c| matches!(c, Call::Stop { .. })),
        "no settle/stop after the kill"
    );
    // Nothing from inside the sandbox survives (the whole tree dies with bwrap).
    let t = std::time::Instant::now();
    loop {
        let survivors: Vec<String> = fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| fs::read(e.ok()?.path().join("cmdline")).ok())
            .map(|c| String::from_utf8_lossy(&c).replace('\0', " "))
            .filter(|c| c.starts_with("sleep ") && c.contains(&token))
            .collect();
        if survivors.is_empty() {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "survivors: {survivors:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ------------------------------------------------------------------------------------------------ msi

#[test]
fn an_msi_runs_through_the_prefix_msiexec_with_the_staged_path() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let mut body = OLE.to_vec();
    body.extend_from_slice(b"rest of a compound file");
    let f = fx(&body);
    fs::create_dir_all(f.c("windows/system32")).unwrap();
    fs::write(f.c(rt_installer::MSIEXEC_RELATIVE), "fake msiexec").unwrap();
    let p = pkg_for(&body, &["/qn", "/norestart"], file_marker());
    let b = backend(&format!("{RECORD}; {MAKE_MARKER}"));
    let got = run_with(&f, &p, &b, &bwrap).unwrap();
    assert!(got.marker_confirmed);
    let calls = b.calls();
    let Some(Call::Command { exe, args, .. }) = calls.iter().find(|c| matches!(c, Call::Command { .. })) else {
        panic!("{calls:?}")
    };
    assert_eq!(exe, &f.c(rt_installer::MSIEXEC_RELATIVE));
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
    assert_eq!(
        args,
        [
            "/i",
            "C:\\windows\\temp\\rt-deps\\testpkg\\testpkg.msi",
            "/qn",
            "/norestart"
        ]
    );
    assert_eq!(
        fs::read(f.c("staged-copy.bin")).unwrap(),
        b"fake msiexec",
        "$0 is msiexec"
    );
    assert!(!f.staging_left());
}

#[test]
fn an_msi_without_msiexec_in_the_prefix_is_a_typed_error() {
    let mut body = OLE.to_vec();
    body.extend_from_slice(b"x");
    let f = fx(&body);
    let p = pkg_for(&body, &["/qn"], file_marker());
    let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
    assert!(matches!(err, InstallerPkgError::MsiExecMissing), "{err:?}");
    assert!(!f.ran());
    assert!(!f.staging_left());
}

#[test]
fn an_exe_installer_without_explorer_in_the_prefix_is_a_typed_error() {
    for kind in ["missing", "dir", "symlink"] {
        let f = fx(BODY);
        fs::remove_file(f.c(EXPLORER_RELATIVE)).unwrap();
        match kind {
            "dir" => fs::create_dir(f.c(EXPLORER_RELATIVE)).unwrap(),
            "symlink" => symlink("/bin/sh", f.c(EXPLORER_RELATIVE)).unwrap(),
            _ => {}
        }
        let p = pkg_for(BODY, &["/S"], file_marker());
        let err = run_with(&f, &p, &backend(MAKE_MARKER), Path::new(NO_RUN_BWRAP)).unwrap_err();
        assert!(matches!(err, InstallerPkgError::ExplorerMissing), "{kind}: {err:?}");
        assert!(!f.ran());
        assert!(!f.staging_left());
    }
}

#[test]
fn msi_detection_is_by_magic_or_url_extension() {
    let mut ole = OLE.to_vec();
    ole.push(0);
    assert!(is_msi(&ole, "https://e.com/setup.exe"));
    assert!(is_msi(b"MZ", "https://e.com/pkg.MSI?x=1"));
    assert!(!is_msi(b"MZ", "https://e.com/setup.exe"));
    assert!(!is_msi(&OLE[..7], "https://e.com/setup.exe"));
    assert!(!is_msi(b"MZ", "https://e.com/msi"));
}

// ------------------------------------------------------------------------------------------------ real Wine

/// Real Wine 10.0 + real bwrap + a real NSIS installer (`sh tools/build-fixtures.sh` first):
/// `cargo test -p runtime-deps --lib install_installer -- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore = "needs Wine, bwrap and the NSIS fixture"]
fn e2e_real_wine_nsis_installer_both_marker_kinds() {
    use backend_wine::WineBackend;
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build/dep-installer.exe");
    let body = fs::read(&exe).expect("fixture missing: run sh tools/build-fixtures.sh");
    let bwrap = rt_installer::find_bwrap_on_path().expect("bwrap must be installed");
    for marker in [
        Marker::File("rt-dep-marker.txt".into()),
        reg_marker("HKLM\\Software\\RuntimeDepFixture", "Installed"),
    ] {
        let launcher = Launcher::new();
        let backend = WineBackend::discover_with(launcher.clone()).expect("Wine must be installed");
        let tmp = tempfile::tempdir().unwrap(); // never ~/.wine: a scratch store
        let env = Store::new(tmp.path().join("apps"))
            .unwrap()
            .create(&AppId::parse("e2e").unwrap())
            .unwrap();
        backend.prepare(&env).unwrap();
        let cache = tmp.path().join(sha(&body));
        fs::write(&cache, &body).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o400)).unwrap();
        let mut p = pkg_for(&body, &["/S"], marker.clone());
        p.id = "depfixture".into();
        let present = |m: &Marker| match m {
            Marker::File(rel) => marker_present(&env, &Marker::File(rel.clone())).unwrap(),
            m => marker_present(&env, m).unwrap(),
        };
        assert!(!present(&marker), "{marker:?} present before the run");
        let t = std::time::Instant::now();
        let got = install_with(
            &p,
            &cache,
            &env,
            &backend,
            &launcher,
            Some(bwrap.clone()),
            INSTALLER_DEADLINE,
        )
        .unwrap();
        eprintln!("{marker:?}: {got:?} in {:?}", t.elapsed());
        assert!(got.marker_confirmed && got.staged_removed);
        assert!(present(&marker), "{marker:?} absent after the run");
        assert!(
            fs::read_dir(env.drive_c().join("windows/temp/rt-deps"))
                .map(|mut r| r.next().is_none())
                .unwrap_or(true),
            "staging not empty"
        );
        // No wineserver of this prefix is left (the settle wait ran inside the sandbox).
        let ours = format!("WINEPREFIX={}", env.prefix().display());
        let servers: Vec<_> = fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                fs::read(e.path().join("cmdline")).is_ok_and(|c| String::from_utf8_lossy(&c).contains("wineserver"))
                    && fs::read(e.path().join("environ"))
                        .is_ok_and(|v| v.split(|b| *b == 0).any(|kv| kv == ours.as_bytes()))
            })
            .map(|e| e.file_name())
            .collect();
        assert!(servers.is_empty(), "wineserver left: {servers:?}");
        let sys = fs::read_to_string(env.prefix().join("system.reg")).unwrap();
        let section = sys
            .split("\n\n")
            .find(|s| s.to_ascii_lowercase().contains("runtimedepfixture]"))
            .unwrap_or("<none>");
        eprintln!("{marker:?}: system.reg section:\n{section}");
        backend.stop(&env).unwrap();
    }
}

/// A fresh real Wine 10.0 prefix in a scratch store, the fixture `name` as a verified cache file, and a package for
/// it (id `depfixture`).
struct RealWine {
    _tmp: tempfile::TempDir,
    launcher: Launcher,
    backend: backend_wine::WineBackend,
    env: AppEnv,
    cache: PathBuf,
    body: Vec<u8>,
}

fn real_wine(fixture: &str) -> RealWine {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(fixture);
    let body = fs::read(&path).expect("fixture missing: run sh tools/build-fixtures.sh");
    let launcher = Launcher::new();
    let backend = backend_wine::WineBackend::discover_with(launcher.clone()).expect("Wine must be installed");
    let tmp = tempfile::tempdir().unwrap(); // never ~/.wine: a scratch store
    let env = Store::new(tmp.path().join("apps"))
        .unwrap()
        .create(&AppId::parse("e2e").unwrap())
        .unwrap();
    backend.prepare(&env).unwrap();
    backend.stop(&env).unwrap();
    let cache = tmp.path().join(sha(&body));
    fs::write(&cache, &body).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o400)).unwrap();
    RealWine {
        _tmp: tmp,
        launcher,
        backend,
        env,
        cache,
        body,
    }
}

impl RealWine {
    fn install(
        &self,
        args: &[&str],
        marker: Marker,
        deadline: Duration,
    ) -> Result<InstallerPkgInstalled, InstallerPkgError> {
        let mut p = pkg_for(&self.body, args, marker);
        p.id = "depfixture".into();
        let bwrap = rt_installer::find_bwrap_on_path().expect("bwrap must be installed");
        install_with(
            &p,
            &self.cache,
            &self.env,
            &self.backend,
            &self.launcher,
            Some(bwrap),
            deadline,
        )
    }

    /// No wineserver of this prefix is left (the settle wait ran inside the sandbox, or the sandbox was killed).
    fn assert_no_wineserver(&self) {
        let t = std::time::Instant::now();
        loop {
            let left = crate::orchestrate::wineservers_for(&self.env.prefix()).unwrap();
            if left.is_empty() {
                return;
            }
            assert!(t.elapsed() < Duration::from_secs(10), "wineserver left: {left:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn staging_empty(&self) -> bool {
        fs::read_dir(self.env.drive_c().join("windows/temp/rt-deps"))
            .map(|mut r| r.next().is_none())
            .unwrap_or(true)
    }
}

/// Real Wine: an exe installer runs through `explorer.exe /desktop=...,null`. Its arguments arrive exactly (spaces,
/// quotes, backslashes, as rebuilt by Wine's Windows quoting), and its exit status is NOT seen (explorer exits 0),
/// so a failing installer is reported by its missing marker. `fs64.exe write <text>` writes C:\runtime-test.txt;
/// `fs64.exe stat <path>` exits 3 for a missing path.
#[test]
#[ignore = "needs Wine, bwrap and the mingw fixtures"]
fn e2e_real_wine_null_desktop_passes_args_exactly_and_judges_by_marker() {
    let text = r#"a b  "q" c:\x\ \\y\ %PATH% $(touch pwned)"#;
    let w = real_wine("fs64.exe");
    let got = w
        .install(
            &["write", text],
            Marker::File("runtime-test.txt".into()),
            INSTALLER_DEADLINE,
        )
        .unwrap();
    assert!(got.marker_confirmed && got.staged_removed, "{got:?}");
    assert!(got.warnings.is_empty(), "{got:?}");
    assert_eq!(
        fs::read_to_string(w.env.drive_c().join("runtime-test.txt")).unwrap(),
        text
    );
    assert!(!w.env.drive_c().join("pwned").exists());
    assert!(w.staging_empty());
    w.assert_no_wineserver();
    // The prefix's graphics driver setting is untouched (the null driver was for that run only).
    let user_reg = fs::read_to_string(w.env.prefix().join("user.reg")).unwrap();
    assert!(
        !user_reg.contains("\"Graphics\""),
        "the run changed the prefix's driver"
    );

    let w = real_wine("fs64.exe");
    let err = w
        .install(
            &["stat", r"C:\nope"],
            Marker::File("runtime-test.txt".into()),
            INSTALLER_DEADLINE,
        )
        .unwrap_err();
    assert!(matches!(err, InstallerPkgError::MarkerMissing), "{err:?}");
    assert!(w.staging_empty());
    w.assert_no_wineserver();
}

/// Real Wine: an exe installer that never finishes (`gui64.exe` waits on a message box nobody can click on the
/// null desktop) is killed at the deadline, the staged copy is removed and no wineserver is left.
#[test]
#[ignore = "needs Wine, bwrap and the mingw fixtures"]
fn e2e_real_wine_hanging_installer_on_the_null_desktop_times_out_and_is_cleaned_up() {
    let w = real_wine("gui64.exe");
    let t = std::time::Instant::now();
    let err = w
        .install(&["/S"], Marker::File("never.txt".into()), Duration::from_secs(20))
        .unwrap_err();
    eprintln!("hanging installer: {err:?} after {:?}", t.elapsed());
    assert!(matches!(err, InstallerPkgError::TimedOut { secs: 20 }), "{err:?}");
    assert!(t.elapsed() < Duration::from_secs(40), "{:?}", t.elapsed());
    assert!(w.staging_empty());
    w.assert_no_wineserver();
}

/// The BUNDLED vcrun2022, downloaded for real and installed by `install_installer_pkg` into a fresh real Wine 10.0
/// prefix: its registry marker is absent before and present after, every name it `provides` is then a native
/// (non-Wine-builtin) DLL in `system32`, and no wineserver is left. It then reports which copy Wine actually loads
/// for each DLL (`rundll32 <dll>,x` with `WINEDEBUG=+loaddll`). Needs network, Wine and bwrap, so it is NOT
/// selected by CI's `e2e_real_wine` filter: `cargo test -p runtime-deps --lib real_net_wine -- --ignored --nocapture`.
#[test]
#[ignore = "needs network, Wine and bwrap"]
fn real_net_wine_bundled_vcrun2022_installs_and_writes_its_marker() {
    use backend_wine::WineBackend;
    use rt_core::RunOpts;
    let vc = crate::Manifest::bundled().get("vcrun2022").expect("bundled vcrun2022");
    let Install::Installer { marker, .. } = &vc.install else {
        panic!("vcrun2022 is not an installer package")
    };
    assert!(matches!(marker, Marker::RegistryValue { .. }), "{marker:?}");
    let tmp = tempfile::tempdir().unwrap(); // never ~/.wine: a scratch store
    let file = fetch::fetch(vc, &tmp.path().join("cache"), &fetch::FetchOpts::default()).unwrap();
    let launcher = Launcher::new();
    let backend = WineBackend::discover_with(launcher.clone()).expect("Wine must be installed");
    let env = Store::new(tmp.path().join("apps"))
        .unwrap()
        .create(&AppId::parse("vcrun").unwrap())
        .unwrap();
    backend.prepare(&env).unwrap();
    backend.stop(&env).unwrap();
    assert!(!marker_present(&env, marker).unwrap(), "marker in a fresh prefix");
    let t = std::time::Instant::now();
    let got = install_installer_pkg(vc, &file, &env, &backend, &launcher).unwrap();
    eprintln!("vcrun2022: {got:?} in {:?}", t.elapsed());
    assert!(got.marker_confirmed && got.staged_removed);
    assert!(marker_present(&env, marker).unwrap(), "marker absent after the run");
    assert!(
        crate::orchestrate::wineservers_for(&env.prefix()).unwrap().is_empty(),
        "wineserver left"
    );
    let sys = fs::read_to_string(env.prefix().join("system.reg")).unwrap();
    for section in sys
        .split("\n\n")
        .filter(|s| s.to_ascii_lowercase().contains("vc\\\\runtimes\\\\x64]"))
    {
        eprintln!("system.reg:\n{section}");
    }
    for name in &vc.provides {
        let p = env.drive_c().join(format!("windows/system32/{name}.dll"));
        let bytes = fs::read(&p).unwrap_or_default();
        let builtin = bytes.windows(16).any(|w| w == b"Wine builtin DLL");
        eprintln!("{name}.dll: {} bytes, Wine builtin: {builtin}", bytes.len());
        assert!(!bytes.is_empty() && !builtin, "{name}.dll is not the redistributable's");
    }
    // Which copy does Wine load, without any DllOverrides entry and with `<name>=n,b`? Reported, not asserted
    // (the Task 8b report records the result: Wine 10.0 prefers its own builtin where it has one).
    let rundll32 = env.drive_c().join("windows/system32/rundll32.exe");
    for name in &vc.provides {
        let mut how = Vec::new();
        for overrides in [None, Some(format!("{name}=n,b"))] {
            let arg = OsString::from(format!("{name}.dll,rtDepsProbe"));
            let mut cmd = backend
                .command(&env, &rundll32, &env.drive_c(), &[arg], &RunOpts::default())
                .unwrap();
            cmd.env("WINEDEBUG", "+loaddll");
            if let Some(o) = &overrides {
                cmd.env("WINEDLLOVERRIDES", o);
            }
            let out = launcher
                .run_helper(backend.settle(cmd), Duration::from_secs(120))
                .unwrap();
            let text = String::from_utf8_lossy(&out.output).into_owned();
            let needle = format!("\\\\system32\\\\{name}.dll\"");
            how.push(
                text.lines()
                    .find(|l| l.contains("Loaded") && l.to_ascii_lowercase().contains(&needle))
                    .and_then(|l| l.rsplit(": ").next())
                    .unwrap_or("not loaded")
                    .to_owned(),
            );
        }
        eprintln!("LOADS {name}.dll: no override: {}; with {name}=n,b: {}", how[0], how[1]);
    }
    backend.stop(&env).unwrap();
}

#[test]
fn a_hive_with_more_keys_than_are_read_is_an_error_when_the_marker_is_not_among_them() {
    let tmp = tempfile::tempdir().unwrap();
    let mut text = String::from(REG_HEAD);
    for i in 0..200_001 {
        text.push_str(&format!("[K\\\\{i}] 1\n\n"));
    }
    fs::write(tmp.path().join("system.reg"), text).unwrap();
    let err = registry_marker_present(tmp.path(), "HKLM\\Software\\Missing", "V").unwrap_err();
    assert!(matches!(err, InstallerPkgError::Registry(_)), "{err:?}");
}

// ------------------------------------------------------------------------------------------------ hostile cleanup

/// The installer (hostile, prefix bound read-write at its host path) swaps part of the staging path for something
/// else before it exits. Cleanup must never follow it out of the prefix, and says it could not clean up.
fn hostile_swap(swap: &str, host_layout: &[&str]) {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let host = f.tmp.path().join("host");
    for rel in host_layout {
        let p = host.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "host file").unwrap();
    }
    fs::create_dir_all(&host).unwrap();
    let script = format!("{MAKE_MARKER}; {}", swap.replace("HOST", host.to_str().unwrap()));
    let p = pkg_for(BODY, &["/S"], file_marker());
    let got = run_with(&f, &p, &backend(&script), &bwrap).unwrap();
    assert!(got.marker_confirmed, "the result still reflects the marker");
    assert!(!got.staged_removed, "{got:?}");
    assert!(
        got.warnings.iter().any(|w| w.contains("staged")),
        "no warning: {:?}",
        got.warnings
    );
    for rel in host_layout {
        assert_eq!(
            fs::read_to_string(host.join(rel)).unwrap(),
            "host file",
            "{rel} outside the prefix was touched"
        );
    }
}

#[test]
fn cleanup_never_follows_a_symlink_the_installer_put_at_the_staging_dir() {
    hostile_swap(
        "rm -rf windows/temp/rt-deps/testpkg; ln -s HOST windows/temp/rt-deps/testpkg",
        &["testpkg.exe"],
    );
}

#[test]
fn cleanup_never_follows_a_symlink_the_installer_put_at_an_ancestor() {
    hostile_swap(
        "mv windows/temp windows/temp.real; ln -s HOST windows/temp",
        &["rt-deps/testpkg/testpkg.exe"],
    );
}

#[test]
fn cleanup_leaves_a_directory_the_installer_put_at_the_staged_path() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let f = fx(BODY);
    let script = format!(
        "{MAKE_MARKER}; rm -f windows/temp/rt-deps/testpkg/testpkg.exe; mkdir windows/temp/rt-deps/testpkg/testpkg.exe"
    );
    let p = pkg_for(BODY, &["/S"], file_marker());
    let got = run_with(&f, &p, &backend(&script), &bwrap).unwrap();
    assert!(got.marker_confirmed);
    assert!(!got.staged_removed);
    assert!(got.warnings.iter().any(|w| w.contains("staged")), "{:?}", got.warnings);
    assert!(f.c("windows/temp/rt-deps/testpkg/testpkg.exe").is_dir());
}
