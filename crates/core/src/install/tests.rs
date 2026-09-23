use super::*;
use crate::fake::{Call, FakeBackend};
use crate::testutil::*;
use std::io::Cursor;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::PathBuf;

const HOST: &str = "x86_64";

/// A tempdir holding `apps/` (the store), `in/` (inputs) and a `canary` outside the store.
struct Fx {
    tmp: tempfile::TempDir,
    store: Store,
    backend: FakeBackend,
}

fn fx() -> Fx {
    fx_with(FakeBackend::new())
}

fn fx_with(backend: FakeBackend) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("in")).unwrap();
    fs::write(tmp.path().join("canary"), "canary").unwrap();
    let store = Store::new(tmp.path().join("apps")).unwrap();
    Fx { tmp, store, backend }
}

fn tunables<'a>(limits: Limits, pick: &'a dyn Fn(&Store, &AppId) -> Result<AppId, StoreError>) -> Tunables<'a> {
    Tunables {
        host_arch: HOST,
        limits,
        pick_id: pick,
    }
}

impl Fx {
    fn apps(&self) -> PathBuf {
        self.tmp.path().join("apps")
    }

    fn input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        write_file(&self.tmp.path().join("in"), name, bytes)
    }

    fn run(&self, path: &Path, opts: &InstallOpts) -> Result<InstallOutcome, InstallError> {
        self.run_with(&self.backend, path, opts)
    }

    fn run_with(
        &self,
        backend: &dyn CompatBackend,
        path: &Path,
        opts: &InstallOpts,
    ) -> Result<InstallOutcome, InstallError> {
        install_with(
            &self.store,
            backend,
            path,
            opts,
            &tunables(Limits::default(), &unique_id),
        )
    }

    fn run_limits(&self, path: &Path, limits: Limits) -> Result<InstallOutcome, InstallError> {
        install_with(
            &self.store,
            &self.backend,
            path,
            &InstallOpts::default(),
            &tunables(limits, &unique_id),
        )
    }

    fn ok(&self, path: &Path, opts: &InstallOpts) -> InstallOutcome {
        self.run(path, opts).unwrap_or_else(|e| panic!("install failed: {e}"))
    }

    /// The whole tempdir apart from the inputs: what an install may leave behind.
    fn outside(&self) -> Vec<String> {
        tree(self.tmp.path())
            .into_iter()
            .filter(|p| !p.starts_with("in/"))
            .collect()
    }

    /// No app directory (not even an empty one) and no backend call: nothing was created.
    fn assert_nothing_created(&self, what: &str) {
        assert!(
            !self.apps().exists(),
            "{what}: apps dir was created: {:?}",
            self.outside()
        );
        assert!(
            self.backend.calls().is_empty(),
            "{what}: backend called: {:?}",
            self.backend.calls()
        );
        assert_eq!(fs::read_to_string(self.tmp.path().join("canary")).unwrap(), "canary");
    }

    /// Nothing left in the store (an empty apps dir is fine after a cleanup).
    fn assert_no_app_left(&self, what: &str) {
        if self.apps().exists() {
            assert_eq!(tree(&self.apps()), Vec::<String>::new(), "{what}: residue in the store");
        }
    }
}

fn named(name: &str) -> InstallOpts {
    InstallOpts {
        name: Some(name.into()),
        exe: None,
    }
}

fn with_exe(exe: &str) -> InstallOpts {
    InstallOpts {
        name: None,
        exe: Some(exe.into()),
    }
}

/// The mingw console fixture: carries a version resource (ProductName "Runtime Fixture", version 1.2.3.4).
fn hello64() -> Vec<u8> {
    fixture("hello64.exe")
}

/// The mingw GUI fixture: no version resource, so apps are named after the file.
fn prog() -> Vec<u8> {
    fixture("gui64.exe")
}

// ---------------------------------------------------------------- portable executables

#[test]
fn a_portable_exe_installs_end_to_end() {
    let f = fx();
    let exe = hello64();
    let path = f.input("hello64.exe", &exe);
    let out = f.ok(&path, &InstallOpts::default());

    assert_eq!(out.id.as_str(), "runtime-fixture", "named after the ProductName");
    assert_eq!(
        out.executable.to_string(),
        "C:\\Program Files\\runtime-fixture\\hello64.exe"
    );
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);

    let env = f.store.get(&out.id).unwrap();
    let md = f.store.read_metadata(&env).unwrap();
    assert_eq!(md.id, out.id);
    assert_eq!(md.name, "Runtime Fixture");
    assert_eq!(md.version.as_deref(), Some("1.2.3.4"));
    assert_eq!(md.architecture, "x86_64");
    assert_eq!(md.executable, "C:\\Program Files\\runtime-fixture\\hello64.exe");
    assert_eq!(md.environment, "default");
    assert_eq!(md.schema_version, 2);
    assert_eq!(md.backend.id, "fake");
    assert_eq!(md.backend.version, "fake-1.0");
    assert_eq!(md.subsystem, "console");
    assert!(md.created > 1_600_000_000);

    let copied = env.drive_c().join("Program Files/runtime-fixture/hello64.exe");
    assert_eq!(fs::read(&copied).unwrap(), exe, "the copy must be byte-identical");
    let mode = fs::metadata(&copied).unwrap().mode();
    assert_eq!(mode & 0o7111, 0, "no setuid/exec bits ({mode:o})");
    assert_eq!(fs::read(&path).unwrap(), exe, "the original is untouched");

    // `prepare` ran exactly once; a successful install never stops or removes anything.
    assert_eq!(f.backend.calls(), vec![Call::Prepare { app: out.id.clone() }]);
    // The resolved executable is exactly the copied file.
    let resolved = resolve_under(&env.drive_c(), &WinPath::parse(&md.executable).unwrap()).unwrap();
    assert_eq!(resolved, copied);
}

#[test]
fn a_32_bit_exe_is_accepted_and_recorded_as_x86() {
    let f = fx();
    let out = f.ok(
        &f.input("hello32.exe", &fixture("hello32.exe")),
        &InstallOpts::default(),
    );
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert_eq!(md.architecture, "x86");
}

#[test]
fn installing_the_same_program_twice_gives_distinct_ids() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let a = f.ok(&path, &InstallOpts::default());
    let b = f.ok(&path, &InstallOpts::default());
    let c = f.ok(&path, &InstallOpts::default());
    assert_eq!(
        [a.id.as_str(), b.id.as_str(), c.id.as_str()],
        ["hello64", "hello64-2", "hello64-3"]
    );
    assert_eq!(b.executable.to_string(), "C:\\Program Files\\hello64-2\\hello64.exe");
    for id in [&a.id, &b.id, &c.id] {
        f.store.read_metadata(&f.store.get(id).unwrap()).unwrap();
    }
}

#[test]
fn the_name_option_sets_the_display_name_and_the_id() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let out = f.ok(&path, &named("My Great App!"));
    assert_eq!(out.id.as_str(), "my-great-app");
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert_eq!(md.name, "My Great App!");
}

#[test]
fn control_characters_are_stripped_from_names_and_long_names_are_capped() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let out = f.ok(&path, &named("A\x1b[31mB\n\u{202e}C\0"));
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert_eq!(md.name, "A[31mBC");
    assert_eq!(out.id.as_str(), "a-31mbc");

    let long = "x".repeat(10_000);
    let out = f.ok(&path, &named(&long));
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert_eq!(md.name.len(), 256);
    assert!(out.id.as_str().len() <= 64);

    let wide = "\u{e9}".repeat(400);
    let out = f.ok(&path, &named(&wide));
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert!(md.name.len() <= 256 && md.name.chars().all(|c| c == '\u{e9}'));
}

#[test]
fn a_name_with_nothing_left_after_cleaning_is_an_error_and_creates_nothing() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    for name in ["", "   ", "\x01\x02\n"] {
        let err = f.run(&path, &named(name)).unwrap_err();
        assert!(matches!(err, InstallError::BadName), "{name:?}: {err}");
    }
    f.assert_nothing_created("empty name");
}

#[test]
fn names_that_are_all_symbols_or_reserved_windows_names_still_get_a_usable_id() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let out = f.ok(&path, &named("\u{1f600}\u{1f600}"));
    assert_eq!(out.id.as_str(), "app");
    for (name, id) in [
        ("con", "app-con"),
        ("NUL", "app-nul"),
        ("Com1", "app-com1"),
        ("lpt9", "app-lpt9"),
    ] {
        let out = f.ok(&path, &named(name));
        assert_eq!(out.id.as_str(), id, "{name}");
        assert!(
            out.executable
                .to_string()
                .starts_with(&format!("C:\\Program Files\\{id}\\"))
        );
    }
}

#[test]
fn the_product_name_beats_the_file_stem_and_the_name_option_beats_both() {
    let f = fx();
    let bytes = prog();
    let mut info = pe::analyze(&bytes).unwrap();
    assert!(
        info.version.is_none(),
        "the gui fixture is expected to carry no version resource"
    );
    assert_eq!(choose_name(None, &info, "stem").unwrap(), "stem");
    let mut strings = std::collections::BTreeMap::new();
    strings.insert("ProductName".to_owned(), "  Cool\x1bProduct\u{202e} ".to_owned());
    info.version = Some(pe::VersionInfo {
        file_version: Some("1.2.3.4".into()),
        strings,
    });
    assert_eq!(choose_name(None, &info, "stem").unwrap(), "CoolProduct");
    assert_eq!(choose_name(Some("Mine"), &info, "stem").unwrap(), "Mine");
    // An empty product name falls back to the stem; an empty stem to "app".
    info.version
        .as_mut()
        .unwrap()
        .strings
        .insert("ProductName".into(), "\x01".into());
    assert_eq!(choose_name(None, &info, "stem").unwrap(), "stem");
    assert_eq!(choose_name(None, &info, "").unwrap(), "app");
    let _ = f;
}

#[test]
fn a_symlink_to_a_regular_file_is_accepted_and_a_symlink_to_a_directory_is_not() {
    let f = fx();
    let real = f.input("real.exe", &prog());
    let link = f.tmp.path().join("in/link.exe");
    symlink(&real, &link).unwrap();
    let out = f.ok(&link, &InstallOpts::default());
    assert_eq!(
        out.executable.to_string(),
        "C:\\Program Files\\link\\link.exe",
        "named after the path given"
    );

    let dir_link = f.tmp.path().join("in/dirlink");
    symlink(f.tmp.path().join("in"), &dir_link).unwrap();
    assert!(matches!(
        f.run(&dir_link, &InstallOpts::default()),
        Err(InstallError::NotRegular)
    ));
    let dangling = f.tmp.path().join("in/dangling");
    symlink(f.tmp.path().join("nope"), &dangling).unwrap();
    assert!(matches!(
        f.run(&dangling, &InstallOpts::default()),
        Err(InstallError::Read(_))
    ));
}

#[test]
fn a_file_name_that_cannot_live_in_a_windows_prefix_is_refused() {
    let f = fx();
    for name in [
        "a\\b.exe",
        "a:b.exe",
        "con.exe",
        "trailing.",
        "trailing ",
        "star*.exe",
        "q?.exe",
    ] {
        let path = f.input(name, &prog());
        let err = f.run(&path, &InstallOpts::default()).unwrap_err();
        assert!(matches!(err, InstallError::BadFileName(_)), "{name:?}: {err}");
    }
    f.assert_nothing_created("bad file names");
}

#[test]
fn an_exe_option_on_a_portable_exe_is_ignored_with_a_warning() {
    let f = fx();
    let out = f.ok(&f.input("hello64.exe", &prog()), &with_exe("other.exe"));
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].contains("--exe"));
}

fn patched(bytes: Vec<u8>, what: &str) -> Vec<u8> {
    match what {
        "driver" => set_subsystem(bytes, 1),
        "arm64" => set_machine(bytes, 0xAA64),
        "arm64ec" => set_machine(bytes, 0xA641),
        "arm32" => set_machine(bytes, 0x01C0),
        "inno" => with_overlay(bytes, b"\0\0Inno Setup Setup Data (6.2.0)\0"),
        "nsis" => with_overlay(bytes, b"\0\0NullsoftInst\0"),
        "installshield" => with_overlay(bytes, b"InstallShield\0"),
        _ => unreachable!(),
    }
}

#[test]
fn programs_that_cannot_run_are_refused_and_leave_nothing_behind() {
    let f = fx();
    type Want = fn(&InstallError) -> bool;
    let cases: [(&str, Vec<u8>, Want); 10] = [
        ("driver", patched(prog(), "driver"), |e| {
            matches!(e, InstallError::KernelDriver)
        }),
        ("dll", fixture("exports64.dll"), |e| matches!(e, InstallError::Dll)),
        (
            "arm64",
            patched(prog(), "arm64"),
            |e| matches!(e, InstallError::UnsupportedArch(a) if a == "arm64"),
        ),
        ("arm64ec", patched(prog(), "arm64ec"), |e| {
            matches!(e, InstallError::UnsupportedArch(_))
        }),
        ("arm32", patched(prog(), "arm32"), |e| {
            matches!(e, InstallError::UnsupportedArch(_))
        }),
        ("inno", patched(prog(), "inno"), |e| {
            matches!(e, InstallError::InstallerDetected("Inno Setup"))
        }),
        ("nsis", patched(prog(), "nsis"), |e| {
            matches!(e, InstallError::InstallerDetected(_))
        }),
        ("installshield", patched(prog(), "installshield"), |e| {
            matches!(e, InstallError::InstallerDetected(_))
        }),
        (
            "msi",
            [&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1][..], &[0u8; 512]].concat(),
            |e| matches!(e, InstallError::Msi),
        ),
        ("unknown", b"just some text, not a program".to_vec(), |e| {
            matches!(e, InstallError::Unknown)
        }),
    ];
    for (what, bytes, want) in cases {
        let path = f.input(&format!("{what}.bin"), &bytes);
        let err = f.run(&path, &InstallOpts::default()).unwrap_err();
        assert!(want(&err), "{what}: unexpected {err}");
        f.assert_nothing_created(what);
    }
    let text = |e: InstallError| e.to_string();
    let inno = f
        .run(&f.input("i.bin", &patched(prog(), "inno")), &InstallOpts::default())
        .unwrap_err();
    assert!(
        text(inno).contains("installer detected")
            && text(
                f.run(
                    &f.input("m.bin", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
                    &InstallOpts::default()
                )
                .unwrap_err()
            )
            .contains("Phase 3")
    );
}

#[test]
fn degenerate_inputs_are_refused_and_leave_nothing_behind() {
    let f = fx();
    let bad_pe = {
        let mut b = prog();
        b.truncate(0x100); // headers cut short
        b
    };
    let mz_only = b"MZ".repeat(100);
    for (what, bytes) in [
        ("empty", Vec::new()),
        ("bad_pe", bad_pe),
        ("mz_only", mz_only),
        ("pk", b"PK\x03\x04".to_vec()),
    ] {
        let path = f.input(what, &bytes);
        assert!(f.run(&path, &InstallOpts::default()).is_err(), "{what}");
        f.assert_nothing_created(what);
    }
    // A directory, a missing path.
    let dir = f.tmp.path().join("in");
    assert!(matches!(
        f.run(&dir, &InstallOpts::default()),
        Err(InstallError::NotRegular)
    ));
    assert!(matches!(
        f.run(&f.tmp.path().join("nope"), &InstallOpts::default()),
        Err(InstallError::Read(_))
    ));
    f.assert_nothing_created("dir/missing");
}

#[test]
fn a_fifo_input_is_refused_and_does_not_hang() {
    let f = fx();
    let fifo = f.tmp.path().join("in/pipe");
    mkfifo(&fifo);
    let store = f.store.clone();
    let err = within_10s(move || {
        let backend = FakeBackend::new();
        install_with(
            &store,
            &backend,
            &fifo,
            &InstallOpts::default(),
            &tunables(Limits::default(), &unique_id),
        )
    })
    .unwrap_err();
    assert!(matches!(err, InstallError::NotRegular), "{err}");
    f.assert_nothing_created("fifo");
}

#[test]
fn a_5_gib_sparse_file_is_refused_without_reading_it() {
    let f = fx();
    let path = f.tmp.path().join("in/huge.exe");
    let file = File::create(&path).unwrap();
    file.set_len(5 << 30).unwrap();
    // It starts like a PE so a reader that did not check the size first would start reading.
    (&file).write_all(&prog()).unwrap();
    let started = std::time::Instant::now();
    let err = f.run(&path, &InstallOpts::default()).unwrap_err();
    assert!(matches!(err, InstallError::TooLarge), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    f.assert_nothing_created("5 GiB sparse file");
}

#[test]
fn the_host_must_be_x86_64() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    for arch in ["aarch64", "riscv64", "x86", ""] {
        let t = Tunables {
            host_arch: arch,
            limits: Limits::default(),
            pick_id: &unique_id,
        };
        let err = install_with(&f.store, &f.backend, &path, &InstallOpts::default(), &t).unwrap_err();
        assert!(matches!(err, InstallError::UnsupportedHost(_)), "{arch}: {err}");
        assert!(err.to_string().contains("x86-64"));
    }
    f.assert_nothing_created("wrong host");
}

#[test]
fn check_pe_applies_every_rule_and_dotnet_is_only_a_warning() {
    let info = pe::analyze(&prog()).unwrap();
    assert!(check_pe(&info).unwrap().is_empty());
    let mut dotnet = info.clone();
    dotnet.dotnet = true;
    let w = check_pe(&dotnet).unwrap();
    assert_eq!(w.len(), 1);
    assert!(w[0].contains(".NET"));
    let mut driver = info.clone();
    driver.subsystem = Subsystem::Native;
    assert!(matches!(check_pe(&driver), Err(InstallError::KernelDriver)));
    let mut dll = info.clone();
    dll.kind = Kind::Dll;
    assert!(matches!(check_pe(&dll), Err(InstallError::Dll)));
    for arch in [Arch::Arm64, Arch::Arm64Ec, Arch::Other(0x1c0)] {
        let mut a = info.clone();
        a.arch = arch;
        assert!(
            matches!(check_pe(&a), Err(InstallError::UnsupportedArch(_))),
            "{arch:?}"
        );
    }
    for arch in [Arch::X86, Arch::X86_64] {
        let mut a = info.clone();
        a.arch = arch;
        check_pe(&a).unwrap();
    }
    let mut warned = info.clone();
    warned.warnings = vec!["resources: \x1b[31mbad\u{202e}".into(); 20];
    let w = check_pe(&warned).unwrap();
    assert!(
        w.len() <= 5
            && w.iter()
                .all(|s| !s.contains(['\x1b', '\u{202e}']) && s.chars().count() <= 200),
        "{w:?}"
    );
}

// ---------------------------------------------------------------- backend failures and cleanup

type Hook = Box<dyn Fn(&AppEnv) + Send + Sync>;

/// A backend that delegates to a `FakeBackend` and can misbehave.
struct Wrap {
    inner: FakeBackend,
    version: Option<String>,
    version_fails: bool,
    stop_fails: bool,
    after_prepare: Option<Hook>,
}

impl Wrap {
    fn new() -> Wrap {
        Wrap {
            inner: FakeBackend::new(),
            version: None,
            version_fails: false,
            stop_fails: false,
            after_prepare: None,
        }
    }
}

impl CompatBackend for Wrap {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn version(&self) -> Result<String, BackendError> {
        if self.version_fails {
            return Err(BackendError::Unavailable(crate::Detail::from_bytes(b"install wine")));
        }
        Ok(self.version.clone().unwrap_or_else(|| "fake-1.0".into()))
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.prepare(env)?;
        if let Some(hook) = &self.after_prepare {
            hook(env);
        }
        Ok(())
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[std::ffi::OsString],
        opts: &crate::RunOpts,
    ) -> Result<std::process::Command, BackendError> {
        self.inner.command(env, exe, cwd, args, opts)
    }
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.stop(env)?;
        if self.stop_fails {
            return Err(BackendError::failed("wineserver -k", b"stuck \x1b[31m server"));
        }
        Ok(())
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        self.inner.dll_dirs()
    }
}

#[test]
fn invalid_metadata_is_caught_before_anything_is_created() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let wrap = Wrap {
        version: Some("v".repeat(5000)), // longer than metadata allows
        ..Wrap::new()
    };
    let err = f.run_with(&wrap, &path, &InstallOpts::default()).unwrap_err();
    assert!(matches!(err, InstallError::Meta(MetaError::TooLong { .. })), "{err}");
    assert!(!f.apps().exists(), "the store was touched: {:?}", f.outside());
    assert!(wrap.inner.calls().is_empty(), "prepare ran: {:?}", wrap.inner.calls());
}

/// A backend whose `prepare` panics after creating the prefix (as buggy zip or PE code would).
fn panicking() -> Wrap {
    Wrap {
        after_prepare: Some(Box::new(|_: &AppEnv| panic!("boom in prepare"))),
        ..Wrap::new()
    }
}

#[test]
fn a_panic_after_create_still_removes_the_environment() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let wrap = panicking();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.run_with(&wrap, &path, &InstallOpts::default())
    }));
    assert!(caught.is_err(), "the panic must propagate to the caller");
    f.assert_no_app_left("panic in prepare");
    let id = AppId::parse("hello64").unwrap();
    assert_eq!(
        wrap.inner.calls(),
        vec![Call::Prepare { app: id.clone() }, Call::Stop { app: id }],
        "the backend is stopped before the directory goes"
    );
    assert_eq!(fs::read_to_string(f.tmp.path().join("canary")).unwrap(), "canary");
}

#[test]
fn a_panic_with_a_backend_that_cannot_stop_leaves_the_tree_and_does_not_abort() {
    let f = fx();
    let wrap = Wrap {
        stop_fails: true,
        ..panicking()
    };
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.run_with(&wrap, &f.input("hello64.exe", &prog()), &InstallOpts::default())
    }));
    assert!(caught.is_err());
    assert!(
        f.apps().join("hello64").is_dir(),
        "not removed while a Wine process may run"
    );
}

#[test]
fn a_successful_install_does_not_trigger_the_unwind_cleanup() {
    let f = fx();
    let out = f.ok(&f.input("hello64.exe", &prog()), &InstallOpts::default());
    assert!(f.store.read_metadata(&f.store.get(&out.id).unwrap()).is_ok());
    assert_eq!(f.backend.calls(), vec![Call::Prepare { app: out.id }]);
}

#[test]
fn every_retried_id_is_validated_before_its_create() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let foreign = f.apps().join("hello64");
    fs::create_dir_all(&foreign).unwrap();
    let first = std::cell::Cell::new(true);
    // The first (stale) answer collides; the second is a valid app id that is not a usable Windows directory name.
    let pick = |_: &Store, base: &AppId| -> Result<AppId, StoreError> {
        if first.replace(false) {
            Ok(base.clone())
        } else {
            Ok(AppId::parse("con")?)
        }
    };
    let err = install_with(
        &f.store,
        &f.backend,
        &path,
        &InstallOpts::default(),
        &tunables(Limits::default(), &pick),
    )
    .unwrap_err();
    assert!(matches!(err, InstallError::Path(_)), "{err}");
    assert_eq!(tree(&f.apps()), ["hello64/"], "nothing was created for the rejected id");
    assert!(f.backend.calls().is_empty());
}

#[test]
fn a_backend_that_is_not_available_stops_the_install_before_anything_is_created() {
    let f = fx();
    let wrap = Wrap {
        version_fails: true,
        ..Wrap::new()
    };
    let err = f
        .run_with(&wrap, &f.input("a.exe", &prog()), &InstallOpts::default())
        .unwrap_err();
    assert!(
        matches!(&err, InstallError::Backend(BackendError::Unavailable(_))),
        "{err}"
    );
    assert!(!f.apps().exists());
    assert!(wrap.inner.calls().is_empty());
}

#[test]
fn a_failing_prepare_is_reported_unchanged_and_the_environment_is_removed() {
    let f = fx_with(FakeBackend::new().failing_prepare());
    let path = f.input("hello64.exe", &prog());
    let err = f.run(&path, &InstallOpts::default()).unwrap_err();
    assert!(
        matches!(&err, InstallError::Backend(BackendError::Failed { .. })),
        "{err}"
    );
    f.assert_no_app_left("failed prepare");
    let id = AppId::parse("hello64").unwrap();
    // The backend is stopped BEFORE the directory goes away.
    assert_eq!(
        f.backend.calls(),
        vec![Call::Prepare { app: id.clone() }, Call::Stop { app: id }]
    );
    assert_eq!(fs::read_to_string(f.tmp.path().join("canary")).unwrap(), "canary");
}

#[test]
fn when_stop_fails_nothing_is_removed_and_the_error_says_so() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    // Prepare succeeds, then the copy fails (a file is already in the way), then the stop fails too.
    let wrap = Wrap {
        stop_fails: true,
        after_prepare: Some(Box::new(|env: &AppEnv| {
            let dir = env.drive_c().join("Program Files/hello64");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("hello64.exe"), "in the way").unwrap();
        })),
        ..Wrap::new()
    };
    let err = f.run_with(&wrap, &path, &InstallOpts::default()).unwrap_err();
    let InstallError::WithCleanup { cause, problems } = &err else {
        panic!("expected cleanup problems: {err}");
    };
    assert!(matches!(**cause, InstallError::Io { .. }), "{cause}");
    assert!(matches!(err.cause(), InstallError::Io { .. }));
    assert_eq!(problems.len(), 1);
    assert!(
        problems[0].contains("could not be stopped") && problems[0].contains("runtime remove hello64"),
        "{problems:?}"
    );
    assert!(!problems[0].contains('\x1b'), "unescaped text: {problems:?}");
    assert!(problems[0].chars().count() <= 400);
    // Left in place for the user; metadata (the commit point) was never written; the obstacle is untouched.
    let root = f.apps().join("hello64");
    assert!(root.is_dir());
    assert!(!root.join("metadata.json").exists());
    assert_eq!(
        fs::read_to_string(root.join("prefix/drive_c/Program Files/hello64/hello64.exe")).unwrap(),
        "in the way"
    );
    assert_eq!(wrap.inner.calls().len(), 2);
}

#[test]
fn an_existing_file_is_never_overwritten() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let wrap = Wrap {
        after_prepare: Some(Box::new(|env: &AppEnv| {
            let dir = env.drive_c().join("Program Files/hello64");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("hello64.exe"), "precious").unwrap();
        })),
        stop_fails: true, // keep the tree so the content can be inspected
        ..Wrap::new()
    };
    assert!(f.run_with(&wrap, &path, &InstallOpts::default()).is_err());
    let kept = f
        .apps()
        .join("hello64/prefix/drive_c/Program Files/hello64/hello64.exe");
    assert_eq!(fs::read_to_string(kept).unwrap(), "precious");
}

#[test]
fn a_symlinked_program_files_directory_is_never_followed() {
    let f = fx();
    let outside = f.tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = outside.clone();
    let wrap = Wrap {
        after_prepare: Some(Box::new(move |env: &AppEnv| {
            symlink(&target, env.drive_c().join("Program Files")).unwrap();
        })),
        ..Wrap::new()
    };
    for input in [
        f.input("hello64.exe", &prog()),
        f.input(
            "app.zip",
            &raw_zip(&[Raw::file("a.exe", &prog()), Raw::file("d/x.txt", b"x")]),
        ),
    ] {
        let err = f.run_with(&wrap, &input, &InstallOpts::default()).unwrap_err();
        assert!(matches!(err, InstallError::Resolve(ResolveError::Symlink)), "{err}");
        assert!(
            fs::read_dir(&outside).unwrap().next().is_none(),
            "wrote through the symlink"
        );
        f.assert_no_app_left("symlinked Program Files");
    }
}

#[test]
fn a_program_directory_that_is_a_symlink_is_never_followed_either() {
    let f = fx();
    let outside = f.tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = outside.clone();
    let wrap = Wrap {
        after_prepare: Some(Box::new(move |env: &AppEnv| {
            let pf = env.drive_c().join("Program Files");
            fs::create_dir_all(&pf).unwrap();
            symlink(&target, pf.join("hello64")).unwrap();
        })),
        ..Wrap::new()
    };
    let err = f
        .run_with(&wrap, &f.input("hello64.exe", &prog()), &InstallOpts::default())
        .unwrap_err();
    assert!(matches!(err, InstallError::Resolve(ResolveError::Symlink)), "{err}");
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
    f.assert_no_app_left("symlinked program dir");
}

// ---------------------------------------------------------------- ids: AlreadyExists is never cleaned up

#[test]
fn a_create_race_moves_to_the_next_id_and_never_removes_the_foreign_directory() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    // Someone else owns `hello64` (created between our id pick and our create, as far as install can tell).
    let foreign = f.apps().join("hello64");
    fs::create_dir_all(&foreign).unwrap();
    fs::write(foreign.join("their-data"), "theirs").unwrap();
    let first = std::cell::Cell::new(true);
    let pick = |store: &Store, base: &AppId| -> Result<AppId, StoreError> {
        if first.replace(false) {
            Ok(base.clone()) // the stale answer: already taken
        } else {
            unique_id(store, base)
        }
    };
    let out = install_with(
        &f.store,
        &f.backend,
        &path,
        &InstallOpts::default(),
        &tunables(Limits::default(), &pick),
    )
    .unwrap();
    assert_eq!(out.id.as_str(), "hello64-2");
    assert_eq!(
        fs::read_to_string(foreign.join("their-data")).unwrap(),
        "theirs",
        "a foreign app was touched"
    );
    assert!(f.store.read_metadata(&f.store.get(&out.id).unwrap()).is_ok());
    assert_eq!(
        f.backend.calls(),
        vec![Call::Prepare { app: out.id }],
        "no Stop (nothing was removed)"
    );
}

#[test]
fn giving_up_after_repeated_collisions_removes_nothing() {
    let f = fx();
    let path = f.input("hello64.exe", &prog());
    let foreign = f.apps().join("hello64");
    fs::create_dir_all(&foreign).unwrap();
    fs::write(foreign.join("their-data"), "theirs").unwrap();
    let picks = std::cell::Cell::new(0);
    let always_taken = |_: &Store, base: &AppId| -> Result<AppId, StoreError> {
        picks.set(picks.get() + 1);
        Ok(base.clone())
    };
    let err = install_with(
        &f.store,
        &f.backend,
        &path,
        &InstallOpts::default(),
        &tunables(Limits::default(), &always_taken),
    )
    .unwrap_err();
    assert!(matches!(err, InstallError::Store(StoreError::AlreadyExists)), "{err}");
    assert!(picks.get() >= 2 && picks.get() <= 6, "{} attempts", picks.get());
    assert_eq!(fs::read_to_string(foreign.join("their-data")).unwrap(), "theirs");
    assert!(f.backend.calls().is_empty(), "prepare ran against a foreign directory");
    assert_eq!(tree(&f.apps()), ["hello64/", "hello64/their-data"]);
}

// ---------------------------------------------------------------- zip archives

fn crate_zip(build: impl FnOnce(&mut zip::ZipWriter<Cursor<Vec<u8>>>)) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    build(&mut w);
    w.finish().unwrap().into_inner()
}

fn opts_deflate() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
}

#[test]
fn a_zip_with_one_program_installs_with_its_directory_tree() {
    let f = fx();
    let exe = prog();
    let zip = crate_zip(|w| {
        let o = opts_deflate();
        w.add_directory("MyGame/", o).unwrap();
        w.add_directory("MyGame/data/", o).unwrap();
        w.start_file("MyGame/game.exe", o).unwrap();
        w.write_all(&exe).unwrap();
        w.start_file("MyGame/data/level1.dat", o).unwrap();
        w.write_all(&[42u8; 10_000]).unwrap();
        w.start_file(
            "MyGame/readme.txt",
            o.compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        w.write_all(b"read me").unwrap();
    });
    let path = f.input("MyGame v1.zip", &zip);
    let out = f.ok(&path, &InstallOpts::default());
    assert_eq!(out.id.as_str(), "mygame-v1", "named after the archive");
    assert_eq!(
        out.executable.to_string(),
        "C:\\Program Files\\mygame-v1\\MyGame\\game.exe"
    );
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let env = f.store.get(&out.id).unwrap();
    let base = env.drive_c().join("Program Files/mygame-v1/MyGame");
    assert_eq!(fs::read(base.join("game.exe")).unwrap(), exe);
    assert_eq!(fs::read(base.join("data/level1.dat")).unwrap(), vec![42u8; 10_000]);
    assert_eq!(fs::read(base.join("readme.txt")).unwrap(), b"read me");
    for p in ["game.exe", "data/level1.dat", "readme.txt"] {
        let m = fs::metadata(base.join(p)).unwrap().mode();
        assert_eq!(m & 0o7111, 0, "{p}: {m:o}");
    }
    let md = f.store.read_metadata(&env).unwrap();
    assert_eq!(md.executable, out.executable.to_string());
    assert_eq!(md.name, "MyGame v1");
    assert_eq!(f.backend.calls(), vec![Call::Prepare { app: out.id }]);
}

fn two_exes() -> Vec<Raw> {
    let gui = fixture("gui64.exe");
    vec![
        Raw::file("tools/a.exe", &hello64()),
        Raw::file("Main.EXE", &gui),
        Raw::file("notes.txt", b"n"),
    ]
}

#[test]
fn the_exe_option_picks_a_program_case_insensitively_and_validates_it() {
    let f = fx();
    let path = f.input("two.zip", &raw_zip(&two_exes()));
    let out = f.ok(&path, &with_exe("TOOLS\\A.exe"));
    assert_eq!(
        out.executable.to_string(),
        "C:\\Program Files\\runtime-fixture\\tools\\a.exe"
    );
    let out = f.ok(&path, &with_exe("./main.exe"));
    assert_eq!(out.executable.to_string(), "C:\\Program Files\\two\\Main.EXE");
    let md = f.store.read_metadata(&f.store.get(&out.id).unwrap()).unwrap();
    assert_eq!(md.subsystem, "gui");

    let before = tree(&f.apps());
    for bad in [
        "../evil.exe",
        "/a.exe",
        "C:\\a.exe",
        "missing.exe",
        "tools",
        "tools/",
        "notes.txt",
        "",
        ".",
    ] {
        let err = f.run(&path, &with_exe(bad)).unwrap_err();
        assert!(matches!(err, InstallError::Select(_)), "--exe {bad:?}: {err}");
        assert!(err.to_string().chars().count() < 400);
    }
    // Names that are not valid entry names are refused as such, not merely "not found".
    for bad in ["../evil.exe", "/a.exe", "C:\\a.exe", "a/../b.exe", ""] {
        let err = f.run(&path, &with_exe(bad)).unwrap_err().to_string();
        assert!(
            !err.contains("not a file in the archive"),
            "--exe {bad:?} was only looked up: {err}"
        );
    }
    assert_eq!(tree(&f.apps()), before, "a bad --exe must not create anything");
}

#[test]
fn the_only_exe_is_chosen_even_when_it_is_a_console_program() {
    let f = fx();
    let zip = raw_zip(&[
        Raw::file("bin/run.exe", &hello64()),
        Raw::file("lib/x.dll", &fixture("exports64.dll")),
    ]);
    let out = f.ok(&f.input("one.zip", &zip), &InstallOpts::default());
    assert_eq!(
        out.executable.to_string(),
        "C:\\Program Files\\runtime-fixture\\bin\\run.exe"
    );
}

#[test]
fn among_several_exes_the_largest_gui_program_wins() {
    let f = fx();
    let gui = fixture("gui64.exe");
    let big_gui = with_overlay(gui.clone(), &[0u8; 5000]);
    let huge_console = with_overlay(hello64(), &[0u8; 50_000]);
    let dll_as_exe = fixture("exports64.dll");
    let zip = raw_zip(&[
        Raw::file("small.exe", &gui),
        Raw::file("big.exe", &big_gui),
        Raw::file("console.exe", &huge_console),
        Raw::file("not-a-program.exe", b"text"),
        Raw::file("dll.exe", &dll_as_exe),
        Raw::file("driver.exe", &patched(gui.clone(), "driver")),
        Raw::file(
            "setup.exe",
            &with_overlay(with_overlay(gui, &[0u8; 90_000]), b"NullsoftInst"),
        ),
    ]);
    let out = f.ok(&f.input("many.zip", &zip), &InstallOpts::default());
    assert_eq!(out.executable.to_string(), "C:\\Program Files\\many\\big.exe");
    // Four candidates (text, DLL, driver, installer) were dropped: that is said once, with the first reason.
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(
        out.warnings[0].starts_with("4 of the 7 .exe files"),
        "{:?}",
        out.warnings
    );
    assert!(out.warnings[0].contains("first reason"), "{:?}", out.warnings);
    assert!(out.warnings[0].chars().count() < 250, "{:?}", out.warnings);
}

#[test]
fn an_ambiguous_archive_asks_for_the_exe_option_and_lists_escaped_names() {
    let f = fx();
    let gui = fixture("gui64.exe");
    // Two GUI programs of the same size; one name carries a bidi override.
    let zip = raw_zip(&[Raw::file("one.exe", &gui), Raw::file("tw\u{202e}o.exe", &gui)]);
    let err = f.run(&f.input("amb.zip", &zip), &InstallOpts::default()).unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, InstallError::Select(_)), "{text}");
    assert!(text.contains("--exe"), "{text}");
    assert!(text.contains("\"one.exe\"") && text.contains("\\u{202e}"), "{text}");
    assert!(!text.contains('\u{202e}'), "{text}");
    f.assert_nothing_created("ambiguous archive");

    // No GUI program at all among several exes: also an error asking for --exe.
    let zip = raw_zip(&[
        Raw::file("a.exe", &hello64()),
        Raw::file("b.exe", &with_overlay(hello64(), &[1])),
    ]);
    let err = f.run(&f.input("cons.zip", &zip), &InstallOpts::default()).unwrap_err();
    assert!(
        matches!(err, InstallError::Select(_)) && err.to_string().contains("--exe"),
        "{err}"
    );
    // No exe at all.
    let zip = raw_zip(&[Raw::file("a.txt", b"x")]);
    let err = f.run(&f.input("none.zip", &zip), &InstallOpts::default()).unwrap_err();
    assert!(
        matches!(err, InstallError::Select(_)) && err.to_string().contains("--exe"),
        "{err}"
    );
    f.assert_nothing_created("no program");
}

#[test]
fn the_candidate_list_in_an_error_is_short_and_bounded() {
    let f = fx();
    let entries: Vec<Raw> = (0..30)
        .map(|i| Raw::file(&format!("{}{i}.exe", "n".repeat(150)), &prog()))
        .collect();
    let err = f
        .run(&f.input("thirty.zip", &raw_zip(&entries)), &InstallOpts::default())
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.matches(".exe\"").count() <= 10,
        "more than 10 names listed: {text}"
    );
    assert!(text.chars().count() < 2000, "{} chars", text.chars().count());
}

#[test]
fn more_exes_than_the_candidate_cap_need_an_explicit_choice_without_analysing_them() {
    let f = fx();
    let entries: Vec<Raw> = (0..65)
        .map(|i| Raw::file(&format!("p{i}.exe"), &fixture("gui64.exe")))
        .collect();
    let path = f.input("sixtyfive.zip", &raw_zip(&entries));
    let err = f.run(&path, &InstallOpts::default()).unwrap_err();
    assert!(
        matches!(err, InstallError::Select(_)) && err.to_string().contains("--exe"),
        "{err}"
    );
    assert!(err.to_string().contains("65 .exe files"), "{err}");
    f.assert_nothing_created("65 candidates");
    f.ok(&path, &with_exe("p7.exe"));
}

#[test]
fn the_program_of_a_zip_is_held_to_the_same_rules_as_a_portable_exe() {
    let f = fx();
    let gui = fixture("gui64.exe");
    let bad: [(&str, Vec<u8>); 6] = [
        ("driver", patched(gui.clone(), "driver")),
        ("dll", fixture("exports64.dll")),
        ("arm64", patched(gui.clone(), "arm64")),
        ("inno", patched(gui.clone(), "inno")),
        ("text", b"MZ not really".to_vec()),
        (
            "msi",
            [&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1][..], &[0u8; 100]].concat(),
        ),
    ];
    for (what, bytes) in bad {
        let zip = raw_zip(&[Raw::file("app/x.exe", &bytes)]);
        let err = f
            .run(&f.input(&format!("{what}.zip"), &zip), &InstallOpts::default())
            .unwrap_err();
        assert!(!matches!(err, InstallError::Io { .. }), "{what}: {err}");
        f.assert_nothing_created(what);
        let err = f
            .run(
                &f.input(
                    &format!("{what}2.zip"),
                    &raw_zip(&[Raw::file("app/x.exe", &bytes), Raw::file("y.exe", b"")]),
                ),
                &with_exe("app/x.exe"),
            )
            .unwrap_err();
        assert!(!matches!(err, InstallError::Io { .. }), "{what}: {err}");
        f.assert_nothing_created(what);
    }
}

#[test]
fn zip_slip_and_other_hostile_entry_names_write_nothing_anywhere() {
    let hostile = [
        "../evil",
        "/abs",
        "/etc/cron.d/evil",
        "C:\\x",
        "C:/Windows/x",
        "a/../../b",
        "..\\..\\x",
        "a/..",
        ".",
        "",
        "a\0b",
        "C:foo",
        "\\\\srv\\x",
        "\\\\?\\unix\\etc\\x",
        "a:b",
        "con.txt",
        "trail.",
        "trail ",
    ];
    let f = fx();
    let before = f.outside();
    for name in hostile {
        let zip = raw_zip(&[Raw::file("good.exe", &prog()), Raw::file(name, b"evil")]);
        let path = f.input("slip.zip", &zip);
        let err = f.run(&path, &InstallOpts::default()).unwrap_err();
        assert!(
            matches!(err, InstallError::Zip(ZipError::BadName { .. })),
            "{name:?}: {err}"
        );
        assert!(err.to_string().chars().count() < 300 && !err.to_string().contains(['\0', '\x1b']));
        assert_eq!(f.outside(), before, "{name:?}: something was written");
        assert!(f.backend.calls().is_empty(), "{name:?}: prepare ran");
    }
    assert_eq!(f.outside(), ["canary"], "the whole tree apart from the inputs");
    // The same names as the program to run (--exe).
    let path = f.input("slip2.zip", &raw_zip(&[Raw::file("good.exe", &prog())]));
    for name in ["../evil.exe", "/abs.exe", "C:\\x.exe", "..\\..\\x.exe"] {
        assert!(f.run(&path, &with_exe(name)).is_err(), "{name:?}");
    }
    assert_eq!(f.outside(), ["canary"]);
}

#[test]
fn symlink_and_special_entries_are_skipped_and_counted_in_one_warning() {
    let f = fx();
    let zip = raw_zip(&[
        Raw::file("app.exe", &prog()),
        Raw::special("link", S_IFLNK | 0o777, b"/etc/passwd"),
        Raw::special("dir/link2", S_IFLNK | 0o777, b"../../../etc"),
        Raw::special("fifo", S_IFIFO | 0o644, b""),
        Raw::special("dev", S_IFCHR | 0o666, b""),
    ]);
    let out = f.ok(&f.input("special.zip", &zip), &InstallOpts::default());
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].contains('4'), "{:?}", out.warnings);
    let env = f.store.get(&out.id).unwrap();
    assert_eq!(tree(&env.drive_c().join("Program Files/special")), ["app.exe"]);
}

#[test]
fn a_setuid_entry_never_becomes_a_setuid_file() {
    let f = fx();
    let zip = raw_zip(&[
        Raw::file("app.exe", &prog()).mode(S_IFREG | 0o4755),
        Raw::file("helper", b"#!/bin/sh").mode(S_IFREG | 0o6777),
    ]);
    let out = f.ok(&f.input("suid.zip", &zip), &InstallOpts::default());
    let base = f.store.get(&out.id).unwrap().drive_c().join("Program Files/suid");
    for name in ["app.exe", "helper"] {
        let m = fs::metadata(base.join(name)).unwrap().mode();
        assert_eq!(m & 0o7111, 0, "{name}: mode {m:o}");
    }
}

#[test]
fn hostile_archives_are_refused_before_anything_is_created() {
    let f = fx();
    let exe = prog();
    let base = vec![Raw::file("ok.exe", &exe)];
    let with = |extra: Vec<Raw>| raw_zip(&[base.clone(), extra].concat());
    let dup = {
        let z = raw_zip(&[
            Raw::file("aaaaaaa.txt", b"1"),
            Raw::file("bbbbbbb.txt", b"2"),
            Raw::file("ok.exe", &exe),
        ]);
        let (from, to) = (b"bbbbbbb.txt".as_slice(), b"aaaaaaa.txt".as_slice());
        let mut z = z;
        let mut i = 0;
        while i + from.len() <= z.len() {
            if &z[i..i + from.len()] == from {
                z[i..i + to.len()].copy_from_slice(to);
                i += to.len();
            } else {
                i += 1;
            }
        }
        z
    };
    let zeros = deflated_zeros(300 << 20);
    let bomb = Raw {
        method: 8,
        data: zeros,
        declared_size: 300 << 20,
        crc: 0,
        ..Raw::file("zeros.bin", b"")
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("encrypted", with(vec![Raw::file("s.txt", b"secret").flags(1)])),
        (
            "case collision",
            with(vec![Raw::file("A.txt", b"1"), Raw::file("a.txt", b"2")]),
        ),
        (
            "case collision exe",
            raw_zip(&[Raw::file("A.exe", &exe), Raw::file("a.exe", &exe)]),
        ),
        ("file and dir", with(vec![Raw::file("d", b"1"), Raw::file("d/x", b"2")])),
        ("duplicate", dup),
        (
            "declared bomb",
            with(vec![Raw::file("b.bin", b"0123456789").declared(0xF000_0000)]),
        ),
        ("real bomb", raw_zip(&[Raw::file("ok.exe", &exe), bomb])),
        ("unsupported method", with(vec![Raw::file("b.bin", b"data").method(12)])),
        (
            "too many entries",
            raw_zip(
                &(0..20_001)
                    .map(|i| Raw::file(&format!("f{i}"), b""))
                    .chain([Raw::file("ok.exe", &exe)])
                    .collect::<Vec<_>>(),
            ),
        ),
        ("not a zip", [&b"PK\x03\x04"[..], &[0u8; 100]].concat()),
        (
            "decoy end record",
            with_comment(raw_zip(&base), &[b"PK\x05\x06".as_slice(), &[0u8; 18]].concat()),
        ),
        ("trailing garbage", [raw_zip(&base), b"junk".to_vec()].concat()),
        (
            "prepended data",
            [b"PK\x03\x04 prefix".to_vec(), raw_zip(&base)].concat(),
        ),
        ("count mismatch", {
            let mut z = raw_zip(&[base.clone(), vec![Raw::file("b.txt", b"b")]].concat());
            let end = eocd_at(&z);
            put16(&mut z, end + 8, 3);
            z
        }),
        ("zip64 memory attack shape", {
            let z = raw_zip(&base);
            let attack = Z64 {
                entries_disk: 30_000_000,
                total: 30_000_000,
                sentinel_count: false,
                sentinel_offset: true,
                ..Z64::honest(&z)
            };
            to_zip64_with(z, &attack)
        }),
    ];
    for (what, bytes) in cases {
        let path = f.input("hostile.zip", &bytes);
        let err = f.run(&path, &InstallOpts::default()).unwrap_err();
        assert!(matches!(err, InstallError::Zip(_)), "{what}: {err}");
        assert!(
            err.to_string().chars().count() < 600,
            "{what}: {} chars",
            err.to_string().chars().count()
        );
        f.assert_nothing_created(what);
    }
}

#[test]
fn an_entry_that_fails_mid_extraction_leaves_no_residue() {
    let f = fx();
    let mut broken = Raw::file("later/b.bin", &[1u8; 5000]);
    broken.crc ^= 0xdead; // detected only when the data has been read
    let zip = raw_zip(&[Raw::file("app.exe", &prog()), Raw::file("a/one.txt", b"1"), broken]);
    let path = f.input("broken.zip", &zip);
    let err = f.run(&path, &InstallOpts::default()).unwrap_err();
    assert!(matches!(err, InstallError::Zip(_)), "{err}");
    f.assert_no_app_left("mid-extraction failure");
    let id = AppId::parse("broken").unwrap();
    assert_eq!(
        f.backend.calls(),
        vec![Call::Prepare { app: id.clone() }, Call::Stop { app: id }]
    );

    // With a backend that cannot be stopped the half-extracted tree is kept, and metadata (last) is absent.
    let wrap = Wrap {
        stop_fails: true,
        ..Wrap::new()
    };
    let err = f.run_with(&wrap, &path, &InstallOpts::default()).unwrap_err();
    assert!(matches!(err, InstallError::WithCleanup { .. }), "{err}");
    let root = f.apps().join("broken");
    assert!(
        root.join("prefix/drive_c/Program Files/broken/app.exe").is_file(),
        "extraction did not get that far"
    );
    assert!(!root.join("metadata.json").exists(), "metadata must be written last");
    assert!(
        f.store.list().iter().all(|e| e.is_err()),
        "a half-installed app must not be listed as an app"
    );
}

#[test]
fn an_archive_with_a_lying_directory_stops_at_the_declared_size() {
    let f = fx();
    let liar = Raw::file("data.bin", &[9u8; 50_000]).declared(1000);
    let zip = raw_zip(&[Raw::file("app.exe", &prog()), liar]);
    let err = f.run(&f.input("liar.zip", &zip), &InstallOpts::default()).unwrap_err();
    assert!(
        matches!(err, InstallError::Zip(ZipError::LiesAboutSize { .. })),
        "{err}"
    );
    f.assert_no_app_left("lying archive");
}

#[test]
fn zip_limits_are_applied_by_install() {
    let f = fx();
    let exe = prog();
    let zip = raw_zip(&[Raw::file("app.exe", &exe), Raw::file("d.bin", &[1u8; 4000])]);
    let path = f.input("caps.zip", &zip);
    let tight = Limits {
        max_total_bytes: exe.len() as u64 + 3000,
        ..Limits::default()
    };
    let err = f.run_limits(&path, tight).unwrap_err();
    assert!(
        matches!(err, InstallError::Zip(ZipError::TotalTooLarge { .. })),
        "{err}"
    );
    f.assert_nothing_created("declared total");
    let limits = Limits::default();
    f.run_limits(&path, limits).unwrap();
}

#[test]
fn a_program_too_big_to_analyse_is_refused_or_skipped_as_a_candidate() {
    let f = fx();
    let small_cap = Limits {
        max_candidate_bytes: 1000,
        ..Limits::default()
    };
    // The only exe is over the cap: an error naming the limit, nothing created.
    let one = f.input("one.zip", &raw_zip(&[Raw::file("big.exe", &prog())]));
    let err = f.run_limits(&one, small_cap.clone()).unwrap_err();
    assert!(
        matches!(err, InstallError::Select(_)) && err.to_string().contains("1000 bytes"),
        "{err}"
    );
    f.assert_nothing_created("oversize program");
    // Among several, the oversize one is skipped (it cannot be analysed, so it cannot win).
    let two = f.input(
        "two.zip",
        &raw_zip(&[Raw::file("big.exe", &prog()), Raw::file("tiny.exe", b"MZ")]),
    );
    let err = f.run_limits(&two, small_cap).unwrap_err();
    assert!(
        matches!(err, InstallError::Select(_)) && err.to_string().contains("--exe"),
        "{err}"
    );
    f.assert_nothing_created("oversize candidate");
}

#[test]
fn a_zip_named_like_a_reserved_device_gets_a_usable_program_directory() {
    let f = fx();
    let zip = raw_zip(&[Raw::file("x.exe", &prog())]);
    let out = f.ok(&f.input("con.zip", &zip), &InstallOpts::default());
    assert_eq!(out.id.as_str(), "app-con");
    assert_eq!(out.executable.to_string(), "C:\\Program Files\\app-con\\x.exe");
}

#[test]
fn install_error_cause_looks_through_cleanup_problems() {
    let inner = InstallError::Dll;
    let e = InstallError::WithCleanup {
        cause: Box::new(InstallError::WithCleanup {
            cause: Box::new(inner),
            problems: vec!["a".into()],
        }),
        problems: vec!["b".into()],
    };
    assert!(matches!(e.cause(), InstallError::Dll));
    assert_eq!(
        e.to_string(),
        "a DLL is not an application; in addition: a; in addition: b"
    );
}
