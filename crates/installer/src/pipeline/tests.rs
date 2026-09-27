use super::*;
use crate::InstallerFamily;
use rt_core::{AppId, Call, FakeBackend};
use std::path::Path;

/// A binary built by `tools/build-fixtures.sh` (needs Wine/wixl/mingw; committed for this repo).
fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"))
}

struct Fx {
    tmp: tempfile::TempDir,
    store: Store,
}

fn fx() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("in")).unwrap();
    fs::write(tmp.path().join("canary"), "canary").unwrap();
    let store = Store::new(tmp.path().join("apps")).unwrap();
    Fx { tmp, store }
}

impl Fx {
    fn apps(&self) -> PathBuf {
        self.tmp.path().join("apps")
    }

    fn input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.tmp.path().join("in").join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    /// Nothing left in the store: an empty (or missing) apps dir is fine after a cleanup.
    fn assert_no_app_left(&self) {
        if self.apps().exists() {
            let left: Vec<_> = fs::read_dir(self.apps())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert!(left.is_empty(), "residue in the store: {left:?}");
        }
        assert_eq!(fs::read_to_string(self.tmp.path().join("canary")).unwrap(), "canary");
    }
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

/// `FakeBackend::command` hardcodes `/bin/sh`; `InstallerSandbox::RO_BINDS` deliberately does not include `/bin`
/// (it is not part of a real Wine install: real backends' binaries live under `/usr`, which IS bound, so this
/// never bites `WineBackend`). On this distro `/bin` is a symlink to `usr/bin` on the HOST, but that resolution
/// happens before the bind, not inside the sandboxed mount namespace, so `/bin/sh` is simply missing once
/// sandboxed unless something binds it. `FakeBackend::dll_dirs()` feeds `SandboxOpts::extra_ro_binds` (Ruling
/// 3), so this is the same mechanism a real backend would use for a Wine install outside the fixed set — not a
/// workaround specific to this test double.
fn fake_backend(script: &str) -> FakeBackend {
    FakeBackend::with_script(script).with_dll_dirs(vec![PathBuf::from("/bin")])
}

/// `Some(path)` if a real `bwrap` is on `$PATH`; otherwise skips loudly (never a silent pass) and returns `None`,
/// same discipline as `crate::sandbox::tests::require_real_bwrap` (duplicated here: it is `mod tests`-private
/// over there). `RUNTIME_REQUIRE_BWRAP=1` turns a missing `bwrap` into a hard failure for CI.
fn require_real_bwrap() -> Option<PathBuf> {
    let require = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    match find_bwrap_on_path() {
        Some(p) => Some(p),
        None if require => {
            panic!("bwrap not found on $PATH and RUNTIME_REQUIRE_BWRAP is set: the pipeline tests must run for real")
        }
        None => {
            eprintln!("SKIP: bwrap not found on $PATH; the real-sandbox pipeline tests need bubblewrap installed");
            None
        }
    }
}

/// Serialises [`install_via_installer_isolated`] across this whole test binary: `std::env::set_var` is
/// process-global and `cargo test` runs `#[test]`s on separate threads of the same process by default. Nothing
/// else in this binary reads `XDG_DATA_HOME`/`HOME` from the real process environment for its own logic — every
/// other real-`HOME`-like need in this crate's tests (`crate::sandbox::tests`) sets it on a *child* `Command`
/// instead — so this lock only has to cover this file's own calls to be sufficient.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The options of a plain, non-silent install; the runtime executable is this test binary, which runs the real
/// `sandbox-init` shim (`crate::sandbox`'s `TEST_SHIM`).
fn opts() -> InstallerOpts {
    InstallerOpts {
        silent: false,
        allow_network: false,
        exe_override: None,
        runtime_exe: std::env::current_exe().unwrap(),
    }
}

/// [`install_via_installer`], with `XDG_DATA_HOME` pointed at a fresh scratch directory for the call's duration.
///
/// Task 7 wired `rt_desktop::entry::write`/`mime::register` into `run_after_create` on every path that returns
/// `InstallOutcome::Installed`; both are real-env only BY DESIGN (`crates/desktop/src/entry.rs`'s public
/// `write`/`register` take no injectable environment — that seam is deliberately internal to `rt_desktop`, to
/// match the brief's own fixed signature). A test that calls `install_via_installer` directly, in-process, is
/// therefore the one and only place a successful real install in THIS test binary could otherwise write straight
/// into the real developer's `~/.local/share/applications` — exactly what happened before this wrapper existed
/// (see the Task 7 report). Every call in this file goes through this wrapper rather than the bare function,
/// even the ones that fail before reaching that point: cheap, and it removes the need to keep re-verifying which
/// paths do or do not reach it as this pipeline evolves.
fn install_via_installer_isolated(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: Launcher,
    path: &Path,
    opts: InstallerOpts,
) -> Result<InstallOutcome, InstallerError> {
    let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("XDG_DATA_HOME");
    // SAFETY: serialised by `ENV_LOCK` above; nothing else in this process reads this variable concurrently.
    unsafe {
        std::env::set_var("XDG_DATA_HOME", scratch.path());
    }
    let result = install_via_installer(store, backend, launcher, path, opts);
    unsafe {
        match &previous {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
    result
}

// ---------------------------------------------------------------- detection against real bytes; clean failure

/// `hello.msi`'s real `MsiInfo`/family are used for naming and planning; `FakeBackend` never creates a real
/// `msiexec.exe`, so the pipeline's own Ruling-2 existence check refuses cleanly (never a panic) and the
/// half-built environment is removed. Needs no real `bwrap`: the refusal happens before the sandbox is ever
/// consulted.
#[test]
fn real_hello_msi_is_detected_and_the_install_fails_cleanly_without_a_real_msiexec() {
    let f = fx();
    let path = f.input("hello.msi", &fixture("hello.msi"));
    let backend = FakeBackend::new();
    let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap_err();
    assert!(matches!(err, InstallerError::MsiExecMissing), "{err}");
    f.assert_no_app_left();
    // Named after the real MsiInfo::read'd ProductName ("Runtime Fixture MSI"), slugged the same way as Phase 2.
    let id = AppId::parse("runtime-fixture-msi").unwrap();
    assert_eq!(
        backend.calls(),
        vec![Call::Prepare { app: id.clone() }, Call::Stop { app: id }]
    );
}

/// The real `hello-nsis.exe` fixture, run through a `FakeBackend` script standing in for Wine: the script copies
/// the placed installer's own real PE bytes to "install" itself and registers an `Uninstall` entry, then exits
/// non-zero. Proves: family/plan (NSIS -> plain exe run, no msiexec), the non-zero-exit-is-a-warning-not-a-
/// failure rule (discovery still runs), product name/uninstall command recovered from the real registry text,
/// and id/name uniqueness across two installs of the same file. Needs a real `bwrap` (it really spawns).
#[test]
fn real_hello_nsis_installs_end_to_end_and_warns_on_a_nonzero_exit_code() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let script = r#"
set -e
dest_dir="$WINEPREFIX/drive_c/Program Files/HelloNsis"
mkdir -p "$dest_dir"
cp "$0" "$dest_dir/hello.exe"
cat > "$WINEPREFIX/system.reg" <<'REG'
WINE REGISTRY Version 2
;; All keys relative to REGISTRY\\Machine

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{TESTGUID}] 1700000000
#time=1
"DisplayName"="Hello Nsis"
"UninstallString"="C:\\Program Files\\HelloNsis\\uninstall.exe /S"
REG
exit 5
"#;
    let backend = fake_backend(script);

    let outcome = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap();
    let InstallOutcome::Installed {
        id,
        executable,
        warnings,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(id.as_str(), "hello-nsis", "named after the installer file's own stem");
    assert_eq!(executable.to_string(), "C:\\Program Files\\HelloNsis\\hello.exe");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("exited with"), "{warnings:?}");
    assert!(warnings[0].contains("not treated as a failure"), "{warnings:?}");

    let env = f.store.get(&id).unwrap();
    let md = f.store.read_metadata(&env).unwrap();
    assert_eq!(
        md.name, "Hello Nsis",
        "the Uninstall DisplayName wins over the provisional file-stem name"
    );
    assert_eq!(md.executable, "C:\\Program Files\\HelloNsis\\hello.exe");
    assert_eq!(md.schema_version, 4, "new installs write schema 4");
    let installer = md.installer.as_ref().expect("installer field (added in schema v2)");
    assert_eq!(installer.family, "nsis");
    assert_eq!(installer.product_name.as_deref(), Some("Hello Nsis"));
    assert_eq!(
        installer.uninstall_command.as_deref(),
        // Real NSIS shape: a separate uninstaller. (An `UninstallString` naming the app itself would make
        // discovery refuse to auto-pick it: `discover::rank` never auto-picks an exe an UninstallString names.)
        Some("C:\\Program Files\\HelloNsis\\uninstall.exe /S")
    );
    // The "app" is a copy of the real NSIS stub's own bytes: its real architecture/subsystem are recorded.
    assert_eq!(md.architecture, "x86");
    assert_eq!(md.subsystem, "gui");
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::Prepare { .. }))
            .count(),
        1
    );
    assert!(
        !backend.calls().iter().any(|c| matches!(c, Call::Stop { .. })),
        "a successful install never stops the backend: {:?}",
        backend.calls()
    );

    // Installing the very same file again must not collide: the id (and metadata) diverge, mirroring Phase 2's
    // "installing the same program twice gives distinct ids".
    let second = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap();
    let InstallOutcome::Installed { id: id2, .. } = second else {
        panic!("expected Installed");
    };
    assert_eq!(id2.as_str(), "hello-nsis-2");
    assert_ne!(id, id2);
}

/// Regression test for the Critical fix-round-1 finding: with a prefix shaped like a REAL Wine one (a
/// pre-existing, all-lowercase `drive_c/windows/temp` — `FakeBackend::prepare` alone never creates one, which is
/// exactly why every other test in this file was blind to the bug), `place_installer_file`'s `join_new` reuses
/// the real lowercase `windows`/`temp` components verbatim, so the installer actually lands at
/// `windows/temp/rt-installer/hello-nsis.exe` on disk — NOT `Windows/Temp/rt-installer/hello-nsis.exe`, the
/// spelling a naive string-based exclusion (what this pipeline used to do) would have compared against. The
/// fix removes that comparison entirely (the installer is placed before the "before" snapshot, so it is never a
/// diff candidate to begin with, regardless of casing); this test proves the REAL app still wins discovery
/// against this realistic filesystem shape, not the installer's own staged copy.
///
/// Mutation-check (reasoned, not executed): the previous code compared `diff.new_files` entries against
/// `installer_winpath.components().join("/")`, i.e. the literal string `"Windows/Temp/rt-installer/hello-nsis.exe"`
/// (the WinPath text as requested). Against this test's realistic fixture the installer's REAL on-disk path is
/// `"windows/temp/rt-installer/hello-nsis.exe"` (lowercase `windows`/`temp`, reused from the pre-created
/// directory) — the two strings never compare equal, so that old filter would have let the installer itself
/// through as a candidate. Since the installer copy is a real GUI PE roughly the same size as (or larger than)
/// the "app" this test plants, the installer would have won `discover::rank` outright and this test's
/// `executable` assertion below would have failed with the installer's own staged path instead.
#[test]
fn real_hello_nsis_installs_correctly_against_a_prefix_shaped_like_a_real_one() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let script = r#"
set -e
dest_dir="$WINEPREFIX/drive_c/Program Files/HelloNsis"
mkdir -p "$dest_dir"
cp "$0" "$dest_dir/hello.exe"
exit 0
"#;
    let wrap = Wrap {
        precreate_windows_temp: true,
        ..Wrap::new(fake_backend(script))
    };
    let outcome = install_via_installer_isolated(&f.store, &wrap, launcher(), &path, opts()).unwrap();
    let InstallOutcome::Installed { id, executable, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(
        executable.to_string(),
        "C:\\Program Files\\HelloNsis\\hello.exe",
        "the real app must win, not the installer's own staged copy"
    );
    let env = f.store.get(&id).unwrap();
    // The fixture really is realistic: `windows/temp` pre-existed (lowercase), proving this test actually
    // exercises the case-reuse path `join_new` takes on a real Wine prefix, not the "component missing, create
    // verbatim" path every other test in this file exercises.
    assert!(env.drive_c().join("windows/temp").is_dir());
    // Finding 3: the staged installer copy is deleted once the install has succeeded — it must not permanently
    // double the app's disk footprint. (It would have landed at `windows/temp/rt-installer/hello-nsis.exe`,
    // reusing the pre-existing lowercase directories; that whole `rt-installer` staging directory is now gone.)
    assert!(
        !env.drive_c().join("windows/temp/rt-installer").exists(),
        "the staged installer copy must be deleted after a successful install"
    );
}

// ---------------------------------------------------------------- nothing created before Store::create

#[test]
fn silent_on_an_unrecognised_installer_family_creates_nothing() {
    let f = fx();
    // A plain PE with no installer marker at all: `analyze_installer` reports `InstallerFamily::Unknown`, and
    // `--silent` on `Unknown` is refused (never a guessed flag) before anything is created.
    let path = f.input("gui.exe", &fixture("gui64.exe"));
    let backend = FakeBackend::new();
    let opts = InstallerOpts { silent: true, ..opts() };
    let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts).unwrap_err();
    assert!(
        matches!(
            err,
            InstallerError::Plan(PlanError::NoSilentFlags(InstallerFamily::Unknown))
        ),
        "{err}"
    );
    assert!(!f.apps().exists());
    assert!(backend.calls().is_empty());
}

#[test]
fn a_backend_without_installer_support_is_refused_before_anything_is_created() {
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let backend = FakeBackend::new().with_capabilities(rt_core::backend::Capabilities {
        installers: false,
        ..FakeBackend::new().capabilities()
    });
    let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap_err();
    assert!(
        matches!(
            err,
            InstallerError::Unsupported(rt_core::backend::Unsupported::Feature { backend: "fake", .. })
        ),
        "{err}"
    );
    assert!(!f.apps().exists());
    assert!(backend.calls().is_empty());
}

#[test]
fn unrecognised_file_formats_are_refused_before_anything_is_created() {
    let f = fx();
    let backend = FakeBackend::new();
    for (name, bytes) in [
        ("text.bin", b"just some text, not a program".to_vec()),
        ("zip.bin", b"PK\x03\x04 not a real zip either".to_vec()),
        ("empty.bin", Vec::new()),
    ] {
        let path = f.input(name, &bytes);
        let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap_err();
        assert!(matches!(err, InstallerError::NotAnInstaller), "{name}: {err}");
    }
    assert!(!f.apps().exists());
    assert!(backend.calls().is_empty());
}

// ---------------------------------------------------------------- ambiguous discovery installs nothing

/// Two new `.exe` files of equal size, neither a parseable PE (so neither scores as GUI), no `.lnk`, no
/// `Uninstall` entry: every tier ties, so `rank` cannot pick a winner. Needs a real `bwrap`.
const AMBIGUOUS_SCRIPT: &str = r#"
set -e
mkdir -p "$WINEPREFIX/drive_c/App"
printf 'AAAAAAAAAA' > "$WINEPREFIX/drive_c/App/one.exe"
printf 'BBBBBBBBBB' > "$WINEPREFIX/drive_c/App/two.exe"
exit 0
"#;

#[test]
fn ambiguous_discovery_returns_candidates_and_installs_nothing() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let backend = fake_backend(AMBIGUOUS_SCRIPT);

    let outcome = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap();
    let InstallOutcome::NeedsChoice(candidates) = outcome else {
        panic!("expected NeedsChoice, got {outcome:?}");
    };
    let mut paths: Vec<_> = candidates.iter().map(|c| c.path.clone()).collect();
    paths.sort();
    assert_eq!(paths, ["App/one.exe", "App/two.exe"]);
    // Nothing is installed: the environment created for this attempt is gone.
    f.assert_no_app_left();
}

#[test]
fn exe_override_skips_discovery_and_installs_the_named_file() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let backend = fake_backend(AMBIGUOUS_SCRIPT);
    let opts = InstallerOpts {
        exe_override: Some("App/two.exe".to_owned()),
        ..opts()
    };

    let outcome = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts).unwrap();
    let InstallOutcome::Installed { executable, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(executable.to_string(), "C:\\App\\two.exe");
}

// ---------------------------------------------------------------- cleanup on a late failure (after the run)

/// Delegates to a `FakeBackend`, but can fail `version`/`command` on demand (mirrors
/// `rt_core::install::tests::Wrap`).
struct Wrap {
    inner: FakeBackend,
    version_fails: bool,
    command_fails: bool,
    /// Mimics a REAL Wine prefix's pre-existing `drive_c/windows/temp` (Windows always has one, and a real
    /// `wineboot -u` creates it too; `FakeBackend::prepare` does not). This is exactly the shape that made the
    /// original (fixed) staged-installer-exclusion bug reproducible: with a real, pre-existing, all-lowercase
    /// `windows/temp` directory, `join_new`'s case-insensitive component matching reuses it verbatim, so the
    /// installer actually lands at `windows/temp/rt-installer/<name>` — a different string, in a different case,
    /// than a hand-written `Windows\Temp\...` comparison would ever match. See
    /// `real_hello_nsis_installs_correctly_against_a_prefix_shaped_like_a_real_one`.
    precreate_windows_temp: bool,
}

impl Wrap {
    fn new(inner: FakeBackend) -> Wrap {
        Wrap {
            inner,
            version_fails: false,
            command_fails: false,
            precreate_windows_temp: false,
        }
    }
}

impl CompatBackend for Wrap {
    fn capabilities(&self) -> rt_core::backend::Capabilities {
        self.inner.capabilities()
    }
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn version(&self) -> Result<String, BackendError> {
        if self.version_fails {
            return Err(BackendError::Unavailable(rt_core::Detail::from_bytes(b"boom")));
        }
        self.inner.version()
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.prepare(env)?;
        if self.precreate_windows_temp {
            fs::create_dir_all(env.drive_c().join("windows/temp")).map_err(|source| BackendError::Io {
                what: "test fixture: windows/temp",
                source,
            })?;
        }
        Ok(())
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<std::process::Command, BackendError> {
        if self.command_fails {
            return Err(BackendError::Unavailable(rt_core::Detail::from_bytes(b"no command")));
        }
        self.inner.command(env, exe, cwd, args, opts)
    }
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.stop(env)
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        self.inner.dll_dirs()
    }
}

/// A failure that only surfaces AFTER the installer has already run and discovery has already picked a winner
/// (fetching the backend's version, right before writing metadata) still removes the half-built environment.
/// Needs a real `bwrap` (the installer really runs before the failure is hit).
#[test]
fn a_late_backend_failure_after_the_installer_ran_still_cleans_up_the_environment() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let script = r#"
set -e
mkdir -p "$WINEPREFIX/drive_c/Program Files/HelloNsis"
cp "$0" "$WINEPREFIX/drive_c/Program Files/HelloNsis/hello.exe"
exit 0
"#;
    let wrap = Wrap {
        version_fails: true,
        ..Wrap::new(fake_backend(script))
    };
    let err = install_via_installer_isolated(&f.store, &wrap, launcher(), &path, opts()).unwrap_err();
    assert!(
        matches!(err, InstallerError::Backend(BackendError::Unavailable(_))),
        "{err}"
    );
    f.assert_no_app_left();
}

/// A backend that cannot even describe the process to run (the sandboxed-spawn failure class): cleaned up the
/// same way. Still needs a real `bwrap` to reach the point where `backend.command` is consulted.
#[test]
fn a_backend_command_failure_cleans_up_the_environment() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let wrap = Wrap {
        command_fails: true,
        ..Wrap::new(FakeBackend::new())
    };
    let err = install_via_installer_isolated(&f.store, &wrap, launcher(), &path, opts()).unwrap_err();
    assert!(
        matches!(err, InstallerError::Backend(BackendError::Unavailable(_))),
        "{err}"
    );
    f.assert_no_app_left();
}

// ------------------------------------------------------------- I3: host-side discovery reads never follow/hang

/// A hostile installer leaves only a FIFO (no writer: a plain `fs::read` would block forever) and a symlink to a
/// host file as its "new" `.exe`/`.lnk` files. Discovery must refuse both: no hang, no candidate, and the
/// symlink's target is never read (`read_bounded_regular_file` sees a symlink, not the host file).
#[test]
fn discovery_refuses_a_planted_fifo_and_symlink_without_hanging_or_following() {
    use std::os::unix::ffi::OsStrExt;
    let f = fx();
    let env = f.store.create(&AppId::parse("t").unwrap()).unwrap();
    let app = env.drive_c().join("App");
    fs::create_dir_all(&app).unwrap();
    for name in ["fifo.exe", "fifo.lnk"] {
        let c = std::ffi::CString::new(app.join(name).as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }
    let host = f.tmp.path().join("canary");
    std::os::unix::fs::symlink(&host, app.join("link.exe")).unwrap();
    std::os::unix::fs::symlink(&host, app.join("link.lnk")).unwrap();
    let diff = InstallDiff {
        new_files: ["App/fifo.exe", "App/fifo.lnk", "App/link.exe", "App/link.lnk"]
            .map(String::from)
            .to_vec(),
        ..Default::default()
    };

    // Everything runs on a worker thread so a regression fails at the deadline instead of hanging the suite.
    let (tx, rx) = std::sync::mpsc::channel();
    let d = diff.clone();
    let e = env.clone();
    std::thread::spawn(move || {
        let reads: Vec<_> = d
            .new_files
            .iter()
            .map(|p| read_bounded_regular_file(&e.drive_c().join(p)))
            .collect();
        tx.send((
            reads,
            load_shortcuts(&e, &d).len(),
            discover_winner(&e, &d, None).map(|x| match x {
                Discovery::Winner(p) => Some(p),
                Discovery::NeedsChoice(_) => None,
            }),
        ))
        .unwrap()
    });
    let (reads, shortcuts, winner) = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("discovery hung on a planted FIFO");
    assert!(reads.iter().all(Option::is_none), "{reads:?}");
    assert_eq!(shortcuts, 0);
    assert!(
        !matches!(winner, Ok(Some(_))),
        "a FIFO/symlink must never win: {winner:?}"
    );
}

// ------------------------------------------------------------- which Uninstall entry gets recorded

fn entry(name: &str, uninstall: Option<&str>, icon: Option<&str>) -> UninstallEntry {
    UninstallEntry {
        display_name: Some(name.into()),
        uninstall_string: uninstall.map(Into::into),
        icon_path: icon.map(Into::into),
    }
}

fn entries_diff(entries: Vec<UninstallEntry>) -> InstallDiff {
    InstallDiff {
        uninstall_entries: entries,
        ..Default::default()
    }
}

fn chosen_name(entries: Vec<UninstallEntry>, winner: &str) -> Option<String> {
    let d = entries_diff(entries);
    choose_uninstall_entry(&d, winner).and_then(|e| e.display_name.clone())
}

fn vc_redist() -> UninstallEntry {
    entry(
        "Microsoft Visual C++ 2015-2022 Redistributable (x64)",
        Some("MsiExec.exe /X{0000-VC}"),
        Some(r"C:\ProgramData\Package Cache\{0000-VC}\VC_redist.x64.exe,0"),
    )
}

#[test]
fn choose_uninstall_entry_ties_the_app_entry_by_display_icon_or_same_directory() {
    const WINNER: &str = "Program Files/App/app.exe";
    // The redistributable comes FIRST, so a `first()` fallback would record it.
    let by_icon = vec![
        vc_redist(),
        entry("My App", None, Some(r#""C:\Program Files\App\APP.exe",0"#)),
    ];
    let by_dir = vec![
        vc_redist(),
        entry("My App", Some(r#""C:\Program Files\App\uninstall.exe" /S"#), None),
    ];
    assert_eq!(chosen_name(by_icon, WINNER).as_deref(), Some("My App"));
    assert_eq!(chosen_name(by_dir, WINNER).as_deref(), Some("My App"));
}

#[test]
fn choose_uninstall_entry_records_nothing_when_several_entries_tie_to_nothing() {
    let entries = vec![
        vc_redist(),
        // A subdirectory of the winner's directory is not "the same directory".
        entry("Other", Some(r"C:\Program Files\App\Sub\uninstall.exe /S"), None),
    ];
    assert_eq!(chosen_name(entries, "Program Files/App/app.exe"), None);
}

#[test]
fn choose_uninstall_entry_keeps_a_single_entry() {
    let entries = vec![entry("Only", Some("MsiExec.exe /I{GUID}"), None)];
    assert_eq!(
        chosen_name(entries, "Program Files/App/app.exe").as_deref(),
        Some("Only")
    );
    assert_eq!(chosen_name(Vec::new(), "Program Files/App/app.exe"), None);
}

#[test]
fn choose_uninstall_entry_never_matches_by_substring() {
    // `c:/myapp/app.exe` CONTAINS `app/app.exe`: the old substring match wrongly tied these to App/app.exe.
    let entries = vec![
        entry(
            "Mine",
            Some(r#""C:\MyApp\app.exe" /uninstall"#),
            Some(r"C:\MyApp\app.exe,0"),
        ),
        entry("Else", Some(r"C:\Else\x.exe"), None),
    ];
    assert_eq!(chosen_name(entries, "App/app.exe"), None);
}

#[test]
fn choose_uninstall_entry_never_panics_on_hostile_strings() {
    let hostile = [
        String::new(),
        "\"".repeat(5000),
        ".exe".repeat(10_000),
        "\u{e9}.exe\u{e9}".repeat(1000),
        "C:\\\u{130}.EXE,0".to_owned(),
        "C:\\".to_owned() + &"a\\".repeat(100_000) + "x.exe",
    ];
    for s in &hostile {
        let entries = vec![entry("a", Some(s), Some(s)), entry("b", Some(s), None)];
        for winner in ["", "/", "a.exe", "\u{130}/\u{e9}.exe", s.as_str()] {
            let _ = chosen_name(entries.clone(), winner);
        }
    }
}

/// The pipeline-level shape of an `hello.exe /uninstall` app with no shortcut and no other `DisplayIcon`: its
/// exclusion is doubtful, so the one other exe must NOT win by elimination; nothing is installed. Needs `bwrap`.
#[test]
fn a_doubtful_exclusion_makes_the_pipeline_ask_instead_of_picking_the_helper() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let script = r#"
set -e
dest_dir="$WINEPREFIX/drive_c/Program Files/HelloNsis"
mkdir -p "$dest_dir"
cp "$0" "$dest_dir/hello.exe"
printf 'helper' > "$dest_dir/helper.exe"
cat > "$WINEPREFIX/system.reg" <<'REG'
WINE REGISTRY Version 2
;; All keys relative to REGISTRY\\Machine

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{TESTGUID}] 1700000000
#time=1
"DisplayName"="Hello Nsis"
"UninstallString"="\"C:\\Program Files\\HelloNsis\\hello.exe\" /uninstall"
REG
exit 0
"#;
    let backend = fake_backend(script);
    let outcome = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap();
    let InstallOutcome::NeedsChoice(candidates) = outcome else {
        panic!("expected NeedsChoice, got {outcome:?}");
    };
    let mut paths: Vec<_> = candidates.iter().map(|c| c.path.clone()).collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "Program Files/HelloNsis/hello.exe",
            "Program Files/HelloNsis/helper.exe"
        ]
    );
    f.assert_no_app_left();
}

/// Two Uninstall entries, neither tied to the installed exe: nothing from the registry is recorded (the
/// provisional name stays) and a warning says why. Needs `bwrap`.
#[test]
fn several_unrelated_uninstall_entries_record_nothing_and_warn() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
    let script = r#"
set -e
dest_dir="$WINEPREFIX/drive_c/Program Files/HelloNsis"
mkdir -p "$dest_dir"
cp "$0" "$dest_dir/hello.exe"
cat > "$WINEPREFIX/system.reg" <<'REG'
WINE REGISTRY Version 2
;; All keys relative to REGISTRY\\Machine

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{VCREDIST}] 1700000000
#time=1
"DisplayName"="Microsoft Visual C++ Redistributable"
"UninstallString"="MsiExec.exe /X{VCREDIST}"

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{OTHER}] 1700000000
#time=1
"DisplayName"="Other Tool"
"UninstallString"="C:\\Other\\uninstall.exe /S"
REG
exit 0
"#;
    let backend = fake_backend(script);
    let outcome = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap();
    let InstallOutcome::Installed { id, warnings, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert!(
        warnings.iter().any(|w| w.contains("none could be tied")),
        "{warnings:?}"
    );
    let md = f.store.read_metadata(&f.store.get(&id).unwrap()).unwrap();
    assert_eq!(md.name, "hello-nsis", "the provisional name, not a redistributable's");
    let installer = md.installer.expect("installer field");
    assert_eq!(installer.product_name, None);
    assert_eq!(installer.uninstall_command, None);
}

/// Phase 5B Task 6 fix round 1: a runtime executable the installer sandbox cannot use is a typed error that names the
/// reason, before anything runs (never an installer "exit 126" warning followed by an empty discovery).
#[test]
fn an_unusable_runtime_executable_is_a_sandbox_refusal_and_nothing_runs() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let deleted = format!("{} (deleted)", std::env::current_exe().unwrap().display());
    for (exe, why) in [
        (PathBuf::from("runtime"), "not an absolute path"),
        (PathBuf::from(&deleted), "replaced or deleted"),
        (PathBuf::from("/nonexistent/runtime"), "cannot be resolved"),
    ] {
        let f = fx();
        let path = f.input("hello-nsis.exe", &fixture("hello-nsis.exe"));
        let backend = fake_backend("exit 0");
        let opts = InstallerOpts {
            runtime_exe: exe.clone(),
            ..opts()
        };
        let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts).unwrap_err();
        let cause = match err {
            InstallerError::WithCleanup { cause, .. } => *cause,
            e => e,
        };
        assert!(matches!(cause, InstallerError::SandboxRefused(_)), "{exe:?}: {cause:?}");
        let text = cause.to_string();
        assert!(text.contains(why) && text.contains("nothing was run"), "{text}");
        assert!(
            !backend.calls().iter().any(|c| matches!(c, Call::Command { .. })),
            "{exe:?}: {:?}",
            backend.calls()
        );
    }
}

#[test]
fn an_installed_program_of_an_architecture_the_backend_lacks_is_refused_and_cleaned_up() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let f = fx();
    let bytes = fixture("hello-nsis.exe");
    let path = f.input("hello-nsis.exe", &bytes);
    // The "installed" program is a copy of the installer itself: the backend supports the other architecture only.
    let other: &'static [pe::Arch] = match pe::analyze(&bytes).unwrap().arch {
        pe::Arch::X86 => &[pe::Arch::X86_64],
        _ => &[pe::Arch::X86],
    };
    let script = r#"
dest_dir="$WINEPREFIX/drive_c/Program Files/HelloNsis"
mkdir -p "$dest_dir" && cp "$0" "$dest_dir/hello.exe"
"#;
    let backend = fake_backend(script).with_capabilities(rt_core::backend::Capabilities {
        arches: other,
        ..rt_core::FAKE_CAPABILITIES
    });
    let err = install_via_installer_isolated(&f.store, &backend, launcher(), &path, opts()).unwrap_err();
    assert!(
        matches!(
            err,
            InstallerError::Unsupported(rt_core::backend::Unsupported::Arch { .. })
        ),
        "{err}"
    );
    f.assert_no_app_left();
}
