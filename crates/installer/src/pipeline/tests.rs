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
    let err = install_via_installer(&f.store, &backend, launcher(), &path, InstallerOpts::default()).unwrap_err();
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
"UninstallString"="C:\\Program Files\\HelloNsis\\hello.exe /uninstall"
REG
exit 5
"#;
    let backend = fake_backend(script);

    let outcome = install_via_installer(&f.store, &backend, launcher(), &path, InstallerOpts::default()).unwrap();
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
    assert_eq!(md.schema_version, 2);
    let installer = md.installer.as_ref().expect("schema v2 installer field");
    assert_eq!(installer.family, "nsis");
    assert_eq!(installer.product_name.as_deref(), Some("Hello Nsis"));
    assert_eq!(
        installer.uninstall_command.as_deref(),
        Some("C:\\Program Files\\HelloNsis\\hello.exe /uninstall")
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
    let second = install_via_installer(&f.store, &backend, launcher(), &path, InstallerOpts::default()).unwrap();
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
    let outcome = install_via_installer(&f.store, &wrap, launcher(), &path, InstallerOpts::default()).unwrap();
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
    let opts = InstallerOpts {
        silent: true,
        ..Default::default()
    };
    let err = install_via_installer(&f.store, &backend, launcher(), &path, opts).unwrap_err();
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
fn unrecognised_file_formats_are_refused_before_anything_is_created() {
    let f = fx();
    let backend = FakeBackend::new();
    for (name, bytes) in [
        ("text.bin", b"just some text, not a program".to_vec()),
        ("zip.bin", b"PK\x03\x04 not a real zip either".to_vec()),
        ("empty.bin", Vec::new()),
    ] {
        let path = f.input(name, &bytes);
        let err = install_via_installer(&f.store, &backend, launcher(), &path, InstallerOpts::default()).unwrap_err();
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

    let outcome = install_via_installer(&f.store, &backend, launcher(), &path, InstallerOpts::default()).unwrap();
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
        ..Default::default()
    };

    let outcome = install_via_installer(&f.store, &backend, launcher(), &path, opts).unwrap();
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
    let err = install_via_installer(&f.store, &wrap, launcher(), &path, InstallerOpts::default()).unwrap_err();
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
    let err = install_via_installer(&f.store, &wrap, launcher(), &path, InstallerOpts::default()).unwrap_err();
    assert!(
        matches!(err, InstallerError::Backend(BackendError::Unavailable(_))),
        "{err}"
    );
    f.assert_no_app_left();
}
