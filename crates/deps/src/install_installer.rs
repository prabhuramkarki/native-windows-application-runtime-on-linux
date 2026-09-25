//! Installs an `installer` package: runs the vendor's own setup program (hash-verified, but treated as hostile
//! code) in the Phase 3 sandbox, offline, inside the app's prefix, and confirms success by the package's declared
//! marker, never by the exit code alone.
//!
//! **Steps** ([`install_installer_pkg`]), in this order:
//! 1. The package is checked again even though the manifest validator already did (a `Package` can be built by
//!    hand): installer kind, id, sha256, size, `silent_args` ([`check_silent_args`]) and the marker (a file path
//!    must be a plain relative path inside `drive_c`; a registry key must start with `HKLM\`/`HKCU\` or their long
//!    names). `bwrap` must be on `$PATH` ([`InstallerPkgError::BwrapNotFound`] otherwise), before anything is
//!    written.
//! 2. The verified cache file (`cache/<sha256>`, `0400`) is opened read-only (`O_NOFOLLOW`, regular file of exactly
//!    the declared size) and COPIED to `C:\windows\temp\rt-deps\<id>\<id>.exe` (`.msi` for an MSI) with
//!    [`rt_installer::stage_file`], the same containment discipline as Phase 3 (`join_new`, `O_EXCL`, `0644`). The
//!    cache file is never executed, never opened for writing and never bound into the sandbox. A staged file left
//!    by a killed earlier run (a regular file at that exact path) is deleted first.
//! 3. The staged copy is hashed again and must equal `pkg.sha256` (closes the window between fetch and use).
//! 4. **Marker absent first.** If the marker already exists the installer is NOT run:
//!    [`InstallerPkgError::MarkerAlreadyPresent`] (the run could prove nothing; the caller treats it as foreign or
//!    already-installed state). This is checked AFTER staging, so a marker that the staged copy itself would
//!    satisfy is caught here instead of being "confirmed" by the run.
//! 5. The installer runs through [`rt_installer::run_sandboxed`]: `backend.command` (cwd `drive_c`), wrapped by
//!    `backend.settle` (the `wineserver` wait happens inside the sandbox, so registry writes reach `system.reg`/
//!    `user.reg` before the run returns), inside `InstallerSandbox` with `allow_network = false` ALWAYS and
//!    `extra_ro_binds = backend.dll_dirs()`. Every silent argument is one argv element (never shell text). An MSI
//!    (OLE2 magic, or a url ending `.msi`) runs as `msiexec.exe /i <staged C:\ path> <silent_args>` from the
//!    prefix's own `windows/system32` (as Phase 3 does). Anything else runs on a virtual desktop with Wine's
//!    `null` graphics driver: `explorer.exe /desktop=`[`NULL_DESKTOP`]` <staged C:\ path> <silent_args>` from the
//!    prefix's `windows` directory ([`InstallerPkgError::ExplorerMissing`] if it is not there). The sandbox has no
//!    display, so without a driver any window fails to open, even a hidden one: the real VC++ redistributable
//!    (a WiX Burn bundle) exits `0x7e` "Failed to create window" in `/quiet` mode. The `null` driver lets windows
//!    exist without a display, for this run only (nothing is written to the prefix's driver settings). Wine
//!    rebuilds the program's command line from these argv elements with Windows quoting, so arguments with
//!    spaces, quotes and backslashes arrive exactly (tested on real Wine).
//!    **Exit status of a wrapped run:** `explorer.exe` always exits 0 once it has started the program (checked on
//!    Wine 10.0: a program exiting 3 still gives 0), so for these installers the exit code carries no information
//!    and success or failure is decided by the marker ALONE; a failed installer shows up as
//!    [`InstallerPkgError::MarkerMissing`]. `backend.settle` still waits for every process of the prefix, so the
//!    installer itself has finished (or was killed at the deadline) when the marker is read.
//! 6. **Deadline.** Phase 3 waits forever (an interactive GUI install); a dependency runs silently, so it gets
//!    [`INSTALLER_DEADLINE`]. The sandbox has no display (no X11/Wayland socket, `DISPLAY` denied): a vendor
//!    installer that opens a dialog despite its silent flags would wait forever for a click that cannot come, and
//!    the deadline is the backstop. On expiry the whole sandbox tree is killed (`bwrap` dies, its PID namespace
//!    and `--die-with-parent` take everything inside, `wineserver` included), `backend.stop` is called best-effort,
//!    and the result is [`InstallerPkgError::TimedOut`].
//! 7. The marker is read again (the hives are re-read from disk: registry markers only exist after the settle
//!    wait flushed them). Marker present: success; with a non-zero exit it is still success, with a warning
//!    (Phase 3's convention: some installers exit non-zero on success). Exit 0 and no marker:
//!    [`InstallerPkgError::MarkerMissing`] (an installer that "succeeds" without its marker FAILED). Non-zero and
//!    no marker: [`InstallerPkgError::NonZeroAndNoMarker`].
//! 8. The staged copy (and its now-empty directories) is removed best-effort on every path, success or failure;
//!    [`InstallerPkgInstalled::staged_removed`] reports it on success. The staging path is resolved AGAIN (no
//!    symlink anywhere) right before each removal: the installer may have swapped part of it for a symlink to a
//!    host directory, and cleanup must never follow that out of the prefix. What cannot be removed safely is left
//!    in place, with a warning.
//! 9. Only after the marker is confirmed, the package's `dll_overrides` are set to `native,builtin` with Wine's
//!    `reg.exe` (the same settled, bounded helper as archive packages, but run in the installer sandbox, offline:
//!    Ruling 17; the Wine session it starts also starts what the installer registered, e.g. auto-start services). Without them Wine keeps
//!    loading its own builtin DLL of the same name even though the installer put the native one in `system32`
//!    (seen for real with the VC++ redistributable on Wine 10.0). If one cannot be set, the ones already set are
//!    deleted again, newest first, and the result is [`InstallerPkgError::DllOverride`] (the caller records
//!    nothing; the installer's own changes stay, as for any failure after it ran).
//!
//! **Registry markers.** `HKLM\...` is looked up in `<prefix>/system.reg`, `HKCU\...` in `<prefix>/user.reg`
//! (Wine's text format, parsed by [`rt_installer::read_reg_file`] with its size, line and key bounds). Keys and
//! value names compare case-insensitively, as on Windows; an empty value name is the key's default value. For
//! `HKLM\Software\<rest>` the 32-bit view `HKLM\Software\Wow6432Node\<rest>` is checked too: `backend_wine` only
//! makes win64 prefixes and a 32-bit installer's writes land there (seen for real with the Phase 3 NSIS fixture).
//! `HKCU\Software` is not redirected on 64-bit Windows, so no mirror is checked there. Only values Wine writes as
//! a string (`"..."`, `str(2):`) or `dword:` are seen; a value stored as `hex...:` (REG_BINARY, REG_MULTI_SZ,
//! REG_QWORD) is not modelled by the parser and reads as absent (a false "missing", never a false "present"). A
//! hive that cannot be read, or that has more keys than the parser keeps, is an error, not "absent".
//! With `min_dword` the value must also be a DWORD of at least that much, in EVERY check (before the run, after it,
//! and the orchestrator's checks before consent and download): an older version's value (e.g. the VC++ 2015
//! redistributable's build number under the same key) is "absent", so the installer runs and upgrades in place, and
//! only the new value confirms success. The hive is read by [`read_hive`]: no symlink followed, at most
//! [`MAX_MARKER_HIVE_BYTES`], size checked before reading.
//!
//! **No rollback of the installer's effects.** The vendor installer is opaque code; nothing here can know what it
//! changed, so nothing is undone on failure except the staged copy. A failed or killed run may leave partial
//! state in the prefix (files, registry values, even the marker without the rest). The caller (Task 7) must say
//! so and recommend recreating the environment. Nothing is recorded here: the caller records the package only
//! after `Ok`.
//!
//! **What the pin proves.** The sha256 proves which file was staged and started, nothing more. The marker is the
//! installer's own claim (a hostile installer can write it and exit), and the programs the prefix itself provides
//! are not pinned: `explorer.exe` (which starts every non-MSI installer), `msiexec.exe` and `reg.exe` are whatever
//! is in the prefix. A native program planted there (by an earlier app in the same prefix) runs instead of Wine's
//! and could write the marker without running the installer. Same residual as the marker itself; the sandbox
//! bounds what either can touch.
//!
//! **Not covered** (as for the archive installer): a process that can write inside `drive_c` while this runs could
//! swap a checked path for a symlink between check and use. Callers install only while no Windows program runs in
//! the prefix; Phase 5's sandbox is the real boundary.
use crate::fetch;
use crate::install_archive::{self, open_archive};
use crate::manifest::{self, Install, Kind, MAX_LIST_LEN, MAX_PACKAGE_SIZE, MAX_TEXT_LEN, Marker, Package, clip};
use rt_core::{AppEnv, CompatBackend, Launcher, ResolveError, WinPath, join_new, resolve_under};
use rt_installer::{MSIEXEC_RELATIVE, RegValue, SandboxOpts, WineReg, find_bwrap_on_path, run_sandboxed, stage_file};
use std::ffi::OsString;
use std::fmt::Display;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long one dependency installer may run (including the in-sandbox `wineserver` wait) before its whole
/// sandbox is killed. Generous: a real VC++ redistributable takes well under a minute under Wine; the deadline
/// only exists for an installer that hangs (typically on a dialog nobody can see, see the module docs).
pub const INSTALLER_DEADLINE: Duration = Duration::from_secs(20 * 60);
/// Where the installer copy is staged, per package id. Lowercase, as Wine itself spells `windows\temp` on disk.
pub const STAGING_DIR: &str = r"C:\windows\temp\rt-deps";
/// Wine's `explorer.exe`, relative to `drive_c`: it starts a non-MSI installer on a [`NULL_DESKTOP`].
pub const EXPLORER_RELATIVE: &str = "windows/explorer.exe";
/// `explorer.exe /desktop=` argument: a fixed desktop name, a size, and Wine's `null` graphics driver.
pub const NULL_DESKTOP: &str = "rt-deps,800x600,null";
/// Largest prefix hive read for a marker. A real Wine 10.0 win64 `system.reg` with the VC++ redistributable
/// installed measured 3,243,297 bytes (`user.reg` 78,808); 64 MiB is a ~20x margin that still keeps a hostile
/// hive from making `deps`/`doctor`/the install hint allocate gigabytes (Phase 3's own reader allows 4 GiB).
pub const MAX_MARKER_HIVE_BYTES: u64 = 64 * 1024 * 1024;
/// OLE2 compound-file magic (an `.msi`).
const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Longest error text built from something outside this crate (a path, an OS error, a registry file's name).
const MAX_MESSAGE: usize = 300;

/// Error texts carry untrusted strings only bounded and without control characters.
#[derive(Debug, thiserror::Error)]
pub enum InstallerPkgError {
    #[error("not an installer package")]
    NotInstallerKind,
    #[error("unusable package: {0}")]
    BadPackage(String),
    #[error("cannot stage the installer inside the prefix: {0}")]
    Stage(String),
    #[error("bwrap (bubblewrap) was not found on $PATH: install it to run dependency installers sandboxed")]
    BwrapNotFound,
    #[error("cannot run the installer in the sandbox: {0}")]
    Sandbox(String),
    #[error("the package's marker is already present in this prefix; the installer was not run")]
    MarkerAlreadyPresent,
    #[error(
        "the installer finished but its marker is missing: the install FAILED and may have left partial changes \
         in the prefix (the exit status of an exe installer is not visible through the desktop wrapper)"
    )]
    MarkerMissing,
    #[error(
        "the installer failed (exit {}) and its marker is missing; it may have left partial changes in the prefix",
        code.map_or_else(|| "by signal".to_owned(), |c| c.to_string())
    )]
    NonZeroAndNoMarker { code: Option<i32> },
    #[error("unusable silent argument: {0}")]
    BadSilentArg(String),
    #[error("cannot read the prefix registry: {0}")]
    Registry(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error(
        "the installer did not finish within {secs} s and was killed (a hidden dialog?); it may have left partial \
         changes in the prefix"
    )]
    TimedOut { secs: u64 },
    #[error("msiexec.exe is missing from this prefix's windows/system32")]
    MsiExecMissing,
    #[error("explorer.exe is missing from this prefix's windows directory")]
    ExplorerMissing,
    #[error(
        "the installer succeeded but setting its dll overrides failed ({0}); the installer's own changes stay in the \
         prefix"
    )]
    DllOverride(String),
    #[error("cannot check the marker file: {0}")]
    Marker(String),
}

/// A successful install: the marker was confirmed after the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerPkgInstalled {
    /// Always `true` on success (success means the marker was found after the run); kept explicit for the caller's
    /// report.
    pub marker_confirmed: bool,
    /// E.g. a non-zero exit code that still produced the marker.
    pub warnings: Vec<String>,
    /// The staged installer copy was removed (best effort; `false` leaves it, or whatever replaced it, in
    /// `windows\temp`, and a warning says why).
    pub staged_removed: bool,
}

/// Installs `pkg` (an installer package) from `file`, the verified download, into `env`. See the module docs.
pub fn install_installer_pkg(
    pkg: &Package,
    file: &Path,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<InstallerPkgInstalled, InstallerPkgError> {
    install_with(
        pkg,
        file,
        env,
        backend,
        launcher,
        find_bwrap_on_path(),
        INSTALLER_DEADLINE,
    )
}

/// [`install_installer_pkg`] with the `bwrap` lookup and the deadline injected (tests).
fn install_with(
    pkg: &Package,
    file: &Path,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    bwrap: Option<PathBuf>,
    deadline: Duration,
) -> Result<InstallerPkgInstalled, InstallerPkgError> {
    let (silent_args, marker, overrides) = check_package(pkg)?;
    let bwrap = bwrap.ok_or(InstallerPkgError::BwrapNotFound)?;

    let stage_err = |e: &dyn Display| InstallerPkgError::Stage(bounded(e));
    let mut src = open_archive(file, pkg.size).map_err(|e| stage_err(&e))?;
    let mut head = Vec::with_capacity(OLE_MAGIC.len());
    (&src).take(OLE_MAGIC.len() as u64).read_to_end(&mut head)?;
    src.seek(SeekFrom::Start(0))?;
    let msi = is_msi(&head, &pkg.url);

    let drive_c = env.drive_c();
    let dir = format!("{STAGING_DIR}\\{}", pkg.id);
    let name = format!("{}.{}", pkg.id, if msi { "msi" } else { "exe" });
    remove_stale_stage(&drive_c, &format!("{dir}\\{name}")).map_err(|e| stage_err(&e))?;
    let winpath = stage_file(env, &dir, &name, &mut src).map_err(|e| stage_err(&e))?;
    let mut staged = Staged {
        drive_c: drive_c.clone(),
        winpath: Some(winpath.clone()),
    };
    let staged_unix = resolve_under(&drive_c, &winpath).map_err(|e| stage_err(&e))?;
    verify_staged(&staged_unix, pkg)?;

    if marker_present(env, marker)? {
        return Err(InstallerPkgError::MarkerAlreadyPresent);
    }

    let (exe, args) = if msi {
        let msiexec = drive_c.join(MSIEXEC_RELATIVE);
        if !fs::symlink_metadata(&msiexec).is_ok_and(|m| m.file_type().is_file()) {
            return Err(InstallerPkgError::MsiExecMissing);
        }
        let mut args = vec![OsString::from("/i"), OsString::from(winpath.to_string())];
        args.extend(silent_args.iter().map(OsString::from));
        (msiexec, args)
    } else {
        let explorer = drive_c.join(EXPLORER_RELATIVE);
        if !fs::symlink_metadata(&explorer).is_ok_and(|m| m.file_type().is_file()) {
            return Err(InstallerPkgError::ExplorerMissing);
        }
        let mut args = vec![
            OsString::from(format!("/desktop={NULL_DESKTOP}")),
            OsString::from(winpath.to_string()),
        ];
        args.extend(silent_args.iter().map(OsString::from));
        (explorer, args)
    };
    let opts = SandboxOpts {
        allow_network: false,
        extra_ro_binds: backend.dll_dirs(),
    };
    let status = run_sandboxed(backend, launcher, env, &bwrap, &exe, &args, opts, Some(deadline))
        .map_err(|e| InstallerPkgError::Sandbox(bounded(&e)))?;
    let Some(status) = status else {
        // The sandbox tree is already dead; this only makes sure nothing of the prefix is left running outside it.
        let _ = backend.stop(env);
        return Err(InstallerPkgError::TimedOut {
            secs: deadline.as_secs(),
        });
    };

    let present = marker_present(env, marker)?;
    let removed = staged.remove();
    match (status.success(), present) {
        (ok, true) => {
            let mut warnings = Vec::new();
            if !ok {
                warnings.push(format!(
                    "the installer exited with {status} but its marker is present; treated as installed (some \
                     installers exit non-zero on success)"
                ));
            }
            if let Err(why) = &removed {
                warnings.push(format!("the staged installer copy was not removed: {why}"));
            }
            set_overrides(overrides, env, backend, launcher, &bwrap)?;
            Ok(InstallerPkgInstalled {
                marker_confirmed: true,
                warnings,
                staged_removed: removed.is_ok(),
            })
        }
        (true, false) => Err(InstallerPkgError::MarkerMissing),
        (false, false) => Err(InstallerPkgError::NonZeroAndNoMarker { code: status.code() }),
    }
}

/// Whether `pkg`'s marker is in `env`'s prefix now, the package validated as for an install. The orchestrator asks
/// this before any download or consent prompt (Ruling 15). Reads only: a file lookup, or the bounded hive parse.
pub fn marker_already_present(pkg: &Package, env: &AppEnv) -> Result<bool, InstallerPkgError> {
    let (_, marker, _) = check_package(pkg)?;
    marker_present(env, marker)
}

// ------------------------------------------------------------------------------------------------ validation

fn bad_package(pkg: &Package, why: &str) -> InstallerPkgError {
    InstallerPkgError::BadPackage(format!("package {:?}: {why}", clip(&pkg.id)))
}

type Checked<'a> = (&'a [String], &'a Marker, &'a [String]);

fn check_package(pkg: &Package) -> Result<Checked<'_>, InstallerPkgError> {
    let (
        Kind::Installer,
        Install::Installer {
            silent_args,
            marker,
            dll_overrides,
        },
    ) = (pkg.kind, &pkg.install)
    else {
        return Err(InstallerPkgError::NotInstallerKind);
    };
    install_archive::check_overrides(dll_overrides, Some(&pkg.provides))
        .map_err(|e| bad_package(pkg, &e.to_string()))?;
    if !manifest::valid_id(&pkg.id) {
        return Err(bad_package(pkg, "invalid id"));
    }
    if !manifest::valid_sha256(&pkg.sha256) {
        return Err(bad_package(pkg, "sha256 is not 64 lowercase hex characters"));
    }
    if pkg.size == 0 || pkg.size > MAX_PACKAGE_SIZE {
        return Err(bad_package(pkg, "invalid size"));
    }
    check_silent_args(silent_args)?;
    match marker {
        Marker::File(p) => {
            marker_winpath(p).map_err(|why| bad_package(pkg, &why))?;
        }
        Marker::RegistryValue { key, name, min_dword } => {
            parse_key(key).map_err(|why| bad_package(pkg, &why))?;
            if min_dword.is_some() && name.is_empty() {
                return Err(bad_package(pkg, "min_dword needs a named (DWORD) value"));
            }
            if name.len() > MAX_TEXT_LEN || name.chars().any(char::is_control) {
                return Err(bad_package(
                    pkg,
                    "registry value name is too long or has control characters",
                ));
            }
        }
    }
    Ok((silent_args, marker, dll_overrides))
}

/// Sets each DLL override (`native,builtin`, through the same settled `reg.exe` helper as archive packages). If
/// one fails, the ones already set are deleted again, newest first, and the install fails: the vendor installer's
/// own changes stay (they cannot be undone), and nothing is recorded by the caller. Every `reg.exe` run (set,
/// delete, query) is in the installer sandbox, offline (Ruling 17): the vendor installer has just run, and whatever
/// it registered to start with the next Wine session (services, ...) starts with these.
fn set_overrides(
    names: &[String],
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    bwrap: &Path,
) -> Result<(), InstallerPkgError> {
    let sandbox = Some(bwrap);
    for (i, name) in names.iter().enumerate() {
        if let Err(e) = install_archive::set_override(name, env, backend, launcher, sandbox) {
            // Delete the failed one too: a `reg add` that fails may still have written it.
            let undo: Vec<String> = names[..=i]
                .iter()
                .rev()
                .filter_map(|n| install_archive::delete_override(n, env, backend, launcher, sandbox).err())
                .map(|e| bounded(&e))
                .collect();
            let mut why = format!("{name}: {}", bounded(&e));
            if !undo.is_empty() {
                why.push_str(&format!(
                    "; removing the overrides already set also failed: {}",
                    undo.join("; ")
                ));
            }
            return Err(InstallerPkgError::DllOverride(bounded(&why)));
        }
    }
    Ok(())
}

/// At most [`MAX_LIST_LEN`] arguments, each non-empty, at most [`MAX_TEXT_LEN`] bytes, no control characters (NUL
/// included). Each is later passed as exactly one argv element.
fn check_silent_args(args: &[String]) -> Result<(), InstallerPkgError> {
    if args.len() > MAX_LIST_LEN {
        return Err(InstallerPkgError::BadSilentArg(format!(
            "{} arguments, at most {MAX_LIST_LEN}",
            args.len()
        )));
    }
    for (i, a) in args.iter().enumerate() {
        if a.is_empty() || a.len() > MAX_TEXT_LEN || a.chars().any(char::is_control) {
            return Err(InstallerPkgError::BadSilentArg(format!(
                "argument {i} ({:?}) must be 1 to {MAX_TEXT_LEN} bytes without control characters",
                clip(a)
            )));
        }
    }
    Ok(())
}

/// A marker file path (relative to `drive_c`, `/`-separated) as a `C:\` path.
fn marker_winpath(p: &str) -> Result<WinPath, String> {
    manifest::check_rel_path(p).map_err(|why| format!("unsafe marker path {:?} ({why})", clip(p)))?;
    WinPath::parse(&format!("C:\\{}", p.replace('/', "\\")))
        .map_err(|e| format!("unsafe marker path {:?} ({e})", clip(p)))
}

/// `(hive file, key relative to the hive)` for `HKLM\...`/`HKEY_LOCAL_MACHINE\...` (`system.reg`) and
/// `HKCU\...`/`HKEY_CURRENT_USER\...` (`user.reg`); the hive name is case-insensitive.
fn parse_key(key: &str) -> Result<(&'static str, &str), String> {
    let bad = |why: &str| format!("registry key {:?}: {why}", clip(key));
    if key.len() > MAX_TEXT_LEN || key.chars().any(char::is_control) {
        return Err(bad("too long or has control characters"));
    }
    let (hive, rest) = key.split_once('\\').ok_or_else(|| bad("no key below the hive"))?;
    let file = match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "system.reg",
        "HKCU" | "HKEY_CURRENT_USER" => "user.reg",
        _ => return Err(bad("the hive must be HKLM or HKCU")),
    };
    if rest.split('\\').any(str::is_empty) {
        return Err(bad("empty key component"));
    }
    Ok((file, rest))
}

// ------------------------------------------------------------------------------------------------ staging

/// Removes a regular file left at the staging path by a killed earlier run, so the `O_EXCL` copy can proceed.
/// Anything else there (a directory, a symlink on the way) is left alone and the copy then fails.
fn remove_stale_stage(drive_c: &Path, winpath: &str) -> Result<(), String> {
    let wp = WinPath::parse(winpath).map_err(|e| e.to_string())?;
    match join_new(drive_c, &wp) {
        Ok(p) => {
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                fs::remove_file(&p).map_err(|e| format!("cannot remove a stale staged copy: {e}"))?;
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The staged copy, removed (with its package and `rt-deps` directories, when empty) when dropped.
///
/// Only the `WinPath` is kept, never a host path resolved earlier: the installer ran in between with the prefix
/// bound read-write at its host path, so it may have replaced any part of the staging path with a symlink to a
/// host directory. Every removal resolves again with [`resolve_under`] (which refuses a symlink anywhere on the
/// way) right before it acts, and removes only what that re-resolution shows is a regular file (or, for the
/// parents, a real directory). Anything else is left alone and reported. The installer is no longer running when
/// this happens (the run returned, or its sandbox was killed).
struct Staged {
    drive_c: PathBuf,
    winpath: Option<WinPath>,
}

impl Staged {
    /// Removes the copy now; `Err` says why it (or something that replaced it) was left in place.
    fn remove(&mut self) -> Result<(), String> {
        let Some(wp) = self.winpath.take() else {
            return Ok(());
        };
        match resolve_under(&self.drive_c, &wp) {
            Err(ResolveError::NotFound) => {}
            Err(e) => return Err(format!("{wp} cannot be resolved safely ({e})")),
            // `resolve_under` only returns a regular file or a directory, and `remove_file` refuses a directory.
            Ok(p) => fs::remove_file(&p).map_err(|e| format!("{wp}: {}", bounded(&e)))?,
        }
        // The `<id>` and `rt-deps` directories, each re-resolved; `remove_dir` only removes an empty directory.
        let comps = wp.components();
        for n in [comps.len() - 1, comps.len() - 2] {
            let Ok(dir) = WinPath::parse(&format!("C:\\{}", comps[..n].join("\\"))) else {
                break;
            };
            match resolve_under(&self.drive_c, &dir) {
                Ok(p) if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_dir()) => {
                    if fs::remove_dir(&p).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// The staged copy must still be the verified package: regular file, `pkg.size` bytes, `pkg.sha256`.
fn verify_staged(path: &Path, pkg: &Package) -> Result<(), InstallerPkgError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| InstallerPkgError::Stage(bounded(&e)))?;
    match fetch::verify(f, pkg) {
        Ok(true) => Ok(()),
        Ok(false) => Err(InstallerPkgError::Stage(
            "the staged copy does not match the package's size and sha256".into(),
        )),
        Err(e) => Err(InstallerPkgError::Stage(bounded(&e))),
    }
}

/// An MSI: OLE2 magic, or a url whose path ends in `.msi` (any case).
fn is_msi(head: &[u8], url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    head.starts_with(&OLE_MAGIC) || path.to_ascii_lowercase().ends_with(".msi")
}

// ------------------------------------------------------------------------------------------------ markers

/// Whether `marker` exists in `env` now. A file marker must be a regular file (found case-insensitively, no
/// symlink anywhere on the way); a directory or special file there is an error, not "present".
fn marker_present(env: &AppEnv, marker: &Marker) -> Result<bool, InstallerPkgError> {
    match marker {
        Marker::File(p) => {
            let wp = marker_winpath(p).map_err(InstallerPkgError::BadPackage)?;
            match resolve_under(&env.drive_c(), &wp) {
                Ok(path) => match fs::symlink_metadata(&path) {
                    Ok(m) if m.file_type().is_file() => Ok(true),
                    Ok(_) => Err(InstallerPkgError::Marker(format!(
                        "{:?} is not a regular file",
                        clip(p)
                    ))),
                    Err(e) => Err(InstallerPkgError::Marker(bounded(&e))),
                },
                Err(ResolveError::NotFound) => Ok(false),
                Err(e) => Err(InstallerPkgError::Marker(format!("{:?}: {e}", clip(p)))),
            }
        }
        Marker::RegistryValue { key, name, min_dword } => {
            registry_marker_present_min(&env.prefix(), key, name, *min_dword)
        }
    }
}

/// [`registry_marker_present_min`] without a minimum (tests).
#[cfg(test)]
fn registry_marker_present(prefix: &Path, key: &str, name: &str) -> Result<bool, InstallerPkgError> {
    registry_marker_present_min(prefix, key, name, None)
}

/// Whether value `name` of `key` exists in the prefix's registry files (and, with `min`, is a DWORD >= `min`). See
/// the module docs for the lookup rules.
fn registry_marker_present_min(
    prefix: &Path,
    key: &str,
    name: &str,
    min: Option<u32>,
) -> Result<bool, InstallerPkgError> {
    let (file, rel) = parse_key(key).map_err(InstallerPkgError::BadPackage)?;
    let mut candidates = vec![rel.to_lowercase()];
    if file == "system.reg"
        && let Some((first, rest)) = rel.split_once('\\')
        && first.eq_ignore_ascii_case("software")
        && !rest.to_ascii_lowercase().starts_with("wow6432node\\")
        && !rest.eq_ignore_ascii_case("wow6432node")
    {
        candidates.push(format!("software\\wow6432node\\{}", rest.to_lowercase()));
    }
    let reg = match read_hive(prefix, file)? {
        Some(reg) => reg,
        None => return Ok(false),
    };
    let name = name.to_lowercase();
    let satisfies = |v: &RegValue| match (min, v) {
        (None, _) => true,
        (Some(min), RegValue::Dword(d)) => *d >= min,
        (Some(_), _) => false,
    };
    let found = reg.keys.iter().any(|(k, v)| {
        candidates.contains(&k.to_lowercase())
            && v.values
                .iter()
                .any(|(n, val)| n.to_lowercase() == name && satisfies(val))
    });
    if !found && reg.truncated {
        return Err(InstallerPkgError::Registry(format!(
            "{file} has more keys than are read; the marker cannot be checked"
        )));
    }
    Ok(found)
}

/// A prefix hive (`system.reg`/`user.reg`) read for a marker: `None` if it does not exist (or is a directory or
/// other non-regular file, which Wine never writes). The prefix directory must be a real directory and the hive is
/// opened with `O_NOFOLLOW` (a symlink is an error, never followed: this read also runs for `deps`, the install
/// hint and `doctor`, outside any sandbox), `O_NONBLOCK` (a FIFO cannot hang the open), and its size is checked on
/// the open file against [`MAX_MARKER_HIVE_BYTES`] before anything is read (a huge sparse file costs nothing).
fn read_hive(prefix: &Path, file: &str) -> Result<Option<WineReg>, InstallerPkgError> {
    let err = |why: String| InstallerPkgError::Registry(format!("{file}: {}", bounded(&why)));
    match fs::symlink_metadata(prefix) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return Err(err("the prefix is not a plain directory".into())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(e.to_string())),
    }
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(prefix.join(file))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(err("is a symlink: not followed".into())),
        Err(e) => return Err(err(e.to_string())),
    };
    let meta = f.metadata().map_err(|e| err(e.to_string()))?;
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > MAX_MARKER_HIVE_BYTES {
        return Err(err(format!(
            "{} bytes, over the {MAX_MARKER_HIVE_BYTES}-byte cap for a marker read: not read",
            meta.len()
        )));
    }
    let mut bytes = Vec::new();
    f.take(MAX_MARKER_HIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| err(e.to_string()))?;
    if bytes.len() as u64 > MAX_MARKER_HIVE_BYTES {
        return Err(err("grew past the cap while being read".into()));
    }
    WineReg::parse(&bytes).map(Some).map_err(|e| err(e.to_string()))
}

/// `e` as text without control characters, at most [`MAX_MESSAGE`] bytes.
fn bounded(e: &dyn Display) -> String {
    let s: String = e.to_string().chars().filter(|c| !c.is_control()).collect();
    if s.len() <= MAX_MESSAGE {
        return s;
    }
    let mut end = MAX_MESSAGE;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests;
