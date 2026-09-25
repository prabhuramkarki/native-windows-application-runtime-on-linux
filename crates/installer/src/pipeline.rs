//! The install pipeline for `.msi`/`.exe` installers (master prompt §22, Phase 3 Task 6).
//!
//! Stages, in order (see [`install_via_installer`]): detect the file's real shape (content, never extension) ->
//! analyze it (installer family, `MsiInfo` for an MSI) -> plan the run (silent flags, `msiexec` vs. the exe
//! itself, [`crate::family::plan`]) -> pick a provisional name/id and `Store::create` + `backend.prepare` (Phase
//! 2, unchanged) -> place the installer file inside `drive_c` (never run from outside it) -> ONLY THEN snapshot
//! the environment ("before") -> run it sandboxed ([`crate::sandbox::InstallerSandbox`] via
//! [`rt_core::Launcher::wrap`]) -> snapshot again ("after") and diff -> locate `.lnk`s and rank candidates
//! ([`crate::discover::rank`]) -> on ambiguity, return [`InstallOutcome::NeedsChoice`] and remove the half-built
//! environment (nothing is installed); an `exe_override` short-circuits ranking entirely -> delete the staged
//! installer file (its job is done) -> write `Metadata` (schema v2's `installer` field) -> return.
//!
//! **The installer is placed before the "before" snapshot, not after.** `Snapshot`/`InstallDiff` compare real
//! on-disk paths; placing the installer first means it (and any directories created for it) are already part of
//! the baseline and can never appear in `diff.new_files`, so ranking never has to know it was even involved. An
//! earlier version of this pipeline placed the installer AFTER the "before" snapshot and tried to exclude its
//! own path from the candidate list by string comparison after the fact — that comparison used the WinPath text
//! as requested (`Windows\Temp\...`) rather than the real on-disk casing a live Wine prefix actually uses
//! (`windows/temp/...`, all lowercase), so the exclusion silently never matched and the installer itself could
//! win ranking outright on a real prefix. See the Task 6 fix-round report for the full story; the reorder here
//! removes the whole fragile comparison rather than trying to get the casing right.
//!
//! **A non-zero installer exit code is not a failure.** Some installers (older InstallShield stubs especially)
//! exit non-zero on a successful, silent install. The exit status is recorded as a warning and discovery is
//! attempted regardless; only a genuine spawn/backend/metadata failure aborts the install.
//!
//! **No display access in the sandbox (default, non-`--silent` mode).** `InstallerSandbox`'s bwrap profile
//! (Task 5) binds no X11/Wayland socket and unshares IPC (breaking X11 SHM), and provides no `$XDG_RUNTIME_DIR`.
//! An installer run WITHOUT `--silent` (the CLI's own default: "show its own GUI") therefore likely cannot
//! render a window inside this sandbox at all; only `--silent` installs are known to work reliably today. This
//! is a property of Task 5's sandbox profile, not something this task changes — see `crates/cli/src/install.rs`
//! for the user-facing warning. Task 8's real-Wine e2e tests are what will settle this for real.
//!
//! **Cleanup.** Every failure after `Store::create` (including the "ambiguous, nothing installed" case) stops
//! the backend and removes the environment, exactly like `rt_core::install` (see `cleanup`/`cleanup_problem`
//! below, and its module docs for why a foreign directory from a losing `Store::create` race is never touched).
//! ponytail: unlike `rt_core::install`, there is no `UnwindCleanup` drop-guard for a panic mid-pipeline. Every
//! byte-parsing dependency here (`MsiInfo`, `ShellLink`, `pe::analyze`) was hand-rolled specifically because it
//! is fuzzed panic-free (see their own module docs), so the panic risk this pipeline actually carries is much
//! lower than Phase 2's zip/PE path; add the same drop-guard back if a real panic here is ever observed.
//!
//! **Desktop integration (Task 7).** After `Metadata` is written, this pipeline writes a `.desktop` launcher
//! (`rt_desktop::entry::write`) and registers the `.exe`/`.msi` MIME association (`rt_desktop::mime::register`).
//! Both run only after the app itself is already fully installed and runnable; either failing becomes a warning
//! on the returned `InstallOutcome`, never an install failure (see `run_after_create`'s own comment there).
use crate::InstallerFamily;
use crate::discover::{Candidate, RankResult, exe_in, rank};
use crate::family::{self, PlanError, Program};
use crate::lnk::ShellLink;
use crate::msi::{MsiError, MsiInfo};
use crate::run::{run_sandboxed, stage_file};
use crate::sandbox::{SandboxOpts, find_bwrap_on_path};
use crate::snapshot::{InstallDiff, Snapshot, UninstallEntry};
use rt_core::{
    AppEnv, AppId, BackendError, BackendInfo, CompatBackend, InstallerMeta, LaunchError, Launcher, MAX_FIELD_LEN,
    MAX_NAME_LEN, MetaError, Metadata, ResolveError, Store, StoreError, WinPath, WinPathError, is_format,
    resolve_under, unique_id,
};
// Only the tests (`use super::*`) still name it; the run itself moved to `crate::run`.
#[cfg(test)]
use rt_core::RunOpts;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Largest installer file this pipeline reads whole into memory. Matches `rt_core::install::INPUT_CAP`
/// (duplicated, not imported: that constant lives on a service module of a sibling crate, not a shared-constants
/// one; a future cleanup could hoist both, as `crate::reg`'s own doc comment already notes for its own cap).
pub const INPUT_CAP: u64 = 4 * 1024 * 1024 * 1024;
/// How many times `Store::create` is retried with a fresh id after `AlreadyExists` (mirrors
/// `rt_core::install::CREATE_ATTEMPTS`).
const CREATE_ATTEMPTS: usize = 5;
/// Where the installer file itself is placed inside `drive_c` before it is run (never outside it). A fixed,
/// dedicated staging directory: nothing about the eventual app install location is known yet at this point.
const INSTALLER_STAGING_DIR: &str = "C:\\Windows\\Temp\\rt-installer";
/// `msiexec.exe`'s fixed location in every Wine prefix (verified for real: `WINEPREFIX=<tmp> WINEARCH=win64
/// wine wineboot -u` on Wine 10.0/Ubuntu creates exactly this file). See Ruling 2 in the task brief. Also used
/// by `crate::uninstall` (an `UninstallString` of `MsiExec.exe /X{GUID}` needs the same resolution).
pub const MSIEXEC_RELATIVE: &str = "windows/system32/msiexec.exe";

/// What the caller asked for. `silent`/`allow_network` default OFF ("default = show installer GUI", matching
/// the task brief and this project's stance that Phase 3's target is offline-only installers).
#[derive(Debug, Clone, Default)]
pub struct InstallerOpts {
    pub silent: bool,
    pub allow_network: bool,
    /// The app's own executable, as a path inside the installed prefix (drive_c-relative, either separator,
    /// e.g. `Program Files\App\app.exe`). When `Some`, discovery ([`crate::discover::rank`]) is skipped
    /// entirely and this path is used, resolved the same case-insensitive, symlink-refusing way as everything
    /// else under `drive_c` ([`resolve_under`]).
    pub exe_override: Option<String>,
}

#[derive(Debug, Clone)]
pub enum InstallOutcome {
    Installed {
        id: AppId,
        /// Canonical, e.g. `C:\Program Files\App\app.exe`.
        executable: WinPath,
        /// Human text; may quote untrusted data (an installer's own strings), capped, but the CLI must still
        /// sanitise it before printing (same contract as `rt_core::InstallOutcome::warnings`).
        warnings: Vec<String>,
    },
    /// Discovery could not tell which installed file is the application (an empty diff and a genuine tie share
    /// this one variant, see `crate::discover`'s own docs for why). Nothing was installed: the environment this
    /// attempt created has already been removed by the time this is returned.
    NeedsChoice(Vec<Candidate>),
}

#[derive(Debug, thiserror::Error)]
pub enum InstallerError {
    #[error("cannot read the input: {0}")]
    Read(#[source] io::Error),
    #[error("the input is not a regular file")]
    NotRegular,
    #[error("the input is larger than {INPUT_CAP} bytes")]
    TooLarge,
    #[error("not an MSI package or a recognised installer executable (Inno Setup, NSIS, InstallShield, WiX Burn)")]
    NotAnInstaller,
    #[error("not a usable Windows program: {0}")]
    Malformed(String),
    #[error("not a usable MSI package: {0}")]
    Msi(#[from] MsiError),
    #[error("{0}")]
    Plan(#[from] PlanError),
    #[error("the file name cannot be used inside a Windows prefix: {0}")]
    BadFileName(String),
    #[error("cannot place or locate the installer inside the prefix: {0}")]
    Resolve(#[from] ResolveError),
    #[error("cannot place or locate the installer inside the prefix: {0}")]
    Path(#[from] WinPathError),
    #[error(
        "msiexec.exe is missing from this prefix's windows/system32 (Wine did not create it during `prepare`; \
         this Wine installation may be broken)"
    )]
    MsiExecMissing,
    #[error("bwrap (bubblewrap) was not found on $PATH: install it to run installers sandboxed")]
    BwrapNotFound,
    #[error("the chosen --exe {0} is not a file inside this app's environment")]
    ExeOverrideNotAFile(String),
    #[error("environment setup failed: {0}")]
    Backend(#[from] BackendError),
    #[error("cannot run the installer: {0}")]
    Launch(#[from] LaunchError),
    #[error("{0}")]
    Meta(#[from] MetaError),
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    /// `cause` happened, and cleaning up afterwards had `problems` (mirrors
    /// `rt_core::InstallError::WithCleanup`).
    #[error("{cause}; in addition: {}", problems.join("; "))]
    WithCleanup {
        cause: Box<InstallerError>,
        problems: Vec<String>,
    },
}

/// True when `bytes` are something only [`install_via_installer`] can handle: an MSI package (OLE2 magic) or a
/// PE file carrying a recognised installer marker. Content decides, never the file extension, matching every
/// other detection in this project. The CLI uses this to route `runtime install` between this pipeline and the
/// unchanged `rt_core::install` (see the dispatch comment in `crates/cli/src/install.rs`).
pub fn looks_like_installer(bytes: &[u8]) -> bool {
    match pe::detect(bytes) {
        pe::FileKind::Msi => true,
        pe::FileKind::Pe => pe::analyze(bytes).is_ok_and(|info| info.installer.is_some()),
        pe::FileKind::Zip | pe::FileKind::Unknown => false,
    }
}

pub fn install_via_installer(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: Launcher,
    path: &Path,
    opts: InstallerOpts,
) -> Result<InstallOutcome, InstallerError> {
    // Stage 1+2: detect and analyze. Pure; nothing is created yet.
    let bytes = read_whole_file(path)?;
    let analyzed = analyze_installer(&bytes)?;
    // Stage 3 (plan): validated before anything is created, exactly like Phase 2's metadata-before-create rule.
    let run_plan = family::plan(analyzed.family, opts.silent)?;

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let provisional_name = provisional_name(&analyzed, &stem);
    let base = AppId::slug(&provisional_name);

    // Stage 4: create the environment. `AlreadyExists` means a losing race: pick again, never touch the winner's
    // directory (mirrors `rt_core::install_with`'s own retry loop and its "never remove a foreign dir" rule).
    let mut id = unique_id(store, &base)?;
    let mut env = None;
    for _ in 0..CREATE_ATTEMPTS {
        match store.create(&id) {
            Ok(created) => {
                env = Some(created);
                break;
            }
            Err(StoreError::AlreadyExists) => id = unique_id(store, &base)?,
            Err(e) => return Err(e.into()),
        }
    }
    let Some(env) = env else {
        return Err(StoreError::AlreadyExists.into());
    };

    match run_after_create(
        store,
        backend,
        &launcher,
        &env,
        path,
        &bytes,
        &analyzed,
        run_plan,
        &opts,
        &provisional_name,
    ) {
        Ok(InstallOutcome::NeedsChoice(candidates)) => {
            // "Ambiguous discovery installs nothing": the half-built, metadata-less environment goes too.
            discard_ambiguous(store, backend, &env);
            Ok(InstallOutcome::NeedsChoice(candidates))
        }
        Ok(installed) => Ok(installed),
        Err(cause) => Err(cleanup(store, backend, &env, cause)),
    }
}

// ---------------------------------------------------------------- stage 1+2: detect and analyze

struct Analyzed {
    family: InstallerFamily,
    msi: Option<MsiInfo>,
}

fn open_nonblocking(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

/// At most [`INPUT_CAP`] bytes of `path`, whole into memory (an MSI's structural facts and a PE's installer
/// marker both need the complete file, the marker being an overlay appended at the very end). Mirrors
/// `rt_core::install::read_input`'s FIFO/size-cap discipline: `metadata` before `open`, `O_NONBLOCK` (a FIFO
/// with no writer returns at once instead of blocking forever), the size cap checked on the fstat'd length
/// BEFORE any bulk read.
fn read_whole_file(path: &Path) -> Result<Vec<u8>, InstallerError> {
    let stat = fs::metadata(path).map_err(InstallerError::Read)?;
    if !stat.is_file() {
        return Err(InstallerError::NotRegular);
    }
    let file = open_nonblocking(path).map_err(InstallerError::Read)?;
    let opened = file.metadata().map_err(InstallerError::Read)?;
    if !opened.is_file() {
        return Err(InstallerError::NotRegular);
    }
    if opened.len() > INPUT_CAP {
        return Err(InstallerError::TooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(usize::try_from(opened.len()).unwrap_or(usize::MAX))
        .map_err(|_| InstallerError::Read(io::ErrorKind::OutOfMemory.into()))?;
    (&file)
        .take(INPUT_CAP + 1 - bytes.len() as u64)
        .read_to_end(&mut bytes)
        .map_err(InstallerError::Read)?;
    if bytes.len() as u64 > INPUT_CAP {
        return Err(InstallerError::TooLarge);
    }
    Ok(bytes)
}

fn analyze_installer(bytes: &[u8]) -> Result<Analyzed, InstallerError> {
    match pe::detect(bytes) {
        pe::FileKind::Msi => {
            let info = MsiInfo::read(bytes)?;
            Ok(Analyzed {
                family: InstallerFamily::Msi,
                msi: Some(info),
            })
        }
        pe::FileKind::Pe => {
            let info = pe::analyze(bytes).map_err(|e| InstallerError::Malformed(clean(&e.to_string(), 200)))?;
            let family = info
                .installer
                .as_ref()
                .map(|i| InstallerFamily::from(i.kind))
                .unwrap_or(InstallerFamily::Unknown);
            Ok(Analyzed { family, msi: None })
        }
        pe::FileKind::Zip | pe::FileKind::Unknown => Err(InstallerError::NotAnInstaller),
    }
}

/// Removes control characters and bidi/format overrides, trims, and cuts to at most `max_bytes` bytes (on a
/// character boundary). A small, deliberate duplicate of `rt_core::text::clean` (private to that crate): every
/// string this pipeline stores or displays that came out of the installer itself (an MSI `ProductName`, an
/// `Uninstall` registry string) is exactly the kind of attacker-controlled text that function exists to sanitise.
fn clean(s: &str, max_bytes: usize) -> String {
    let filtered: String = s.chars().filter(|&c| !(c.is_control() || is_format(c))).collect();
    let mut out = filtered.trim().to_owned();
    if out.len() > max_bytes {
        let mut end = max_bytes;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.truncate(out.trim_end().len());
    }
    out
}

fn family_label(f: InstallerFamily) -> &'static str {
    match f {
        InstallerFamily::Inno => "inno",
        InstallerFamily::Nsis => "nsis",
        InstallerFamily::InstallShield => "installshield",
        InstallerFamily::WixBurn => "wix-burn",
        InstallerFamily::Msi => "msi",
        InstallerFamily::Unknown => "unknown",
    }
}

/// The name used to derive the app id, BEFORE the installer has run: an MSI's own `ProductName` (known up
/// front), else the installer file's stem, else `"app"`.
fn provisional_name(analyzed: &Analyzed, stem: &str) -> String {
    let from_msi = analyzed
        .msi
        .as_ref()
        .map(|m| clean(&m.product_name, MAX_NAME_LEN))
        .filter(|s| !s.is_empty());
    from_msi.unwrap_or_else(|| {
        let stem = clean(stem, MAX_NAME_LEN);
        if stem.is_empty() { "app".to_owned() } else { stem }
    })
}

// ---------------------------------------------------------------- stage 5: place the installer inside drive_c

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> InstallerError {
    move |source| InstallerError::Io { what, source }
}

/// The installer's own file name, checked to be exactly one path component (mirrors
/// `rt_core::install::prepare_exe`'s identical check on a portable exe's file name).
fn single_component_file_name(path: &Path) -> Result<String, InstallerError> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| InstallerError::BadFileName("the name is not valid UTF-8".into()))?
        .to_owned();
    match WinPath::parse(&format!("C:\\{file_name}")) {
        Ok(p) => match p.components() {
            [only] if *only == file_name => Ok(file_name),
            _ => Err(InstallerError::BadFileName(
                "the name is not a single path component".into(),
            )),
        },
        Err(e) => Err(InstallerError::BadFileName(e.to_string())),
    }
}

/// Copies the installer file to [`INSTALLER_STAGING_DIR`] inside `drive_c` with [`crate::run::stage_file`] (the
/// same containment-safe way Phase 2's `install::place` copies a portable exe). Returns the placed file's
/// `WinPath`, which is what is actually run (never anything outside `drive_c`).
fn place_installer_file(env: &AppEnv, path: &Path, bytes: &[u8]) -> Result<WinPath, InstallerError> {
    let file_name = single_component_file_name(path)?;
    stage_file(env, INSTALLER_STAGING_DIR, &file_name, &mut &bytes[..])
}

// ---------------------------------------------------------------- stage 6: run it, sandboxed

/// Assembles `exe_unix`/`args` (Ruling 2: `msiexec.exe /i <path> [flags]` for MSI, the placed installer itself
/// for an exe family) and runs it through the sandboxed launcher. The exit status is NOT itself an error (see
/// the module docs): a non-zero exit becomes one warning, never a failure, and discovery still runs.
fn run_installer_process(
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    env: &AppEnv,
    installer_winpath: &WinPath,
    run_plan: family::RunPlan,
    opts: &InstallerOpts,
) -> Result<Vec<String>, InstallerError> {
    let drive_c = env.drive_c();
    let installer_unix = resolve_under(&drive_c, installer_winpath)?;

    let (exe_unix, args): (PathBuf, Vec<OsString>) = match run_plan.program {
        Program::MsiExec => {
            let msiexec = drive_c.join(MSIEXEC_RELATIVE);
            if !fs::symlink_metadata(&msiexec).is_ok_and(|m| m.file_type().is_file()) {
                return Err(InstallerError::MsiExecMissing);
            }
            let mut args = vec![OsString::from("/i"), OsString::from(installer_winpath.to_string())];
            args.extend(run_plan.args);
            (msiexec, args)
        }
        Program::Exe => (installer_unix, run_plan.args),
    };

    let bwrap = find_bwrap_on_path().ok_or(InstallerError::BwrapNotFound)?;
    // Ruling 3: extra read-only binds come from the backend's own `dll_dirs()` (backend-agnostic), never a
    // dependency on `backend-wine`'s concrete discovery module.
    let sandbox_opts = SandboxOpts {
        allow_network: opts.allow_network,
        extra_ro_binds: backend.dll_dirs(),
    };
    // No deadline (`None`): an interactive installer GUI may take as long as the user needs, so `Ok(None)`
    // (deadline reached) cannot happen; mapped defensively rather than unwrapped.
    let status = run_sandboxed(backend, launcher, env, &bwrap, &exe_unix, &args, sandbox_opts, None)?
        .ok_or_else(|| io_err("cannot wait for the installer process")(io::ErrorKind::TimedOut.into()))?;

    let mut warnings = Vec::new();
    if !status.success() {
        warnings.push(format!(
            "the installer exited with {status} (not treated as a failure: some installers exit non-zero even \
             on success); attempting to discover what it installed anyway"
        ));
    }
    Ok(warnings)
}

// ---------------------------------------------------------------- stage 7+8: locate .lnk's, discover, name

enum Discovery {
    Winner(String),
    NeedsChoice(Vec<Candidate>),
}

/// Refuses anything that is not a genuine regular file — checked with `symlink_metadata`, which does NOT follow
/// a final symlink (the same discipline `resolve_exe_override` already uses) — before ever attempting to read
/// it, then reads it with [`read_whole_file`]'s existing bounded-size, `O_NONBLOCK` discipline. Every path this
/// is called on (a `.lnk`/`.exe` named by `diff.new_files`, an eventual winner's own bytes) is installer-written,
/// hostile-input territory: without this check, a hostile installer leaving a FIFO as the sole new file would
/// hang an unbounded `fs::read` forever (no writer), and a symlink (to `/dev/zero`, or a large/sensitive host
/// file it can predict the path of) would have its TARGET read instead of being refused outright.
fn read_bounded_regular_file(path: &Path) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file()) {
        return None;
    }
    read_whole_file(path).ok()
}

/// `.lnk` files among `diff.new_files`, read and parsed (a file that fails to parse is silently excluded, same
/// as `rank`'s own "no candidate" handling: this is best-effort signal, not a hard requirement). Each is paired
/// with its own `new_files` path: `rank` reads the `.lnk`'s file name to skip "Uninstall" shortcuts.
fn load_shortcuts(env: &AppEnv, diff: &InstallDiff) -> Vec<(String, ShellLink)> {
    let drive_c = env.drive_c();
    diff.new_files
        .iter()
        .filter(|p| p.to_lowercase().ends_with(".lnk"))
        .filter_map(|p| {
            let link = ShellLink::parse(&read_bounded_regular_file(&drive_c.join(p))?).ok()?;
            Some((p.clone(), link))
        })
        .collect()
}

/// `exe_override`, resolved (case-insensitive, symlink-refusing) under `drive_c`; else `crate::discover::rank`
/// over the diff and any `.lnk`s found in it. The staged installer file itself is never a candidate here: it is
/// placed inside `drive_c` BEFORE the "before" snapshot is captured (see `run_after_create`), so it is already
/// present in both snapshots and never shows up in `diff.new_files` at all — no separate exclusion needed (an
/// earlier version of this function tried to exclude it by comparing path strings after the fact, which was
/// fragile against the installer's own real on-disk casing; see the Task 6 fix-round report for why that was
/// wrong and how this reorder fixes it for good).
fn discover_winner(env: &AppEnv, diff: &InstallDiff, exe_override: Option<&str>) -> Result<Discovery, InstallerError> {
    if let Some(raw) = exe_override {
        return Ok(Discovery::Winner(resolve_exe_override(env, raw)?));
    }
    let shortcuts = load_shortcuts(env, diff);
    let drive_c = env.drive_c();
    let read = |p: &str| read_bounded_regular_file(&drive_c.join(p));
    // `symlink_metadata`, not `metadata`: a candidate whose bytes `read` above would refuse (a symlink, a FIFO,
    // ...) must not be reported as having a size either — `rank` should see the same "not a genuine regular
    // file" verdict from both closures, not a size for a file `read` then silently drops.
    let size = |p: &str| {
        fs::symlink_metadata(drive_c.join(p))
            .ok()
            .filter(|m| m.file_type().is_file())
            .map(|m| m.len())
    };
    Ok(match rank(diff, &shortcuts, read, size) {
        RankResult::Winner(c) => Discovery::Winner(c.path),
        RankResult::NeedsManualChoice(candidates) => Discovery::NeedsChoice(candidates),
    })
}

/// Resolves a `--exe`-style override (drive_c-relative, either separator) to the same `/`-joined,
/// drive_c-relative form `crate::discover::Candidate::path` uses, so the rest of the pipeline treats both
/// sources identically.
fn resolve_exe_override(env: &AppEnv, raw: &str) -> Result<String, InstallerError> {
    let normalized = raw.replace('/', "\\");
    let winpath = WinPath::parse(&format!("C:\\{normalized}"))?;
    let resolved = resolve_under(&env.drive_c(), &winpath)?;
    if !fs::symlink_metadata(&resolved).is_ok_and(|m| m.file_type().is_file()) {
        return Err(InstallerError::ExeOverrideNotAFile(clean(raw, 200)));
    }
    let rel = resolved
        .strip_prefix(env.drive_c())
        .expect("resolve_under always returns a path under drive_c");
    Ok(rel.to_string_lossy().replace('\\', "/"))
}

/// The `Uninstall` entry whose `DisplayName`/`UninstallString` get recorded for `winner_path`: the only one when
/// there is exactly one (the common case: one installer, one Uninstall registration); else the one whose
/// `DisplayIcon` names the winner; else the one whose `UninstallString` program sits in the winner's own
/// directory. Paths are compared structurally ([`exe_in`]: parsed program path, component-wise, case-insensitive),
/// never by substring. `None` when several entries exist and none ties to the winner (e.g. the app plus a bundled
/// VC++ redistributable): the caller then records nothing from the registry and warns, rather than recording an
/// unrelated product's name and uninstall command.
fn choose_uninstall_entry<'a>(diff: &'a InstallDiff, winner_path: &str) -> Option<&'a UninstallEntry> {
    let entries = &diff.uninstall_entries;
    if let [only] = entries.as_slice() {
        return Some(only);
    }
    let winner = winner_path.to_lowercase();
    let dir = |p: &str| p.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
    let winner_dir = dir(&winner);
    let exe = |v: &Option<String>| v.as_deref().and_then(exe_in);
    entries
        .iter()
        .find(|e| exe(&e.icon_path).as_deref() == Some(winner.as_str()))
        .or_else(|| {
            entries
                .iter()
                .find(|e| exe(&e.uninstall_string).is_some_and(|u| dir(&u) == winner_dir))
        })
}

/// The app's real product name, if one could be determined: an MSI's own `ProductName` first (known and
/// authoritative), else the matched `Uninstall` entry's `DisplayName`. `None` when neither is available (the
/// metadata `name` field then falls back to the provisional, pre-run name).
fn resolved_product_name(analyzed: &Analyzed, uninstall_entry: Option<&UninstallEntry>) -> Option<String> {
    if let Some(msi) = &analyzed.msi {
        let cleaned = clean(&msi.product_name, MAX_NAME_LEN);
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }
    let display = uninstall_entry.and_then(|e| e.display_name.as_deref())?;
    let cleaned = clean(display, MAX_NAME_LEN);
    (!cleaned.is_empty()).then_some(cleaned)
}

fn arch_and_subsystem(pe_info: Option<&pe::PeInfo>) -> (&'static str, &'static str) {
    match pe_info {
        Some(info) => (
            if info.arch == pe::Arch::X86 { "x86" } else { "x86_64" },
            match info.subsystem {
                pe::Subsystem::Gui => "gui",
                pe::Subsystem::Console => "console",
                _ => "other",
            },
        ),
        // The winner's own bytes could not be read/analysed (unusual, but not fatal: the app was still
        // installed). Every app this project runs is on an x86-64 host; "gui" is the more common case.
        None => ("x86_64", "gui"),
    }
}

// ---------------------------------------------------------------- orchestration after Store::create

#[allow(clippy::too_many_arguments)]
fn run_after_create(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    env: &AppEnv,
    path: &Path,
    bytes: &[u8],
    analyzed: &Analyzed,
    run_plan: family::RunPlan,
    opts: &InstallerOpts,
    provisional_name: &str,
) -> Result<InstallOutcome, InstallerError> {
    backend.prepare(env)?;

    // The installer is placed BEFORE the "before" snapshot is captured, on purpose: `Snapshot`/`InstallDiff`
    // only know about real on-disk paths (see their own module docs on why an exact-string comparison against
    // `new_files` is fragile — case, 8.3 names, ... are out of scope for that type). Placing it first means the
    // staged file and the directories `place_installer_file` creates for it are already part of the baseline,
    // so they can never appear in `diff.new_files` at all; no separate exclusion-by-path-string is needed (a
    // prior version of this function tried that after the fact and got it wrong — see the Task 6 fix-round
    // report).
    let installer_winpath = place_installer_file(env, path, bytes)?;
    let before = Snapshot::capture(env);
    let mut warnings = run_installer_process(backend, launcher, env, &installer_winpath, run_plan, opts)?;

    let after = Snapshot::capture(env);
    let diff = Snapshot::diff(&before, &after);

    let winner_path = match discover_winner(env, &diff, opts.exe_override.as_deref())? {
        Discovery::Winner(p) => p,
        Discovery::NeedsChoice(candidates) => return Ok(InstallOutcome::NeedsChoice(candidates)),
    };

    // The installer has done its job: remove the scratch copy (and, best-effort, the now-empty staging
    // directory) so it does not permanently double the app's disk footprint (unlike Phase 2's `install::place`,
    // where the copy IS the app, this one is pure scratch). Best effort throughout: a failure here is cosmetic
    // (a leftover temp file), never worth failing an otherwise-successful install over, and every failure path
    // below this point removes the whole environment anyway.
    if let Ok(installer_unix) = resolve_under(&env.drive_c(), &installer_winpath) {
        let _ = fs::remove_file(&installer_unix);
        if let Some(dir) = installer_unix.parent() {
            let _ = fs::remove_dir(dir); // only succeeds if now empty; never removes a non-empty directory
        }
    }

    let winner_bytes = read_bounded_regular_file(&env.drive_c().join(&winner_path));
    let pe_info = winner_bytes.as_deref().and_then(|b| pe::analyze(b).ok());
    let (architecture, subsystem) = arch_and_subsystem(pe_info.as_ref());

    // Hoisted (Task 7's Ruling 4) so it is still in scope below, at the `.desktop`/icon-writing call site: the
    // bytes are handed to `rt_desktop::entry::write` directly, never re-read off disk.
    let icons: Vec<(u32, Vec<u8>)> = winner_bytes
        .as_deref()
        .and_then(|b| rt_desktop::icon::extract_icon_png(b, &rt_desktop::entry::HICOLOR_SIZES).ok())
        .unwrap_or_default();

    let uninstall_entry = choose_uninstall_entry(&diff, &winner_path);
    if uninstall_entry.is_none() && diff.uninstall_entries.len() > 1 {
        warnings.push(format!(
            "{} Uninstall registry entries were found and none could be tied to the installed executable; no \
             uninstall command or product name was recorded from the registry",
            diff.uninstall_entries.len()
        ));
    }
    let product_name = resolved_product_name(analyzed, uninstall_entry);
    let uninstall_command = uninstall_entry
        .and_then(|e| e.uninstall_string.as_deref())
        .map(|s| clean(s, MAX_FIELD_LEN))
        .filter(|s| !s.is_empty());
    let name = product_name.clone().unwrap_or_else(|| provisional_name.to_owned());

    let exe_winpath = WinPath::parse(&format!("C:\\{}", winner_path.replace('/', "\\")))?;
    let backend_info = BackendInfo {
        id: backend.id().to_owned(),
        version: backend.version()?,
    };
    let mut md = Metadata::new(
        env.id().clone(),
        name,
        None,
        architecture,
        &exe_winpath,
        backend_info,
        subsystem,
    );
    md.installer = Some(InstallerMeta {
        family: family_label(analyzed.family).to_owned(),
        product_name,
        uninstall_command,
    });
    md.validate()?;
    store.write_metadata(env, &md)?;

    // Desktop integration (Task 7): the app is already fully installed and runnable via `runtime run <id>` at
    // this point, exactly like the icon extraction above — a `.desktop` entry or MIME association failing here
    // is cosmetic desktop-shell integration, never a reason to fail an otherwise-successful install (the same
    // stance `store_icons` used to document for icon extraction). Both failures become warnings instead.
    if let Err(e) = rt_desktop::entry::write(env, &md, &icons) {
        warnings.push(format!(
            "could not create the desktop menu entry: {}",
            clean(&e.to_string(), MAX_FIELD_LEN)
        ));
    }
    if let Err(e) = rt_desktop::mime::register() {
        warnings.push(format!(
            "could not register the .exe/.msi file association: {}",
            clean(&e.to_string(), MAX_FIELD_LEN)
        ));
    }

    Ok(InstallOutcome::Installed {
        id: env.id().clone(),
        executable: exe_winpath,
        warnings: std::mem::take(&mut warnings),
    })
}

// ---------------------------------------------------------------- cleanup (mirrors rt_core::install)

/// Stops the backend, then removes the environment; returns what went wrong, if anything. When the backend
/// cannot be stopped a Wine process may still be using the prefix: nothing is removed and the text says so
/// (mirrors `rt_core::install`'s identically-named, private helper).
fn cleanup_problem(store: &Store, backend: &dyn CompatBackend, env: &AppEnv) -> Option<String> {
    let id = env.id();
    match backend.stop(env) {
        Err(e) => Some(format!(
            "the backend could not be stopped ({e}); the partly installed app `{id}` was left in place: remove \
             it with `runtime uninstall {id}` once no Wine process is running"
        )),
        Ok(()) => store
            .remove(id)
            .err()
            .map(|e| format!("could not remove the partly installed app `{id}`: {e}")),
    }
}

fn cleanup(store: &Store, backend: &dyn CompatBackend, env: &AppEnv, cause: InstallerError) -> InstallerError {
    match cleanup_problem(store, backend, env) {
        None => cause,
        Some(p) => InstallerError::WithCleanup {
            cause: Box::new(cause),
            problems: vec![p],
        },
    }
}

/// Ambiguous discovery "installs nothing" (module docs): the half-built, metadata-less environment is removed
/// best-effort. Unlike every other failure path, a removal failure here is not surfaced as an error: there is
/// nothing new to report beyond the ambiguity itself, and `Store::list`/`Store::read_metadata` already treat a
/// directory with no `metadata.json` as invisible, not a listed app.
fn discard_ambiguous(store: &Store, backend: &dyn CompatBackend, env: &AppEnv) {
    let _ = cleanup_problem(store, backend, env);
}

#[cfg(test)]
mod tests;
