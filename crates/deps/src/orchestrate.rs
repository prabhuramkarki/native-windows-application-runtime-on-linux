//! The dependency orchestrator: plans what an app needs, then (only when explicitly asked, through
//! [`install_plan`]) fetches and installs it behind consent, recording each success in the app's metadata.
//!
//! This is the one place that decides whether anything touches the network or the prefix. Order of a run:
//!
//! 1. A plan with nothing to install returns at once: no lock, no prompt, no network.
//! 2. Run-level guards, before any prompt or download: an exclusive non-blocking `flock` on `<app root>/deps.lock`
//!    ([`DepsError::LockHeld`]) and no `wineserver` serving this prefix ([`DepsError::PrefixBusy`]: installing
//!    under a running app blocks on `wineserver -w`, swaps DLLs under it and lets its later registry flush
//!    overwrite the installer's writes; the user closes the app, the runtime never kills it).
//! 3. The plan is resolved again from the metadata read under the lock, then every `Install` entry is decided up
//!    front (dependency order; never a `Blocked` or `AlreadyInstalled` entry, nor one behind a refusal):
//!    - UPGRADES ARE REFUSED (Ruling 13): a package the metadata already records (at another version or sha256,
//!      or it would be `AlreadyInstalled`) is refused without a prompt: the kept install journal and an installer's
//!      marker would make the new version fail anyway, after a wasted download. The user recreates the
//!      environment to get the new version.
//!    - an INSTALLER package whose marker is already in the prefix (typically the app's own installer put the
//!      component there) is skipped with [`MARKER_PRESENT`] (Ruling 15): never asked about, never downloaded,
//!      never recorded as installed by the runtime (Ruling 11e). What needs it proceeds. The component's files are
//!      there, but NOT the package's DLL overrides (Ruling 18): Wine may keep loading its builtin copies, and the
//!      only way to get the runtime's install today is to recreate the environment.
//!    - a consent-gated package asks the [`ConsentProvider`]. Recorded consent would count only for the same
//!      version AND the same [`consent_text`] hash ([`reusable_consent`]), but with upgrades refused that path is
//!      unreachable today: consent lives on the install record, any record refuses the package, and
//!      `state::forget` drops the consent with the record. It is kept as the spec's rule for when upgrades land.
//! 4. The plan is resolved once more with the denied and refused ids, so they and everything that needs them are
//!    `Blocked` (and reported as skipped, a refused upgrade with its own reason) and nothing is downloaded for
//!    them. What a denied package itself NEEDS still installs (spec §4: only the denied package and its dependents
//!    are blocked).
//! 5. Packages install in plan order: busy re-check, the installer marker check again (right before the download),
//!    fetch, install, then record (read, `state::record`, atomic
//!    write) after EACH success. The first failure stops the run; the rest are skipped.
//!
//! Library code prints nothing; every report string is one line, bounded, with control and format characters
//! escaped (callers still print through their sanitiser).

use crate::fetch::{self, FetchError, FetchOpts};
use crate::install_archive::{self, ArchiveError, DiscardReport};
use crate::install_installer::{self, InstallerPkgError};
use crate::manifest::{self, Kind, Manifest, Package};
use crate::resolve::{Action, Facts, Plan, block_for_vulkan, resolve};
use crate::state;
use rt_core::{
    AppEnv, CompatBackend, ConsentRecord, DependencyRecord, Input, Launcher, Metadata, Store, StoreError,
    VulkanVerdict, WinPath, read_input, resolve_under,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The [`RunReport`] skip reason of a package that was already installed (the only skip that is not a shortfall).
pub const ALREADY_INSTALLED: &str = "already installed";
/// The per-app lock file, directly in the app root.
pub const LOCK_FILE: &str = "deps.lock";
/// Longest reason string in a [`RunReport`].
const MAX_REASON: usize = 400;
/// Most bytes of `/proc/<pid>/environ` examined (a `WINEPREFIX` past this is not seen).
const MAX_ENVIRON: u64 = 1 << 20;
/// Packages that replace Direct3D DLLs and are extracted for 64-bit only (Task 2 limitation).
pub const X64_ONLY_CAPS: &[&str] = &["d3d8", "d3d9", "d3d10core", "d3d11", "dxgi", "d3d12", "d3d12core"];
const VENDOR_PARTIAL: &str =
    "vendor installers can leave partial changes in the prefix; if the app misbehaves, recreate the environment";
/// The skip reason of an installer package whose marker is already in the prefix (Ruling 15). Also what
/// [`plan_for_app`] warns instead of planning it, so the hint does not keep asking for it.
pub const MARKER_PRESENT: &str = "present in the prefix (probably from the app's own installer); the runtime did not \
                                  install it and did not set its DLL overrides, so Wine may still load its builtin \
                                  copies; recreate the environment to let the runtime install it";

/// Where downloads come from. [`NetFetcher`] is the real one; tests inject fakes.
pub trait Fetcher {
    /// The verified file for `pkg` (`cache_dir/<sha256>`).
    fn fetch(&self, pkg: &Package, cache_dir: &Path) -> Result<PathBuf, FetchError>;
}

/// [`fetch::fetch`] with the default (safe) options.
pub struct NetFetcher;

impl Fetcher for NetFetcher {
    fn fetch(&self, pkg: &Package, cache_dir: &Path) -> Result<PathBuf, FetchError> {
        fetch::fetch(pkg, cache_dir, &FetchOpts::default())
    }
}

/// Asks the user (or a fixed `--yes` list) whether a consent-gated package may be downloaded and installed.
pub trait ConsentProvider {
    /// Returns `true` ONLY after `consent_text` was displayed to the user verbatim and in full (a `--yes` list
    /// still prints it), because the `true` is recorded against the text's hash as the licence the user accepted.
    /// If the text could not be shown (e.g. the write failed), the answer is `false`.
    fn confirm(&self, pkg: &Package, consent_text: &str) -> bool;
}

/// The plan for an app, the facts it was made from (so [`install_plan`] can re-resolve) and warnings for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPlan {
    pub facts: Facts,
    pub plan: Plan,
    pub warnings: Vec<String>,
}

pub struct Orchestrator<'a> {
    pub manifest: &'a Manifest,
    /// Passed to the fetcher, which creates and checks it.
    pub cache_dir: &'a Path,
    pub env: &'a AppEnv,
    pub store: &'a Store,
    pub backend: &'a dyn CompatBackend,
    pub launcher: &'a Launcher,
    pub fetcher: &'a dyn Fetcher,
    pub consent: &'a dyn ConsentProvider,
    /// Unix seconds for `installed_at` / `given_at` ([`unix_now`] in real use).
    pub now: fn() -> u64,
    /// The host's Vulkan verdict; the install re-resolves the plan, so it applies [`block_for_vulkan`] again and
    /// installs exactly what `plan_for_app` showed as installable.
    pub vulkan: VulkanFor<'a>,
}

/// Unix seconds (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What a run did, per package id, in plan order. Reasons are bounded single lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    pub completed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Blocked, consent denied, already installed, or not attempted after a failure.
    pub skipped: Vec<(String, String)>,
    /// Non-fatal notes about completed packages (e.g. an installer's non-zero exit that still left its marker).
    pub warnings: Vec<(String, String)>,
}

/// Run-level refusals; package failures are in the [`RunReport`] instead.
#[derive(Debug, thiserror::Error)]
pub enum DepsError {
    /// Held exclusively by a dependency install, `remove` or `uninstall`, or shared by an app being started.
    #[error(
        "another runtime command is using this app (a dependency install, a removal, or an app being started); \
         wait for it to finish, then try again"
    )]
    LockHeld,
    #[error(
        "a Wine program is running in this app's prefix (wineserver pid {pids:?}); close the app first, then \
         install again"
    )]
    PrefixBusy { pids: Vec<u32> },
    /// `deps.lock` is a symlink, a directory or another non-regular file: no lock can be taken on it by anyone.
    #[error("{LOCK_FILE} in the app's directory is unusable ({0}); delete it to install dependencies again")]
    LockFileUnusable(String),
    /// The file system refuses `flock` itself (`ENOLCK`, `EOPNOTSUPP`, `ENOSYS`: e.g. some network mounts): no
    /// lock can be taken there by anyone.
    #[error(
        "the file system holding this app does not support locking ({0}); dependencies cannot be installed \
         safely there"
    )]
    LockUnsupported(String),
    #[error("cannot read the app's metadata: {0}")]
    Metadata(#[source] StoreError),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("package {0:?} is recorded as installed: use remove/recreate, not discard")]
    Recorded(String),
    #[error("cannot discard what the interrupted install left: {0}")]
    Discard(#[source] ArchiveError),
}

impl DepsError {
    /// No lock on `deps.lock` can be taken by anyone ([`DepsError::LockFileUnusable`], [`DepsError::LockUnsupported`]),
    /// so no dependency install can be running either (an install refuses without the lock): `run`, `remove` and
    /// `uninstall` may warn and go on. Every other lock error, [`DepsError::LockHeld`] above all, refuses.
    pub fn nobody_can_lock(&self) -> bool {
        matches!(self, DepsError::LockFileUnusable(_) | DepsError::LockUnsupported(_))
    }
}

// ------------------------------------------------------------------------------------------------ text

/// One bounded line: control and format characters escaped, at most [`MAX_REASON`] bytes.
fn line(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_control() || rt_core::is_format(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
        if out.len() > MAX_REASON {
            let mut end = MAX_REASON;
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
            out.push_str("...");
            break;
        }
    }
    out
}

/// Exactly what a consent prompt shows, and what a consent record's `licence_text_sha256` hashes: any change of
/// id, version, licence, url, size or sha256 changes it, so earlier consent no longer counts. Manifest values are
/// validated, but escaped anyway so the text is safe to print as it is. The licence is shown as its LABEL only
/// (the manifest carries no licence text); for an installer package the text says plainly that running the
/// vendor's silent installer accepts the vendor's licence terms on the user's behalf without showing them.
pub fn consent_text(pkg: &Package) -> String {
    let installer = if pkg.kind == Kind::Installer {
        " The vendor's installer runs silently: running it accepts the vendor's own licence terms (its EULA) on \
         your behalf, and those terms are not displayed here; read them at the vendor before answering yes."
    } else {
        ""
    };
    format!(
        "Package: {}\nVersion: {}\nLicence: {}\nDownload: {}\nSize: {} bytes\nSHA-256: {}\n\
         This package is not free software or needs your consent to its licence. Answering yes gives your \
         consent to download it from the address above and install it into this app's Wine prefix under that \
         licence.{installer}",
        esc(&pkg.id),
        esc(&pkg.version),
        esc(&pkg.licence),
        esc(&pkg.url),
        pkg.size,
        esc(&pkg.sha256)
    )
}

/// Escapes control and format characters without cutting (consent text must show the whole value).
fn esc(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || rt_core::is_format(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    fetch::hex(&Sha256::digest(bytes))
}

// ------------------------------------------------------------------------------------------------ planning

/// Plans `md`'s app against `manifest`. Never fails: an executable that cannot be read safely (missing, not a
/// regular file, a FIFO, a symlink, not a PE, over the size cap) gives a warning and a plan without imports.
/// Delay-load imports are included (a missed need is worse than an unused package).
pub fn plan_for_app(env: &AppEnv, md: &Metadata, manifest: &Manifest, vulkan: VulkanFor<'_>) -> AppPlan {
    let mut plan = plan_for_pe(md, read_exe(env, md).as_ref().map_err(String::as_str), manifest, vulkan);
    drop_present_installers(env, manifest, &mut plan);
    plan
}

/// Takes out of the plan every installer package (to install) whose marker is already in `env`'s prefix, with a
/// warning instead, so `deps`, the install hint and `doctor` stop asking for something the prefix has. Only reads
/// the marker (a file lookup or the bounded registry parse); a marker that cannot be read keeps the entry (the
/// install run checks again under its lock). The resolver stays pure: this is a fact about the prefix.
pub fn drop_present_installers(env: &AppEnv, manifest: &Manifest, app: &mut AppPlan) {
    let present = |e: &crate::resolve::PlanEntry| {
        e.action == Action::Install
            && manifest.get(&e.package).is_some_and(|p| {
                p.kind == Kind::Installer && install_installer::marker_already_present(p, env).unwrap_or(false)
            })
    };
    let (gone, kept): (Vec<_>, Vec<_>) = app.plan.entries.drain(..).partition(|e| present(e));
    app.plan.entries = kept;
    for e in gone {
        app.warnings.push(line(&format!("{}: {MARKER_PRESENT}", e.package)));
    }
}

/// The host's Vulkan verdict for a minimum API version; asked lazily, once per distinct minimum (see
/// [`block_for_vulkan`]), so a caller can probe the host only when a package actually needs Vulkan.
pub type VulkanFor<'a> = &'a dyn Fn(Option<(u32, u32)>) -> VulkanVerdict;

/// [`plan_for_app`] for a caller that already analysed the app's executable (`doctor`), so it is not read twice.
/// `Err` is why it could not be read, shown in the warning. Packages that need a Vulkan the host lacks are
/// `Blocked` (see [`block_for_vulkan`]).
pub fn plan_for_pe(
    md: &Metadata,
    exe: Result<&pe::PeInfo, &str>,
    manifest: &Manifest,
    vulkan: VulkanFor<'_>,
) -> AppPlan {
    let mut warnings = Vec::new();
    let mut facts = Facts::default();
    let mut arch = md.architecture.clone();
    match exe {
        Ok(info) => {
            facts.imports = info.imports.iter().map(|i| i.dll.clone()).collect();
            arch = match info.arch {
                pe::Arch::X86 => "x86".into(),
                _ => "x86_64".into(),
            };
        }
        Err(why) => warnings.push(line(&format!(
            "cannot read the app's executable ({why}); the plan does not include what it imports"
        ))),
    }
    let mut plan = resolve(&facts, &state::installed_set(md), &[], manifest);
    block_for_vulkan(&mut plan, manifest, vulkan);
    if arch == "x86" {
        for e in &plan.entries {
            if let Some(p) = manifest.get(&e.package)
                && p.provides.iter().any(|c| X64_ONLY_CAPS.contains(&c.as_str()))
            {
                warnings.push(line(&format!(
                    "{} is installed for 64-bit only; a 32-bit app keeps using Wine's builtin DLL",
                    p.id
                )));
            }
        }
    }
    for cap in &plan.unsatisfied {
        warnings.push(line(&format!(
            "the app needs {cap:?}, which no available package provides"
        )));
    }
    AppPlan { facts, plan, warnings }
}

/// The app's executable, contained in `drive_c` with no symlink anywhere, read with `read_input`'s discipline.
fn read_exe(env: &AppEnv, md: &Metadata) -> Result<pe::PeInfo, String> {
    let wp = WinPath::parse(&md.executable).map_err(|e| e.to_string())?;
    let path = resolve_under(&env.drive_c(), &wp).map_err(|e| e.to_string())?;
    match read_input(&path).map_err(|e| e.to_string())? {
        Input::Pe(bytes) => pe::analyze(&bytes).map_err(|e| e.to_string()),
        Input::Zip(_) => Err("not a PE file".into()),
    }
}

// ------------------------------------------------------------------------------------------------ run guards

/// Holds the app's dependency lock; released on drop (or process exit).
#[derive(Debug)]
pub struct AppLock(File);

impl Drop for AppLock {
    /// Unlocks explicitly: closing the fd alone does not release a flock while another reference to the same open
    /// file description exists, e.g. a child another thread forked and has not yet exec'd (O_CLOEXEC only closes
    /// it at exec).
    fn drop(&mut self) {
        // SAFETY: flock on a file descriptor we own; no memory is passed.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Takes `<app root>/deps.lock` exclusively without waiting. The file is created 0600 and never followed if it
/// is a symlink; the fd is close-on-exec, so no child (a Wine program, an installer) inherits the lock.
pub fn lock_app(env: &AppEnv) -> Result<AppLock, DepsError> {
    lock_app_as(env, libc::LOCK_EX)
}

/// [`lock_app`] in shared mode: any number of shared holders (apps being started) at once, but never alongside an
/// exclusive holder (a dependency install or a removal).
pub fn lock_app_shared(env: &AppEnv) -> Result<AppLock, DepsError> {
    lock_app_as(env, libc::LOCK_SH)
}

fn lock_app_as(env: &AppEnv, mode: libc::c_int) -> Result<AppLock, DepsError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(env.root().join(LOCK_FILE))
        .map_err(|e| match e.raw_os_error() {
            // O_NOFOLLOW on a symlink; a directory opened for writing.
            Some(libc::ELOOP | libc::EISDIR) => DepsError::LockFileUnusable(e.to_string()),
            _ => e.into(),
        })?;
    if !file.metadata()?.is_file() {
        return Err(DepsError::LockFileUnusable("not a regular file".into()));
    }
    // SAFETY: flock on a file descriptor we own; no memory is passed.
    if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
        return Err(flock_error(io::Error::last_os_error()));
    }
    Ok(AppLock(file))
}

/// A failed non-blocking `flock`: held by someone else, unsupported by the file system, or another I/O error.
fn flock_error(e: io::Error) -> DepsError {
    match e.raw_os_error() {
        Some(libc::EWOULDBLOCK) => DepsError::LockHeld,
        Some(libc::ENOLCK | libc::EOPNOTSUPP | libc::ENOSYS) => DepsError::LockUnsupported(e.to_string()),
        _ => e.into(),
    }
}

/// How a `wineserver` for one prefix is recognised: by `WINEPREFIX` spelled as the runtime spells it (the backend
/// sets exactly `env.prefix()`), or by its working directory, which Wine names after the prefix's device and inode
/// (so any other spelling, e.g. through a symlink, is caught too).
struct Target {
    /// `WINEPREFIX` values meaning the prefix (as given and canonical), without trailing slashes.
    spellings: Vec<Vec<u8>>,
    /// `server-<dev>-<ino>` of the prefix: Wine's name for the server directory, the wineserver's cwd.
    server_dir: Option<String>,
}

fn trim_slashes(b: &[u8]) -> &[u8] {
    let mut b = b;
    while b.len() > 1 && b.ends_with(b"/") {
        b = &b[..b.len() - 1];
    }
    b
}

impl Target {
    fn of(prefix: &Path) -> Target {
        let mut spellings = vec![trim_slashes(prefix.as_os_str().as_bytes()).to_vec()];
        if let Ok(c) = fs::canonicalize(prefix) {
            spellings.push(trim_slashes(c.as_os_str().as_bytes()).to_vec());
        }
        let server_dir = fs::metadata(prefix)
            .ok()
            .map(|m| format!("server-{:x}-{:x}", m.dev(), m.ino()));
        Target { spellings, server_dir }
    }

    /// Whether a process with this (possibly truncated) environment block and working directory serves the prefix.
    fn serves(&self, environ: Option<&[u8]>, cwd: Option<&Path>) -> bool {
        let by_env = environ.is_some_and(|e| {
            e.split(|&b| b == 0)
                .filter_map(|v| v.strip_prefix(b"WINEPREFIX="))
                .any(|v| self.spellings.iter().any(|s| s.as_slice() == trim_slashes(v)))
        });
        let by_cwd = cwd
            .and_then(Path::file_name)
            .is_some_and(|n| self.server_dir.as_deref().is_some_and(|d| n.as_bytes() == d.as_bytes()));
        by_env || by_cwd
    }
}

/// A `wineserver*` executable (also `wineserver64`, or a deleted binary), by `/proc/<pid>/exe` or `comm`.
fn is_wineserver(exe: Option<&Path>, comm: Option<&[u8]>) -> bool {
    exe.and_then(Path::file_name)
        .is_some_and(|n| n.as_bytes().starts_with(b"wineserver"))
        || comm.is_some_and(|c| c.starts_with(b"wineserver"))
}

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path).ok()?.take(max).read_to_end(&mut out).ok()?;
    Some(out)
}

/// The pids of `wineserver` processes serving `prefix`, from `/proc`. A process whose entries cannot be read (it
/// exited, or belongs to another user) does not match: another user's wineserver cannot serve this user's prefix
/// (Wine keeps the server socket in a per-uid directory). Only an unreadable `/proc` itself is an error.
pub fn wineservers_for(prefix: &Path) -> io::Result<Vec<u32>> {
    let target = Target::of(prefix);
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let dir = entry.path();
        let exe = fs::read_link(dir.join("exe")).ok();
        let comm = read_bounded(&dir.join("comm"), 64);
        if !is_wineserver(exe.as_deref(), comm.as_deref()) {
            continue;
        }
        let environ = read_bounded(&dir.join("environ"), MAX_ENVIRON);
        let cwd = fs::read_link(dir.join("cwd")).ok();
        if target.serves(environ.as_deref(), cwd.as_deref()) {
            found.push(pid);
        }
    }
    found.sort_unstable();
    Ok(found)
}

fn check_not_busy(env: &AppEnv) -> Result<(), DepsError> {
    let pids = wineservers_for(&env.prefix())?;
    if pids.is_empty() {
        Ok(())
    } else {
        Err(DepsError::PrefixBusy { pids })
    }
}

// ------------------------------------------------------------------------------------------------ installing

/// Installs what `app`'s plan needs, behind consent (see the module docs). `Err` only for run-level refusals.
pub fn install_plan(o: &Orchestrator, app: &AppPlan) -> Result<RunReport, DepsError> {
    if !has_install(&app.plan) {
        return Ok(execute(o, &app.plan, &Decisions::default(), &[]));
    }
    let _lock = lock_app(o.env)?;
    check_not_busy(o.env)?;
    let md = o.store.read_metadata(o.env).map_err(DepsError::Metadata)?;
    let installed = state::installed_set(&md);
    let mut first = resolve(&app.facts, &installed, &[], o.manifest);
    block_for_vulkan(&mut first, o.manifest, o.vulkan);
    let d = decide(o, &md, &first);
    let mut plan = resolve(&app.facts, &installed, &d.denied, o.manifest);
    block_for_vulkan(&mut plan, o.manifest, o.vulkan);
    Ok(execute(o, &plan, &d, &md.dependencies))
}

fn has_install(plan: &Plan) -> bool {
    plan.entries.iter().any(|e| e.action == Action::Install)
}

/// The up-front decisions of a run.
#[derive(Default)]
struct Decisions {
    /// Consent denied or upgrade refused: re-resolved as denied, so they and their dependents are `Blocked`.
    denied: Vec<String>,
    /// The consent to record for each authorised consent-gated package.
    consents: HashMap<String, ConsentRecord>,
    /// Refused upgrades and the reason reported for them.
    refused: HashMap<String, String>,
    /// Installer packages whose marker is already in the prefix: skipped with [`MARKER_PRESENT`].
    present: HashSet<String>,
}

fn upgrade_reason(installed: &str, planned: &str) -> String {
    format!(
        "version {} is installed; upgrading installed packages is not supported yet: recreate the environment to \
         get version {}",
        manifest::clip(installed),
        manifest::clip(planned)
    )
}

/// Recorded consent that still counts for `pkg`: same version, and given to exactly the current [`consent_text`]
/// (`hash`). Unreachable from [`install_plan`] while upgrades are refused (see the module docs).
fn reusable_consent(md: &Metadata, pkg: &Package, hash: &str) -> Option<ConsentRecord> {
    state::consent_of(md, &pkg.id, &pkg.version)
        .filter(|c| c.licence_text_sha256 == hash)
        .cloned()
}

/// Decides every `Install` entry before anything is downloaded: refused upgrades, then consent.
fn decide(o: &Orchestrator, md: &Metadata, plan: &Plan) -> Decisions {
    let mut d = Decisions::default();
    // Denied, refused, or needing one of those: never asked about (the re-resolve blocks it).
    let mut out: HashSet<&str> = HashSet::new();
    for e in plan.entries.iter().filter(|e| e.action == Action::Install) {
        let Some(pkg) = o.manifest.get(&e.package) else {
            continue;
        };
        if pkg.requires.iter().any(|r| out.contains(r.as_str())) {
            out.insert(&e.package);
            continue;
        }
        if let Some(rec) = md.dependencies.iter().find(|r| r.id == pkg.id) {
            d.refused
                .insert(pkg.id.clone(), upgrade_reason(&rec.version, &pkg.version));
            d.denied.push(pkg.id.clone());
            out.insert(&e.package);
            continue;
        }
        // Before any prompt (and so before any download): the component may be there already. An unreadable
        // marker is left to the install step, which reports it.
        if pkg.kind == Kind::Installer && install_installer::marker_already_present(pkg, o.env).unwrap_or(false) {
            d.present.insert(pkg.id.clone());
            continue;
        }
        if !pkg.requires_consent {
            continue;
        }
        let text = consent_text(pkg);
        let hash = sha256_hex(text.as_bytes());
        let given = reusable_consent(md, pkg, &hash).or_else(|| {
            o.consent.confirm(pkg, &text).then(|| ConsentRecord {
                given_at: (o.now)(),
                licence_text_sha256: hash,
            })
        });
        match given {
            Some(c) => {
                d.consents.insert(pkg.id.clone(), c);
            }
            None => {
                d.denied.push(pkg.id.clone());
                out.insert(&e.package);
            }
        }
    }
    d
}

fn execute(o: &Orchestrator, plan: &Plan, d: &Decisions, recorded: &[DependencyRecord]) -> RunReport {
    let mut report = RunReport::default();
    let mut stopped = false;
    for e in &plan.entries {
        let id = e.package.clone();
        match &e.action {
            Action::AlreadyInstalled => report.skipped.push((id, ALREADY_INSTALLED.into())),
            Action::Blocked { reason } => {
                let why = d.refused.get(&id).unwrap_or(reason);
                report.skipped.push((id, line(why)));
            }
            Action::Install if d.present.contains(&id) => report.skipped.push((id, MARKER_PRESENT.into())),
            Action::Install if stopped => report
                .skipped
                .push((id, "not attempted: an earlier package failed".into())),
            Action::Install => match install_one(o, &e.package, &d.consents, recorded) {
                Ok(None) => report.skipped.push((id, MARKER_PRESENT.into())),
                Ok(Some(warnings)) => {
                    report.warnings.extend(warnings.iter().map(|w| (id.clone(), line(w))));
                    report.completed.push(id);
                }
                Err(why) => {
                    report.failed.push((id, line(&why)));
                    stopped = true;
                }
            },
        }
    }
    report
}

/// Fetch, install and record one package; the error is the report reason. `Ok(None)`: an installer package whose
/// marker is already in the prefix (nothing fetched, run or recorded).
fn install_one(
    o: &Orchestrator,
    id: &str,
    consents: &HashMap<String, ConsentRecord>,
    recorded: &[DependencyRecord],
) -> Result<Option<Vec<String>>, String> {
    let pkg = o.manifest.get(id).ok_or("not in the manifest")?;
    // Defence in depth: `decide` already refused every recorded package (no upgrades, Ruling 13).
    if let Some(rec) = recorded.iter().find(|r| r.id == pkg.id) {
        return Err(upgrade_reason(&rec.version, &pkg.version));
    }
    let consent = consents.get(id).cloned();
    // Defence in depth: the re-resolve already blocks every gated package without consent.
    if pkg.requires_consent && consent.is_none() {
        return Err("consent missing; nothing was downloaded".into());
    }
    if !manifest::valid_sha256(&pkg.sha256) {
        return Err("the manifest's sha256 for this package is malformed; nothing was downloaded".into());
    }
    // Before the download (saves it) and again right before installing: an app may start while it downloads.
    not_busy_now(o)?;
    // Under the lock, the prefix idle: an installer whose marker is there already has nothing to do (Ruling 15).
    if pkg.kind == Kind::Installer
        && install_installer::marker_already_present(pkg, o.env).map_err(|e| {
            format!("cannot check whether it is already in the prefix ({e}); nothing was downloaded or run")
        })?
    {
        return Ok(None);
    }
    let file = o
        .fetcher
        .fetch(pkg, o.cache_dir)
        .map_err(|e| format!("download failed: {e}"))?;
    not_busy_now(o)?;
    let warnings = match pkg.kind {
        Kind::Archive => install_archive::install_archive(pkg, &file, o.env, o.backend, o.launcher)
            .map(|_| Vec::new())
            .map_err(|e| archive_reason(e, o.env.id().as_str(), &pkg.id))?,
        Kind::Installer => match install_installer::install_installer_pkg(pkg, &file, o.env, o.backend, o.launcher) {
            Ok(done) => {
                let mut w = done.warnings;
                if !done.staged_removed {
                    w.push("the staged installer copy could not be removed from windows\\temp".into());
                }
                w
            }
            // Present by now although it was not a moment ago: still nothing of ours to record.
            Err(InstallerPkgError::MarkerAlreadyPresent) => return Ok(None),
            Err(e) => return Err(installer_reason(e)),
        },
    };
    record(o, pkg, consent).map_err(|e| {
        format!(
            "installed but not recorded ({e}); the runtime does not count it as installed, and installing it \
             again may be refused: recreate the environment if that happens"
        )
    })?;
    Ok(Some(warnings))
}

/// No `wineserver` serves the prefix at this moment; the error is the report reason (nothing was installed).
fn not_busy_now(o: &Orchestrator) -> Result<(), String> {
    match wineservers_for(&o.env.prefix()) {
        Ok(pids) if pids.is_empty() => Ok(()),
        Ok(_) => Err(
            "not installed: a Wine program is now running in this app's prefix; close the app first, \
                      then install again"
                .into(),
        ),
        Err(e) => Err(format!("not installed: cannot check for running Wine programs: {e}")),
    }
}

/// Records `pkg` in the app's metadata: read, edit, atomic write. Only called after the installer returned `Ok`.
fn record(o: &Orchestrator, pkg: &Package, consent: Option<ConsentRecord>) -> Result<(), String> {
    let mut md = o.store.read_metadata(o.env).map_err(|e| e.to_string())?;
    state::record(
        &mut md,
        DependencyRecord {
            id: pkg.id.clone(),
            version: pkg.version.clone(),
            sha256: pkg.sha256.clone(),
            installed_at: (o.now)(),
            consent,
        },
    )
    .map_err(|e| e.to_string())?;
    o.store.write_metadata(o.env, &md).map_err(|e| e.to_string())
}

fn archive_reason(e: ArchiveError, app: &str, pkg: &str) -> String {
    match e {
        ArchiveError::Journal(_) => format!(
            "{e}; nothing was installed. If this package is not recorded as installed, an earlier install of it \
             was interrupted: discard what that left with `runtime deps {app} --discard-interrupted {pkg}`, then \
             install again"
        ),
        other => other.to_string(),
    }
}

/// Every installer error that can come after the vendor code ran carries [`VENDOR_PARTIAL`]; a marker already
/// present is [`MARKER_PRESENT`] (the installer never ran, and the package is never recorded).
fn installer_reason(e: InstallerPkgError) -> String {
    use InstallerPkgError as E;
    match e {
        E::MarkerAlreadyPresent => MARKER_PRESENT.into(),
        E::NotInstallerKind
        | E::BadPackage(_)
        | E::Stage(_)
        | E::BwrapNotFound
        | E::BadSilentArg(_)
        | E::MsiExecMissing
        | E::ExplorerMissing => e.to_string(),
        E::Sandbox(_)
        | E::MarkerMissing
        | E::NonZeroAndNoMarker { .. }
        | E::Registry(_)
        | E::Io(_)
        | E::TimedOut { .. }
        | E::Marker(_)
        | E::DllOverride(_) => format!("{}; {VENDOR_PARTIAL}", line(&e.to_string())),
    }
}

/// [`install_archive::discard_interrupted`] behind the run guards, for the CLI to offer after a journal error:
/// holds `deps.lock` for the whole call (a running install's live journal is never adopted), refuses under a
/// running app, and refuses a package the metadata records (discarding would undo a recorded install while the
/// record stays).
pub fn discard_interrupted_for(store: &Store, env: &AppEnv, pkg_id: &str) -> Result<DiscardReport, DepsError> {
    let _lock = lock_app(env)?;
    check_not_busy(env)?;
    let md = store.read_metadata(env).map_err(DepsError::Metadata)?;
    if md.dependencies.iter().any(|d| d.id == pkg_id) {
        return Err(DepsError::Recorded(manifest::clip(pkg_id)));
    }
    install_archive::discard_interrupted(pkg_id, env).map_err(DepsError::Discard)
}

#[cfg(test)]
mod tests;
