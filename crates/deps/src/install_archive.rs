//! Installs an `archive` package: copies the files its manifest entry declares from a hash-verified zip or tar.gz
//! into the app's `drive_c`, sets its DLL overrides, and undoes all of that on failure or on removal.
//!
//! The archive's hash was verified by `fetch`, but its CONTENTS are treated as hostile: names, sizes, modes and
//! counts come from the zip planner ([`rt_core::unzip::open`]) and the bounded tar reader ([`crate::tarball`]),
//! and every destination is mapped onto `drive_c` again here.
//!
//! **`extract` semantics.** `from` is the FULL path inside the archive, `/`-separated, exactly as the archive
//! spells it (case-sensitive; a zip's `\` separators and `.` components are normalised by the planner first). No
//! wrapper directory is stripped: for `dxvk-2.4/x64/d3d11.dll` the manifest says exactly that.
//! * `from` without a trailing `/` selects the ONE regular file with that path; `to` is the destination FILE.
//! * `from` ending in `/` selects every regular file below that directory (at any depth); `to` is a destination
//!   DIRECTORY and each file lands at `to/<rest of its path>`.
//! * Directory entries are never selected; directories are created only as parents of selected files.
//! * An `extract` entry that selects nothing is [`ArchiveError::NoMatch`] (a package whose declared files are
//!   missing must not report success). A file selected by two `extract` entries, and two files mapped to the
//!   same destination (compared case-insensitively, as Wine does; this includes a selected path that occurs twice
//!   in the archive) are [`ArchiveError::Destination`]. All of this is decided BEFORE anything is written: a zip is planned from
//!   its central directory, a tar.gz is read twice (a first pass that writes nothing validates the whole archive
//!   and lists its files; the second pass writes, and must see the same file list).
//! * Everything not selected is never written.
//!
//! **Writing.** A destination is `C:\<to...>` parsed by [`WinPath`] (reserved names, `..`, streams, trailing dots
//! and over-long components are refused) and mapped with [`join_new`] under `drive_c`: existing components are
//! reused case-insensitively and may not be symlinks. Missing parent directories are created one by one (`0755`)
//! and recorded. The destination must be absent or a regular file; a directory, a symlink or anything else is
//! refused. The data goes to a temporary file in the destination's directory (`O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`),
//! is fsynced, chmodded to `0644` (never the archive's mode bits: no setuid, no exec) and renamed over the
//! destination, so a killed process never leaves a half-written destination (at worst a `.rt-deps-*.tmp` file;
//! on an error or unwind the temporary file is removed).
//!
//! **Replaced files.** Wine ships builtin placeholder DLLs, so a destination may already be a regular file. Its
//! original is first copied (same temp + rename discipline, `0600`) to `<app root>/deps-backup/<package id>/<path
//! relative to drive_c>` (directories `0700`; outside the prefix, so nothing running in the prefix can reach it).
//! A backup that already exists there is KEPT, not overwritten: it can only be the original saved by an earlier
//! install of the same package that was killed before it was recorded, and the file now at the destination may
//! be that install's copy. Restoring copies the backup back (temp + rename, `0644`: the original's mode is not
//! kept), deletes it and prunes empty backup directories up to `deps-backup`.
//!
//! **Failure.** On any error [`install_archive`] undoes exactly what the call did (overrides deleted newest
//! first, new files deleted, replaced files restored, created directories removed when empty) and returns the
//! ORIGINAL error; if undoing fails too, the result is [`ArchiveError::Rollback`] carrying both. A process that is
//! KILLED mid-install cannot roll back: earlier files (and backups) stay. That is why the caller records a package
//! in the app's state only after `install_archive` returned `Ok`, and why a stale backup is kept (see above).
//!
//! **DLL overrides** (ledger Ruling 2). Each name must be in the package's `provides` (checked again here) and
//! match `[a-z0-9_]{1,32}` before it is used, and then only as ONE argv element (never shell text). The value is
//! written by Wine's own `reg.exe` in the prefix, run through the backend:
//! `reg add HKCU\Software\Wine\DllOverrides /v <name> /d native,builtin /f`, wrapped by
//! [`CompatBackend::settle`] (so `wineserver` has flushed `user.reg` before the call returns) and run by
//! [`Launcher::run_helper`] with a deadline; a non-zero exit is [`ArchiveError::Registry`]. Removal runs
//! `reg delete ... /v <name> /f`; if that fails, `reg query ... /v <name>` decides whether the value is already
//! gone (then it is not an error, so removal can be retried). Verified on real Wine 10.0 by the ignored test
//! `e2e_real_wine_zip_and_tar_gz_with_a_dll_override`: `reg.exe` exists in a fresh prefix, the value is in
//! `user.reg` once the settled command returns, and `reg delete` removes it. The `user.reg` writer the ruling
//! also allowed was therefore not needed.
//!
//! **Recording.** [`ArchiveInstalled`] is (de)serialisable so the caller can persist it; [`remove_archive`]
//! re-validates every recorded path and name (and the list sizes) before touching anything, since a recorded
//! state file is not trusted either.
//!
//! **Not covered** (as for `rt_core::unzip` and `winpath`): a process that can write inside `drive_c` WHILE this
//! runs could swap a checked directory for a symlink. Callers install only while no Windows program runs in the
//! prefix; Phase 5's sandbox is the real boundary.
use crate::manifest::{self, ArchiveFormat, Extract, Install, Kind, MAX_LIST_LEN, MAX_PACKAGE_SIZE, Package, clip};
use crate::tarball::{self, Selection, TarEntryKind, TarError, TarLimits};
use rt_core::unzip;
use rt_core::{AppEnv, CompatBackend, Detail, Launcher, ResolveError, RunOpts, WinPath, join_new, resolve_under};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Directory under the app root that holds the originals of replaced files, per package id.
pub const BACKUP_DIR: &str = "deps-backup";
/// Where Wine reads per-DLL load order.
pub const OVERRIDES_KEY: &str = r"HKCU\Software\Wine\DllOverrides";
/// Deadline of one `reg.exe` run (including the settle wait for `wineserver`).
const REG_TIMEOUT: Duration = Duration::from_secs(60);
/// Most entries in a zip, and most recorded files or directories in an [`ArchiveInstalled`].
const MAX_ENTRIES: usize = 4096;
/// Most bytes a zip may expand to (also bounded by 200 x its size).
const MAX_EXPANDED: u64 = 2 << 30;
const MAX_RATIO: u64 = 200;
const MAX_OVERRIDE_LEN: usize = 32;
/// Most rollback failures quoted in an error.
const MAX_REPORTED: usize = 5;

/// What one [`install_archive`] call put into the prefix: exactly what [`remove_archive`] takes away again. Paths
/// are relative to `drive_c`, with the real on-disk spelling of existing components.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInstalled {
    /// Every file this package wrote, in the order written.
    pub files: Vec<PathBuf>,
    /// The subset of `files` that existed before and whose original is in the backup directory.
    pub replaced: Vec<PathBuf>,
    /// Directories this call created, parents first.
    pub created_dirs: Vec<PathBuf>,
    /// DLL overrides this call set.
    pub overrides: Vec<String>,
}

/// Error texts carry untrusted names only clipped and `Debug`-escaped.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("unusable zip archive: {0}")]
    Zip(String),
    #[error("unusable tar.gz archive: {0}")]
    Tar(#[source] TarError),
    #[error("extract entry {0:?} matches no file in the archive")]
    NoMatch(String),
    #[error("cannot install a file: {0}")]
    Destination(String),
    #[error("dll override {0:?} is not in the package's provides list")]
    NotInProvides(String),
    #[error("invalid dll override name {0:?} (lowercase letters, digits and _ only, at most 32, no duplicates)")]
    BadOverrideName(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("setting a dll override failed: {0}")]
    Registry(String),
    #[error("{0}")]
    Rollback(String),
    #[error("unusable package or record: {0}")]
    BadPackage(String),
}

/// Installs `pkg` (an archive package) from `file`, the verified download, into `env`'s `drive_c`. See the module
/// docs. `file` is only ever opened read-only.
pub fn install_archive(
    pkg: &Package,
    file: &Path,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<ArchiveInstalled, ArchiveError> {
    let (format, extract, overrides) = check_package(pkg)?;
    check_overrides(overrides, Some(&pkg.provides))?;
    let src = open_archive(file, pkg.size)?;
    let mut ledger = Ledger::new(env, &pkg.id);
    let result = (|| {
        match format {
            ArchiveFormat::Zip => install_zip(&src, pkg.size, extract, &mut ledger)?,
            ArchiveFormat::TarGz => install_tar(&src, pkg.size, extract, &mut ledger)?,
        }
        for name in overrides {
            // Recorded first: a `reg add` that fails may still have written the value, and deleting an absent
            // value is not an error (see `delete_override`).
            ledger.done.overrides.push(name.clone());
            set_override(name, env, backend, launcher)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(ledger.done),
        Err(original) => {
            let failures = ledger.undo(env, backend, launcher);
            Err(if failures.is_empty() {
                original
            } else {
                rollback_error(&original, &failures)
            })
        }
    }
}

/// Removes what `installed` records for package `pkg_id`: deletes the overrides, deletes exactly the recorded new
/// files, restores replaced originals from the backup directory (then deletes the backups) and removes the
/// recorded directories that are empty. Files and directories already gone are fine, so it can be retried. The
/// record is validated first; on failures the first one is returned after everything else was attempted.
pub fn remove_archive(
    installed: &ArchiveInstalled,
    pkg_id: &str,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<(), ArchiveError> {
    if !manifest::valid_id(pkg_id) {
        return Err(ArchiveError::BadPackage(format!(
            "invalid package id {:?}",
            clip(pkg_id)
        )));
    }
    check_record(installed)?;
    let mut ledger = Ledger::new(env, pkg_id);
    ledger.done = installed.clone();
    // A record may list directories in any order: children first.
    ledger.done.created_dirs.sort_by_key(|d| d.components().count());
    match ledger.undo(env, backend, launcher).into_iter().next() {
        Some(first) => Err(first),
        None => Ok(()),
    }
}

// ------------------------------------------------------------------------------------------------ validation

fn bad_package(pkg: &Package, why: &str) -> ArchiveError {
    ArchiveError::BadPackage(format!("package {:?}: {why}", clip(&pkg.id)))
}

/// The manifest checks that containment relies on, again: the `Package` fields are public.
fn check_package(pkg: &Package) -> Result<(ArchiveFormat, &[Extract], &[String]), ArchiveError> {
    let Install::Archive {
        format,
        extract,
        dll_overrides,
    } = &pkg.install
    else {
        return Err(bad_package(pkg, "not an archive package"));
    };
    if pkg.kind != Kind::Archive {
        return Err(bad_package(pkg, "not an archive package"));
    }
    if !manifest::valid_id(&pkg.id) {
        return Err(bad_package(pkg, "invalid id"));
    }
    if !manifest::valid_sha256(&pkg.sha256) {
        return Err(bad_package(pkg, "invalid sha256"));
    }
    if pkg.size == 0 || pkg.size > MAX_PACKAGE_SIZE {
        return Err(bad_package(pkg, "invalid size"));
    }
    if extract.is_empty() || extract.len() > MAX_LIST_LEN {
        return Err(bad_package(pkg, "extract must have 1 to 64 entries"));
    }
    for e in extract {
        let from = e.from.strip_suffix('/').unwrap_or(&e.from);
        if manifest::check_rel_path(from).is_err() || manifest::check_rel_path(&e.to).is_err() {
            return Err(bad_package(
                pkg,
                &format!("unsafe extract entry {:?} -> {:?}", clip(&e.from), clip(&e.to)),
            ));
        }
    }
    Ok((*format, extract, dll_overrides))
}

/// `[a-z0-9_]{1,32}`: safe as one argv element of `reg.exe` and as a registry value name.
fn valid_override(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_OVERRIDE_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Every name valid and unique; with `provides`, every name also in it.
fn check_overrides(names: &[String], provides: Option<&[String]>) -> Result<(), ArchiveError> {
    if names.len() > MAX_LIST_LEN {
        return Err(ArchiveError::BadOverrideName(format!("({} names)", names.len())));
    }
    let mut seen: HashSet<&String> = HashSet::new();
    for name in names {
        if !valid_override(name) || !seen.insert(name) {
            return Err(ArchiveError::BadOverrideName(clip(name)));
        }
        if provides.is_some_and(|p| !p.contains(name)) {
            return Err(ArchiveError::NotInProvides(clip(name)));
        }
    }
    Ok(())
}

/// A recorded install is re-validated before [`remove_archive`] acts on it.
fn check_record(r: &ArchiveInstalled) -> Result<(), ArchiveError> {
    let bad = |why: String| ArchiveError::BadPackage(format!("recorded install: {why}"));
    if r.files.len() > MAX_ENTRIES || r.created_dirs.len() > MAX_ENTRIES || r.replaced.len() > r.files.len() {
        return Err(bad("too many entries".into()));
    }
    for p in r.files.iter().chain(&r.created_dirs) {
        win_path(p).map_err(|_| bad(format!("unsafe path {:?}", clip(&p.to_string_lossy()))))?;
    }
    if let Some(p) = r.replaced.iter().find(|p| !r.files.contains(p)) {
        return Err(bad(format!(
            "replaced {:?} is not a recorded file",
            clip(&p.to_string_lossy())
        )));
    }
    check_overrides(&r.overrides, None).map_err(|e| bad(e.to_string()))
}

/// A `drive_c`-relative path as a [`WinPath`]: plain UTF-8 components only, then the full Windows name rules.
fn win_path(rel: &Path) -> Result<WinPath, ArchiveError> {
    let bad = || ArchiveError::Destination(format!("unsafe path {:?}", clip(&rel.to_string_lossy())));
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str().ok_or_else(bad)?),
            _ => return Err(bad()),
        }
    }
    if parts.is_empty() {
        return Err(bad());
    }
    WinPath::parse(&format!("C:/{}", parts.join("/"))).map_err(|_| bad())
}

/// Opens the archive read-only without following a symlink, and checks it is the regular file `size` bytes long
/// that was verified (the same inode that `lstat` saw).
fn open_archive(file: &Path, size: u64) -> Result<File, ArchiveError> {
    let bad = |why: &str| ArchiveError::BadPackage(format!("archive {}: {why}", file.display()));
    let before = fs::symlink_metadata(file)?;
    if !before.file_type().is_file() {
        return Err(bad("not a regular file"));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)?;
    let m = f.metadata()?;
    if !m.file_type().is_file() || (m.dev(), m.ino()) != (before.dev(), before.ino()) {
        return Err(bad("changed while being opened"));
    }
    if m.len() != size {
        return Err(bad(&format!("is {} bytes, the package declares {size}", m.len())));
    }
    Ok(f)
}

// ------------------------------------------------------------------------------------------------ selection

/// Maps the archive's regular files (`/`-separated paths, archive order) onto destinations, see the module docs.
/// Returns `(index into files, destination)` in archive order.
fn map_files(extract: &[Extract], files: &[String]) -> Result<Vec<(usize, WinPath)>, ArchiveError> {
    let dest_err = |why: String| ArchiveError::Destination(why);
    let mut hit = vec![false; extract.len()];
    let mut dests: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for (i, path) in files.iter().enumerate() {
        let mut chosen = None;
        for (j, e) in extract.iter().enumerate() {
            let dest = if e.from.ends_with('/') {
                path.strip_prefix(e.from.as_str())
                    .map(|rest| format!("{}/{rest}", e.to))
            } else {
                (*path == e.from).then(|| e.to.clone())
            };
            let Some(dest) = dest else { continue };
            hit[j] = true;
            if chosen.replace(dest).is_some() {
                return Err(dest_err(format!("{:?} is selected by two extract entries", clip(path))));
            }
        }
        let Some(dest) = chosen else { continue };
        let win = WinPath::parse(&format!("C:/{dest}"))
            .map_err(|e| dest_err(format!("{:?} cannot be a Windows path: {e}", clip(&dest))))?;
        if !dests.insert(win.to_string().to_lowercase()) {
            return Err(dest_err(format!(
                "two archive files (or one path listed twice) map to {:?}",
                clip(&dest)
            )));
        }
        out.push((i, win));
    }
    if let Some(j) = hit.iter().position(|h| !h) {
        return Err(ArchiveError::NoMatch(clip(&extract[j].from)));
    }
    Ok(out)
}

fn install_zip(src: &File, size: u64, extract: &[Extract], ledger: &mut Ledger) -> Result<(), ArchiveError> {
    let cap = size.saturating_mul(MAX_RATIO).min(MAX_EXPANDED);
    let limits = unzip::Limits {
        max_entries: MAX_ENTRIES,
        max_dirs: MAX_ENTRIES,
        max_total_bytes: cap,
        max_entry_bytes: cap,
        max_ratio: MAX_RATIO,
        ..unzip::Limits::default()
    };
    let (mut archive, plan) = unzip::open(src.try_clone()?, &limits).map_err(|e| ArchiveError::Zip(e.to_string()))?;
    // The planner skips links and devices; a package archive has no business containing any.
    if plan.skipped > 0 {
        return Err(ArchiveError::Zip(format!(
            "{} entries are symbolic links, devices or other special files",
            plan.skipped
        )));
    }
    let names: Vec<String> = plan.files.iter().map(|f| f.path.join("/")).collect();
    for (i, dest) in map_files(extract, &names)? {
        let f = &plan.files[i];
        let mut entry = archive
            .by_index(f.index)
            .map_err(|e| ArchiveError::Zip(clip(&e.to_string())))?;
        ledger.write(&dest, &mut entry, f.size)?;
    }
    Ok(())
}

fn install_tar(src: &File, size: u64, extract: &[Extract], ledger: &mut Ledger) -> Result<(), ArchiveError> {
    let limits = TarLimits::for_package(size);
    let rewind = || (&*src).seek(SeekFrom::Start(0));
    // Pass 1: validate the whole archive and list its files; nothing is written.
    let mut files = Vec::new();
    rewind()?;
    tarball::walk(
        src,
        &limits,
        |e| {
            if e.kind == TarEntryKind::File {
                files.push(e.path.clone());
            }
            Selection::Skip
        },
        |_, _| Ok(()),
    )
    .map_err(ArchiveError::Tar)?;
    let map = map_files(extract, &files)?;
    // Pass 2: write the selected files. `next` numbers the file entries as pass 1 did.
    rewind()?;
    let (next, current, changed) = (Cell::new(0usize), Cell::new(0usize), Cell::new(false));
    let mut written = 0usize;
    let mut failure = None;
    let walked = tarball::walk(
        src,
        &limits,
        |e| {
            if e.kind != TarEntryKind::File {
                return Selection::Skip;
            }
            let i = next.replace(next.get() + 1);
            if files.get(i) != Some(&e.path) {
                changed.set(true);
                return Selection::Skip;
            }
            match map.binary_search_by_key(&i, |(k, _)| *k) {
                Ok(m) => {
                    current.set(m);
                    Selection::Take
                }
                Err(_) => Selection::Skip,
            }
        },
        |e, data| match ledger.write(&map[current.get()].1, data, e.size) {
            Ok(()) => {
                written += 1;
                Ok(())
            }
            Err(err) => {
                failure = Some(err);
                Err(TarError::Callback("writing a destination failed".into()))
            }
        },
    );
    match (walked, failure) {
        (Err(TarError::Callback(_)), Some(err)) => return Err(err),
        (Err(e), _) => return Err(ArchiveError::Tar(e)),
        (Ok(_), _) => {}
    }
    if changed.get() || written != map.len() {
        return Err(ArchiveError::Tar(TarError::BadHeader(
            "the archive changed while being read",
        )));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ writing

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Removes the temporary file unless disarmed (error or unwind before the rename).
struct TempFile(Option<PathBuf>);

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// Writes `src` to `dest` through a temporary file in the same directory, then renames it into place. With
/// `expect`, the source must yield exactly that many bytes (at most one more is read). Final mode: `mode`.
fn atomic_write(dest: &Path, src: &mut dyn Read, expect: Option<u64>, mode: u32) -> Result<(), ArchiveError> {
    let dir = dest
        .parent()
        .ok_or_else(|| ArchiveError::Destination(format!("{} has no parent", dest.display())))?;
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".rt-deps-{}-{n}.tmp", std::process::id()));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let mut guard = TempFile(Some(tmp));
    let copied = match expect {
        Some(size) => io::copy(&mut src.take(size.saturating_add(1)), &mut out)?,
        None => io::copy(src, &mut out)?,
    };
    if let Some(size) = expect
        && copied != size
    {
        return Err(ArchiveError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("an archive entry holds {copied} bytes or more but declares {size}"),
        )));
    }
    out.sync_all()?;
    out.set_permissions(Permissions::from_mode(mode))?;
    let tmp = guard.0.take().unwrap_or_default();
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Creates the missing directories of `base/rel` (with `mode`), refusing anything that is not a real directory.
/// Each created one is pushed to `created` (relative to `base`, parents first) as soon as it exists.
fn make_dirs(base: &Path, rel: &Path, mode: u32, created: &mut Vec<PathBuf>) -> Result<(), ArchiveError> {
    let mut cur = base.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ArchiveError::Destination(format!(
                    "{} is not a directory",
                    cur.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new().mode(mode).create(&cur)?;
                fs::set_permissions(&cur, Permissions::from_mode(mode))?;
                created.push(cur.strip_prefix(base).unwrap_or(&cur).to_path_buf());
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn resolve_err(what: &Path, e: ResolveError) -> ArchiveError {
    ArchiveError::Destination(format!("{:?}: {e}", clip(&what.to_string_lossy())))
}

/// What this call (or the recorded install) did, and how to undo it.
struct Ledger {
    drive_c: PathBuf,
    app_root: PathBuf,
    /// `deps-backup/<package id>`, relative to `app_root`.
    backups: PathBuf,
    done: ArchiveInstalled,
}

impl Ledger {
    fn new(env: &AppEnv, id: &str) -> Ledger {
        Ledger {
            drive_c: env.drive_c(),
            app_root: env.root().to_path_buf(),
            backups: Path::new(BACKUP_DIR).join(id),
            done: ArchiveInstalled::default(),
        }
    }

    /// Writes one selected file (see the module docs).
    fn write(&mut self, dest: &WinPath, src: &mut dyn Read, size: u64) -> Result<(), ArchiveError> {
        let path = join_new(&self.drive_c, dest).map_err(|e| resolve_err(Path::new(&dest.to_string()), e))?;
        let rel = path
            .strip_prefix(&self.drive_c)
            .map_err(|_| ArchiveError::Destination(format!("{dest} is outside drive_c")))?
            .to_path_buf();
        let parent = rel.parent().unwrap_or(Path::new(""));
        make_dirs(&self.drive_c, parent, 0o755, &mut self.done.created_dirs)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_file() => {
                self.backup(&rel, &path)?;
                self.done.replaced.push(rel.clone());
            }
            Ok(_) => {
                return Err(ArchiveError::Destination(format!(
                    "{:?} exists and is not a regular file",
                    clip(&rel.to_string_lossy())
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        atomic_write(&path, src, Some(size), 0o644)?;
        self.done.files.push(rel);
        Ok(())
    }

    /// Saves the original at `path` (relative `rel`) unless a backup is already there (module docs).
    fn backup(&self, rel: &Path, path: &Path) -> Result<(), ArchiveError> {
        let below_root = self.backups.join(rel);
        // Backup directories are not recorded: `restore` prunes them once empty.
        make_dirs(
            &self.app_root,
            below_root.parent().unwrap_or(&self.backups),
            0o700,
            &mut Vec::new(),
        )?;
        let target = self.app_root.join(below_root);
        match fs::symlink_metadata(&target) {
            Ok(m) if m.file_type().is_file() => return Ok(()),
            Ok(_) => {
                return Err(ArchiveError::Destination(format!(
                    "backup {} is not a file",
                    target.display()
                )));
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        let mut original = open_nofollow(path)?;
        atomic_write(&target, &mut original, None, 0o600)
    }

    /// Puts the backup of `rel` back and deletes it.
    fn restore(&self, rel: &Path) -> Result<(), ArchiveError> {
        // A missing backup (or a symlink in its place) fails the `O_NOFOLLOW` open below.
        let target = self.app_root.join(&self.backups).join(rel);
        let dir = match rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            None => self.drive_c.clone(),
            Some(parent) => self.resolve(parent)?.ok_or_else(|| {
                ArchiveError::Destination(format!("the directory of {:?} is gone", clip(&rel.to_string_lossy())))
            })?,
        };
        // `rename` replaces a file or a symlink itself (never its target) and fails on a directory.
        let dest = dir.join(rel.file_name().unwrap_or_default());
        atomic_write(&dest, &mut open_nofollow(&target)?, None, 0o644)?;
        fs::remove_file(&target)?;
        // Prune empty backup directories up to and including `deps-backup`.
        let top = self.app_root.join(BACKUP_DIR);
        let mut dir = target.parent();
        while let Some(d) = dir
            && d.starts_with(&top)
            && fs::remove_dir(d).is_ok()
        {
            dir = d.parent();
        }
        Ok(())
    }

    /// The host path of `rel` under `drive_c` through real directories only (no symlinks); `None` if it is gone.
    fn resolve(&self, rel: &Path) -> Result<Option<PathBuf>, ArchiveError> {
        match resolve_under(&self.drive_c, &win_path(rel)?) {
            Ok(p) => Ok(Some(p)),
            Err(ResolveError::NotFound) => Ok(None),
            Err(e) => Err(resolve_err(rel, e)),
        }
    }

    fn remove_file(&self, rel: &Path) -> Result<(), ArchiveError> {
        // `resolve` refuses symlinks; `remove_file` refuses directories.
        match self.resolve(rel)? {
            Some(p) => Ok(fs::remove_file(p)?),
            None => Ok(()),
        }
    }

    fn remove_dir(&self, rel: &Path) -> Result<(), ArchiveError> {
        let Some(p) = self.resolve(rel)? else {
            return Ok(());
        };
        match fs::remove_dir(&p) {
            Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY) || e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => Ok(other?),
        }
    }

    /// Undoes everything in `done`, continuing past failures; returns them.
    fn undo(&self, env: &AppEnv, backend: &dyn CompatBackend, launcher: &Launcher) -> Vec<ArchiveError> {
        let mut failures = Vec::new();
        let mut note = |r: Result<(), ArchiveError>| {
            if let Err(e) = r {
                failures.push(e);
            }
        };
        for name in self.done.overrides.iter().rev() {
            note(delete_override(name, env, backend, launcher));
        }
        for rel in self.done.files.iter().rev() {
            if !self.done.replaced.contains(rel) {
                note(self.remove_file(rel));
            }
        }
        for rel in self.done.replaced.iter().rev() {
            note(self.restore(rel));
        }
        for rel in self.done.created_dirs.iter().rev() {
            note(self.remove_dir(rel));
        }
        failures
    }
}

fn open_nofollow(p: &Path) -> Result<File, ArchiveError> {
    Ok(OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(p)?)
}

fn rollback_error(original: &ArchiveError, failures: &[ArchiveError]) -> ArchiveError {
    let shown: Vec<String> = failures
        .iter()
        .take(MAX_REPORTED)
        .map(|f| clip(&f.to_string()))
        .collect();
    let more = failures.len().saturating_sub(MAX_REPORTED);
    let more = if more > 0 {
        format!(" (and {more} more)")
    } else {
        String::new()
    };
    ArchiveError::Rollback(format!(
        "{original}; undoing the partial install also failed: {}{more}",
        shown.join("; ")
    ))
}

// ------------------------------------------------------------------------------------------------ registry

/// Runs Wine's `reg.exe` in the prefix with `args` (each one argv element), settled and bounded. Returns whether it
/// exited 0, and its output.
fn reg(
    args: &[&str],
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<(bool, String), ArchiveError> {
    let drive_c = env.drive_c();
    let exe = WinPath::parse(r"C:\windows\system32\reg.exe")
        .map_err(|e| ArchiveError::Registry(e.to_string()))
        .and_then(|w| resolve_under(&drive_c, &w).map_err(|e| ArchiveError::Registry(format!("reg.exe: {e}"))))?;
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let cmd = backend
        .command(env, &exe, &drive_c, &args, &RunOpts::default())
        .map_err(|e| ArchiveError::Registry(e.to_string()))?;
    let out = launcher
        .run_helper(backend.settle(cmd), REG_TIMEOUT)
        .map_err(|e| ArchiveError::Registry(e.to_string()))?;
    let detail = format!("{}: {}", out.status, Detail::from_bytes(&out.output).as_str().trim());
    Ok((out.status.success(), clip(&detail)))
}

fn set_override(
    name: &str,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<(), ArchiveError> {
    let (ok, detail) = reg(
        &["add", OVERRIDES_KEY, "/v", name, "/d", "native,builtin", "/f"],
        env,
        backend,
        launcher,
    )?;
    if ok {
        Ok(())
    } else {
        Err(ArchiveError::Registry(format!("reg add {name}: {detail}")))
    }
}

/// Deletes the override; a failed delete is fine if `reg query` then says the value does not exist.
fn delete_override(
    name: &str,
    env: &AppEnv,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
) -> Result<(), ArchiveError> {
    let (ok, detail) = reg(&["delete", OVERRIDES_KEY, "/v", name, "/f"], env, backend, launcher)?;
    if ok {
        return Ok(());
    }
    let (present, _) = reg(&["query", OVERRIDES_KEY, "/v", name], env, backend, launcher)?;
    if present {
        Err(ArchiveError::Registry(format!("reg delete {name}: {detail}")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
