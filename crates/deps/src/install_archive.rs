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
//!   in the archive) are [`ArchiveError::Destination`]. All of this is decided BEFORE anything is written: a zip
//!   is planned from its central directory, a tar.gz is read twice (a first pass that writes nothing validates the
//!   whole archive and lists its files; the second pass writes, and must see the same file list).
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
//! original is first copied (same temp + rename discipline, `0600`) to `<app root>/deps-backup/<package id>/c/<path
//! relative to drive_c>` (directories `0700`; outside the prefix, but NOT out of reach: Wine's `Z:` drive maps `/`,
//! so a program in the prefix running as the same user can reach it by path, like anything else of that user; the
//! Phase 5 sandbox is the real boundary).
//! A backup that already exists there is KEPT, not overwritten: only this package writes there, and only before
//! replacing a file it did not create, so it is the original saved by an earlier attempt that was killed, and the
//! file now at the destination may be that attempt's copy. Restoring copies the backup back (temp + rename,
//! `0644`: the original's mode is not kept), deletes it and prunes empty backup directories up to `deps-backup`.
//!
//! **Journal (interrupted installs).** Before the first write, `<app root>/deps-backup/<package id>/journal` is
//! created atomically (temp + fsync + rename, then the directory is fsynced) with the header
//! `rt-deps-journal 1 <package sha256>`. Before each directory it creates and each file it writes to an ABSENT
//! destination, and before each backup it creates, the install appends `D <path>` / `F <path>` / `R <path>`
//! (drive_c-relative) and fsyncs. So after a kill, every new file or directory and every replaced file that may
//! exist is listed. On the next install of the SAME archive (same sha256):
//! * a listed directory that exists is adopted into `created_dirs`;
//! * a listed file that exists is the killed attempt's own (`F` is only written for an absent destination): it is
//!   overwritten and recorded in
//!   `files`, never backed up and never in `replaced`;
//! * an existing file that is not listed is handled as above (backed up, or its kept backup reused);
//! * if the retry fails, its rollback also removes the listed files and directories and restores the listed
//!   replaced files it had not reached yet, so a fully rolled-back retry leaves the prefix as before the first
//!   attempt.
//!
//! * if the retry SUCCEEDS but selects less than the killed run wrote (the selection comes from the manifest's
//!   `extract`, which can change while the archive stays pinned), the listed files it did not write again are
//!   still recorded in `files` (and listed replaced ones in `replaced`), so [`remove_archive`] removes them too.
//!
//! The `F`/`D`/`R` entries are facts about the prefix, not about an archive. A journal written for a DIFFERENT
//! archive of the package (another sha256) is still [`ArchiveError::Journal`] for [`install_archive`]: the way out
//! is [`discard_interrupted`], which undoes exactly what the journal lists and deletes it. Calling
//! [`remove_archive`] with an empty record instead would delete the journal and make the next install back up the
//! killed run's files as originals, so it refuses (with [`ArchiveError::Journal`]) while a journal exists.
//!
//! The journal is read defensively (regular file only, `O_NOFOLLOW`, at most 4 MiB and 16384 entries, UTF-8, a
//! header naming a valid sha256, strict `F `/`D `/`R ` lines whose paths pass the same rules as a recorded
//! install); anything else is [`ArchiveError::Journal`], never ignored. One exception: a LAST line without its
//! newline is dropped, because it was being appended when the process died and the step it announced had not
//! started; before appending to such a journal, the torn tail is cut off (`ftruncate`), so reading and appending
//! agree. A torn HEADER cannot come from a crash (the journal is created atomically) and is an error. The journal
//! stays after a successful install (the caller may die before recording it) and is deleted by a successful
//! [`remove_archive`] and by a fully rolled-back install (which also removes what the killed attempt left).
//!
//! **Failure.** On any error [`install_archive`] undoes exactly what the call did (overrides deleted newest
//! first, new files deleted, replaced files restored, created directories removed when empty) and returns the
//! ORIGINAL error; if undoing fails too, the result is [`ArchiveError::Rollback`] carrying both. A process that is
//! KILLED mid-install cannot roll back: earlier files, backups and the journal stay, and the next install (or its
//! rollback) takes them over (see the journal). The caller records a package in the app's state only after
//! `install_archive` returned `Ok`.
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
/// The journal of an install, inside `deps-backup/<package id>/`, next to the `c/` backup tree.
const JOURNAL: &str = "journal";
const JOURNAL_MAGIC: &str = "rt-deps-journal 1";
const MAX_JOURNAL_BYTES: u64 = 4 << 20;
const MAX_JOURNAL_ENTRIES: usize = 4 * MAX_ENTRIES;
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
    #[error("unusable install journal: {0}")]
    Journal(String),
}

#[cfg(test)]
thread_local! {
    /// Test hook: simulate SIGKILL (a panic, so no rollback runs) after this many steps; see `crash_point`.
    pub(crate) static CRASH_AFTER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
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
    ledger.sha256.clone_from(&pkg.sha256);
    ledger.adopt()?;
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
        Ok(()) => {
            // The selection comes from the manifest, not the archive: a retry may select less than the killed run
            // wrote. Whatever it did not write again stays ours (the file on disk is the killed run's copy, the
            // backup the original), so it is recorded and `remove_archive` takes it away too.
            for f in &ledger.adopted {
                if !ledger.done.files.contains(f) {
                    ledger.done.files.push(f.clone());
                }
            }
            for r in &ledger.adopted_replaced {
                if !ledger.done.replaced.contains(r) {
                    ledger.done.replaced.push(r.clone());
                    ledger.done.files.push(r.clone());
                }
            }
            Ok(ledger.done)
        }
        Err(original) => {
            let mut failures = ledger.undo_overrides(env, backend, launcher);
            failures.extend(ledger.undo_files());
            if failures.is_empty()
                && let Err(e) = ledger.drop_journal()
            {
                failures.push(e);
            }
            Err(if failures.is_empty() {
                original
            } else {
                rollback_error(&original, &failures)
            })
        }
    }
}

/// What [`discard_interrupted`] undid. DLL overrides are not journaled, so it never touches the registry: an
/// override a killed install had already added stays (it is only a `native,builtin` load order; the next install
/// of the package sets it again and records it, so its removal deletes it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscardReport {
    /// Files the killed install had created, deleted.
    pub removed_files: Vec<PathBuf>,
    /// Files it had replaced, restored from their backups.
    pub restored: Vec<PathBuf>,
    /// Directories it had created, removed if empty.
    pub removed_dirs: Vec<PathBuf>,
}

/// Undoes what an interrupted install of package `pkg_id` left, as its journal lists it, WHATEVER archive it was
/// installing (the entries are facts about the prefix, not about an archive), then deletes the journal. This is the
/// way out when [`install_archive`] refuses because a journal of a different archive exists. No journal: nothing
/// to do. A corrupt journal is [`ArchiveError::Journal`] and is kept. On undo failures the first one is returned
/// and the journal is kept, so it can be retried.
pub fn discard_interrupted(pkg_id: &str, env: &AppEnv) -> Result<DiscardReport, ArchiveError> {
    if !manifest::valid_id(pkg_id) {
        return Err(ArchiveError::BadPackage(format!(
            "invalid package id {:?}",
            clip(pkg_id)
        )));
    }
    let mut ledger = Ledger::new(env, pkg_id);
    let Some(j) = read_journal(&ledger.journal_path(), None)? else {
        return Ok(DiscardReport::default());
    };
    ledger.adopt_entries(j)?;
    let report = DiscardReport {
        removed_files: ledger.adopted.clone(),
        restored: ledger.adopted_replaced.clone(),
        removed_dirs: ledger.done.created_dirs.clone(),
    };
    match ledger.undo_files().into_iter().next() {
        Some(first) => Err(first),
        None => ledger.drop_journal().map(|()| report),
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
    if installed.files.is_empty() && fs::symlink_metadata(ledger.journal_path()).is_ok() {
        return Err(ArchiveError::Journal(format!(
            "package {pkg_id:?} has an interrupted install; an empty record would drop its journal and leak it: use \
             discard_interrupted"
        )));
    }
    ledger.done = installed.clone();
    // A record may list directories in any order: children first.
    ledger.done.created_dirs.sort_by_key(|d| d.components().count());
    let mut failures = ledger.undo_overrides(env, backend, launcher);
    failures.extend(ledger.undo_files());
    match failures.into_iter().next() {
        Some(first) => Err(first),
        None => ledger.drop_journal(),
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
pub(crate) fn check_overrides(names: &[String], provides: Option<&[String]>) -> Result<(), ArchiveError> {
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
pub(crate) fn open_archive(file: &Path, size: u64) -> Result<File, ArchiveError> {
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
/// `announce` runs before each is created; each is pushed to `created` (relative to `base`, parents first) as soon
/// as it exists.
fn make_dirs(
    base: &Path,
    rel: &Path,
    mode: u32,
    created: &mut Vec<PathBuf>,
    announce: &mut dyn FnMut(&Path) -> Result<(), ArchiveError>,
) -> Result<(), ArchiveError> {
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
                let rel = cur.strip_prefix(base).unwrap_or(&cur).to_path_buf();
                announce(&rel)?;
                DirBuilder::new().mode(mode).create(&cur)?;
                fs::set_permissions(&cur, Permissions::from_mode(mode))?;
                created.push(rel);
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
    /// `deps-backup/<package id>`, relative to `app_root`: holds the journal and the `c/` backup tree.
    pkg_dir: PathBuf,
    /// `deps-backup/<package id>/c`, relative to `app_root`.
    backups: PathBuf,
    done: ArchiveInstalled,
    /// The package's sha256 (install only): the journal header.
    sha256: String,
    /// Open for appending once the first write is near.
    journal: Option<File>,
    /// Files a killed earlier attempt listed in the journal.
    prior_files: HashSet<PathBuf>,
    /// Those of them that exist: ours, removed on rollback even if not rewritten yet. (An `F` line is only written
    /// for an absent destination and a backup only for a present one, so a listed file never has a backup.)
    adopted: Vec<PathBuf>,
    /// Files the killed attempt listed as replaced whose backup still exists: restored on rollback.
    adopted_replaced: Vec<PathBuf>,
}

/// Appends one journal line and makes it durable before the step it announces.
fn journal_line(journal: &mut File, kind: char, rel: &Path) -> Result<(), ArchiveError> {
    let s = rel
        .to_str()
        .ok_or_else(|| ArchiveError::Journal(format!("{} is not UTF-8", rel.display())))?;
    io::Write::write_all(journal, format!("{kind} {s}\n").as_bytes())?;
    journal.sync_data()?;
    Ok(())
}

/// Test hook: counts down `CRASH_AFTER` and panics at zero, as if the process were killed there.
fn crash_point() {
    #[cfg(test)]
    CRASH_AFTER.with(|c| match c.get() {
        Some(0) => {
            c.set(None);
            panic!("simulated crash");
        }
        Some(n) => c.set(Some(n - 1)),
        None => {}
    });
}

/// The entries of a journal, in order: `F` new files, `D` created directories, `R` files whose original was
/// backed up.
#[derive(Default)]
struct JournalEntries {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    replaced: Vec<PathBuf>,
}

/// Reads and validates a journal (module docs). `None` if there is none.
/// With `sha256`, the header must name exactly that archive; without, any well-formed header is accepted.
fn read_journal(path: &Path, sha256: Option<&str>) -> Result<Option<JournalEntries>, ArchiveError> {
    let bad = |why: &str| ArchiveError::Journal(format!("{}: {why}", path.display()));
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.file_type().is_file() => return Err(bad("not a regular file")),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    open_nofollow(path)?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(bad("too large"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("not UTF-8"))?;
    // A last line without its newline was being appended when the process died: its step never started.
    let complete = &text[..text.rfind('\n').map_or(0, |i| i + 1)];
    let mut lines = complete.lines();
    let named = lines
        .next()
        .and_then(|h| h.strip_prefix(JOURNAL_MAGIC)?.strip_prefix(' '))
        .filter(|sha| manifest::valid_sha256(sha))
        .ok_or_else(|| bad("missing or unknown header"))?;
    if sha256.is_some_and(|want| want != named) {
        return Err(bad(
            "left by an interrupted install of a different archive of this package (see discard_interrupted)",
        ));
    }
    let mut j = JournalEntries::default();
    for (n, line) in lines.enumerate() {
        if n >= MAX_JOURNAL_ENTRIES {
            return Err(bad("too many entries"));
        }
        let (list, rel) = match line.split_at_checked(2) {
            Some(("F ", rel)) => (&mut j.files, rel),
            Some(("D ", rel)) => (&mut j.dirs, rel),
            Some(("R ", rel)) => (&mut j.replaced, rel),
            _ => return Err(bad("malformed entry")),
        };
        let rel = PathBuf::from(rel);
        win_path(&rel).map_err(|_| bad(&format!("unsafe path {:?}", clip(&rel.to_string_lossy()))))?;
        list.push(rel);
    }
    Ok(Some(j))
}

impl Ledger {
    fn new(env: &AppEnv, id: &str) -> Ledger {
        let pkg_dir = Path::new(BACKUP_DIR).join(id);
        Ledger {
            drive_c: env.drive_c(),
            app_root: env.root().to_path_buf(),
            backups: pkg_dir.join("c"),
            pkg_dir,
            done: ArchiveInstalled::default(),
            sha256: String::new(),
            journal: None,
            prior_files: HashSet::new(),
            adopted: Vec::new(),
            adopted_replaced: Vec::new(),
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.app_root.join(&self.pkg_dir).join(JOURNAL)
    }

    /// Takes over what a killed earlier attempt of the same archive listed in its journal (module docs).
    fn adopt(&mut self) -> Result<(), ArchiveError> {
        match read_journal(&self.journal_path(), Some(&self.sha256))? {
            Some(j) => self.adopt_entries(j),
            None => Ok(()),
        }
    }

    fn adopt_entries(&mut self, j: JournalEntries) -> Result<(), ArchiveError> {
        for d in j.dirs {
            if !self.done.created_dirs.contains(&d) && self.resolve(&d)?.is_some_and(|p| p.is_dir()) {
                self.done.created_dirs.push(d);
            }
        }
        for f in j.files {
            if self.prior_files.insert(f.clone()) && self.resolve(&f)?.is_some() {
                self.adopted.push(f);
            }
        }
        for r in j.replaced {
            if !self.adopted_replaced.contains(&r)
                && fs::symlink_metadata(self.app_root.join(&self.backups).join(&r)).is_ok_and(|m| m.is_file())
            {
                self.adopted_replaced.push(r);
            }
        }
        Ok(())
    }

    /// Opens the journal for appending, creating it (atomically, with its header) if needed.
    fn open_journal(&mut self) -> Result<&mut File, ArchiveError> {
        if self.journal.is_none() {
            make_dirs(&self.app_root, &self.pkg_dir, 0o700, &mut Vec::new(), &mut |_| Ok(()))?;
            let path = self.journal_path();
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file()) {
                let header = format!("{JOURNAL_MAGIC} {}\n", self.sha256);
                atomic_write(&path, &mut header.as_bytes(), None, 0o600)?;
                File::open(self.app_root.join(&self.pkg_dir))?.sync_all()?;
            }
            let mut journal = OpenOptions::new()
                .read(true)
                .append(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            // Cut a torn last line (reading drops it) so the next line cannot be glued onto it.
            let mut text = Vec::new();
            (&mut journal).take(MAX_JOURNAL_BYTES).read_to_end(&mut text)?;
            let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            if complete < text.len() {
                journal.set_len(complete as u64)?;
                journal.sync_data()?;
            }
            self.journal = Some(journal);
            crash_point();
        }
        Ok(self.journal.as_mut().expect("just opened"))
    }

    /// Deletes the journal and prunes the empty package and `deps-backup` directories.
    fn drop_journal(&self) -> Result<(), ArchiveError> {
        match fs::remove_file(self.journal_path()) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        for d in [&self.backups, &self.pkg_dir, Path::new(BACKUP_DIR)] {
            let _ = fs::remove_dir(self.app_root.join(d));
        }
        Ok(())
    }

    /// Writes one selected file (see the module docs).
    fn write(&mut self, dest: &WinPath, src: &mut dyn Read, size: u64) -> Result<(), ArchiveError> {
        let path = join_new(&self.drive_c, dest).map_err(|e| resolve_err(Path::new(&dest.to_string()), e))?;
        let rel = path
            .strip_prefix(&self.drive_c)
            .map_err(|_| ArchiveError::Destination(format!("{dest} is outside drive_c")))?
            .to_path_buf();
        let parent = rel.parent().unwrap_or(Path::new(""));
        self.open_journal()?;
        let journal = self.journal.as_mut().expect("opened above");
        make_dirs(&self.drive_c, parent, 0o755, &mut self.done.created_dirs, &mut |d| {
            journal_line(journal, 'D', d)
        })?;
        match fs::symlink_metadata(&path) {
            // Written by a killed earlier attempt of this archive (journal): ours, not an original.
            Ok(m) if m.file_type().is_file() && self.prior_files.contains(&rel) => {}
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                journal_line(self.open_journal()?, 'F', &rel)?;
            }
            Err(e) => return Err(e.into()),
        }
        atomic_write(&path, src, Some(size), 0o644)?;
        self.done.files.push(rel);
        crash_point();
        Ok(())
    }

    /// Saves the original at `path` (relative `rel`) unless a backup is already there (module docs).
    fn backup(&mut self, rel: &Path, path: &Path) -> Result<(), ArchiveError> {
        let below_root = self.backups.join(rel);
        // Backup directories are not recorded: `restore` prunes them once empty.
        make_dirs(
            &self.app_root,
            below_root.parent().unwrap_or(&self.backups),
            0o700,
            &mut Vec::new(),
            &mut |_| Ok(()),
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
        journal_line(self.open_journal()?, 'R', rel)?;
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

    /// Deletes the overrides in `done`, newest first, continuing past failures.
    fn undo_overrides(&self, env: &AppEnv, backend: &dyn CompatBackend, launcher: &Launcher) -> Vec<ArchiveError> {
        let deleted = self.done.overrides.iter().rev();
        deleted
            .filter_map(|name| delete_override(name, env, backend, launcher).err())
            .collect()
    }

    /// Undoes the file-system part of `done` plus what was adopted from a journal, continuing past failures.
    fn undo_files(&self) -> Vec<ArchiveError> {
        let mut failures = Vec::new();
        let mut note = |r: Result<(), ArchiveError>| {
            if let Err(e) = r {
                failures.push(e);
            }
        };
        for rel in self.done.files.iter().rev() {
            if !self.done.replaced.contains(rel) {
                note(self.remove_file(rel));
            }
        }
        for rel in self.adopted.iter().rev() {
            if !self.done.files.contains(rel) {
                note(self.remove_file(rel));
            }
        }
        for rel in self.done.replaced.iter().rev() {
            note(self.restore(rel));
        }
        for rel in self.adopted_replaced.iter().rev() {
            if !self.done.replaced.contains(rel) {
                note(self.restore(rel));
            }
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

pub(crate) fn set_override(
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
pub(crate) fn delete_override(
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
