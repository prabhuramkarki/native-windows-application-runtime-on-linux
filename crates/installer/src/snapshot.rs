//! A before/after snapshot of an app's Wine environment (its `drive_c` file tree and its `system.reg`/
//! `user.reg`), and the diff between two snapshots that an install pipeline uses to discover what an installer
//! just did.
//!
//! **Everything here is attacker-controlled**: file names under `drive_c` and every registry key/value name and
//! string come from a hostile installer that just ran under Wine. Every string that reaches [`InstallDiff`]
//! ([`Snapshot::files`] entries, registry key paths and value names via [`crate::reg`], [`UninstallEntry`]'s
//! fields) MUST be escaped by the caller's sanitiser (`rt_core`/`cli`'s) before being shown to a person; nothing
//! here does that itself.
//!
//! **Hive namespacing.** `system.reg` (HKEY_LOCAL_MACHINE) and `user.reg` (HKEY_CURRENT_USER) are Wine's own
//! separate files for two genuinely separate registry hives; nothing stops the SAME key path existing in both
//! with different values. Rather than merge them into one flat map (where one hive would silently shadow the
//! other's values for a colliding path), [`Snapshot::registry`] keeps ONE [`WineReg`] whose key paths are
//! prefixed `HKLM\` or `HKCU\`, so the two hives can never collide and a caller can still tell them apart.
//!
//! **File listing.** [`Snapshot::files`] is a bounded, recursive walk of `drive_c` (unlike
//! `rt_core::doctor::Listing`, which lists exactly one directory; a literal reuse of `Listing` here would mean
//! calling it once per subdirectory and hand-aggregating its `truncated`/`errors` across an arbitrary-depth
//! tree, which is more code than a small dedicated walker with the same "cap it, and say so" discipline).
//! Symlinks are recorded as leaf entries but never followed (matches Phase 2's stance on `drive_c` symlinks: one
//! could point outside the prefix). [`Snapshot::files_truncated`] is set, mirroring `Listing::truncated`, when
//! the total-entry cap or the depth cap cut the walk short, or a directory could not be read — an incomplete
//! file list must never be silently reported as complete, since [`InstallDiff::new_files`] is derived from it.
use crate::reg::{RegKey, RegValue, WineReg};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Files listed under `drive_c` at most (a real Wine `drive_c` for a small app is a few thousand entries; this
/// matches the order of magnitude of `rt_core::doctor::MAX_LISTING`, generous headroom over that).
pub const MAX_FILES: usize = 200_000;
/// Directory nesting under `drive_c` followed at most.
pub const MAX_DEPTH: usize = 32;
/// A registry file (`system.reg`/`user.reg`) larger than this is refused UNREAD (metadata only): the same 4 GiB
/// ceiling as `rt_core::install::INPUT_CAP` and `crate::reg::MAX_REG_BYTES`.
pub const MAX_REG_FILE_BYTES: u64 = crate::reg::MAX_REG_BYTES;

/// A point-in-time view of one app's Wine environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Paths relative to `drive_c`, `/`-joined as they are found on disk (no attempt to render them as Windows
    /// `C:\...` paths: that conversion is out of scope here, see `rt_core::winpath` for the real thing).
    pub files: Vec<String>,
    /// `true` when [`Snapshot::files`] is known to be incomplete (a cap was hit, or a directory could not be
    /// read). A missing `drive_c` entirely (a fresh env) is NOT incomplete: it is simply empty.
    pub files_truncated: bool,
    /// `system.reg` and `user.reg`, merged with `HKLM\`/`HKCU\`-prefixed key paths (see the module docs).
    pub registry: WineReg,
}

/// What changed between two [`Snapshot`]s of the same app, before and after running an installer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallDiff {
    /// Files present after but not before. Exact string match against `before.files`; path normalisation
    /// (case, `8.3` names, ...) is out of scope for this task.
    pub new_files: Vec<String>,
    /// `(full key path, value names)`: for a key that is new entirely, every one of its value names (the
    /// default value's name is `""`, same as [`WineReg`]); for a key that already existed, only the value names
    /// that are new. A key or value present before but removed after is NEVER reported here.
    ///
    /// **This detects new value NAMES only, never changed content.** A value whose name existed in `before` and
    /// still exists in `after`, but whose content changed (a repair/upgrade overwriting an existing
    /// `DisplayVersion`, for example), is NOT reported here at all — `diff()` only compares which names are
    /// present in each key, never what the existing names' values equal. A caller that needs to detect a
    /// changed-in-place value must compare `before`'s and `after`'s [`WineReg`] directly, name by name.
    pub new_registry_keys: Vec<(String, Vec<String>)>,
    /// Every `...\Software\Microsoft\Windows\CurrentVersion\Uninstall\<subkey>` key present after but not
    /// before, under either hive.
    pub uninstall_entries: Vec<UninstallEntry>,
}

/// One `Uninstall` registry subkey's facts, each `Option` because a hostile or merely incomplete installer can
/// leave any of them unset — never a reason to fail or panic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UninstallEntry {
    pub display_name: Option<String>,
    pub uninstall_string: Option<String>,
    pub icon_path: Option<String>,
}

/// A key path directly under this (relative to a hive prefix already applied), e.g.
/// `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}`.
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

/// `true` when `path` is a direct child of `HKLM\`/`HKCU\` + [`UNINSTALL_KEY`] (the Wow6432Node mirror some real
/// prefixes also have is out of scope: it is not the `Uninstall` key the shell reads).
fn is_uninstall_subkey(path: &str) -> bool {
    for hive in ["HKLM\\", "HKCU\\"] {
        if let Some(rest) = path.strip_prefix(hive) {
            let prefix = format!("{UNINSTALL_KEY}\\");
            if let Some(name) = rest.strip_prefix(prefix.as_str())
                && !name.is_empty()
                && !name.contains('\\')
            {
                return true;
            }
        }
    }
    false
}

fn str_value(key: &RegKey, name: &str) -> Option<String> {
    match key.values.get(name)? {
        RegValue::Str(s) | RegValue::Default(s) => Some(s.clone()),
        RegValue::Dword(_) => None,
    }
}

impl Snapshot {
    /// Captures the current state of `env`'s `drive_c` and registry. Never fails: a fresh environment with no
    /// prefix yet, or one whose registry files do not exist, produces an empty (but not truncated) `Snapshot`.
    /// Every read is bounded; see the module and [`crate::reg`] docs for exactly how.
    pub fn capture(env: &rt_core::AppEnv) -> Snapshot {
        let mut registry = WineReg::default();
        read_hive(&env.prefix().join("system.reg"), "HKLM", &mut registry);
        read_hive(&env.prefix().join("user.reg"), "HKCU", &mut registry);
        let (files, files_truncated) = list_drive_c(&env.drive_c());
        Snapshot {
            files,
            files_truncated,
            registry,
        }
    }

    /// What is in `after` but not in `before`. See [`InstallDiff`] for exactly what counts as "new". Registry
    /// changes are detected by NAME presence only: a value name that existed in both `before` and `after` is
    /// never reported here even if its content differs between the two — see
    /// [`InstallDiff::new_registry_keys`]'s doc comment for exactly what that means for repair/upgrade installs.
    pub fn diff(before: &Snapshot, after: &Snapshot) -> InstallDiff {
        let before_files: HashSet<&str> = before.files.iter().map(String::as_str).collect();
        let new_files = after
            .files
            .iter()
            .filter(|f| !before_files.contains(f.as_str()))
            .cloned()
            .collect();

        let mut new_registry_keys = Vec::new();
        let mut uninstall_entries = Vec::new();
        for (path, key) in &after.registry.keys {
            match before.registry.keys.get(path) {
                None => {
                    // The key itself is new: every one of its value names is new by definition, even zero of
                    // them (an empty container key is still a new key, reported with an empty `Vec`).
                    let names: Vec<String> = key.values.keys().cloned().collect();
                    new_registry_keys.push((path.clone(), names));
                    if is_uninstall_subkey(path) {
                        uninstall_entries.push(UninstallEntry {
                            display_name: str_value(key, "DisplayName"),
                            uninstall_string: str_value(key, "UninstallString"),
                            icon_path: str_value(key, "DisplayIcon"),
                        });
                    }
                }
                Some(before_key) => {
                    // Name presence only: a name in both `before_key` and `key` is excluded here even if its
                    // value changed (see `InstallDiff::new_registry_keys`'s doc comment) — this is not a value
                    // equality diff.
                    let added: Vec<String> = key
                        .values
                        .keys()
                        .filter(|n| !before_key.values.contains_key(*n))
                        .cloned()
                        .collect();
                    if !added.is_empty() {
                        new_registry_keys.push((path.clone(), added));
                    }
                    // An Uninstall key that already existed before is not a NEW registration, even if this run
                    // added values to it (e.g. a repair/update): only a brand-new key counts, per the module docs.
                }
            }
        }
        InstallDiff {
            new_files,
            new_registry_keys,
            uninstall_entries,
        }
    }
}

/// Reads and parses one `.reg` file into `registry`, with every key path prefixed `{hive}\`. A missing file is
/// silent (not every app has a `user.reg`, and a fresh env has neither); an oversized or unreadable one is
/// reported as a warning on `registry`, never a panic and never a partial read of a huge file.
fn read_hive(path: &Path, hive: &str, registry: &mut WineReg) {
    let bytes = match read_capped(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return, // does not exist: fine, nothing to add
        Err(why) => {
            registry.warnings.push(format!("{}: {why}", path.display()));
            return;
        }
    };
    let parsed = match WineReg::parse(&bytes) {
        Ok(parsed) => parsed,
        Err(why) => {
            registry.warnings.push(format!("{}: {why}", path.display()));
            return;
        }
    };
    for (path, key) in parsed.keys {
        registry.keys.insert(format!("{hive}\\{path}"), key);
    }
    registry.warnings.extend(parsed.warnings);
    registry.truncated |= parsed.truncated;
}

/// `Ok(Some(bytes))`: the file was read whole (at most [`MAX_REG_FILE_BYTES`]). `Ok(None)`: it does not exist.
/// `Err`: it exists but is not a plain regular file, is too large, or could not be read. Mirrors
/// `rt_core::install::read_input`'s discipline: `metadata` before `open`, the size cap checked BEFORE any bulk
/// read (so a multi-GiB sparse file is refused unread, not read up to the cap and then rejected).
fn read_capped(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let stat = match fs::metadata(path) {
        Ok(stat) => stat,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot stat: {e}")),
    };
    if !stat.is_file() {
        return Ok(None); // a directory or other non-regular entry named system.reg/user.reg: nothing to read
    }
    if stat.len() > MAX_REG_FILE_BYTES {
        return Err(format!(
            "larger than the {MAX_REG_FILE_BYTES} byte cap: refused without reading it"
        ));
    }
    let mut file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let opened = file.metadata().map_err(|e| format!("cannot stat open file: {e}"))?;
    if !opened.is_file() || opened.len() > MAX_REG_FILE_BYTES {
        return Err(format!(
            "larger than the {MAX_REG_FILE_BYTES} byte cap: refused without reading it"
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REG_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read: {e}"))?;
    if bytes.len() as u64 > MAX_REG_FILE_BYTES {
        return Err(format!(
            "larger than the {MAX_REG_FILE_BYTES} byte cap: refused without reading it"
        ));
    }
    Ok(Some(bytes))
}

/// A bounded, recursive, symlink-incurious listing of `root`'s files (relative `/`-joined paths) and whether it
/// is known to be incomplete. `root` not existing (or not a directory) is empty and complete, not an error.
fn list_drive_c(root: &Path) -> (Vec<String>, bool) {
    let mut files = Vec::new();
    let mut truncated = false;
    if !root.is_dir() {
        return (files, truncated);
    }
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    'walk: while let Some((dir, rel_prefix, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                truncated = true;
                continue;
            }
        };
        for entry in entries {
            if files.len() >= MAX_FILES {
                truncated = true;
                break 'walk;
            }
            let Ok(entry) = entry else {
                truncated = true;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if rel_prefix.is_empty() {
                name
            } else {
                format!("{rel_prefix}/{name}")
            };
            let Ok(file_type) = entry.file_type() else {
                truncated = true;
                continue;
            };
            if file_type.is_symlink() {
                files.push(rel); // recorded, never followed (it could lead outside drive_c)
            } else if file_type.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((entry.path(), rel, depth + 1));
                } else {
                    truncated = true;
                }
            } else {
                files.push(rel);
            }
        }
    }
    (files, truncated)
}

#[cfg(test)]
mod tests;
