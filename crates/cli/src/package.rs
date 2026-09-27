//! `runtime pack`, `inspect`, `unpack` and `import`: `.wrun` v1 packages (`rt_package`; the design is
//! `docs/superpowers/specs/2026-09-27-backend-interface-and-wrun-design.md`, sections 5.3 and 5.4).
//!
//! **A package can only request.** `inspect` and `unpack` run nothing and never touch the data directory. `import`
//! creates the app through the unchanged install flows (`rt_core::install` in subtree mode for a portable package,
//! `rt_installer::install_via_installer` for an installer one) under the package's fixed id, and records what the
//! package requested in the app's metadata; it grants nothing: no `permissions.toml`, no dependency install, the app
//! is never started. An id that is taken is refused and the existing app is not read, locked or changed. The request
//! lines are fixed wording built from the manifest's enums; every string from a package is printed through `safe()`.
//! They are information, not something the user confirms: consent stays with `runtime deps --install` (per package,
//! bound by the plan digest) and `runtime permissions --set`.
use crate::CmdError;
use crate::safe::{json_safe, safe, warn};
use rt_core::{AppId, InstallOpts, PackageMeta, Store, StoreError};
use rt_installer::InstallerOpts;
use rt_package::{Entry, Manifest, PAYLOAD_PREFIX, Package};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const UNSIGNED: &str = "unsigned: its origin is not verified";

/// `runtime pack <DIR> -o <FILE>`.
pub fn pack(dir: &Path, out: &Path) -> Result<u8, CmdError> {
    let digest = rt_package::pack(dir, out)?;
    crate::emit(&format!(
        "Packed: {}\nDigest: {}\n{UNSIGNED}\n",
        safe(&out.to_string_lossy()),
        rt_package::hex(&digest)
    ))?;
    Ok(0)
}

/// `runtime inspect <FILE> [--json]`: every payload file is verified; nothing is written.
pub fn inspect(file: &Path, json: bool) -> Result<u8, CmdError> {
    let mut pkg = open(file)?;
    let deps = dependencies(&pkg.manifest)?;
    pkg.verify()?;
    let installed = taken(&crate::store()?, &pkg.manifest.id);
    if !json {
        crate::emit(&summary(&pkg, &deps, installed))?;
        return Ok(0);
    }
    let m = &pkg.manifest;
    let (kind, entry) = kind_and_entry(m);
    let doc = serde_json::json!({
        "id": m.id.as_str(), "name": m.name, "version": m.version, "arch": arch(m),
        "kind": kind, "entry": entry, "files": m.files.len(), "bytes": bytes(m),
        "digest": rt_package::hex(&pkg.digest), "signed": false, "installed": installed,
        "requests": {
            "dependencies": deps.iter().map(|(id, gated)| serde_json::json!({
                "id": id, "consent": if *gated { "needed" } else { "none" },
            })).collect::<Vec<_>>(),
            "permissions": m.permissions.exprs(),
        },
    });
    crate::emit(&format!("{}\n", json_safe(&serde_json::to_string_pretty(&doc)?)))?;
    Ok(0)
}

/// `runtime unpack <FILE> -o <DIR>`: `DIR` must not exist; it is removed again on any error.
pub fn unpack(file: &Path, dest: &Path) -> Result<u8, CmdError> {
    open(file)?.unpack(dest)?;
    crate::emit(&format!("Unpacked into {}\n", safe(&dest.to_string_lossy())))?;
    Ok(0)
}

/// `runtime import <FILE> [--silent] [--network]`. Exit code 1 also when the installer pipeline could not tell
/// which installed file is the app (as `install`).
pub fn import(file: &Path, silent: bool, network: bool) -> Result<u8, CmdError> {
    let mut pkg = open(file)?;
    let deps = dependencies(&pkg.manifest)?;
    let m = pkg.manifest.clone();
    if matches!(m.entry, Entry::Portable { .. }) && (silent || network) {
        return Err("--silent/--network only apply to installer packages; nothing was installed".into());
    }
    let store = crate::store()?;
    let id = m.id.as_str();
    if taken(&store, &m.id) {
        return Err(format!(
            "{id} is already installed; nothing was changed (a package never replaces an app: `runtime remove {id}` \
             first)"
        )
        .into());
    }
    let launcher = rt_core::Launcher::new();
    let backend = crate::backend(&launcher)?;
    if !backend.capabilities().arches.contains(&m.arch) {
        return Err(rt_core::Unsupported::Arch {
            backend: backend.id(),
            arch: arch(&m).to_owned(),
        }
        .into());
    }
    crate::emit(&summary(&pkg, &deps, false))?;
    let record = PackageMeta {
        id: id.to_owned(),
        version: m.version.clone(),
        digest: rt_package::hex(&pkg.digest),
        requested_dependencies: m.dependencies.clone(),
        requested_permissions: m.permissions.exprs(),
    };
    eprintln!("note: creating the Wine environment can take up to a minute");
    match &m.entry {
        Entry::Portable { exe } => {
            let outcome = rt_core::install(
                &store,
                &*backend,
                file,
                &InstallOpts {
                    name: Some(m.name.clone()),
                    exe: Some(exe.strip_prefix(PAYLOAD_PREFIX).unwrap_or(exe).to_owned()),
                    id: Some(m.id.clone()),
                    subtree: Some(PAYLOAD_PREFIX.trim_end_matches('/').to_owned()),
                    digests: Some(pkg.digests()),
                    package: Some(record),
                    expect_arch: Some(m.arch),
                },
            )?;
            crate::install::print_installed(&store, &outcome.id, &outcome.executable.to_string(), &outcome.warnings)?;
        }
        Entry::Installer {
            installer,
            installed_exe,
        } => {
            if !silent {
                warn(
                    "the installer runs in an isolated sandbox with no display access; if it hangs waiting for a \
                     window, retry with --silent",
                );
            }
            crate::sandbox::print_hardening_caveat();
            let staged = Staged::new(installer.rsplit('/').next().unwrap_or(installer))?;
            pkg.extract_one(installer, &staged.file)?;
            let opts = InstallerOpts {
                silent,
                allow_network: network,
                exe_override: installed_exe.clone(),
                runtime_exe: crate::runtime_exe(),
                id: Some(m.id.clone()),
                package: Some(record),
            };
            match rt_installer::install_via_installer(&store, &*backend, launcher, &staged.file, opts)? {
                rt_installer::InstallOutcome::Installed {
                    id,
                    executable,
                    warnings,
                    ..
                } => crate::install::print_installed(&store, &id, &executable.to_string(), &warnings)?,
                rt_installer::InstallOutcome::NeedsChoice(candidates) => {
                    crate::install::print_candidates(&candidates)?;
                    return Ok(1);
                }
            }
        }
    }
    crate::emit(&grant_commands(&m))?;
    crate::deps::print_hint(&store, &m.id);
    Ok(0)
}

/// Opens `file` without blocking on a FIFO (`O_NONBLOCK`; a regular file reads as usual) and validates the container
/// and the manifest. No payload byte is read.
fn open(file: &Path) -> Result<Package, CmdError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file)
        .map_err(|e| format!("cannot open {}: {e}", file.display()))?;
    if !f.metadata()?.is_file() {
        return Err(format!("{} is not a regular file", file.display()).into());
    }
    Ok(rt_package::open(f)?)
}

/// Whether an app directory (or anything else) is at the id's place: only `NotFound` is free.
fn taken(store: &Store, id: &AppId) -> bool {
    !matches!(store.get(id), Err(StoreError::NotFound))
}

/// Each requested dependency with whether it needs consent; an id the bundled deps manifest does not know is an
/// error (a package cannot bring its own dependency definitions).
fn dependencies(m: &Manifest) -> Result<Vec<(String, bool)>, CmdError> {
    let bundled = rt_deps::Manifest::bundled();
    m.dependencies
        .iter()
        .map(|d| match bundled.get(d) {
            Some(p) => Ok((d.clone(), p.requires_consent)),
            None => Err(format!(
                "the package requests dependency {d:?}, which is not in the runtime's dependency manifest (see \
                 `runtime deps list`)"
            )
            .into()),
        })
        .collect()
}

fn arch(m: &Manifest) -> &'static str {
    if m.arch == pe::Arch::X86 { "x86" } else { "x86_64" }
}

fn kind_and_entry(m: &Manifest) -> (&'static str, &str) {
    match &m.entry {
        Entry::Portable { exe } => ("portable", exe),
        Entry::Installer { installer, .. } => ("installer", installer),
    }
}

fn bytes(m: &Manifest) -> u64 {
    m.files.iter().fold(0u64, |t, f| t.saturating_add(f.size))
}

/// What `inspect` prints and `import` prints first (so a job log shows the requests).
fn summary(pkg: &Package, deps: &[(String, bool)], installed: bool) -> String {
    let m = &pkg.manifest;
    let id = safe(m.id.as_str());
    let (kind, entry) = kind_and_entry(m);
    let mut o = format!(
        "Package:   {id} {}\nName:      {}\nArch:      {}\nKind:      {kind} ({})\nFiles:     {} ({} bytes)\n\
         Digest:    {}\n{UNSIGNED}\nAlready installed: {}\n",
        safe(&m.version),
        safe(&m.name),
        arch(m),
        safe(entry),
        m.files.len(),
        bytes(m),
        rt_package::hex(&pkg.digest),
        if installed { "yes" } else { "no" },
    );
    let exprs = m.permissions.exprs();
    if deps.is_empty() && exprs.is_empty() {
        o.push_str("It requests nothing.\n");
        return o;
    }
    o.push_str("It would request:\n");
    for (d, gated) in deps {
        let d = safe(d);
        let _ = if *gated {
            writeln!(
                o,
                "  dependency {d}: needs your consent when you run `runtime deps {id} --install`"
            )
        } else {
            writeln!(
                o,
                "  dependency {d}: installed by `runtime deps {id} --install` (no consent needed)"
            )
        };
    }
    for e in exprs {
        let e = safe(&e);
        let _ = writeln!(
            o,
            "  permission {e}: not granted; you can grant it with `runtime permissions {id} --set={e}`"
        );
    }
    o
}

/// After an import: each request as the command that would grant it.
fn grant_commands(m: &Manifest) -> String {
    let id = safe(m.id.as_str());
    let exprs = m.permissions.exprs();
    if exprs.is_empty() && m.dependencies.is_empty() {
        return String::new();
    }
    let mut o = String::from("Nothing was granted or installed. To grant what the package requested:\n");
    for e in exprs {
        let _ = writeln!(o, "  runtime permissions {id} --set={}", safe(&e));
    }
    if !m.dependencies.is_empty() {
        let _ = writeln!(o, "  runtime deps {id} --install");
    }
    o
}

/// The installer of an installer-kind package, extracted (verified) to
/// `<data root>/staging/import-<pid>-<nanos>/<its file name>` (the file name is kept: the installer pipeline copies
/// it into the prefix under that name). The directories are `0700`, the file `create_new` `0600`; the per-import
/// directory is removed on drop, on every path the process itself takes. A signal (a job cancel's SIGTERM, Ctrl-C,
/// SIGKILL) skips the drop: the next import removes each `import-<pid>-*` whose process is gone ([`sweep`]).
struct Staged {
    dir: PathBuf,
    file: PathBuf,
}

impl Staged {
    fn new(name: &str) -> Result<Staged, CmdError> {
        let staging = rt_core::data_root()?.join("staging");
        let mkdir = |d: &Path, recursive: bool| {
            DirBuilder::new()
                .recursive(recursive)
                .mode(0o700)
                .create(d)
                .map_err(|e| format!("cannot create {}: {e}", d.display()))
        };
        mkdir(&staging, true)?;
        if !fs::symlink_metadata(&staging).is_ok_and(|m| m.is_dir()) {
            return Err(format!("{} is not a directory", staging.display()).into());
        }
        sweep(&staging);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = staging.join(format!("import-{}-{nanos}", std::process::id()));
        mkdir(&dir, false)?;
        Ok(Staged {
            file: dir.join(name),
            dir,
        })
    }
}

/// Removes the staging directories of imports that were killed: `import-<pid>-<n>` whose `<pid>` is not a live
/// process (no `/proc/<pid>`). Best effort; anything else in `staging` is left alone. A reused pid only delays the
/// removal until that process ends.
fn sweep(staging: &Path) {
    let Ok(entries) = fs::read_dir(staging) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix("import-"))
            .and_then(|r| r.split_once('-'))
            .filter(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|(pid, _)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if !Path::new("/proc").join(pid.to_string()).exists() {
            // `remove_dir_all` does not follow a symlink at its root: it removes the link.
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
