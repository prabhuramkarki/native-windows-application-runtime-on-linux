//! The install service: turns a portable `.exe` or a `.zip` archive into an isolated app environment.
//!
//! Pipeline (nothing is written to the store before `Store::create`; a failing `create` itself can leave a
//! partially created directory behind, see `Store::create`, and is reported unchanged, never cleaned up here):
//!
//! 1. host must be x86-64 (ARM64 hosts are Phase 9);
//! 2. the input is read (regular files only, at most 4 GiB) and classified by CONTENT with `pe::detect`. A PE
//!    file is analysed with `pe::analyze`; an archive is planned and its program selected (see the `unzip` module);
//!    MSI packages and unrecognised files are refused;
//! 3. the program is refused when it is a kernel driver, a DLL, not x86/x86-64, looks like an installer
//!    (Phase 3), or its architecture or subsystem is outside the backend's capabilities. A .NET program only
//!    produces a warning;
//! 4. name (`--name`, else the version resource's `ProductName`, else the file stem; control characters removed,
//!    at most 256 bytes) and id (`unique_id(AppId::slug(name))`); the metadata is built and VALIDATED (again for
//!    every retried id, before its `create`);
//! 5. only now `Store::create` (retrying with the next id when it reports `AlreadyExists`, and never removing
//!    anything on that path: the existing directory belongs to someone else), `backend.prepare`, then the program
//!    (or the archive contents) is copied below `drive_c/Program Files/<id>/` with `create_new` and no symlink
//!    following, and `metadata.json` is written LAST. Metadata is the commit point: `list` only sees complete apps;
//! 6. any failure after `create` returned `Ok` stops the backend and removes the whole environment. When the
//!    backend cannot be stopped a Wine process may still be running in the prefix, so nothing is removed and the
//!    error says so. Cleanup problems are appended to the returned error ([`InstallError::WithCleanup`]). A PANIC
//!    in that section (zip, PE or backend code) triggers the same best-effort cleanup from a drop guard; it can only
//!    be logged (`tracing::error!`), not reported.
//!
//! **Not a sandbox.** Extraction runs while no Wine process is in the prefix (`prepare` stops the wineserver
//! before it returns). There is no locking: two installs of the same name race on `Store::create`, which
//! arbitrates (`mkdir` is atomic); the loser takes the next id.
use crate::backend::Unsupported;
use crate::text::{clean, quote};
use crate::unzip::{self, Archive, Limits, Plan, ZipError};
use crate::winpath::{ResolveError, WinPath, WinPathError, join_new, resolve_under};
use crate::{
    AppEnv, AppId, BackendError, BackendInfo, CompatBackend, MetaError, Metadata, Store, StoreError, unique_id,
};
use pe::{Arch, FileKind, InstallerKind, Kind, PeInfo, Subsystem};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

/// Largest input file, in bytes (the same cap as `runtime analyze`).
pub const INPUT_CAP: u64 = 4 * 1024 * 1024 * 1024;
/// How many times `create` is retried with a fresh id after `AlreadyExists`.
const CREATE_ATTEMPTS: usize = 5;
const MAX_NAME_BYTES: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct InstallOpts {
    /// Display name; the app id is derived from it.
    pub name: Option<String>,
    /// For archives: the program, as a path inside the archive.
    pub exe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstallOutcome {
    pub id: AppId,
    /// Canonical, e.g. `C:\Program Files\my-app\app.exe`.
    pub executable: WinPath,
    /// Human text; may quote untrusted data, escaped and capped, but the CLI must still sanitise it.
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("this host is {0}: only x86-64 Linux hosts are supported (ARM64 hosts arrive in Phase 9)")]
    UnsupportedHost(String),
    #[error("cannot read the input: {0}")]
    Read(#[source] io::Error),
    #[error("the input is not a regular file")]
    NotRegular,
    #[error("the input is larger than 4 GiB")]
    TooLarge,
    #[error("not a Windows program or a zip archive (unrecognised format)")]
    Unknown,
    #[error("MSI installers arrive in Phase 3")]
    Msi,
    #[error("not a usable Windows program: {0}")]
    Malformed(String),
    #[error("kernel-mode drivers are not supported")]
    KernelDriver,
    #[error("a DLL is not an application")]
    Dll,
    #[error("unsupported architecture ({0}): this host runs x86 and x86-64 programs")]
    UnsupportedArch(String),
    #[error("installer detected ({0}): installers arrive in Phase 3")]
    InstallerDetected(&'static str),
    #[error("the name is empty after removing control characters")]
    BadName,
    #[error("the file name cannot be used inside a Windows prefix: {0}")]
    BadFileName(String),
    /// Choosing the program inside an archive failed; the text is escaped and capped.
    #[error("{0}")]
    Select(String),
    #[error("{0}")]
    Zip(#[from] ZipError),
    #[error("{0}")]
    Meta(#[from] MetaError),
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("cannot place the program inside the prefix: {0}")]
    Resolve(#[from] ResolveError),
    #[error("cannot place the program inside the prefix: {0}")]
    Path(#[from] WinPathError),
    /// The backend's capabilities exclude the program (checked before anything is created).
    #[error("{0}")]
    Unsupported(#[from] Unsupported),
    /// The backend refused or failed; unchanged (a hardening refusal is an `Io` carrying a `HardenError`, see
    /// `backend_wine::harden_cause`).
    #[error("environment setup failed: {0}")]
    Backend(#[from] BackendError),
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    /// `cause` happened, and cleaning up afterwards had `problems`.
    #[error("{cause}; in addition: {}", problems.join("; "))]
    WithCleanup {
        cause: Box<InstallError>,
        problems: Vec<String>,
    },
}

impl InstallError {
    /// The error that started the failure, looking through [`InstallError::WithCleanup`].
    pub fn cause(&self) -> &InstallError {
        match self {
            InstallError::WithCleanup { cause, .. } => cause.cause(),
            other => other,
        }
    }
}

/// Test seams: the host architecture, the zip caps and the id source.
pub(crate) struct Tunables<'a> {
    pub host_arch: &'a str,
    pub limits: Limits,
    pub pick_id: &'a dyn Fn(&Store, &AppId) -> Result<AppId, StoreError>,
}

pub fn install(
    store: &Store,
    backend: &dyn CompatBackend,
    path: &Path,
    opts: &InstallOpts,
) -> Result<InstallOutcome, InstallError> {
    let tunables = Tunables {
        host_arch: std::env::consts::ARCH,
        limits: Limits::default(),
        pick_id: &unique_id,
    };
    install_with(store, backend, path, opts, &tunables)
}

// ---------------------------------------------------------------- reading the input

/// What [`read_input`] found.
pub enum Input {
    /// A PE file, read whole.
    Pe(Vec<u8>),
    /// A zip archive, left as an open file.
    Zip(File),
}

/// Reads and classifies the input. `metadata()` BEFORE `open()`, so a FIFO cannot block the open, then `O_NONBLOCK`
/// and an fstat of the handle (the path may have been swapped since), then the size cap on the fstat length
/// BEFORE any bulk read (a 5 GiB sparse file is refused unread). Symlinks to regular files are followed, like
/// `runtime analyze`. Only PE files are read into memory; an archive stays a file handle. `runtime doctor` reads
/// a file to check with this too (the same caps and the same FIFO safety).
pub fn read_input(path: &Path) -> Result<Input, InstallError> {
    let stat = fs::metadata(path).map_err(InstallError::Read)?;
    if !stat.is_file() {
        return Err(InstallError::NotRegular);
    }
    let file = crate::meta::open_nonblocking(path).map_err(InstallError::Read)?;
    let opened = file.metadata().map_err(InstallError::Read)?;
    if !opened.is_file() {
        return Err(InstallError::NotRegular);
    }
    if opened.len() > INPUT_CAP {
        return Err(InstallError::TooLarge);
    }
    let mut head = Vec::new();
    (&file).take(64).read_to_end(&mut head).map_err(InstallError::Read)?;
    if !head.starts_with(b"MZ") {
        // Not a PE, so nothing more of it is read: an archive stays a file handle.
        return match pe::detect(&head) {
            FileKind::Zip => Ok(Input::Zip(file)),
            FileKind::Msi => Err(InstallError::Msi),
            FileKind::Pe | FileKind::Unknown => Err(InstallError::Unknown),
        };
    }
    // `pe::detect` needs the whole file to follow `e_lfanew`; the size was capped above.
    // ponytail: the whole PE is held in RAM (up to 4 GiB); mmap or streaming if that ever matters
    let mut bytes = head;
    // A failed allocation aborts the process; ask first so a huge file on a small machine is an error instead.
    bytes
        .try_reserve(usize::try_from(opened.len()).unwrap_or(usize::MAX))
        .map_err(|_| InstallError::Read(io::ErrorKind::OutOfMemory.into()))?;
    (&file)
        .take(INPUT_CAP + 1 - bytes.len() as u64)
        .read_to_end(&mut bytes)
        .map_err(InstallError::Read)?;
    if bytes.len() as u64 > INPUT_CAP {
        return Err(InstallError::TooLarge);
    }
    match pe::detect(&bytes) {
        FileKind::Pe => Ok(Input::Pe(bytes)),
        _ => Err(InstallError::Unknown),
    }
}

// ---------------------------------------------------------------- program checks

fn arch_label(arch: Arch) -> String {
    match arch {
        Arch::X86 => "x86".into(),
        Arch::X86_64 => "x86_64".into(),
        Arch::Arm64 => "arm64".into(),
        Arch::Arm64Ec => "arm64ec".into(),
        Arch::Other(m) => format!("machine {m:#06x}"),
    }
}

fn installer_label(kind: InstallerKind) -> &'static str {
    match kind {
        InstallerKind::InnoSetup => "Inno Setup",
        InstallerKind::Nsis => "NSIS",
        InstallerKind::InstallShield => "InstallShield",
        InstallerKind::WixBurn => "WiX Burn",
    }
}

/// The rejection rules for a program, returning the warnings for one that is accepted.
fn check_pe(info: &PeInfo) -> Result<Vec<String>, InstallError> {
    if info.subsystem == Subsystem::Native {
        return Err(InstallError::KernelDriver);
    }
    if info.kind == Kind::Dll {
        return Err(InstallError::Dll);
    }
    if !matches!(info.arch, Arch::X86 | Arch::X86_64) {
        return Err(InstallError::UnsupportedArch(arch_label(info.arch)));
    }
    if let Some(installer) = &info.installer {
        return Err(InstallError::InstallerDetected(installer_label(installer.kind)));
    }
    let mut warnings = Vec::new();
    for w in info.warnings.iter().take(5) {
        warnings.push(format!("analysis: {}", quote(w)));
    }
    Ok(warnings)
}

fn analyse(bytes: &[u8]) -> Result<PeInfo, InstallError> {
    if pe::detect(bytes) != FileKind::Pe {
        return Err(InstallError::Unknown);
    }
    pe::analyze(bytes).map_err(|e| InstallError::Malformed(clean(&e.to_string(), 200)))
}

/// `--name`, else the version resource's `ProductName`, else the file stem, cleaned (see [`clean`]) and capped at
/// 256 bytes. An explicit name that is empty after cleaning is an error; the automatic sources fall through.
fn choose_name(opt: Option<&str>, info: &PeInfo, stem: &str) -> Result<String, InstallError> {
    if let Some(name) = opt {
        let name = clean(name, MAX_NAME_BYTES);
        return if name.is_empty() {
            Err(InstallError::BadName)
        } else {
            Ok(name)
        };
    }
    let product = info
        .version
        .as_ref()
        .and_then(|v| v.strings.get("ProductName"))
        .map(|s| clean(s, MAX_NAME_BYTES))
        .filter(|s| !s.is_empty());
    let stem = clean(stem, MAX_NAME_BYTES);
    Ok(product
        .or_else(|| Some(stem).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "app".to_owned()))
}

/// The id base for `name`. A slug that is a reserved Windows device name (`con`, `com1`, ...) would make the
/// program directory `Program Files\<id>` unusable inside the prefix, so it gets an `app-` prefix.
fn base_id(name: &str) -> AppId {
    let slug = AppId::slug(name);
    if WinPath::parse(&format!("C:\\Program Files\\{slug}\\x")).is_ok() {
        slug
    } else {
        AppId::slug(&format!("app-{slug}"))
    }
}

// ---------------------------------------------------------------- choosing the program inside an archive

fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Up to 10 quoted names (each capped by `quote`), then how many more.
fn list_names(plan: &Plan, files: &[usize]) -> String {
    let shown: Vec<String> = files
        .iter()
        .take(10)
        .map(|&i| quote(&plan.files[i].path.join("\\")))
        .collect();
    let more = files.len().saturating_sub(10);
    let mut s = shown.join(", ");
    if more > 0 {
        s.push_str(&format!(" and {more} more"));
    }
    s
}

struct Chosen {
    /// Index into `plan.files`.
    file: usize,
    info: PeInfo,
    warnings: Vec<String>,
}

/// Reads one archive entry (already known to be within the caps) and analyses it.
fn analyse_entry(
    archive: &mut Archive,
    plan: &Plan,
    file: usize,
    budget: &mut u64,
    limits: &Limits,
) -> Result<PeInfo, InstallError> {
    let entry = &plan.files[file];
    if entry.size > limits.max_candidate_bytes {
        return Err(InstallError::Select(format!(
            "{} is larger than {} bytes and cannot be analysed",
            quote(&entry.path.join("\\")),
            limits.max_candidate_bytes
        )));
    }
    let bytes = unzip::read_entry(archive, entry, budget, limits)?;
    analyse(&bytes).map_err(|e| match e {
        InstallError::Unknown => {
            InstallError::Select(format!("{} is not a Windows program", quote(&entry.path.join("\\"))))
        }
        other => other,
    })
}

/// `--exe`, else the only `.exe`, else the largest GUI program that passes the rules; see the module docs.
fn select_exe(archive: &mut Archive, plan: &Plan, want: Option<&str>, limits: &Limits) -> Result<Chosen, InstallError> {
    let mut budget = limits.max_analysis_bytes;
    let strict = |archive: &mut Archive, file: usize, budget: &mut u64| -> Result<Chosen, InstallError> {
        let info = analyse_entry(archive, plan, file, budget, limits)?;
        let warnings = check_pe(&info)?;
        Ok(Chosen { file, info, warnings })
    };
    if let Some(want) = want {
        let comps =
            unzip::entry_path(want).map_err(|why| InstallError::Select(format!("--exe {}: {why}", quote(want))))?;
        let key = fold(&comps.join("\\"));
        let file = plan
            .files
            .iter()
            .position(|f| fold(&f.path.join("\\")) == key)
            .ok_or_else(|| InstallError::Select(format!("--exe {} is not a file in the archive", quote(want))))?;
        return strict(archive, file, &mut budget);
    }
    let exes: Vec<usize> = (0..plan.files.len())
        .filter(|&i| plan.files[i].path.last().is_some_and(|n| fold(n).ends_with(".exe")))
        .collect();
    let hint = "pass --exe <path of the program inside the archive>";
    match exes.len() {
        0 => Err(InstallError::Select(format!(
            "the archive contains no .exe file: {hint}"
        ))),
        1 => strict(archive, exes[0], &mut budget),
        n if n > limits.max_candidates => Err(InstallError::Select(format!(
            "the archive contains {n} .exe files (more than {} can be analysed): {hint}. Some of them: {}",
            limits.max_candidates,
            list_names(plan, &exes)
        ))),
        _ => {
            // The largest GUI program that passes every rule; a tie for the largest is ambiguous.
            let mut best: Vec<Chosen> = Vec::new();
            let mut skipped = 0usize;
            let mut first_reason = String::new();
            for &file in &exes {
                let chosen = match strict(archive, file, &mut budget) {
                    Ok(chosen) => chosen,
                    Err(e) => {
                        // Not an error for the install (another program may win) but never silent.
                        if skipped == 0 {
                            first_reason = clean(&e.to_string(), 100);
                        }
                        skipped += 1;
                        continue;
                    }
                };
                if chosen.info.subsystem != Subsystem::Gui {
                    continue;
                }
                let size = |c: &Chosen| plan.files[c.file].size;
                match best.first().map(size) {
                    Some(top) if size(&chosen) < top => {}
                    Some(top) if size(&chosen) == top => best.push(chosen),
                    _ => best = vec![chosen],
                }
            }
            match best.len() {
                0 => Err(InstallError::Select(format!(
                    "none of the {} .exe files is a GUI program that can be installed: {hint}. Candidates: {}",
                    exes.len(),
                    list_names(plan, &exes)
                ))),
                1 => {
                    let mut chosen = best.remove(0);
                    if skipped > 0 {
                        chosen.warnings.push(format!(
                            "{skipped} of the {} .exe files could not be considered as the program (first reason: {})",
                            exes.len(),
                            quote(&first_reason)
                        ));
                    }
                    Ok(chosen)
                }
                _ => {
                    let tied: Vec<usize> = best.iter().map(|c| c.file).collect();
                    Err(InstallError::Select(format!(
                        "several GUI programs are equally large: {hint}. Candidates: {}",
                        list_names(plan, &tied)
                    )))
                }
            }
        }
    }
}

// ---------------------------------------------------------------- the pipeline

enum Payload {
    Exe {
        file_name: String,
        bytes: Vec<u8>,
    },
    Zip {
        archive: Archive,
        plan: Plan,
        exe: Vec<String>,
    },
}

struct Prepared {
    info: PeInfo,
    warnings: Vec<String>,
    payload: Payload,
}

impl Payload {
    /// The program's path below the program directory.
    fn exe_components(&self) -> Vec<String> {
        match self {
            Payload::Exe { file_name, .. } => vec![file_name.clone()],
            Payload::Zip { exe, .. } => exe.clone(),
        }
    }
}

fn prepare_exe(path: &Path, bytes: Vec<u8>, opts: &InstallOpts) -> Result<Prepared, InstallError> {
    let info = analyse(&bytes)?;
    let mut warnings = check_pe(&info)?;
    if opts.exe.is_some() {
        warnings.push("--exe is only used for zip archives and was ignored".to_owned());
    }
    // The file keeps its name; it must be exactly one valid component inside the prefix.
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| InstallError::BadFileName("the name is not valid UTF-8".into()))?
        .to_owned();
    let single = WinPath::parse(&format!("C:\\{file_name}"))
        .map_err(|e| InstallError::BadFileName(e.to_string()))
        .and_then(|p| match p.components() {
            [only] if *only == file_name => Ok(()),
            _ => Err(InstallError::BadFileName(
                "the name is not a single path component".into(),
            )),
        });
    single?;
    Ok(Prepared {
        info,
        warnings,
        payload: Payload::Exe { file_name, bytes },
    })
}

fn prepare_zip(file: File, opts: &InstallOpts, limits: &Limits) -> Result<Prepared, InstallError> {
    let (mut archive, plan) = unzip::open(file, limits)?;
    let mut warnings = Vec::new();
    if plan.skipped > 0 {
        warnings.push(format!(
            "skipped {} archive entries that are not regular files or directories (symlinks, devices, FIFOs, sockets)",
            plan.skipped
        ));
    }
    let chosen = select_exe(&mut archive, &plan, opts.exe.as_deref(), limits)?;
    warnings.extend(chosen.warnings);
    let exe = plan.files[chosen.file].path.clone();
    Ok(Prepared {
        info: chosen.info,
        warnings,
        payload: Payload::Zip { archive, plan, exe },
    })
}

fn program_path(id: &AppId, exe: &[String]) -> Result<WinPath, InstallError> {
    Ok(WinPath::parse(&format!("C:\\Program Files\\{id}\\{}", exe.join("\\")))?)
}

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> InstallError {
    move |source| InstallError::Io { what, source }
}

/// Copies the program or the archive below `drive_c/Program Files/<id>/`.
fn place(env: &AppEnv, payload: Payload, limits: &Limits) -> Result<(), InstallError> {
    let drive_c = env.drive_c();
    let dir = WinPath::parse(&format!("C:\\Program Files\\{}", env.id()))?;
    // `join_new` refuses a symlink at any existing component; the missing ones are then created (0755).
    let dest = join_new(&drive_c, &dir)?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&dest)
        .map_err(io_err("cannot create the program directory"))?;
    match payload {
        Payload::Exe { file_name, bytes } => {
            let target = join_new(&drive_c, &program_path(env.id(), &[file_name])?)?;
            // `create_new`: an existing file (or symlink) is an error, never overwritten or followed.
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&target)
                .map_err(io_err("cannot create the program file"))?;
            out.write_all(&bytes).map_err(io_err("cannot write the program file"))?;
        }
        Payload::Zip { mut archive, plan, .. } => {
            unzip::extract(&mut archive, &plan, &dest, limits)?;
        }
    }
    Ok(())
}

/// Stops the backend, then removes the environment; returns what went wrong, if anything. When the backend cannot
/// be stopped a Wine process may still be using the prefix: nothing is removed and the text says so.
fn cleanup_problem(store: &Store, backend: &dyn CompatBackend, env: &AppEnv) -> Option<String> {
    let id = env.id();
    match backend.stop(env) {
        Err(e) => Some(format!(
            "the backend could not be stopped ({}); the partly installed app `{id}` was left in place: \
             remove it with `runtime remove {id}` once no Wine process is running",
            quote(&e.to_string())
        )),
        Ok(()) => store.remove(id).err().map(|e| {
            format!(
                "could not remove the partly installed app `{id}`: {}",
                quote(&e.to_string())
            )
        }),
    }
}

fn cleanup(store: &Store, backend: &dyn CompatBackend, env: &AppEnv, cause: InstallError) -> InstallError {
    match cleanup_problem(store, backend, env) {
        None => cause,
        Some(p) => InstallError::WithCleanup {
            cause: Box::new(cause),
            problems: vec![p],
        },
    }
}

/// Best-effort cleanup when the section after `Store::create` unwinds (a panic in zip, PE or backend code): the
/// half-made environment would otherwise stay in the store. Disarmed on the normal path, where `cleanup` reports
/// its problems in the returned error; here they can only be logged. A panic inside the cleanup itself is
/// contained (a second panic during unwinding would abort the process).
struct UnwindCleanup<'a> {
    store: &'a Store,
    backend: &'a dyn CompatBackend,
    env: &'a AppEnv,
    armed: bool,
}

impl Drop for UnwindCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let id = self.env.id();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cleanup_problem(self.store, self.backend, self.env)
        }));
        match outcome {
            Ok(None) => tracing::error!("install of `{id}` panicked; the half-made environment was removed"),
            Ok(Some(problem)) => tracing::error!("install of `{id}` panicked; cleanup problem: {problem}"),
            Err(_) => {
                tracing::error!("install of `{id}` panicked and the cleanup panicked too; `{id}` may be left behind")
            }
        }
    }
}

pub(crate) fn install_with(
    store: &Store,
    backend: &dyn CompatBackend,
    path: &Path,
    opts: &InstallOpts,
    t: &Tunables<'_>,
) -> Result<InstallOutcome, InstallError> {
    if t.host_arch != "x86_64" {
        return Err(InstallError::UnsupportedHost(clean(t.host_arch, 32)));
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prepared = match read_input(path)? {
        Input::Pe(bytes) => prepare_exe(path, bytes, opts)?,
        Input::Zip(file) => prepare_zip(file, opts, &t.limits)?,
    };
    let Prepared {
        info,
        warnings,
        payload,
    } = prepared;
    let dotnet = info.dotnet;
    // What the backend cannot run is refused here, before anything is created.
    backend.capabilities().check(backend.id(), info.arch, info.subsystem)?;

    // Everything that can be decided without touching the disk, decided (and validated) before `create`.
    let name = choose_name(opts.name.as_deref(), &info, &stem)?;
    let base = base_id(&name);
    let backend_info = BackendInfo {
        id: backend.id().to_owned(),
        version: backend.version()?,
    };
    let architecture = if info.arch == Arch::X86 { "x86" } else { "x86_64" };
    let subsystem = match info.subsystem {
        Subsystem::Gui => "gui",
        Subsystem::Console => "console",
        _ => "other",
    };
    let version = info
        .version
        .as_ref()
        .and_then(|v| v.file_version.as_deref())
        .map(|v| clean(v, 128))
        .filter(|v| !v.is_empty());
    let exe_rel = payload.exe_components();
    let metadata_for = |id: &AppId| -> Result<(Metadata, WinPath), InstallError> {
        let exe = program_path(id, &exe_rel)?;
        let md = Metadata::new(
            id.clone(),
            name.clone(),
            version.clone(),
            architecture,
            &exe,
            backend_info.clone(),
            subsystem,
        );
        md.validate()?;
        Ok((md, exe))
    };
    let mut id = (t.pick_id)(store, &base)?;

    // `create` is the arbiter. `AlreadyExists` means the directory belongs to someone else: pick again and NEVER
    // remove anything. Cleanup below happens only for an id whose `create` returned `Ok`. The metadata for each
    // candidate id is validated before its `create`, so an invalid one leaves nothing behind.
    let mut env = None;
    for _ in 0..CREATE_ATTEMPTS {
        metadata_for(&id)?;
        match store.create(&id) {
            Ok(created) => {
                env = Some(created);
                break;
            }
            Err(StoreError::AlreadyExists) => id = (t.pick_id)(store, &base)?,
            Err(e) => return Err(e.into()),
        }
    }
    let Some(env) = env else {
        return Err(StoreError::AlreadyExists.into());
    };

    let mut unwind = UnwindCleanup {
        store,
        backend,
        env: &env,
        armed: true,
    };
    let committed = (|| -> Result<WinPath, InstallError> {
        backend.prepare(&env)?;
        let (md, exe) = metadata_for(env.id())?;
        place(&env, payload, &t.limits)?;
        // The program must now be a real file at the path metadata will name.
        let resolved = resolve_under(&env.drive_c(), &exe)?;
        if !fs::symlink_metadata(resolved).is_ok_and(|m| m.file_type().is_file()) {
            return Err(io_err("the installed program is missing")(
                io::ErrorKind::NotFound.into(),
            ));
        }
        // Metadata last: only a complete environment becomes visible to `list` and `run`.
        store.write_metadata(&env, &md)?;
        Ok(exe)
    })();
    unwind.armed = false;
    match committed {
        Ok(executable) => {
            let mut warnings = warnings;
            if dotnet {
                warnings.push(format!(
                    ".NET program: Wine Mono is not installed for this app; run `runtime deps {} --install`",
                    env.id()
                ));
            }
            Ok(InstallOutcome {
                id: env.id().clone(),
                executable,
                warnings,
            })
        }
        Err(cause) => Err(cleanup(store, backend, &env, cause)),
    }
}

#[cfg(test)]
mod tests;
