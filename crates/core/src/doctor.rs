//! `doctor`: a read-only health report. Every input is injected (the environment, the file system probes, the
//! backend, the parsed PE, the app's directory listing and the prefix audit), so each check is unit-testable
//! without the host; the CLI gathers the real inputs. Nothing here writes or spawns (except the backend's
//! `version()` helper), and no input can make it panic.
//!
//! **Consumers must not parse [`Check::text`]**: it is prose for people, may change between versions and carries
//! escaped, shortened excerpts of untrusted data (DLL names, error messages). [`Area`] and [`Status`] and the
//! [`Verdict`] are the contract.
//!
//! **Bounds.** Directory listings are read through [`FsProbe::list`] with a cap of [`MAX_LISTING`] names (at most
//! [`MAX_DLL_DIRS`] Wine directories); a check text is at most 300 characters, a list of names (imports) 1200: at
//! most 20 names, each cut to 40 escaped characters. The number of checks is fixed by the code, not by the input.
//! Names printed from the input go through `text::quote_max` (control, bidi and other invisible characters are
//! escaped); free-form messages through `text::clean` (those characters are removed).
//!
//! **What "available" means for an imported DLL** (case-insensitive): an `api-ms-win-*`/`ext-ms-win-*` API-set
//! name (Wine 10 has no stub files: it resolves them inside `ntdll`, so this is NOT verified and the text says
//! so), or a file in one of the backend's DLL directories, in the app's own directory, or in the prefix's
//! `system32`/`syswow64`. When the backend reports no DLL directory (or none can be listed) the answer is "not
//! verified", never "missing". Names past the listing cap are not seen.
use crate::CompatBackend;
use crate::text::{clean, quote_max};
use pe::{Arch, InstallerKind, Kind, PeInfo, Subsystem};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What the report is about. The strings are untrusted (metadata, a file name): print them escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    System,
    App {
        id: String,
        name: Option<String>,
        version: Option<String>,
    },
    File {
        path: String,
    },
}

/// The section a check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Architecture,
    Pe,
    Imports,
    Graphics,
    Audio,
    Runtime,
    Prefix,
    Program,
}

/// `Ok` and information: nothing to do. `Warn`: the program may fail. `Fail`: it cannot work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

/// `Fail` if any check failed, else `MayFail` if any warned, else `Good`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Fail,
    MayFail,
    Good,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub area: Area,
    pub status: Status,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub subject: Subject,
    pub checks: Vec<Check>,
    pub verdict: Verdict,
}

/// The file system as `doctor` sees it: two questions about specific paths, so a test can answer them without a host.
pub trait FsProbe {
    /// The path exists (symlinks followed; sockets and FIFOs count).
    fn exists(&self, path: &Path) -> bool;
    /// At most `cap` entry names of the directory `dir` (lossy UTF-8); `None` when it is not a listable directory.
    fn list(&self, dir: &Path, cap: usize) -> Option<Vec<String>>;
}

/// What the read-only audit of a prefix found (the CLI converts `backend_wine::AuditReport`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixAudit {
    /// `dosdevices` entries other than `c:`.
    pub extra_devices: Vec<String>,
    /// `dosdevices/c:` links to `../drive_c`.
    pub c_link_ok: bool,
    /// Symlinks below `drive_c` that lead outside it (paths relative to the prefix).
    pub outward: Vec<String>,
    /// The audit did not finish (too deep, too many entries): why. The other fields then mean nothing.
    pub incomplete: Option<String>,
}

/// The prefix of an app, as far as `doctor` could see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixState {
    /// A report about the system or a file has no prefix.
    NotApplicable,
    /// The app has no prefix (yet).
    Missing,
    Audit(PrefixAudit),
    /// The audit refused or failed (a symlinked `drive_c`, an I/O error): why.
    Unexaminable(String),
}

/// What is known about the program file.
pub enum PeState<'a> {
    /// No program to look at (a system report, or the program could not be found: the `program` check says why).
    Skipped,
    Analysed(&'a PeInfo),
    /// Why the file could not be analysed (not a PE, malformed, unreadable).
    Unreadable(&'a str),
}

/// Everything `doctor` looks at.
pub struct DoctorInput<'a> {
    pub subject: Subject,
    /// `std::env::consts::ARCH`.
    pub host_arch: &'a str,
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    pub fs: &'a dyn FsProbe,
    /// The backend, or why it could not be found (the text of the discovery error, with its install hint).
    pub backend: Result<&'a dyn CompatBackend, &'a str>,
    pub pe: PeState<'a>,
    /// `Some` for an installed app: the program's executable text, or why `resolve_program` refused it.
    pub program: Option<Result<&'a str, &'a str>>,
    /// Names in the program's own directory (only what is capped at [`MAX_LISTING`] is used).
    pub app_dir: &'a [String],
    pub prefix: PrefixState,
    /// The prefix directory (its `system32`/`syswow64` count as DLL sources), if there is one.
    pub prefix_root: Option<&'a Path>,
}

/// Names read from one directory listing at most.
pub const MAX_LISTING: usize = 50_000;
/// Wine DLL directories listed at most.
pub const MAX_DLL_DIRS: usize = 16;
/// Names shown in a list before "and N more".
const MAX_SHOWN: usize = 20;
/// Longest ordinary check text, in characters.
const MAX_TEXT: usize = 300;
/// Longest text of a check that lists names.
const MAX_LIST_TEXT: usize = 1200;
/// Width of one name in a list, in escaped characters.
const NAME_WIDTH: usize = 40;
/// Import entries looked at (the PE parser already caps its tables lower).
const MAX_IMPORTS: usize = 20_000;
/// Standard library directories searched for the Vulkan loader.
const VULKAN_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib64",
    "/usr/lib",
    "/lib/x86_64-linux-gnu",
];

/// The real file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFs;

impl FsProbe for HostFs {
    fn exists(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok()
    }

    fn list(&self, dir: &Path, cap: usize) -> Option<Vec<String>> {
        let entries = std::fs::read_dir(dir).ok()?;
        // An entry that cannot be read is skipped; the number of names is bounded by `cap`, however big the directory.
        Some(
            entries
                .filter_map(Result::ok)
                .take(cap)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
        )
    }
}

pub fn verdict(checks: &[Check]) -> Verdict {
    if checks.iter().any(|c| c.status == Status::Fail) {
        Verdict::Fail
    } else if checks.iter().any(|c| c.status == Status::Warn) {
        Verdict::MayFail
    } else {
        Verdict::Good
    }
}

/// `text` cut to `max` characters (`...` at the end when cut).
fn clip(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut out: String = text.chars().take(max - 3).collect();
    out.push_str("...");
    out
}

struct Out(Vec<Check>);

impl Out {
    fn add(&mut self, area: Area, status: Status, text: String) {
        self.0.push(Check {
            area,
            status,
            text: clip(text, MAX_TEXT),
        });
    }

    fn add_list(&mut self, area: Area, status: Status, text: String) {
        self.0.push(Check {
            area,
            status,
            text: clip(text, MAX_LIST_TEXT),
        });
    }
}

pub fn doctor(input: DoctorInput<'_>) -> Report {
    let mut out = Out(Vec::new());
    host_arch(&input, &mut out);
    if let PeState::Unreadable(why) = input.pe {
        out.add(
            Area::Pe,
            Status::Fail,
            format!("the file cannot be analysed: {}", clean(why, 200)),
        );
    }
    if let PeState::Analysed(info) = input.pe {
        pe_facts(info, &mut out);
        imports(info, &input, &mut out);
        runtime_needs(info, &mut out);
    }
    wine(&input, &mut out);
    vulkan(&input, &mut out);
    display(&input, &mut out);
    audio(&input, &mut out);
    prefix(&input.prefix, &mut out);
    program(input.program, &mut out);
    let checks = out.0;
    Report {
        subject: input.subject,
        verdict: verdict(&checks),
        checks,
    }
}

fn host_arch(input: &DoctorInput<'_>, out: &mut Out) {
    if input.host_arch == "x86_64" {
        out.add(Area::Architecture, Status::Ok, "host architecture: x86-64".into());
    } else {
        out.add(
            Area::Architecture,
            Status::Fail,
            format!(
                "host architecture {} is not supported: x86-64 is required (other hosts arrive in Phase 9)",
                quote_max(input.host_arch, NAME_WIDTH)
            ),
        );
    }
}

// ---------------------------------------------------------------- the program file

fn pe_facts(info: &PeInfo, out: &mut Out) {
    let format = match info.format {
        pe::Format::Pe32 => "PE32",
        pe::Format::Pe32Plus => "PE32+",
    };
    out.add(Area::Pe, Status::Ok, format!("valid PE file ({format})"));
    match info.arch {
        Arch::X86_64 => out.add(Area::Architecture, Status::Ok, "program architecture: x86-64".into()),
        Arch::X86 => out.add(
            Area::Architecture,
            Status::Ok,
            "program architecture: x86 (32-bit, runs through Wine's WoW64)".into(),
        ),
        other => {
            let label = match other {
                Arch::Arm64 => "ARM64".to_owned(),
                Arch::Arm64Ec => "ARM64EC".to_owned(),
                _ => format!("machine {:#06x}", info.machine),
            };
            out.add(
                Area::Architecture,
                Status::Fail,
                format!("program architecture {label} is not supported (x86 and x86-64 programs only)"),
            );
        }
    }
    if info.kind == Kind::Dll {
        out.add(
            Area::Pe,
            Status::Fail,
            "this is a DLL, not a program: it is not launchable".into(),
        );
    }
    match info.subsystem {
        Subsystem::Native => out.add(
            Area::Pe,
            Status::Fail,
            "kernel-mode driver: kernel drivers are unsupported".into(),
        ),
        Subsystem::Gui if info.kind == Kind::Exe => out.add(Area::Pe, Status::Ok, "GUI application".into()),
        Subsystem::Console if info.kind == Kind::Exe => out.add(Area::Pe, Status::Ok, "console application".into()),
        Subsystem::Gui | Subsystem::Console => {}
        Subsystem::Efi => out.add(
            Area::Pe,
            Status::Warn,
            "unusual subsystem efi (10): the program may not start".into(),
        ),
        Subsystem::Other(_) => out.add(
            Area::Pe,
            Status::Warn,
            format!("unusual subsystem {}: the program may not start", info.subsystem_raw),
        ),
    }
    let yes = |b: bool| if b { "yes" } else { "no" };
    out.add(
        Area::Pe,
        Status::Ok,
        format!(
            "signed: {} (not verified); ASLR: {}; NX: {}",
            yes(info.signed),
            yes(info.aslr),
            yes(info.nx)
        ),
    );
    let n = info.warnings.len();
    if n > 0 {
        let s = if n == 1 { "" } else { "s" };
        out.add(
            Area::Pe,
            Status::Warn,
            format!("{n} parser warning{s}: parts of the file may be damaged (see `runtime analyze`)"),
        );
    }
}

fn runtime_needs(info: &PeInfo, out: &mut Out) {
    if info.dotnet {
        out.add(
            Area::Runtime,
            Status::Warn,
            ".NET program: needs Mono/.NET (Phase 4); it fails until then".into(),
        );
    }
    if let Some(installer) = &info.installer {
        let label = match installer.kind {
            InstallerKind::InnoSetup => "Inno Setup",
            InstallerKind::Nsis => "NSIS",
            InstallerKind::InstallShield => "InstallShield",
            InstallerKind::WixBurn => "WiX Burn",
        };
        out.add(
            Area::Runtime,
            Status::Warn,
            format!("installer ({label}, a heuristic guess): Phase 3 handles installers"),
        );
    }
}

// ---------------------------------------------------------------- imports

/// `api-ms-win-*` and `ext-ms-win-*` (ASCII case-insensitive; byte comparison, so no char-boundary panic).
fn is_api_set(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 11 && (b[..11].eq_ignore_ascii_case(b"api-ms-win-") || b[..11].eq_ignore_ascii_case(b"ext-ms-win-"))
}

/// `"a", "b" and N more`: at most [`MAX_SHOWN`] names.
fn name_list(names: &[String]) -> String {
    let shown: Vec<String> = names.iter().take(MAX_SHOWN).map(|n| quote_max(n, NAME_WIDTH)).collect();
    let mut s = shown.join(", ");
    if names.len() > MAX_SHOWN {
        s.push_str(&format!(" and {} more", names.len() - MAX_SHOWN));
    }
    s
}

/// The lowercase names of one listing, added to `into`.
fn add_names(into: &mut HashSet<String>, names: &[String]) {
    into.extend(names.iter().take(MAX_LISTING).map(|n| n.to_lowercase()));
}

fn imports(info: &PeInfo, input: &DoctorInput<'_>, out: &mut Out) {
    // Where the DLLs of Wine are: without any listing nothing can be called missing.
    let mut known: HashSet<String> = HashSet::new();
    let mut listed_wine = 0;
    let unverified = match &input.backend {
        Err(_) => Some("Wine not found"),
        Ok(backend) => {
            for dir in backend.dll_dirs().iter().take(MAX_DLL_DIRS) {
                if let Some(names) = input.fs.list(dir, MAX_LISTING) {
                    add_names(&mut known, &names);
                    listed_wine += 1;
                }
            }
            (listed_wine == 0).then_some("Wine DLL directory not found")
        }
    };
    if let Some(reason) = unverified {
        out.add(
            Area::Imports,
            Status::Warn,
            format!("DLL availability not verified ({reason})"),
        );
        return;
    }
    add_names(&mut known, input.app_dir);
    if let Some(root) = input.prefix_root {
        for sub in ["drive_c/windows/system32", "drive_c/windows/syswow64"] {
            // A prefix that does not exist yet has no listing: skipped silently.
            if let Some(names) = input.fs.list(&root.join(sub), MAX_LISTING) {
                add_names(&mut known, &names);
            }
        }
    }
    let available = |name: &str| -> bool {
        let lower = name.to_lowercase();
        known.contains(&lower) || (!lower.contains('.') && known.contains(&format!("{lower}.dll")))
    };
    let mut api_sets: HashSet<String> = HashSet::new();
    let mut found = 0usize;
    let (mut missing, mut missing_delay): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut seen: HashSet<String> = HashSet::new();
    let mut seen_delay: HashSet<String> = HashSet::new();
    // Regular imports first, so a name imported both ways counts as a regular one.
    let entries = || info.imports.iter().take(MAX_IMPORTS);
    for imp in entries().filter(|i| !i.delay).chain(entries().filter(|i| i.delay)) {
        if is_api_set(&imp.dll) {
            api_sets.insert(imp.dll.to_lowercase());
        } else if available(&imp.dll) {
            found += 1;
        } else if !imp.delay {
            if seen.insert(imp.dll.to_lowercase()) {
                missing.push(imp.dll.clone());
            }
        } else if !seen.contains(&imp.dll.to_lowercase()) && seen_delay.insert(imp.dll.to_lowercase()) {
            missing_delay.push(imp.dll.clone());
        }
    }
    let note = if api_sets.is_empty() {
        String::new()
    } else {
        format!(
            " ({} API-set names not verified: Wine resolves them internally)",
            api_sets.len()
        )
    };
    if missing.is_empty() && missing_delay.is_empty() {
        let text = if found == 0 && api_sets.is_empty() {
            "the program imports no DLLs".to_owned()
        } else {
            format!("all imported DLLs were found{note}")
        };
        out.add_list(Area::Imports, Status::Ok, text);
        return;
    }
    if !missing.is_empty() {
        let s = if missing.len() == 1 { "" } else { "s" };
        out.add_list(
            Area::Imports,
            Status::Warn,
            format!(
                "{} imported DLL{s} not found in Wine, the program's directory or the prefix: {}{note}",
                missing.len(),
                name_list(&missing)
            ),
        );
    }
    if !missing_delay.is_empty() {
        let s = if missing_delay.len() == 1 { "" } else { "s" };
        out.add_list(
            Area::Imports,
            Status::Warn,
            format!(
                "{} optional (delay-loaded) DLL{s} not found: {}",
                missing_delay.len(),
                name_list(&missing_delay)
            ),
        );
    }
}

// ---------------------------------------------------------------- Wine and the desktop

fn wine(input: &DoctorInput<'_>, out: &mut Out) {
    match &input.backend {
        Err(why) => out.add(
            Area::Runtime,
            Status::Fail,
            format!("Wine is not usable: {}", clean(why, 250)),
        ),
        Ok(backend) => match backend.version() {
            Ok(v) => out.add(Area::Runtime, Status::Ok, format!("Wine: {}", clean(&v, 80))),
            Err(e) => out.add(
                Area::Runtime,
                Status::Warn,
                format!(
                    "Wine was found, but its version could not be read: {}",
                    clean(&e.to_string(), 200)
                ),
            ),
        },
    }
}

fn vulkan(input: &DoctorInput<'_>, out: &mut Out) {
    match VULKAN_DIRS.iter().find(|d| input.fs.exists(&Path::new(d).join("libvulkan.so.1"))) {
        Some(dir) => out.add(Area::Graphics, Status::Ok, format!("Vulkan loader found in {dir}")),
        None => out.add(
            Area::Graphics,
            Status::Warn,
            "Vulkan loader (libvulkan.so.1) not found in the standard library directories: graphics acceleration will not work".into(),
        ),
    }
}

/// An environment variable that is set and not empty, as text.
fn var(input: &DoctorInput<'_>, name: &str) -> Option<OsString> {
    (input.env)(name).filter(|v| !v.is_empty())
}

/// `$XDG_RUNTIME_DIR` when it is set and absolute.
fn runtime_dir(input: &DoctorInput<'_>) -> Option<PathBuf> {
    var(input, "XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn display(input: &DoctorInput<'_>, out: &mut Out) {
    let wayland = var(input, "WAYLAND_DISPLAY");
    let socket = wayland.as_ref().and_then(|name| {
        let p = PathBuf::from(name);
        if p.is_absolute() {
            Some(p)
        } else {
            runtime_dir(input).map(|d| d.join(p))
        }
    });
    if let (Some(name), Some(socket)) = (&wayland, &socket)
        && input.fs.exists(socket)
    {
        let name = name.to_string_lossy();
        out.add(
            Area::Graphics,
            Status::Ok,
            format!("Wayland display {}", quote_max(&name, 60)),
        );
        return;
    }
    let stale = if wayland.is_some() {
        "; WAYLAND_DISPLAY is set but its socket was not found"
    } else {
        ""
    };
    match var(input, "DISPLAY") {
        Some(d) => out.add(
            Area::Graphics,
            Status::Ok,
            format!("X11 or XWayland display {}{stale}", quote_max(&d.to_string_lossy(), 60)),
        ),
        None => out.add(
            Area::Graphics,
            Status::Warn,
            format!(
                "no display session found (no Wayland socket, no DISPLAY): GUI programs cannot open windows{stale}"
            ),
        ),
    }
}

fn audio(input: &DoctorInput<'_>, out: &mut Out) {
    let found = runtime_dir(input).is_some_and(|d| input.fs.exists(&d.join("pipewire-0")));
    if found {
        out.add(Area::Audio, Status::Ok, "PipeWire socket found".into());
    } else {
        out.add(
            Area::Audio,
            Status::Warn,
            "PipeWire socket ($XDG_RUNTIME_DIR/pipewire-0) not found: audio may not work".into(),
        );
    }
}

// ---------------------------------------------------------------- the prefix and the program

/// Wine's own device links: `com1`, `lpt1`, ... It recreates them on every start.
fn is_port(name: &str) -> bool {
    ["com", "lpt"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn prefix(state: &PrefixState, out: &mut Out) {
    let a = match state {
        PrefixState::NotApplicable => return,
        PrefixState::Missing => {
            return out.add(
                Area::Prefix,
                Status::Warn,
                "no Wine prefix yet (`runtime install` creates it)".into(),
            );
        }
        PrefixState::Unexaminable(why) => {
            return out.add(
                Area::Prefix,
                Status::Fail,
                format!("the prefix cannot be examined: {}", clean(why, 200)),
            );
        }
        PrefixState::Audit(a) => a,
    };
    // An audit that did not finish says nothing about what it did not see.
    if let Some(why) = &a.incomplete {
        return out.add(
            Area::Prefix,
            Status::Warn,
            format!(
                "prefix audit incomplete ({}): not everything could be examined",
                clean(why, 150)
            ),
        );
    }
    let mut problems = false;
    let is_z = |n: &String| n.eq_ignore_ascii_case("z:");
    if a.extra_devices.iter().any(is_z) {
        problems = true;
        out.add(
            Area::Prefix,
            Status::Warn,
            "host root drive present: dosdevices/z: gives Wine programs the whole host file system (hardening removes it)".into(),
        );
    }
    let unexpected: Vec<String> = a
        .extra_devices
        .iter()
        .filter(|n| !is_z(n) && !is_port(n))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        problems = true;
        out.add_list(
            Area::Prefix,
            Status::Warn,
            format!(
                "unexpected dosdevices entries (hardening removes them): {}",
                name_list_short(&unexpected, 10)
            ),
        );
    }
    if !a.c_link_ok {
        problems = true;
        out.add(
            Area::Prefix,
            Status::Warn,
            "dosdevices/c: is missing or does not point to drive_c".into(),
        );
    }
    if !a.outward.is_empty() {
        problems = true;
        out.add_list(
            Area::Prefix,
            Status::Fail,
            format!(
                "{} symbolic link(s) below drive_c lead outside it, so host files are reachable (hardening replaces them): {}",
                a.outward.len(),
                name_list_short(&a.outward, 5)
            ),
        );
    }
    if !problems {
        let ports = if a.extra_devices.is_empty() {
            ""
        } else {
            "; Wine recreates its com*/lpt* device links on every start, tolerated"
        };
        out.add(
            Area::Prefix,
            Status::Ok,
            format!("prefix hardened: dosdevices holds only c: and no link leaves drive_c{ports}"),
        );
    }
}

/// [`name_list`] for `shown` names.
fn name_list_short(names: &[String], shown: usize) -> String {
    let mut s = names
        .iter()
        .take(shown)
        .map(|n| quote_max(n, 60))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > shown {
        s.push_str(&format!(" and {} more", names.len() - shown));
    }
    s
}

fn program(program: Option<Result<&str, &str>>, out: &mut Out) {
    match program {
        None => {}
        Some(Ok(exe)) => out.add(Area::Program, Status::Ok, format!("program found: {}", clean(exe, 150))),
        Some(Err(why)) => out.add(Area::Program, Status::Fail, clean(why, 250)),
    }
}

#[cfg(test)]
mod tests;
