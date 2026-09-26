//! `runtime doctor [<app|file>] [--json]`: a read-only health report.
//!
//! * no argument: the system checks (host architecture, Wine, Vulkan, display, audio: the PulseAudio-compatible
//!   socket Wine 10 uses);
//! * an installed app id: those plus the app's program (PE facts, imports against Wine's DLLs, prefix state) and
//!   its Wine graphics driver setting (read from the prefix's `user.reg`, as `runtime display` does);
//! * a file (the target is classified like `run`'s: it contains `/` or ends in `.exe`/`.zip`): the same PE and
//!   import checks on the file, which is NOT installed. Only Wine's own DLLs count for its imports (the file's
//!   directory is not scanned: `runtime run <file>` copies just the file into a prefix).
//!
//! **Read-only.** Nothing is created, changed or removed: no data directory, no prefix, no `prepare` or
//! `harden`; the prefix is examined with `backend_wine::harden::audit_prefix`, which only reads. The only
//! process it starts is `wine --version`, with a cleared environment.
//!
//! **Output.** Sections in a fixed order (Architecture, PE, Imports, Graphics, Audio, Runtime, Prefix, Program),
//! one line per check, marked `[ok]`, `[warn]` or `[FAIL]` (plain ASCII on purpose: the same bytes on any
//! terminal and in logs), then `Result:`. `--json` prints `{"subject", "verdict", "checks": [{"area", "status",
//! "text"}]}`; `area`, `status` and `verdict` are stable, `text` is prose and NOT a stable API. Every untrusted
//! string is escaped (`safe`, `json_safe`).
//!
//! **Exit code.** 1 when the verdict is `fail`, and for usage and I/O errors (an unknown app id, a file that does
//! not exist); 0 otherwise (a warning is not a failure).
use crate::CmdError;
use crate::safe::{json_safe, safe};
use backend_wine::harden::{HardenError, audit_prefix};
use pe::PeInfo;
use rt_core::doctor::{
    Area, D3dFamily, D3dRoute, DoctorInput, FsProbe, HostFs, ListResult, MAX_LISTING, PeState, PrefixAudit,
    PrefixState, Report, Status, Subject, Verdict, doctor,
};
use rt_core::{AppId, CompatBackend, GraphicsDriver, Input, Launcher, Store, Target};
use rt_deps::wine_config::read_graphics_driver_from_prefix;
use serde_json::json;
use std::fmt::Write;
use std::path::{Path, PathBuf};

pub fn run(target: Option<&str>, as_json: bool) -> Result<u8, CmdError> {
    // The target first, before Wine is looked for: an unknown id is reported as that.
    let found = match target {
        Some(t) => {
            let store = crate::store()?;
            let found = rt_core::find_target(&store, t, Path::new("."))?;
            Some((store, found))
        }
        None => None,
    };
    // The error as text: what `doctor` shows for a Wine that could not be found.
    let wine = backend_wine::WineBackend::discover_with(Launcher::new()).map_err(|e| e.to_string());
    let wine_drivers = wine.as_ref().ok().and_then(|b| crate::display::wine_drivers(b));
    let facts = match &found {
        None => Facts::system(),
        Some((store, Target::Installed(id))) => Facts::app(store, id),
        Some((_, Target::File(path))) => Facts::file(path),
    };
    let sandbox_env = match &found {
        Some((store, Target::Installed(id))) => store.get(id).ok(),
        _ => None,
    };
    let sandbox = crate::sandbox::doctor_state(sandbox_env.as_ref());
    let hardening = crate::sandbox::doctor_hardening();
    let limits = crate::sandbox::doctor_limits(sandbox_env.as_ref());
    let report = doctor(DoctorInput {
        subject: facts.subject,
        host_arch: std::env::consts::ARCH,
        env: &|k| std::env::var_os(k),
        fs: &HostFs,
        backend: match &wine {
            Ok(b) => Ok(b as &dyn CompatBackend),
            Err(e) => Err(e.as_str()),
        },
        pe: match &facts.pe {
            Pe::Skipped => PeState::Skipped,
            Pe::Analysed(info) => PeState::Analysed(info),
            Pe::Unreadable(why) => PeState::Unreadable(why),
            Pe::Archive => PeState::Archive,
        },
        program: facts
            .program
            .as_ref()
            .map(|r| r.as_ref().map(String::as_str).map_err(String::as_str)),
        app_dir: facts.app_dir.as_ref(),
        prefix: facts.prefix,
        app_home: facts
            .app_home
            .as_ref()
            .map(|r| r.as_ref().map(|_| ()).map_err(String::as_str)),
        prefix_root: facts.prefix_root.as_deref(),
        vulkan: Some(crate::graphics::host()),
        vulkan_min: rt_deps::Manifest::bundled().max_min_vulkan(),
        wine_drivers: wine_drivers.as_deref(),
        graphics_driver: facts.graphics_driver.as_ref().map(|r| match r {
            Ok(d) => Ok(d.clone()),
            Err(e) => Err(e.as_str()),
        }),
        d3d_routes: facts.d3d_routes.as_deref(),
        sandbox: sandbox.as_ref().map(Option::as_deref).map_err(String::as_str),
        hardening: hardening.as_deref().map_err(String::as_str),
        limits: limits.as_deref().map_err(String::as_str),
    });
    crate::emit(&if as_json {
        render_json(&report)?
    } else {
        render(&report)
    })?;
    if let Some(h) = &facts.hint {
        eprintln!("{h}");
    }
    for n in &facts.notes {
        eprintln!("{n}");
    }
    Ok(u8::from(report.verdict == Verdict::Fail))
}

enum Pe {
    Skipped,
    Analysed(Box<PeInfo>),
    Unreadable(String),
    /// A zip archive: not analysed, and not an error either.
    Archive,
}

/// Everything about the target that is read from disk.
struct Facts {
    subject: Subject,
    pe: Pe,
    program: Option<Result<String, String>>,
    /// `None`: no program directory to look at.
    app_dir: Option<ListResult>,
    prefix: PrefixState,
    /// Installed apps only: [`backend_wine::check_app_home`], the check `run` makes, as text.
    app_home: Option<Result<(), String>>,
    prefix_root: Option<PathBuf>,
    /// Installed apps only: the missing-dependency hint, planned from the PE facts above (no second read).
    hint: Option<String>,
    /// Installed apps only: installer packages already in the prefix, which the runtime did not install.
    notes: Vec<String>,
    /// Installed apps only: the Wine graphics driver setting, or why `user.reg` could not be read.
    graphics_driver: Option<Result<GraphicsDriver, String>>,
    /// Installed apps whose program was analysed: the predicted Direct3D route per imported family. A file target
    /// has none: nothing is recorded as installed for it, so there is nothing to predict from.
    d3d_routes: Option<Vec<(D3dFamily, D3dRoute)>>,
}

impl Facts {
    fn system() -> Facts {
        Facts {
            subject: Subject::System,
            pe: Pe::Skipped,
            program: None,
            app_dir: None,
            prefix: PrefixState::NotApplicable,
            app_home: None,
            prefix_root: None,
            hint: None,
            notes: vec![],
            graphics_driver: None,
            d3d_routes: None,
        }
    }

    fn file(path: &Path) -> Facts {
        Facts {
            subject: Subject::File {
                path: path.to_string_lossy().into_owned(),
            },
            pe: read_pe(path),
            ..Facts::system()
        }
    }

    fn app(store: &Store, id: &AppId) -> Facts {
        let env = store.get(id).ok();
        let graphics_driver = env.as_ref().map(read_graphics_driver_from_prefix);
        match rt_core::resolve_program(store, id, backend_wine::BACKEND_ID) {
            Ok(p) => {
                let pe = read_pe(&p.exe);
                let exe = match &pe {
                    Pe::Analysed(info) => Ok(info.as_ref()),
                    Pe::Unreadable(why) => Err(why.as_str()),
                    Pe::Skipped | Pe::Archive => Err("not a PE file"),
                };
                let mut plan = rt_deps::plan_for_pe(
                    &p.metadata,
                    exe,
                    rt_deps::Manifest::bundled(),
                    &crate::graphics::verdict_for,
                );
                rt_deps::drop_present_installers(&p.env, rt_deps::Manifest::bundled(), &mut plan);
                let d3d_routes = match &pe {
                    Pe::Analysed(info) => Some(d3d_routes(id.as_str(), info, &plan)),
                    _ => None,
                };
                Facts {
                    d3d_routes,
                    subject: Subject::App {
                        id: id.to_string(),
                        name: Some(p.metadata.name.clone()),
                        version: p.metadata.version.clone(),
                    },
                    hint: crate::deps::hint_for(id.as_str(), &plan),
                    notes: crate::deps::present_notes(&plan),
                    pe,
                    program: Some(Ok(p.metadata.executable.clone())),
                    // Kept as it is: a directory that could not be read (or was cut) is reported by `doctor`.
                    app_dir: Some(HostFs.list(&p.cwd, MAX_LISTING)),
                    prefix: prefix_state(&p.env.prefix()),
                    app_home: Some(home_state(&p.env)),
                    prefix_root: Some(p.env.prefix()),
                    graphics_driver,
                }
            }
            // The program cannot be used, and that is the report: the name and the prefix are still shown.
            Err(e) => {
                let md = env.as_ref().and_then(|env| store.read_metadata(env).ok());
                Facts {
                    subject: Subject::App {
                        id: id.to_string(),
                        name: md.as_ref().map(|m| m.name.clone()),
                        version: md.and_then(|m| m.version),
                    },
                    program: Some(Err(e.to_string())),
                    prefix: env
                        .as_ref()
                        .map_or(PrefixState::NotApplicable, |env| prefix_state(&env.prefix())),
                    app_home: env.as_ref().map(home_state),
                    prefix_root: env.map(|env| env.prefix()),
                    graphics_driver,
                    ..Facts::system()
                }
            }
        }
    }
}

/// The Direct3D families `info` imports (sorted, once each) and the route each is predicted to take, from the
/// plan already made for the hint and the recorded packages (never from prefix files). The host's Vulkan is asked
/// through the shared, once-probed `verdict_for`, and only for an installed provider (a plan entry that would be
/// installed is already `Blocked` when Vulkan is unusable).
fn d3d_routes(app: &str, info: &PeInfo, plan: &rt_deps::AppPlan) -> Vec<(D3dFamily, D3dRoute)> {
    let mut families: Vec<D3dFamily> = info
        .imports
        .iter()
        .filter_map(|i| match rt_deps::capability_for(&i.dll)? {
            "d3d8" => Some(D3dFamily::D3d8),
            "d3d9" => Some(D3dFamily::D3d9),
            "d3d10core" => Some(D3dFamily::D3d10),
            "d3d11" => Some(D3dFamily::D3d11),
            "d3d12" => Some(D3dFamily::D3d12),
            _ => None,
        })
        .collect();
    families.sort();
    families.dedup();
    families
        .into_iter()
        .map(|f| {
            let (pkg, label, route) = match f {
                D3dFamily::D3d12 => ("vkd3d-proton", "vkd3d-proton", D3dRoute::Vkd3dProton),
                _ => ("dxvk", "DXVK", D3dRoute::Dxvk),
            };
            let builtin = |reason: String| D3dRoute::Wined3d {
                reason,
                actionable: true,
            };
            let plain = |reason: String| D3dRoute::Wined3d {
                reason,
                actionable: false,
            };
            let entry = plan.plan.entries.iter().find(|e| e.package == pkg);
            // Installed for 64-bit only: a 32-bit app keeps Wine's built-in DLL, whatever is recorded.
            let x64_only = info.arch == pe::Arch::X86
                && rt_deps::Manifest::bundled()
                    .get(pkg)
                    .is_some_and(|p| p.provides.iter().any(|c| rt_deps::X64_ONLY_CAPS.contains(&c.as_str())));
            let route = match entry.map(|e| &e.action) {
                Some(_) if x64_only => plain(format!(
                    "{label} covers 64-bit only; this 32-bit app uses Wine's built-in Direct3D"
                )),
                None => plain(format!("no package provides {}", family_name(f))),
                Some(rt_deps::Action::Install) => {
                    builtin(format!("{label} not installed: run `runtime deps {app} --install`"))
                }
                Some(rt_deps::Action::Blocked { reason }) => builtin(reason.clone()),
                Some(rt_deps::Action::AlreadyInstalled) => {
                    let min = rt_deps::Manifest::bundled().get(pkg).and_then(|p| p.min_vulkan);
                    match crate::graphics::verdict_for(min) {
                        // Recorded DLLs win over Wine's and nothing at launch consults Vulkan, so this app fails.
                        // (`runtime deps` does not warn about an installed package: block_for_vulkan skips it.)
                        rt_core::VulkanVerdict::Unusable(why) => D3dRoute::Broken { reason: why },
                        _ => route,
                    }
                }
            };
            (f, route)
        })
        .collect()
}

fn family_name(f: D3dFamily) -> &'static str {
    match f {
        D3dFamily::D3d8 => "Direct3D 8",
        D3dFamily::D3d9 => "Direct3D 9",
        D3dFamily::D3d10 => "Direct3D 10",
        D3dFamily::D3d11 => "Direct3D 11",
        D3dFamily::D3d12 => "Direct3D 12",
    }
}

/// Reads and analyses `path` like `install` does (regular files only, at most 4 GiB, no FIFO hang).
fn read_pe(path: &Path) -> Pe {
    match rt_core::read_input(path) {
        Ok(Input::Pe(bytes)) => match pe::analyze(&bytes) {
            Ok(info) => Pe::Analysed(Box::new(info)),
            Err(e) => Pe::Unreadable(e.to_string()),
        },
        Ok(Input::Zip(_)) => Pe::Archive,
        Err(e) => Pe::Unreadable(e.to_string()),
    }
}

/// What `run` would say about the app's `HOME` directory (`Ok` when it is a real directory).
fn home_state(env: &rt_core::AppEnv) -> Result<(), String> {
    backend_wine::check_app_home(env).map_err(|e| e.to_string())
}

/// The read-only audit of `prefix`, in the words of `doctor`.
fn prefix_state(prefix: &Path) -> PrefixState {
    let lossy = |p: &Path| p.to_string_lossy().into_owned();
    match audit_prefix(prefix) {
        Ok(r) => PrefixState::Audit(PrefixAudit {
            extra_devices: r.extra_devices.iter().map(|d| lossy(Path::new(d))).collect(),
            c_link_ok: r.c_link_ok,
            outward: r.outward.iter().map(|p| lossy(p)).collect(),
            incomplete: None,
        }),
        // Not examined completely: a warning, not a verdict on what was not seen.
        Err(e @ (HardenError::TooDeep { .. } | HardenError::TooManyEntries { .. })) => {
            PrefixState::Audit(PrefixAudit {
                incomplete: Some(e.to_string()),
                ..PrefixAudit::default()
            })
        }
        Err(e) => {
            let gone =
                |p: &Path| matches!(std::fs::symlink_metadata(p), Err(io) if io.kind() == std::io::ErrorKind::NotFound);
            if gone(prefix) {
                PrefixState::Missing
            } else if matches!(e, HardenError::NotADirectory { .. }) && gone(&prefix.join("drive_c")) {
                // A prefix directory without drive_c: something began to create it and did not finish.
                PrefixState::Incomplete("drive_c missing".into())
            } else {
                PrefixState::Unexaminable(e.to_string())
            }
        }
    }
}

// ---------------------------------------------------------------- output

/// The order of the sections.
const ORDER: [Area; 8] = [
    Area::Architecture,
    Area::Pe,
    Area::Imports,
    Area::Graphics,
    Area::Audio,
    Area::Runtime,
    Area::Prefix,
    Area::Program,
];

/// The stable JSON name and the heading of an area.
fn names(area: Area) -> (&'static str, &'static str) {
    match area {
        Area::Architecture => ("architecture", "Architecture"),
        Area::Pe => ("pe", "PE"),
        Area::Imports => ("imports", "Imports"),
        Area::Graphics => ("graphics", "Graphics"),
        Area::Audio => ("audio", "Audio"),
        Area::Runtime => ("runtime", "Runtime"),
        Area::Prefix => ("prefix", "Prefix"),
        Area::Program => ("program", "Program"),
    }
}

fn status_id(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Warn => "warn",
        Status::Fail => "fail",
    }
}

fn verdict_id(v: Verdict) -> &'static str {
    match v {
        Verdict::Good => "good",
        Verdict::MayFail => "may_fail",
        Verdict::Fail => "fail",
    }
}

fn render(report: &Report) -> String {
    let mut o = String::from("Runtime Diagnostics\n\n");
    let _ = match &report.subject {
        Subject::System => writeln!(o, "System checks (no application given)"),
        Subject::File { path } => writeln!(o, "File: {}", safe(path)),
        Subject::App { id, name, version } => {
            let name = name
                .as_deref()
                .map_or_else(|| safe(id), |n| format!("{} ({})", safe(n), safe(id)));
            match version {
                Some(v) => writeln!(o, "Application: {name}, version {}", safe(v)),
                None => writeln!(o, "Application: {name}"),
            }
        }
    };
    for area in ORDER {
        let label = names(area).1;
        let checks: Vec<_> = report.checks.iter().filter(|c| c.area == area).collect();
        if checks.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n{label}");
        for c in checks {
            let mark = match c.status {
                Status::Ok => "[ok]",
                Status::Warn => "[warn]",
                Status::Fail => "[FAIL]",
            };
            let _ = writeln!(o, "  {mark:<6} {}", safe(&c.text));
        }
    }
    let result = match report.verdict {
        Verdict::Good => "Looks good.",
        Verdict::MayFail => "Application may fail to start.",
        Verdict::Fail => "Application cannot run: fix the items marked [FAIL].",
    };
    let _ = write!(o, "\nResult: {result}\n");
    o
}

fn render_json(report: &Report) -> Result<String, CmdError> {
    let subject = match &report.subject {
        Subject::System => json!({"kind": "system"}),
        Subject::File { path } => json!({"kind": "file", "path": path}),
        Subject::App { id, name, version } => json!({"kind": "app", "id": id, "name": name, "version": version}),
    };
    let checks: Vec<_> = report
        .checks
        .iter()
        .map(|c| json!({"area": names(c.area).0, "status": status_id(c.status), "text": c.text}))
        .collect();
    let doc = json!({"subject": subject, "verdict": verdict_id(report.verdict), "checks": checks});
    Ok(format!("{}\n", json_safe(&serde_json::to_string_pretty(&doc)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::doctor::Check;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn check(area: Area, status: Status, text: &str) -> Check {
        Check {
            area,
            status,
            text: text.into(),
        }
    }

    #[test]
    fn the_layout_is_sections_in_order_marks_and_a_result_line() {
        let report = Report {
            subject: Subject::App {
                id: "app".into(),
                name: Some("My \u{1b}[31mApp".into()),
                version: Some("1.0".into()),
            },
            checks: vec![
                check(Area::Runtime, Status::Ok, "Wine: wine-10.0"),
                check(Area::Architecture, Status::Ok, "host architecture: x86-64"),
                check(Area::Imports, Status::Warn, "1 imported DLL not found: \"a.dll\""),
                check(Area::Prefix, Status::Fail, "a link leaves drive_c"),
            ],
            verdict: Verdict::Fail,
        };
        let want = "Runtime Diagnostics\n\
                    \n\
                    Application: My \\u{1b}[31mApp (app), version 1.0\n\
                    \n\
                    Architecture\n  [ok]   host architecture: x86-64\n\
                    \n\
                    Imports\n  [warn] 1 imported DLL not found: \"a.dll\"\n\
                    \n\
                    Runtime\n  [ok]   Wine: wine-10.0\n\
                    \n\
                    Prefix\n  [FAIL] a link leaves drive_c\n\
                    \n\
                    Result: Application cannot run: fix the items marked [FAIL].\n";
        assert_eq!(render(&report), want);
        for (verdict, line) in [
            (Verdict::Good, "Result: Looks good.\n"),
            (Verdict::MayFail, "Result: Application may fail to start.\n"),
        ] {
            let r = Report {
                subject: Subject::System,
                checks: vec![],
                verdict,
            };
            let out = render(&r);
            assert!(out.ends_with(line), "{out}");
            assert!(out.contains("System checks (no application given)"));
        }
    }

    #[test]
    fn a_file_subject_and_an_app_without_a_name_are_escaped_too() {
        let r = Report {
            subject: Subject::File {
                path: "a\u{1b}b\u{202e}.exe".into(),
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        let out = render(&r);
        assert!(out.contains("File: a\\u{1b}b\\u{202e}.exe"), "{out}");
        let r = Report {
            subject: Subject::App {
                id: "x".into(),
                name: None,
                version: None,
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        assert!(render(&r).contains("Application: x\n"));
        let r = Report {
            subject: Subject::App {
                id: "x".into(),
                name: Some("n\u{202e}".into()),
                version: Some("1\u{1b}[31m\u{9b}".into()),
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        let out = render(&r);
        assert!(
            out.contains("Application: n\\u{202e} (x), version 1\\u{1b}[31m\\u{9b}\n"),
            "{out}"
        );
    }

    #[test]
    fn a_check_text_is_escaped_even_though_core_already_escapes_it() {
        let r = Report {
            subject: Subject::System,
            checks: vec![check(Area::Runtime, Status::Warn, "x\u{1b}]0;t\u{7}\u{202e}")],
            verdict: Verdict::MayFail,
        };
        let out = render(&r);
        assert!(out.contains("x\\u{1b}]0;t\\u{7}\\u{202e}"), "{out}");
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
    }

    fn prefix_with_c() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("prefix");
        fs::create_dir_all(p.join("drive_c/users")).unwrap();
        fs::create_dir_all(p.join("dosdevices")).unwrap();
        symlink("../drive_c", p.join("dosdevices/c:")).unwrap();
        t
    }

    fn audit_of(t: &tempfile::TempDir) -> PrefixState {
        prefix_state(&t.path().join("prefix"))
    }

    #[test]
    fn the_prefix_audit_is_mapped_for_doctor() {
        // a hardened prefix
        let t = prefix_with_c();
        assert_eq!(
            audit_of(&t),
            PrefixState::Audit(PrefixAudit {
                c_link_ok: true,
                ..PrefixAudit::default()
            })
        );
        // z:, com1 and a link that leaves drive_c
        let p = t.path().join("prefix");
        symlink("/", p.join("dosdevices/z:")).unwrap();
        symlink("/dev/ttyS0", p.join("dosdevices/com1")).unwrap();
        symlink("/etc", p.join("drive_c/users/Desktop")).unwrap();
        let PrefixState::Audit(a) = audit_of(&t) else {
            panic!("not an audit")
        };
        assert_eq!(a.extra_devices, ["com1", "z:"]);
        assert_eq!(a.outward, ["drive_c/users/Desktop"]);
        assert!(a.c_link_ok && a.incomplete.is_none());
        // no prefix at all: not an error, "no prefix yet"
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(audit_of(&empty), PrefixState::Missing);
    }

    #[test]
    fn a_prefix_that_cannot_be_audited_is_not_reported_as_clean() {
        // drive_c is a symlink: refused, and that is a failure to examine
        let t = prefix_with_c();
        let p = t.path().join("prefix");
        fs::rename(p.join("drive_c"), t.path().join("real")).unwrap();
        symlink(t.path().join("real"), p.join("drive_c")).unwrap();
        assert!(matches!(audit_of(&t), PrefixState::Unexaminable(_)));
        // the prefix exists but has no drive_c: incomplete (a warning), not "cannot be examined"
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("prefix")).unwrap();
        assert_eq!(audit_of(&t), PrefixState::Incomplete("drive_c missing".into()));
        // drive_c is a file, the prefix is a file: those are not "missing"
        fs::create_dir_all(t.path().join("prefix")).unwrap();
        fs::write(t.path().join("prefix/drive_c"), b"x").unwrap();
        assert!(matches!(audit_of(&t), PrefixState::Unexaminable(_)));
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("prefix"), b"x").unwrap();
        assert!(matches!(audit_of(&t), PrefixState::Unexaminable(_)));
        // too deep to examine: incomplete, not clean and not a failure
        let t = prefix_with_c();
        let mut deep = t.path().join("prefix/drive_c");
        for i in 0..(backend_wine::harden::MAX_DEPTH + 2) {
            deep.push(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        let PrefixState::Audit(a) = audit_of(&t) else {
            panic!("not an audit")
        };
        assert!(a.incomplete.is_some(), "{a:?}");
    }

    #[test]
    fn json_names_are_stable() {
        let all = [
            (Area::Architecture, "architecture"),
            (Area::Pe, "pe"),
            (Area::Imports, "imports"),
            (Area::Graphics, "graphics"),
            (Area::Audio, "audio"),
            (Area::Runtime, "runtime"),
            (Area::Prefix, "prefix"),
            (Area::Program, "program"),
        ];
        for (area, id) in all {
            assert_eq!(names(area).0, id);
            assert!(ORDER.contains(&area));
        }
        assert_eq!(ORDER.len(), all.len());
        assert_eq!(
            [status_id(Status::Ok), status_id(Status::Warn), status_id(Status::Fail)],
            ["ok", "warn", "fail"]
        );
        assert_eq!(
            [
                verdict_id(Verdict::Good),
                verdict_id(Verdict::MayFail),
                verdict_id(Verdict::Fail)
            ],
            ["good", "may_fail", "fail"]
        );
    }
}

#[cfg(test)]
mod route_tests {
    /// `doctor` says "Vulkan not verified" from the one minimum it is given (the bundled maximum), while the
    /// route asks for each provider's own minimum: they agree only while both providers share it.
    #[test]
    fn both_direct3d_providers_share_the_bundled_vulkan_minimum() {
        let m = rt_deps::Manifest::bundled();
        let min = |id: &str| m.get(id).unwrap().min_vulkan;
        assert_eq!(min("dxvk"), m.max_min_vulkan());
        assert_eq!(min("vkd3d-proton"), m.max_min_vulkan());
    }
}
