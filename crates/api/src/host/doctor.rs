//! What `doctor` looks at, gathered from the host and the app's directory: the target's facts ([`Facts`]: PE,
//! imports, prefix audit, program, home, graphics driver setting, predicted Direct3D routes, .NET state, dependency
//! plan) and the host's (Wine, its driver modules, the sandbox, hardening and limits), turned into the core's
//! [`Report`] by [`report`]. The stable names of areas, statuses and verdicts ([`area_id`], [`status_id`],
//! [`verdict_id`]) are the ones `doctor --json` prints and the API returns.
//!
//! **Read-only.** Nothing is created, changed or removed: no data directory, no prefix, no `prepare` or `harden`;
//! the prefix is examined with `backend_wine::harden::audit_prefix`, which only reads, and the program is located
//! with `rt_core::resolve_program` (contained in `drive_c`, no symlink followed) and read with the size-capped
//! `rt_core::read_input`. The only processes it starts are `wine --version` (cleared environment) and the bounded
//! host probes (`vulkaninfo`, bwrap's probe, the `systemd-run` scope probe).
use backend_wine::harden::{HardenError, audit_prefix};
use pe::PeInfo;
use rt_core::doctor::{
    Area, D3dFamily, D3dRoute, DoctorInput, DotnetState, FsProbe, HostFs, ListResult, MAX_DLL_DIRS, MAX_LISTING,
    PeState, PrefixAudit, PrefixState, Report, Status, Subject, Verdict, doctor,
};
use rt_core::{AppEnv, AppId, CompatBackend, GraphicsDriver, HostVulkan, Input, Launcher, Store};
use rt_deps::VulkanFor;
use rt_deps::wine_config::read_graphics_driver_from_prefix;
use std::fs;
use std::path::{Path, PathBuf};

/// The report for `facts` on this host: Wine is looked for (its discovery error, with the install hint, is a
/// failing check), `vulkan` is the host's Vulkan (the caller's probe, cached as it sees fit).
pub fn report(facts: &Facts, vulkan: &HostVulkan) -> Report {
    // The error as text: what `doctor` shows for a Wine that could not be found.
    let wine = backend_wine::WineBackend::discover_with(Launcher::new()).map_err(|e| e.to_string());
    let wine_drivers = wine.as_ref().ok().and_then(|b| wine_drivers(b));
    let sandbox = crate::host::sandbox::doctor_state(facts.env.as_ref());
    let hardening = crate::host::sandbox::doctor_hardening();
    let limits = crate::host::sandbox::doctor_limits(facts.env.as_ref());
    doctor(DoctorInput {
        subject: facts.subject.clone(),
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
        prefix: facts.prefix.clone(),
        app_home: facts
            .app_home
            .as_ref()
            .map(|r| r.as_ref().map(|_| ()).map_err(String::as_str)),
        prefix_root: facts.prefix_root.as_deref(),
        vulkan: Some(vulkan),
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
        dotnet: facts.dotnet.clone(),
    })
}

/// The stable name of an area (`doctor --json`'s `area`).
pub fn area_id(area: Area) -> &'static str {
    match area {
        Area::Architecture => "architecture",
        Area::Pe => "pe",
        Area::Imports => "imports",
        Area::Graphics => "graphics",
        Area::Audio => "audio",
        Area::Runtime => "runtime",
        Area::Prefix => "prefix",
        Area::Program => "program",
    }
}

pub fn status_id(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Warn => "warn",
        Status::Fail => "fail",
    }
}

pub fn verdict_id(v: Verdict) -> &'static str {
    match v {
        Verdict::Good => "good",
        Verdict::MayFail => "may_fail",
        Verdict::Fail => "fail",
    }
}

/// Driver names kept at most.
const MAX_DRIVERS: usize = 200;

/// The `wine*.drv` names (lowercase) among `entries`; `None` when an entry could not be read or there are more
/// than [`MAX_LISTING`] of them (a refusal must never rest on a partly read directory).
fn drivers_in(entries: impl Iterator<Item = std::io::Result<String>>) -> Option<Vec<String>> {
    let mut found = Vec::new();
    for (i, e) in entries.enumerate() {
        let n = e.ok()?.to_ascii_lowercase();
        if i >= MAX_LISTING {
            return None;
        }
        if n.starts_with("wine") && n.ends_with(".drv") && found.len() < MAX_DRIVERS && !found.contains(&n) {
            found.push(n);
        }
    }
    Some(found)
}

/// File names (lowercase) of the Wine driver modules (`wine*.drv`) in the backend's DLL directories: at most
/// [`MAX_DRIVERS`], from at most [`MAX_DLL_DIRS`] directories. `None` when none of the directories could be listed
/// or one was read only in part. `doctor` and `runtime display` both use it.
pub fn wine_drivers(backend: &dyn CompatBackend) -> Option<Vec<String>> {
    let mut found: Vec<String> = Vec::new();
    let mut verified = false;
    for dir in backend.dll_dirs().iter().take(MAX_DLL_DIRS) {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        let names = rd.map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()));
        for n in drivers_in(names)? {
            if found.len() < MAX_DRIVERS && !found.contains(&n) {
                found.push(n);
            }
        }
        verified = true;
    }
    verified.then_some(found)
}

pub enum Pe {
    Skipped,
    Analysed(Box<PeInfo>),
    Unreadable(String),
    /// A zip archive: not analysed, and not an error either.
    Archive,
}

/// Everything about the target that is read from disk.
pub struct Facts {
    pub subject: Subject,
    pub pe: Pe,
    pub program: Option<Result<String, String>>,
    /// `None`: no program directory to look at.
    pub app_dir: Option<ListResult>,
    pub prefix: PrefixState,
    /// Installed apps only: [`backend_wine::check_app_home`], the check `run` makes, as text.
    pub app_home: Option<Result<(), String>>,
    pub prefix_root: Option<PathBuf>,
    /// Installed apps whose program resolved: the dependency plan, made from the PE facts above (no second read);
    /// the missing-dependency hint and the "already in the prefix" notes come from it.
    pub plan: Option<rt_deps::AppPlan>,
    /// Installed apps whose environment could be opened: the sandbox, hardening and limits checks look at it.
    pub env: Option<AppEnv>,
    /// Installed apps only: the Wine graphics driver setting, or why `user.reg` could not be read.
    pub graphics_driver: Option<Result<GraphicsDriver, String>>,
    /// Installed apps whose program was analysed: the predicted Direct3D route per imported family. A file target
    /// has none: nothing is recorded as installed for it, so there is nothing to predict from.
    d3d_routes: Option<Vec<(D3dFamily, D3dRoute)>>,
    /// Managed or not, and for an installed app whether its metadata records Wine Mono (never the prefix's files).
    pub dotnet: DotnetState,
}

impl Facts {
    pub fn system() -> Facts {
        Facts {
            subject: Subject::System,
            pe: Pe::Skipped,
            program: None,
            app_dir: None,
            prefix: PrefixState::NotApplicable,
            app_home: None,
            prefix_root: None,
            plan: None,
            env: None,
            graphics_driver: None,
            d3d_routes: None,
            dotnet: DotnetState::NotManaged,
        }
    }

    /// A file that is NOT installed (the CLI's `doctor <file>`): the PE checks only.
    pub fn file(path: &Path) -> Facts {
        let pe = read_pe(path);
        Facts {
            dotnet: dotnet_state(&pe, None),
            subject: Subject::File {
                path: path.to_string_lossy().into_owned(),
            },
            pe,
            ..Facts::system()
        }
    }

    /// An installed app. `vulkan` answers the dependency plan and the Direct3D routes (asked only when they need
    /// it).
    pub fn app(store: &Store, id: &AppId, vulkan: VulkanFor<'_>) -> Facts {
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
                let mut plan = rt_deps::plan_for_pe(&p.metadata, exe, rt_deps::Manifest::bundled(), vulkan);
                rt_deps::drop_present_installers(&p.env, rt_deps::Manifest::bundled(), &mut plan);
                let d3d_routes = match &pe {
                    Pe::Analysed(info) => Some(d3d_routes(id.as_str(), info, &plan, vulkan)),
                    _ => None,
                };
                Facts {
                    d3d_routes,
                    dotnet: dotnet_state(&pe, Some(&p.metadata)),
                    subject: Subject::App {
                        id: id.to_string(),
                        name: Some(p.metadata.name.clone()),
                        version: p.metadata.version.clone(),
                    },
                    env,
                    plan: Some(plan),
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
                    prefix_root: env.as_ref().map(|env| env.prefix()),
                    graphics_driver,
                    env,
                    ..Facts::system()
                }
            }
        }
    }
}

/// `.NET` state from the analysed PE and the recorded dependencies (`None`: a file, which has no record).
fn dotnet_state(pe: &Pe, md: Option<&rt_core::Metadata>) -> DotnetState {
    match pe {
        Pe::Analysed(info) if info.dotnet => match md.and_then(|m| m.dependency(rt_core::DOTNET_PACKAGE_ID)) {
            Some(d) => DotnetState::ManagedMonoInstalled {
                version: d.version.clone(),
            },
            None => DotnetState::ManagedNeedsMono,
        },
        _ => DotnetState::NotManaged,
    }
}

/// The Direct3D families `info` imports (sorted, once each) and the route each is predicted to take, from the
/// plan already made for the hint and the recorded packages (never from prefix files). The host's Vulkan is asked
/// through `vulkan`, and only for an installed provider (a plan entry that would be
/// installed is already `Blocked` when Vulkan is unusable).
fn d3d_routes(app: &str, info: &PeInfo, plan: &rt_deps::AppPlan, vulkan: VulkanFor<'_>) -> Vec<(D3dFamily, D3dRoute)> {
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
                    match vulkan(min) {
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
pub fn read_pe(path: &Path) -> Pe {
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
pub fn prefix_state(prefix: &Path) -> PrefixState {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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
            assert_eq!(area_id(area), id);
        }
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

    fn ok(n: &str) -> std::io::Result<String> {
        Ok(n.to_owned())
    }

    #[test]
    fn keeps_wine_drivers_only() {
        let l = drivers_in([ok("WinePulse.drv"), ok("kernel32.dll"), ok("winealsa.drv")].into_iter());
        assert_eq!(l.unwrap(), ["winepulse.drv", "winealsa.drv"]);
        assert_eq!(drivers_in(std::iter::empty()), Some(vec![]));
    }

    #[test]
    fn an_unreadable_entry_means_not_verified() {
        let bad = Err(std::io::Error::other("boom"));
        assert_eq!(drivers_in([ok("winepulse.drv"), bad].into_iter()), None);
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
