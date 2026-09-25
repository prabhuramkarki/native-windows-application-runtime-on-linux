use super::*;
use crate::fake::FakeBackend;
use crate::{BackendError, backend::Detail};
use pe::{Arch, Format, Import, ImportedFn, Installer, InstallerKind, Kind, Subsystem};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

// ---------------------------------------------------------------- a fake host

#[derive(Default)]
struct Host {
    env: HashMap<String, String>,
    files: HashSet<PathBuf>,
    dirs: HashMap<PathBuf, Vec<String>>,
    /// Directories that exist but cannot be read.
    unreadable: HashSet<PathBuf>,
    /// Entries of a directory that could not be read.
    errors: HashMap<PathBuf, usize>,
    /// The `cap` of every `list` call, in order.
    list_caps: RefCell<Vec<usize>>,
    listed: RefCell<Vec<PathBuf>>,
}

impl FsProbe for Host {
    fn exists(&self, p: &Path) -> bool {
        self.files.contains(p) || self.dirs.contains_key(p)
    }
    fn list(&self, dir: &Path, cap: usize) -> ListResult {
        self.list_caps.borrow_mut().push(cap);
        self.listed.borrow_mut().push(dir.to_owned());
        if self.unreadable.contains(dir) {
            return Err(ListError::Unreadable);
        }
        let names = self.dirs.get(dir).ok_or(ListError::NotFound)?;
        Ok(Listing {
            names: names.iter().take(cap).cloned().collect(),
            truncated: names.len() > cap,
            errors: self.errors.get(dir).copied().unwrap_or(0),
        })
    }
}

impl Host {
    fn env(mut self, k: &str, v: &str) -> Host {
        self.env.insert(k.into(), v.into());
        self
    }
    fn file(mut self, p: &str) -> Host {
        self.files.insert(p.into());
        self
    }
    fn dir(mut self, p: &str, names: &[&str]) -> Host {
        self.dirs
            .insert(p.into(), names.iter().map(|s| (*s).to_owned()).collect());
        self
    }
    fn unreadable(mut self, p: &str) -> Host {
        self.unreadable.insert(p.into());
        self
    }
    fn errors(mut self, p: &str, n: usize) -> Host {
        self.errors.insert(p.into(), n);
        self
    }
    /// A desktop with Wayland, PipeWire and Vulkan.
    fn desktop() -> Host {
        Host::default()
            .env("WAYLAND_DISPLAY", "wayland-0")
            .env("XDG_RUNTIME_DIR", "/run/user/1000")
            .file("/run/user/1000/wayland-0")
            .file("/run/user/1000/pipewire-0")
            .file("/usr/lib/x86_64-linux-gnu/libvulkan.so.1")
    }
}

const WINE_DLLS: &str = "/wine/x86_64-windows";

/// A complete listing of `names`.
fn listing(names: &[&str]) -> Listing {
    Listing {
        names: names.iter().map(|s| (*s).to_owned()).collect(),
        ..Listing::default()
    }
}

fn pe_info() -> PeInfo {
    PeInfo {
        format: Format::Pe32Plus,
        arch: Arch::X86_64,
        machine: 0x8664,
        kind: Kind::Exe,
        subsystem: Subsystem::Console,
        subsystem_raw: 3,
        image_base: 0x1_4000_0000,
        entry_point_rva: 0x1000,
        size_of_image: 0x10000,
        aslr: true,
        nx: true,
        signed: false,
        dotnet: false,
        sections: vec![],
        imports: vec![],
        exports: vec![],
        relocation_count: 0,
        tls: None,
        version: None,
        installer: None,
        warnings: vec![],
    }
}

fn import(dll: &str, delay: bool) -> Import {
    Import {
        dll: dll.into(),
        delay,
        functions: vec![ImportedFn::Name("F".into())],
    }
}

/// One scenario; `run` hands everything to `doctor` by reference.
struct Sc {
    subject: Subject,
    arch: String,
    host: Host,
    backend: Result<FakeBackend, String>,
    pe: Option<Result<PeInfo, String>>,
    program: Option<Result<String, String>>,
    app_dir: Option<ListResult>,
    prefix: PrefixState,
    app_home: Option<Result<(), String>>,
    prefix_root: Option<PathBuf>,
    vulkan: Option<crate::HostVulkan>,
    vulkan_min: Option<(u32, u32)>,
}

/// A system report on a good desktop.
fn sc() -> Sc {
    Sc {
        subject: Subject::System,
        arch: "x86_64".into(),
        host: Host::desktop().dir(WINE_DLLS, &["kernel32.dll", "user32.dll", "msvcrt.dll"]),
        backend: Ok(FakeBackend::new().with_dll_dirs(vec![WINE_DLLS.into()])),
        pe: None,
        program: None,
        app_dir: None,
        prefix: PrefixState::NotApplicable,
        app_home: None,
        prefix_root: None,
        vulkan: None,
        vulkan_min: None,
    }
}

/// An app report: a PE that imports `imports`.
fn app(imports: Vec<Import>) -> Sc {
    let mut info = pe_info();
    info.imports = imports;
    Sc {
        subject: Subject::App {
            id: "app".into(),
            name: Some("App".into()),
            version: None,
        },
        pe: Some(Ok(info)),
        program: Some(Ok("C:\\Program Files\\app\\app.exe".into())),
        app_home: Some(Ok(())),
        prefix: PrefixState::Audit(PrefixAudit {
            c_link_ok: true,
            ..PrefixAudit::default()
        }),
        ..sc()
    }
}

impl Sc {
    fn info(&mut self) -> &mut PeInfo {
        self.pe.as_mut().unwrap().as_mut().unwrap()
    }

    fn run(&self) -> Report {
        let env = |k: &str| self.host.env.get(k).map(OsString::from);
        let pe = match &self.pe {
            None => PeState::Skipped,
            Some(Ok(i)) => PeState::Analysed(i),
            Some(Err(e)) => PeState::Unreadable(e),
        };
        doctor(DoctorInput {
            subject: self.subject.clone(),
            host_arch: &self.arch,
            env: &env,
            fs: &self.host,
            backend: match &self.backend {
                Ok(b) => Ok(b as &dyn CompatBackend),
                Err(e) => Err(e.as_str()),
            },
            pe,
            program: self.program.as_ref().map(|r| match r {
                Ok(s) => Ok(s.as_str()),
                Err(s) => Err(s.as_str()),
            }),
            app_dir: self.app_dir.as_ref(),
            prefix: self.prefix.clone(),
            app_home: self
                .app_home
                .as_ref()
                .map(|r| r.as_ref().map(|_| ()).map_err(String::as_str)),
            prefix_root: self.prefix_root.as_deref(),
            vulkan: self.vulkan.as_ref(),
            vulkan_min: self.vulkan_min,
        })
    }
}

fn of(r: &Report, area: Area) -> Vec<&Check> {
    r.checks.iter().filter(|c| c.area == area).collect()
}

/// The one check of `area` whose text contains `needle`.
fn one<'a>(r: &'a Report, area: Area, needle: &str) -> &'a Check {
    let hits: Vec<&Check> = of(r, area).into_iter().filter(|c| c.text.contains(needle)).collect();
    assert_eq!(hits.len(), 1, "{area:?} {needle:?} in {:#?}", r.checks);
    hits[0]
}

fn assert_tame(text: &str) {
    for c in text.chars() {
        assert!(
            !c.is_control()
                && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}' | '\u{feff}'),
            "U+{:04X} in {text:?}",
            c as u32
        );
    }
}

// ---------------------------------------------------------------- the system checks

#[test]
fn a_good_desktop_gives_ok_everywhere_and_a_good_verdict() {
    let r = sc().run();
    assert_eq!(r.subject, Subject::System);
    assert_eq!(r.verdict, Verdict::Good, "{:#?}", r.checks);
    assert!(r.checks.iter().all(|c| c.status == Status::Ok), "{:#?}", r.checks);
    for area in [Area::Architecture, Area::Runtime, Area::Graphics, Area::Audio] {
        assert!(!of(&r, area).is_empty(), "{area:?}");
    }
    // A system report has no application checks.
    for area in [Area::Pe, Area::Imports, Area::Prefix, Area::Program] {
        assert!(of(&r, area).is_empty(), "{area:?}");
    }
    assert!(one(&r, Area::Architecture, "x86-64").status == Status::Ok);
    assert!(
        one(&r, Area::Runtime, "fake-1.0").status == Status::Ok,
        "the version is shown"
    );
}

#[test]
fn a_host_that_is_not_x86_64_fails() {
    for arch in ["aarch64", "x86", "riscv64", "", "x86_64\x1b[31m"] {
        let mut s = sc();
        s.arch = arch.into();
        let r = s.run();
        let c = one(&r, Area::Architecture, "x86-64");
        assert_eq!(c.status, Status::Fail, "{arch:?}");
        assert!(c.text.contains("Phase 9"), "{}", c.text);
        assert_eq!(r.verdict, Verdict::Fail);
        assert_tame(&c.text);
    }
}

#[test]
fn a_missing_wine_fails_with_the_install_hint_and_hostile_text_is_escaped() {
    let mut s = sc();
    s.backend = Err("compatibility backend not available: Wine was not found; install it, e.g. `sudo apt install wine`, or set $RUNTIME_WINE".into());
    let r = s.run();
    let c = one(&r, Area::Runtime, "Wine");
    assert_eq!(c.status, Status::Fail);
    assert!(c.text.contains("sudo apt install wine"), "{}", c.text);
    assert_eq!(r.verdict, Verdict::Fail);

    let mut s = sc();
    s.backend = Err(format!(
        "RUNTIME_WINE points to \"\x1b]0;x\x07\u{202e}{}\"",
        "z".repeat(5000)
    ));
    let c = s.run().checks.into_iter().find(|c| c.area == Area::Runtime).unwrap();
    assert_eq!(c.status, Status::Fail);
    assert_tame(&c.text);
    assert!(c.text.chars().count() <= 300, "{}", c.text.chars().count());
}

/// A backend whose `wine --version` fails, or prints hostile text (`Some`).
struct NoVersion(Option<&'static str>);

impl CompatBackend for NoVersion {
    fn id(&self) -> &'static str {
        "wine"
    }
    fn version(&self) -> Result<String, BackendError> {
        match self.0 {
            Some(v) => Ok(v.to_owned()),
            None => Err(BackendError::Failed {
                what: "wine --version",
                detail: Detail::from_bytes(b"boom \x1b[31m"),
            }),
        }
    }
    fn prepare(&self, _: &crate::AppEnv) -> Result<(), BackendError> {
        unreachable!()
    }
    fn command(
        &self,
        _: &crate::AppEnv,
        _: &Path,
        _: &Path,
        _: &[std::ffi::OsString],
        _: &crate::RunOpts,
    ) -> Result<std::process::Command, BackendError> {
        unreachable!()
    }
    fn stop(&self, _: &crate::AppEnv) -> Result<(), BackendError> {
        unreachable!()
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
}

#[test]
fn a_wine_whose_version_cannot_be_read_is_a_warning_with_escaped_text() {
    let s = sc();
    let env = |k: &str| s.host.env.get(k).map(OsString::from);
    let r = doctor(DoctorInput {
        subject: Subject::System,
        host_arch: "x86_64",
        env: &env,
        fs: &s.host,
        backend: Ok(&NoVersion(None)),
        pe: PeState::Skipped,
        program: None,
        app_dir: None,
        prefix: PrefixState::NotApplicable,
        app_home: None,
        prefix_root: None,
        vulkan: None,
        vulkan_min: None,
    });
    let c = one(&r, Area::Runtime, "version");
    assert_eq!(c.status, Status::Warn);
    assert_tame(&c.text);
    assert!(c.text.contains("boom"));
}

#[test]
fn a_hostile_wine_version_is_cleaned_and_shortened() {
    let s = sc();
    let env = |k: &str| s.host.env.get(k).map(OsString::from);
    let hostile: &'static str = Box::leak(format!("wine-10\x1b]0;x\x07\u{202e}{}", "9".repeat(500)).into_boxed_str());
    let r = doctor(DoctorInput {
        subject: Subject::System,
        host_arch: "x86_64",
        env: &env,
        fs: &s.host,
        backend: Ok(&NoVersion(Some(hostile))),
        pe: PeState::Skipped,
        program: None,
        app_dir: None,
        prefix: PrefixState::NotApplicable,
        app_home: None,
        prefix_root: None,
        vulkan: None,
        vulkan_min: None,
    });
    let c = one(&r, Area::Runtime, "Wine: wine-10");
    assert_eq!(c.status, Status::Ok);
    assert_tame(&c.text);
    assert!(c.text.chars().count() < 100, "{}", c.text.chars().count());
}

fn dev(api: (u32, u32)) -> crate::VulkanDevice {
    crate::VulkanDevice {
        name: "gpu".into(),
        device_type: "X".into(),
        api,
        driver: "d".into(),
    }
}

#[test]
fn vulkan_verdicts_from_the_runner() {
    let mut s = sc();
    s.vulkan = Some(crate::HostVulkan {
        tool_found: true,
        loader_found: true,
        devices: vec![dev((1, 3))],
    });
    let c = one(&s.run(), Area::Graphics, "Vulkan").clone();
    assert_eq!(c.status, Status::Ok);
    assert!(c.text.contains("1 device"), "{}", c.text);

    // Unusable: no loader (the runner's view wins over the file check).
    s.vulkan = Some(crate::HostVulkan {
        tool_found: false,
        loader_found: false,
        devices: vec![],
    });
    let c = one(&s.run(), Area::Graphics, "Vulkan").clone();
    assert_eq!(c.status, Status::Warn);
    assert!(c.text.contains("not found"), "{}", c.text);

    // Unknown: the loader line as before.
    s.vulkan = Some(crate::HostVulkan {
        tool_found: false,
        loader_found: true,
        devices: vec![],
    });
    let c = one(&s.run(), Area::Graphics, "Vulkan").clone();
    assert_eq!(c.status, Status::Ok);
    assert!(c.text.contains("loader found"), "{}", c.text);
}

#[test]
fn a_device_below_the_bundled_minimum_is_a_warning() {
    let mut s = sc();
    s.vulkan = Some(crate::HostVulkan {
        tool_found: true,
        loader_found: true,
        devices: vec![dev((1, 1))],
    });
    assert_eq!(one(&s.run(), Area::Graphics, "Vulkan").status, Status::Ok);
    s.vulkan_min = Some((1, 3));
    let c = one(&s.run(), Area::Graphics, "Vulkan").clone();
    assert_eq!(c.status, Status::Warn);
    assert!(c.text.contains("unusable"), "{}", c.text);
}

#[test]
fn vulkan_is_found_in_any_standard_directory_and_warned_about_otherwise() {
    for dir in [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
    ] {
        let mut s = sc();
        s.host
            .files
            .remove(Path::new("/usr/lib/x86_64-linux-gnu/libvulkan.so.1"));
        s.host.files.insert(format!("{dir}/libvulkan.so.1").into());
        let r = s.run();
        assert_eq!(one(&r, Area::Graphics, "Vulkan").status, Status::Ok, "{dir}");
    }
    let mut s = sc();
    s.host
        .files
        .remove(Path::new("/usr/lib/x86_64-linux-gnu/libvulkan.so.1"));
    s.host.files.insert("/opt/elsewhere/libvulkan.so.1".into());
    let r = s.run();
    let c = one(&r, Area::Graphics, "Vulkan");
    assert_eq!(c.status, Status::Warn);
    assert!(c.text.contains("libvulkan.so.1"), "{}", c.text);
    assert_eq!(r.verdict, Verdict::MayFail);
}

#[test]
fn the_display_is_wayland_then_x11_then_a_warning() {
    // (env, files that exist) -> (status, text must contain)
    type Case = (
        &'static [(&'static str, &'static str)],
        &'static [&'static str],
        Status,
        &'static str,
    );
    let cases: [Case; 10] = [
        (
            &[("WAYLAND_DISPLAY", "wayland-0"), ("XDG_RUNTIME_DIR", "/run/user/1000")],
            &["/run/user/1000/wayland-0"],
            Status::Ok,
            "Wayland",
        ),
        (
            &[("WAYLAND_DISPLAY", "/tmp/sock")],
            &["/tmp/sock"],
            Status::Ok,
            "Wayland",
        ),
        // set, but no socket: X11 is the fallback when there is one
        (
            &[
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
                ("DISPLAY", ":0"),
            ],
            &[],
            Status::Ok,
            "X11",
        ),
        (
            &[("WAYLAND_DISPLAY", "wayland-0"), ("XDG_RUNTIME_DIR", "/run/user/1000")],
            &[],
            Status::Warn,
            "no display",
        ),
        (&[("DISPLAY", ":0")], &[], Status::Ok, "X11"),
        (&[("DISPLAY", ":0"), ("WAYLAND_DISPLAY", "")], &[], Status::Ok, "X11"),
        (&[], &[], Status::Warn, "no display"),
        // a relative name needs an absolute XDG_RUNTIME_DIR
        (
            &[("WAYLAND_DISPLAY", "wayland-0")],
            &["/run/user/1000/wayland-0", "wayland-0"],
            Status::Warn,
            "no display",
        ),
        (
            &[("WAYLAND_DISPLAY", "wayland-0"), ("XDG_RUNTIME_DIR", "run/user")],
            &["run/user/wayland-0"],
            Status::Warn,
            "no display",
        ),
        (&[("DISPLAY", "")], &[], Status::Warn, "no display"),
    ];
    for (env, files, status, needle) in cases {
        let mut s = sc();
        s.host = Host::default()
            .file("/usr/lib/x86_64-linux-gnu/libvulkan.so.1")
            .dir(WINE_DLLS, &[]);
        for (k, v) in env {
            s.host = s.host.env(k, v);
        }
        for f in files {
            s.host = s.host.file(f);
        }
        let r = s.run();
        let display: Vec<&Check> = of(&r, Area::Graphics)
            .into_iter()
            .filter(|c| !c.text.contains("Vulkan"))
            .collect();
        assert_eq!(display.len(), 1, "{env:?}: {:#?}", r.checks);
        assert_eq!(display[0].status, status, "{env:?}: {}", display[0].text);
        assert!(display[0].text.contains(needle), "{env:?}: {}", display[0].text);
    }
}

#[test]
fn a_hostile_display_value_is_escaped() {
    let mut s = sc();
    s.host = Host::default().env("DISPLAY", "\x1b]0;x\x07\u{202e}:0");
    let r = s.run();
    for c in &r.checks {
        assert_tame(&c.text);
    }
    // the Wayland name too (an absolute path that exists)
    let name = "/tmp/\x1b[31m\u{202e}sock";
    let mut s = sc();
    s.host = Host::default().env("WAYLAND_DISPLAY", name).file(name);
    let r = s.run();
    let c = one(&r, Area::Graphics, "Wayland");
    assert_eq!(c.status, Status::Ok);
    assert_tame(&c.text);
}

#[test]
fn pipewire_is_a_socket_in_the_runtime_dir() {
    let r = sc().run();
    assert_eq!(of(&r, Area::Audio).len(), 1);
    assert_eq!(of(&r, Area::Audio)[0].status, Status::Ok);
    for host in [
        Host::desktop(),
        Host::default().env("XDG_RUNTIME_DIR", "run/user"), // relative: ignored
        Host::default().file("/pipewire-0"),
    ] {
        let mut s = sc();
        s.host = host;
        s.host.files.remove(Path::new("/run/user/1000/pipewire-0"));
        let c = &of(&s.run(), Area::Audio).into_iter().cloned().collect::<Vec<_>>()[0];
        assert_eq!(c.status, Status::Warn, "{}", c.text);
        assert!(c.text.contains("PipeWire"), "{}", c.text);
    }
}

#[test]
fn the_verdict_is_fail_over_may_fail_over_good() {
    let mk = |statuses: &[Status]| -> Vec<Check> {
        statuses
            .iter()
            .map(|&status| Check {
                area: Area::Runtime,
                status,
                text: String::new(),
            })
            .collect()
    };
    use Status::{Fail, Ok as O, Warn};
    assert_eq!(verdict(&mk(&[])), Verdict::Good);
    assert_eq!(verdict(&mk(&[O, O])), Verdict::Good);
    assert_eq!(verdict(&mk(&[O, Warn])), Verdict::MayFail);
    assert_eq!(verdict(&mk(&[Warn, Warn])), Verdict::MayFail);
    assert_eq!(verdict(&mk(&[O, Fail])), Verdict::Fail);
    assert_eq!(verdict(&mk(&[Warn, Fail, O])), Verdict::Fail);
    // and `doctor` uses it
    let mut s = sc();
    s.host.env.clear();
    assert_eq!(
        s.run().verdict,
        Verdict::MayFail,
        "no display, no PipeWire: warnings only"
    );
}

// ---------------------------------------------------------------- the PE checks

#[test]
fn a_plain_program_is_valid_and_launchable() {
    let r = app(vec![]).run();
    assert_eq!(r.verdict, Verdict::Good, "{:#?}", r.checks);
    assert_eq!(one(&r, Area::Pe, "valid PE").status, Status::Ok);
    assert!(one(&r, Area::Pe, "valid PE").text.contains("PE32+"));
    assert_eq!(one(&r, Area::Architecture, "program architecture").status, Status::Ok);
    assert_eq!(one(&r, Area::Pe, "console").status, Status::Ok);
}

#[test]
fn the_program_architecture_must_be_x86_or_x86_64() {
    for (arch, machine, ok) in [
        (Arch::X86, 0x14c, true),
        (Arch::X86_64, 0x8664, true),
        (Arch::Arm64, 0xaa64, false),
        (Arch::Arm64Ec, 0xa641, false),
        (Arch::Other(0x1c4), 0x1c4, false),
    ] {
        let mut s = app(vec![]);
        s.info().arch = arch;
        s.info().machine = machine;
        let r = s.run();
        let c = one(&r, Area::Architecture, "program architecture");
        assert_eq!(c.status == Status::Ok, ok, "{arch:?}: {}", c.text);
        assert_eq!(r.verdict == Verdict::Good, ok, "{arch:?}");
        if !ok {
            assert_eq!(c.status, Status::Fail);
        }
    }
    let mut s = app(vec![]);
    s.info().arch = Arch::Other(0x1c4);
    s.info().machine = 0x1c4;
    assert!(
        one(&s.run(), Area::Architecture, "program architecture")
            .text
            .contains("0x01c4")
    );
}

#[test]
fn drivers_and_dlls_are_not_launchable() {
    let mut s = app(vec![]);
    s.info().subsystem = Subsystem::Native;
    let r = s.run();
    let c = one(&r, Area::Pe, "kernel");
    assert_eq!(c.status, Status::Fail);
    assert!(c.text.contains("unsupported"), "{}", c.text);
    assert_eq!(r.verdict, Verdict::Fail);

    let mut s = app(vec![]);
    s.info().kind = Kind::Dll;
    let r = s.run();
    let c = one(&r, Area::Pe, "DLL");
    assert_eq!(c.status, Status::Fail);
    assert!(
        c.text.contains("not launchable") || c.text.contains("cannot be launched"),
        "{}",
        c.text
    );
    assert_eq!(r.verdict, Verdict::Fail);

    for (sub, raw) in [(Subsystem::Efi, 10), (Subsystem::Other(9), 9), (Subsystem::Other(0), 0)] {
        let mut s = app(vec![]);
        s.info().subsystem = sub;
        s.info().subsystem_raw = raw;
        let r = s.run();
        assert_eq!(one(&r, Area::Pe, "subsystem").status, Status::Warn, "{sub:?}");
        assert_eq!(r.verdict, Verdict::MayFail);
    }
    let mut s = app(vec![]);
    s.info().subsystem = Subsystem::Gui;
    assert_eq!(one(&s.run(), Area::Pe, "GUI").status, Status::Ok);
}

#[test]
fn signed_and_aslr_are_information_only() {
    for (signed, aslr, nx) in [(true, true, true), (false, false, false)] {
        let mut s = app(vec![]);
        s.info().signed = signed;
        s.info().aslr = aslr;
        s.info().nx = nx;
        let r = s.run();
        let c = one(&r, Area::Pe, "signed");
        assert_eq!(c.status, Status::Ok, "information never changes the verdict");
        assert!(c.text.contains("not verified"), "{}", c.text);
        assert_eq!(r.verdict, Verdict::Good);
    }
}

#[test]
fn parser_warnings_are_counted_and_never_dumped() {
    let mut s = app(vec![]);
    s.info().warnings = vec!["secret\x1b[31m one".into(), "two".into(), "three".into()];
    let r = s.run();
    let c = one(&r, Area::Pe, "parser warning");
    assert_eq!(c.status, Status::Warn);
    assert!(c.text.contains("3 parser warnings"), "{}", c.text);
    for check in &r.checks {
        assert!(
            !check.text.contains("secret") && !check.text.contains("two"),
            "{}",
            check.text
        );
    }
    assert_eq!(r.verdict, Verdict::MayFail);
    let mut s = app(vec![]);
    s.info().warnings = vec!["only".into()];
    assert!(
        one(&s.run(), Area::Pe, "parser warning")
            .text
            .contains("1 parser warning")
    );
}

#[test]
fn a_file_that_cannot_be_analysed_fails_with_escaped_text() {
    for reason in [
        "not a Windows binary or installer (unrecognised format)",
        "malformed PE: \x1b[31m\u{202e}bad",
    ] {
        let mut s = app(vec![]);
        s.pe = Some(Err(reason.into()));
        let r = s.run();
        let c = r.checks.iter().find(|c| c.area == Area::Pe).unwrap();
        assert_eq!(c.status, Status::Fail);
        assert_tame(&c.text);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(of(&r, Area::Imports).is_empty(), "no import checks without a PE");
    }
}

#[test]
fn dotnet_and_installers_are_warnings_that_name_their_phase() {
    let mut s = app(vec![]);
    s.info().dotnet = true;
    let r = s.run();
    let c = one(&r, Area::Runtime, ".NET");
    assert_eq!(c.status, Status::Warn);
    assert!(c.text.contains("Mono") && c.text.contains("Phase 4"), "{}", c.text);
    assert_eq!(r.verdict, Verdict::MayFail);

    for (kind, label) in [
        (InstallerKind::InnoSetup, "Inno Setup"),
        (InstallerKind::Nsis, "NSIS"),
        (InstallerKind::InstallShield, "InstallShield"),
        (InstallerKind::WixBurn, "WiX Burn"),
    ] {
        let mut s = app(vec![]);
        s.info().installer = Some(Installer {
            kind,
            evidence: "marker\x1b[31m",
        });
        let r = s.run();
        let c = one(&r, Area::Runtime, "installer");
        assert_eq!(c.status, Status::Warn);
        assert!(c.text.contains("Phase 3") && c.text.contains(label), "{}", c.text);
        assert_tame(&c.text);
    }
}

// ---------------------------------------------------------------- imports

fn imports_of(r: &Report) -> Vec<&Check> {
    of(r, Area::Imports)
}

#[test]
fn imports_are_found_ignoring_case_in_wine_the_app_directory_and_the_prefix() {
    let mut s = app(vec![
        import("KERNEL32.dll", false),
        import("User32.DLL", false),
        import("mylib.dll", false),
        import("MYLIB2.DLL", false),
        import("sys32only.dll", false),
        import("wow.dll", true),
        import("kernel32", false), // no extension: Windows appends .dll
    ]);
    s.app_dir = Some(Ok(listing(&["MyLib.dll", "mylib2.dll", "readme.txt"])));
    s.prefix_root = Some("/prefix".into());
    s.host = s
        .host
        .dir("/prefix/drive_c/windows/system32", &["Sys32Only.DLL"])
        .dir("/prefix/drive_c/windows/syswow64", &["wow.dll"]);
    let r = s.run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Ok, "{}", c[0].text);
    assert_eq!(r.verdict, Verdict::Good);
}

#[test]
fn thirty_missing_dlls_list_twenty_and_count_the_rest() {
    let imports: Vec<Import> = (0..30).map(|i| import(&format!("missing{i:02}.dll"), false)).collect();
    let r = app(imports).run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].status, Status::Warn);
    assert!(c[0].text.contains("and 10 more"), "{}", c[0].text);
    assert_eq!(c[0].text.matches("missing").count(), 20, "{}", c[0].text);
    assert!(c[0].text.contains("\"missing00.dll\"") && c[0].text.contains("\"missing19.dll\""));
    assert!(!c[0].text.contains("missing20"), "{}", c[0].text);
    assert_eq!(r.verdict, Verdict::MayFail);
    // exactly 20: all listed, no "more"
    let imports: Vec<Import> = (0..20).map(|i| import(&format!("missing{i:02}.dll"), false)).collect();
    let r = app(imports).run();
    let c = imports_of(&r);
    assert_eq!(c[0].text.matches("missing").count(), 20);
    assert!(!c[0].text.contains("more"), "{}", c[0].text);
    // 21: "and 1 more"
    let imports: Vec<Import> = (0..21).map(|i| import(&format!("missing{i:02}.dll"), false)).collect();
    assert!(imports_of(&app(imports).run())[0].text.contains("and 1 more"));
}

#[test]
fn api_set_names_are_available_and_the_text_says_they_are_not_verified() {
    let r = app(vec![
        import("api-ms-win-core-file-l1-1-0.dll", false),
        import("API-MS-WIN-CRT-runtime-l1-1-0.DLL", false),
        import("ext-ms-win-ntuser-window-l1-1-0.dll", true),
        import("kernel32.dll", false),
    ])
    .run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Ok);
    assert!(
        c[0].text.contains("API-set") && c[0].text.contains("not verified"),
        "{}",
        c[0].text
    );
    assert!(c[0].text.contains('3'), "the number of API-set names: {}", c[0].text);
    // With a missing DLL too, the note is still there.
    let r = app(vec![
        import("api-ms-win-core-file-l1-1-0.dll", false),
        import("nope.dll", false),
    ])
    .run();
    let c = imports_of(&r);
    assert_eq!(c[0].status, Status::Warn);
    assert!(
        c[0].text.contains("nope.dll") && !c[0].text.contains("\"api-ms"),
        "{}",
        c[0].text
    );
    assert!(c[0].text.contains("not verified"), "{}", c[0].text);
    // A name that merely starts like an API set, or is too short, is a normal name.
    let r = app(vec![
        import("api-ms-win", false),
        import("api-ms", false),
        import("api", false),
    ])
    .run();
    assert_eq!(imports_of(&r)[0].status, Status::Warn);
}

#[test]
fn without_a_wine_dll_directory_availability_is_not_verified_never_missing() {
    let imports = || vec![import("zzz-unknown.dll", false), import("zzz-delay.dll", true)];
    for (label, mutate) in [
        (
            "dll_dirs empty",
            (|s: &mut Sc| s.backend = Ok(FakeBackend::new())) as fn(&mut Sc),
        ),
        ("directory not listable", |s| s.host.dirs.clear()),
        ("no Wine at all", |s| s.backend = Err("no wine".into())),
    ] {
        let mut s = app(imports());
        mutate(&mut s);
        let r = s.run();
        let c = imports_of(&r);
        assert_eq!(c.len(), 1, "{label}: {c:#?}");
        assert_eq!(c[0].status, Status::Warn, "{label}");
        assert!(
            c[0].text.contains("DLL availability not verified"),
            "{label}: {}",
            c[0].text
        );
        assert!(
            !c[0].text.contains("zzz"),
            "{label}: no name may be called missing: {}",
            c[0].text
        );
        assert!(!c[0].text.to_lowercase().contains("missing"), "{label}: {}", c[0].text);
    }
    let mut s = app(imports());
    s.backend = Ok(FakeBackend::new());
    assert!(imports_of(&s.run())[0].text.contains("(Wine DLL directory not found)"));
}

#[test]
fn delay_loaded_dlls_get_their_own_optional_warning() {
    let r = app(vec![
        import("kernel32.dll", false),
        import("reg-missing.dll", false),
        import("delay-missing.dll", true),
        import("both.dll", false),
        import("BOTH.DLL", true),
    ])
    .run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 2, "{c:#?}");
    let regular = c.iter().find(|c| c.text.contains("reg-missing")).unwrap();
    let delay = c.iter().find(|c| c.text.contains("delay-missing")).unwrap();
    assert_eq!((regular.status, delay.status), (Status::Warn, Status::Warn));
    assert!(delay.text.contains("optional (delay-loaded)"), "{}", delay.text);
    assert!(!regular.text.contains("delay-missing") && !regular.text.contains("optional"));
    assert!(
        regular.text.to_lowercase().contains("both.dll"),
        "regular wins for a name imported both ways"
    );
    assert!(!delay.text.to_lowercase().contains("both.dll"), "{}", delay.text);
    // only delay-loaded missing
    let r = app(vec![import("delay-missing.dll", true)]).run();
    assert_eq!(imports_of(&r).len(), 1);
    // 30 delay-loaded names: capped the same way
    let imports: Vec<Import> = (0..30).map(|i| import(&format!("late{i:02}.dll"), true)).collect();
    let c = imports_of(&app(imports).run()).into_iter().cloned().collect::<Vec<_>>();
    assert!(
        c[0].text.contains("and 10 more") && c[0].text.matches("late").count() == 20,
        "{}",
        c[0].text
    );
}

#[test]
fn missing_names_are_deduplicated_ignoring_case() {
    let r = app(vec![
        import("Foo.dll", false),
        import("FOO.DLL", false),
        import("foo.dll", false),
    ])
    .run();
    let c = imports_of(&r);
    assert_eq!(c[0].text.to_lowercase().matches("foo.dll").count(), 1, "{}", c[0].text);
    assert!(c[0].text.contains('1'), "{}", c[0].text);
}

#[test]
fn hostile_dll_names_are_escaped_and_short() {
    let hostile = [
        "evil\x1b]0;pwned\x07.dll".to_string(),
        format!("{}.dll", "A".repeat(1000)),
        "\u{202e}gpj.dll".to_string(),
        "\u{9b}31m.dll".to_string(),
        "new\nline.dll".to_string(),
        "\u{e9}\u{4e2d}\u{6587}.dll".to_string(),
        "\u{200b}\u{feff}zw.dll".to_string(),
        "..\\..\\evil.dll".to_string(),
        String::new(),
        "nul\0byte.dll".to_string(),
        "\u{1f600}".repeat(300),
    ];
    let mut imports: Vec<Import> = hostile.iter().map(|n| import(n, false)).collect();
    imports.extend(hostile.iter().map(|n| import(&format!("{n}x"), true)));
    let r = app(imports).run();
    for c in imports_of(&r) {
        assert_eq!(c.status, Status::Warn);
        assert_tame(&c.text);
        assert!(c.text.chars().count() <= 1200, "{}", c.text.chars().count());
    }
    assert!(
        imports_of(&r).iter().any(|c| c.text.contains("\\u{1b}")),
        "escaped, not dropped"
    );
    // 20 maximal names still fit (each cut to a short width)
    let imports: Vec<Import> = (0..30)
        .map(|i| import(&format!("\u{202e}{i:02}{}", "\u{1b}".repeat(500)), false))
        .collect();
    let r = app(imports).run();
    let c = imports_of(&r);
    assert!(
        c[0].text.contains("and 10 more"),
        "the tail of the list survives: {}",
        c[0].text
    );
    assert!(c[0].text.chars().count() <= 1200, "{}", c[0].text.chars().count());
    assert_tame(&c[0].text);
}

#[test]
fn an_import_of_a_thousand_bytes_is_missing_and_no_imports_is_ok() {
    let r = app(vec![import(&"k".repeat(1000), false)]).run();
    assert_eq!(imports_of(&r)[0].status, Status::Warn);
    let r = app(vec![]).run();
    assert_eq!(imports_of(&r).len(), 1);
    assert_eq!(imports_of(&r)[0].status, Status::Ok);
}

#[test]
fn a_prefix_that_does_not_exist_yet_is_skipped_silently_for_imports() {
    let mut s = app(vec![import("kernel32.dll", false)]);
    s.prefix_root = Some("/nowhere".into()); // `list` answers None
    let r = s.run();
    assert_eq!(imports_of(&r).len(), 1);
    assert_eq!(imports_of(&r)[0].status, Status::Ok);
    assert!(
        s.host.listed.borrow().iter().any(|p| p.starts_with("/nowhere")),
        "it did look"
    );
}

// ---------------------------------------------------------------- the prefix

fn with_prefix(p: PrefixState) -> Report {
    let mut s = app(vec![]);
    s.prefix = p;
    s.run()
}

fn audit(f: impl FnOnce(&mut PrefixAudit)) -> PrefixState {
    let mut a = PrefixAudit {
        c_link_ok: true,
        ..PrefixAudit::default()
    };
    f(&mut a);
    PrefixState::Audit(a)
}

#[test]
fn a_hardened_prefix_is_ok_and_a_missing_one_is_a_warning() {
    let r = with_prefix(audit(|_| {}));
    let c = of(&r, Area::Prefix);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Ok);
    assert_eq!(r.verdict, Verdict::Good);
    let r = with_prefix(PrefixState::Missing);
    assert_eq!(of(&r, Area::Prefix)[0].status, Status::Warn);
    assert!(of(&r, Area::Prefix)[0].text.contains("no Wine prefix"));
    assert_eq!(r.verdict, Verdict::MayFail);
    assert!(
        of(&sc().run(), Area::Prefix).is_empty(),
        "a system report has no prefix"
    );
}

#[test]
fn com_and_lpt_links_are_tolerated_but_z_and_other_drives_are_flagged() {
    // Wine recreates com* on every start: tolerated, and the text says why.
    let ports: Vec<String> = (1..=32)
        .map(|i| format!("com{i}"))
        .chain(["lpt1".to_string()])
        .collect();
    let r = with_prefix(audit(|a| a.extra_devices = ports));
    let c = of(&r, Area::Prefix);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Ok);
    assert!(
        c[0].text.contains("com") && c[0].text.contains("recreate"),
        "{}",
        c[0].text
    );
    assert_eq!(r.verdict, Verdict::Good);

    let r = with_prefix(audit(|a| a.extra_devices = vec!["com1".into(), "z:".into()]));
    let z = one(&r, Area::Prefix, "z:");
    assert_eq!(z.status, Status::Warn);
    assert!(z.text.contains("host root drive present"), "{}", z.text);
    assert_eq!(r.verdict, Verdict::MayFail);

    let r = with_prefix(audit(|a| a.extra_devices = vec!["Z:".into()]));
    assert!(one(&r, Area::Prefix, "host root drive").status == Status::Warn);

    // names that only look like ports
    for odd in ["com", "com1x", "lpt", "comx", "xcom1", "com1:", "d:", "e:"] {
        let r = with_prefix(audit(|a| a.extra_devices = vec![odd.into()]));
        let c = of(&r, Area::Prefix);
        assert!(
            c.iter()
                .any(|c| c.status == Status::Warn && c.text.contains("unexpected")),
            "{odd}: {c:#?}"
        );
    }
}

#[test]
fn outward_links_fail_and_a_wrong_c_link_warns() {
    let r = with_prefix(audit(|a| {
        a.outward = vec!["drive_c/users/u/Desktop".into(), "a\x1b[31m".into()]
    }));
    let c = one(&r, Area::Prefix, "Desktop");
    assert_eq!(c.status, Status::Fail);
    assert_tame(&c.text);
    assert_eq!(r.verdict, Verdict::Fail);
    let r = with_prefix(audit(|a| a.c_link_ok = false));
    let c = one(&r, Area::Prefix, "c:");
    assert_eq!(c.status, Status::Warn);
    assert_eq!(r.verdict, Verdict::MayFail);
}

#[test]
fn an_incomplete_audit_is_a_warning_and_hides_nothing_it_did_not_see() {
    let r = with_prefix(PrefixState::Audit(PrefixAudit {
        incomplete: Some("more than 200000 entries below drive_c".into()),
        // the fields of an incomplete audit mean nothing and must not produce Fails
        c_link_ok: false,
        outward: vec!["x".into()],
        extra_devices: vec!["z:".into()],
    }));
    let c = of(&r, Area::Prefix);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Warn);
    assert!(c[0].text.contains("audit incomplete"), "{}", c[0].text);
    assert_ne!(r.verdict, Verdict::Fail);
    // a hostile reason is escaped
    let r = with_prefix(PrefixState::Audit(PrefixAudit {
        incomplete: Some("\x1b[31m\u{202e}".repeat(500)),
        ..PrefixAudit::default()
    }));
    assert_tame(&of(&r, Area::Prefix)[0].text);
    assert!(of(&r, Area::Prefix)[0].text.chars().count() <= 300);
}

#[test]
fn a_prefix_that_cannot_be_examined_fails_and_hostile_lists_are_bounded() {
    let r = with_prefix(PrefixState::Unexaminable("drive_c is a symbolic link\x1b[31m".into()));
    let c = of(&r, Area::Prefix);
    assert_eq!(c[0].status, Status::Fail);
    assert_tame(&c[0].text);

    let many: Vec<String> = (0..500)
        .map(|i| format!("\u{202e}dev{i}{}", "\x1b".repeat(300)))
        .collect();
    let r = with_prefix(audit(|a| {
        a.extra_devices = many.clone();
        a.outward = many.clone();
    }));
    for c in of(&r, Area::Prefix) {
        assert_tame(&c.text);
        assert!(c.text.chars().count() <= 1200, "{}", c.text.chars().count());
    }
}

// ---------------------------------------------------------------- the program and the whole

#[test]
fn the_program_is_ok_or_a_failure_with_sanitised_text() {
    let r = app(vec![]).run();
    let c = one(&r, Area::Program, "app.exe");
    assert_eq!(c.status, Status::Ok);
    assert!(
        c.text.contains("C:\\Program Files\\app\\app.exe"),
        "a Windows path stays readable: {}",
        c.text
    );
    let mut s = app(vec![]);
    s.program = Some(Err(
        "app app: its program \"C:\\x\" cannot be found\x1b[31m\u{202e}".into()
    ));
    let r = s.run();
    let c = of(&r, Area::Program);
    assert_eq!(c[0].status, Status::Fail);
    assert_tame(&c[0].text);
    assert!(c[0].text.contains("cannot be found"));
    assert_eq!(r.verdict, Verdict::Fail);
    let mut s = app(vec![]);
    s.program = Some(Ok("C:\\x\x1b[31m".into()));
    assert_tame(&of(&s.run(), Area::Program)[0].text);
    // a report for a file has no program check
    assert!(of(&sc().run(), Area::Program).is_empty());
}

#[test]
fn the_subject_is_carried_into_the_report() {
    let mut s = sc();
    s.subject = Subject::File { path: "x.exe".into() };
    assert_eq!(s.run().subject, Subject::File { path: "x.exe".into() });
    assert!(matches!(app(vec![]).run().subject, Subject::App { .. }));
}

#[test]
fn everything_is_bounded_under_hostile_input() {
    // Huge listings, many DLL directories, hostile names everywhere.
    let mut s = app((0..8000)
        .map(|i| import(&format!("hostile\u{202e}{i}\x1b.dll"), i % 2 == 0))
        .collect());
    s.info().warnings = (0..1000).map(|i| format!("w{i}")).collect();
    s.info().dotnet = true;
    s.info().installer = Some(Installer {
        kind: InstallerKind::Nsis,
        evidence: "NullsoftInst",
    });
    s.arch = "\x1b".repeat(10_000);
    s.backend = Ok(FakeBackend::new().with_dll_dirs((0..100).map(|i| PathBuf::from(format!("/d{i}"))).collect()));
    for i in 0..100 {
        s.host.dirs.insert(
            format!("/d{i}").into(),
            (0..60_000).map(|n| format!("f{n}.dll")).collect(),
        );
    }
    s.app_dir = Some(Ok(Listing {
        names: (0..100_000).map(|n| format!("a{n}.dll")).collect(),
        ..Listing::default()
    }));
    s.prefix_root = Some("/prefix".into());
    let r = s.run();
    assert!(r.checks.len() <= 40, "{} checks", r.checks.len());
    for c in &r.checks {
        assert_tame(&c.text);
        let max = if c.area == Area::Imports { 1200 } else { 300 };
        assert!(
            c.text.chars().count() <= max,
            "{:?}: {} chars",
            c.area,
            c.text.chars().count()
        );
    }
    let caps = s.host.list_caps.borrow();
    assert!(
        caps.iter().all(|&c| c == MAX_LISTING),
        "every listing is capped at MAX_LISTING: {caps:?}"
    );
    let dll_lists = s
        .host
        .listed
        .borrow()
        .iter()
        .filter(|p| p.to_string_lossy().starts_with("/d"))
        .count();
    assert_eq!(
        dll_lists, MAX_DLL_DIRS,
        "exactly the first {MAX_DLL_DIRS} DLL directories are listed"
    );
}

#[test]
fn a_check_text_is_cut_at_its_limit() {
    let mut out = Out(vec![]);
    out.add(Area::Runtime, Status::Ok, "x".repeat(5000));
    out.add_list(Area::Imports, Status::Ok, "y".repeat(5000));
    out.add(Area::Runtime, Status::Ok, "short".into());
    let lens: Vec<usize> = out.0.iter().map(|c| c.text.chars().count()).collect();
    assert_eq!(lens, [300, 1200, 5]);
    assert!(out.0[0].text.ends_with("..."));
    assert_eq!(
        clip("\u{1f600}".repeat(400), 300).chars().count(),
        300,
        "cuts on characters, not bytes"
    );
}

// ---------------------------------------------------------------- the real probe

#[test]
fn the_host_probe_lists_names_capped_and_answers_none_for_anything_that_is_not_a_listable_directory() {
    use std::os::unix::ffi::OsStringExt;
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    for n in 0..30 {
        std::fs::write(d.join(format!("f{n}.dll")), b"").unwrap();
    }
    let all = HostFs.list(d, MAX_LISTING).unwrap();
    assert_eq!(all.names.len(), 30);
    assert!(all.is_complete());
    assert!(all.names.contains(&"f7.dll".to_owned()));
    // The cap boundary: `cap` entries are complete, `cap + 1` are not (the reader looks one entry further).
    let ten = HostFs.list(d, 10).unwrap();
    assert_eq!(
        (ten.names.len(), ten.truncated),
        (10, true),
        "the cap is honoured and reported"
    );
    let exact = HostFs.list(d, 30).unwrap();
    assert_eq!(
        (exact.names.len(), exact.truncated),
        (30, false),
        "exactly the cap is complete"
    );
    let one_short = HostFs.list(d, 29).unwrap();
    assert_eq!((one_short.names.len(), one_short.truncated), (29, true));
    let zero = HostFs.list(d, 0).unwrap();
    assert_eq!((zero.names.len(), zero.truncated), (0, true));
    assert_eq!(HostFs.list(&d.join("nope"), 10), Err(ListError::NotFound));
    assert_eq!(
        HostFs.list(&d.join("f1.dll"), 10),
        Err(ListError::NotFound),
        "a file is not a directory"
    );
    // A name that is not UTF-8 is listed lossily, not skipped and not a panic.
    let odd = std::ffi::OsString::from_vec(b"bad-\xff-name".to_vec());
    std::fs::write(d.join(&odd), b"").unwrap();
    assert!(HostFs.list(d, 100).unwrap().names.iter().any(|n| n.starts_with("bad-")));
    assert!(HostFs.exists(d) && HostFs.exists(&d.join("f1.dll")));
    assert!(!HostFs.exists(&d.join("nope")));
    // Sockets and FIFOs exist (the Wayland and PipeWire sockets); a dangling symlink does not.
    let sock = std::os::unix::net::UnixListener::bind(d.join("wayland-0")).unwrap();
    assert!(HostFs.exists(&d.join("wayland-0")));
    drop(sock);
    std::os::unix::fs::symlink(d.join("gone"), d.join("dangling")).unwrap();
    assert!(!HostFs.exists(&d.join("dangling")));
}

#[test]
fn a_directory_that_exists_but_cannot_be_read_is_unreadable_not_missing() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path().join("locked");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("a.dll"), b"").unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable_anyway = std::fs::read_dir(&d).is_ok();
    let got = HostFs.list(&d, 10);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable_anyway {
        eprintln!("SKIPPED: running as root, a mode 000 directory is still readable");
        return;
    }
    assert_eq!(got, Err(ListError::Unreadable));
}

#[test]
fn collect_listing_reports_the_cap_boundary_and_unreadable_entries() {
    let ok = |n: &str| -> std::io::Result<String> { Ok(n.to_owned()) };
    let bad = || -> std::io::Result<String> { Err(std::io::Error::other("vanished")) };
    let list = |v: Vec<std::io::Result<String>>, cap| collect_listing(v.into_iter(), cap);

    assert_eq!(list(vec![], 3), Listing::default(), "empty is complete");
    let l = list(vec![ok("a"), ok("b"), ok("c")], 3);
    assert_eq!(
        (l.names.len(), l.truncated, l.errors),
        (3, false, 0),
        "exactly cap: complete"
    );
    let l = list(vec![ok("a"), ok("b"), ok("c"), ok("d")], 3);
    assert_eq!(
        (l.names.len(), l.truncated, l.errors),
        (3, true, 0),
        "cap + 1: truncated"
    );
    let l = list(vec![ok("a")], 0);
    assert_eq!((l.names.len(), l.truncated), (0, true));
    // Unreadable entries are counted and do not use up the cap.
    let l = list(vec![bad(), ok("a"), bad(), ok("b")], 2);
    assert_eq!(
        (l.names, l.truncated, l.errors),
        (vec!["a".to_owned(), "b".to_owned()], false, 2)
    );
    let l = list(vec![ok("a"), ok("b"), bad()], 2);
    assert_eq!((l.names.len(), l.truncated, l.errors), (2, false, 1));
    assert!(!l.is_complete(), "unreadable entries make a listing incomplete");
    // Bounded: an endless directory stops, whether its entries are names or errors.
    let l = collect_listing(std::iter::repeat_with(|| ok("x")), 5);
    assert_eq!((l.names.len(), l.truncated), (5, true));
    // (finite, so that a missing bound fails this test instead of hanging it)
    let l = collect_listing(std::iter::repeat_with(bad).take(1_000_000), 5);
    assert!(l.truncated && l.errors <= 5 + 1000, "{l:?}");
}

// ---------------------------------------------------------------- incomplete listings are reported

fn incomplete_warns(r: &Report) -> Vec<&Check> {
    imports_of(r)
        .into_iter()
        .filter(|c| c.text.contains("DLL listing incomplete"))
        .collect()
}

/// The check that lists the regular missing DLLs.
fn missing_line(r: &Report) -> &Check {
    imports_of(r)
        .into_iter()
        .find(|c| c.text.contains("imported DLL"))
        .expect("a missing-DLL check")
}

#[test]
fn a_wine_directory_cut_at_the_cap_is_reported_and_names_past_it_are_not_claimed_missing() {
    // The replacement of the test that used to lock in "f59999.dll is not found" for a 60 000-name directory.
    let mut s = app(vec![import("f59999.dll", false), import("f5.dll", false)]);
    s.host
        .dirs
        .insert(WINE_DLLS.into(), (0..60_000).map(|n| format!("f{n}.dll")).collect());
    let r = s.run();
    assert!(s.host.list_caps.borrow().contains(&MAX_LISTING));
    assert_eq!(MAX_LISTING, 50_000);
    let warns = incomplete_warns(&r);
    assert_eq!(warns.len(), 1, "{:#?}", r.checks);
    assert_eq!(warns[0].status, Status::Warn);
    assert!(
        warns[0].text.contains("Wine DLL directory: directory too large"),
        "{}",
        warns[0].text
    );
    assert!(
        warns[0].text.contains("missing-DLL results may be wrong"),
        "{}",
        warns[0].text
    );
    assert!(warns[0].text.chars().count() <= 300);
    // The name past the cap is reported, but as "not found in the listed files", never as a fact about Wine.
    let m = missing_line(&r);
    assert!(
        m.text.contains("f59999.dll") && !m.text.contains("f5.dll"),
        "{}",
        m.text
    );
    assert!(m.text.contains("the listed files"), "{}", m.text);
    assert!(!m.text.contains("Wine, the program's directory"), "{}", m.text);
    assert_eq!(r.verdict, Verdict::MayFail);
}

#[test]
fn the_cap_boundary_exactly_the_cap_is_complete_and_one_more_is_not() {
    let mut s = app(vec![import("f0.dll", false)]);
    s.host.dirs.insert(
        WINE_DLLS.into(),
        (0..MAX_LISTING).map(|n| format!("f{n}.dll")).collect(),
    );
    let r = s.run();
    assert!(incomplete_warns(&r).is_empty(), "{:#?}", r.checks);
    assert_eq!(imports_of(&r).len(), 1);
    assert_eq!(imports_of(&r)[0].status, Status::Ok);
    s.host.dirs.insert(
        WINE_DLLS.into(),
        (0..=MAX_LISTING).map(|n| format!("f{n}.dll")).collect(),
    );
    assert_eq!(incomplete_warns(&s.run()).len(), 1);
}

#[test]
fn a_truncated_or_unreadable_program_directory_is_reported() {
    for (label, dir, what) in [
        (
            "truncated",
            Ok(Listing {
                names: vec!["a.dll".into()],
                truncated: true,
                errors: 0,
            }),
            "program directory: directory too large",
        ),
        (
            "unreadable",
            Err(ListError::Unreadable),
            "program directory: unreadable",
        ),
        (
            "entries vanished",
            Ok(Listing {
                names: vec!["a.dll".into()],
                truncated: false,
                errors: 3,
            }),
            "program directory: 3 unreadable entries",
        ),
    ] {
        let mut s = app(vec![import("zzz.dll", false), import("zzz-late.dll", true)]);
        s.app_dir = Some(dir);
        let r = s.run();
        let warns = incomplete_warns(&r);
        assert_eq!(warns.len(), 1, "{label}: {:#?}", r.checks);
        assert!(warns[0].text.contains(what), "{label}: {}", warns[0].text);
        // Both missing lists are still there (the incomplete Warn is in addition), and neither claims a fact.
        for c in imports_of(&r).into_iter().filter(|c| c.text.contains("zzz")) {
            assert!(c.text.contains("the listed files"), "{label}: {}", c.text);
            assert!(!c.text.contains("the program's directory"), "{label}: {}", c.text);
        }
        assert_eq!(
            imports_of(&r).len(),
            3,
            "{label}: regular list, delay list, incomplete warn"
        );
        assert_eq!(r.verdict, Verdict::MayFail);
    }
}

#[test]
fn a_program_directory_that_does_not_exist_is_silent_and_a_complete_look_says_not_found() {
    let mut s = app(vec![import("zzz.dll", false)]);
    s.app_dir = Some(Err(ListError::NotFound));
    let r = s.run();
    assert!(incomplete_warns(&r).is_empty());
    assert!(
        missing_line(&r)
            .text
            .contains("not found in Wine, the program's directory or the prefix")
    );
    s.app_dir = None;
    assert!(incomplete_warns(&s.run()).is_empty());
}

#[test]
fn one_unreadable_wine_directory_among_two_is_reported_and_the_other_still_counts() {
    let mut s = app(vec![import("kernel32.dll", false), import("zzz.dll", false)]);
    s.backend = Ok(FakeBackend::new().with_dll_dirs(vec![WINE_DLLS.into(), "/wine/i386-windows".into()]));
    s.host = s.host.dir("/wine/i386-windows", &[]).unreadable("/wine/i386-windows");
    let r = s.run();
    let warns = incomplete_warns(&r);
    assert_eq!(warns.len(), 1, "{:#?}", r.checks);
    assert!(
        warns[0].text.contains("Wine DLL directory: unreadable"),
        "{}",
        warns[0].text
    );
    let m = missing_line(&r);
    assert!(
        m.text.contains("zzz.dll") && !m.text.contains("kernel32"),
        "verified against the readable one: {}",
        m.text
    );
    assert!(m.text.contains("the listed files"), "{}", m.text);
    // A Wine directory that has vanished (not unreadable) is silent.
    let mut s = app(vec![import("zzz.dll", false)]);
    s.backend = Ok(FakeBackend::new().with_dll_dirs(vec![WINE_DLLS.into(), "/wine/gone".into()]));
    assert!(incomplete_warns(&s.run()).is_empty());
}

#[test]
fn when_every_wine_directory_is_unreadable_the_answer_is_not_verified() {
    let mut s = app(vec![import("zzz.dll", false)]);
    s.host = s.host.unreadable(WINE_DLLS);
    let r = s.run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert!(
        c[0].text
            .contains("DLL availability not verified (Wine DLL directory unreadable)"),
        "{}",
        c[0].text
    );
    assert!(!c[0].text.contains("zzz"));
}

#[test]
fn an_unreadable_prefix_system_directory_or_lost_entries_are_reported() {
    let mut s = app(vec![import("zzz.dll", false)]);
    s.prefix_root = Some("/prefix".into());
    s.host = s
        .host
        .dir("/prefix/drive_c/windows/system32", &["a.dll"])
        .unreadable("/prefix/drive_c/windows/system32");
    let r = s.run();
    let warns = incomplete_warns(&r);
    assert_eq!(warns.len(), 1, "{:#?}", r.checks);
    assert!(
        warns[0].text.contains("prefix system32: unreadable"),
        "{}",
        warns[0].text
    );
    assert!(!warns[0].text.contains("syswow64"), "syswow64 does not exist: silent");
    // entries that vanished mid-listing are only counted
    let mut s = app(vec![import("zzz.dll", false)]);
    s.prefix_root = Some("/prefix".into());
    s.host = s
        .host
        .dir("/prefix/drive_c/windows/syswow64", &["a.dll"])
        .errors("/prefix/drive_c/windows/syswow64", 7);
    let warns = incomplete_warns(&s.run()).into_iter().cloned().collect::<Vec<_>>();
    assert_eq!(warns.len(), 1);
    assert!(
        warns[0].text.contains("prefix syswow64: 7 unreadable entries"),
        "{}",
        warns[0].text
    );
    let mut s = app(vec![]);
    s.host = s.host.errors(WINE_DLLS, 2);
    assert!(
        incomplete_warns(&s.run())[0]
            .text
            .contains("Wine DLL directory: 2 unreadable entries")
    );
}

#[test]
fn an_incomplete_listing_adds_a_warn_even_when_every_import_was_found() {
    let mut s = app(vec![import("kernel32.dll", false)]);
    s.host = s.host.errors(WINE_DLLS, 1);
    let r = s.run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 2, "{c:#?}");
    assert!(
        c.iter()
            .any(|c| c.status == Status::Ok && c.text.contains("all imported DLLs were found"))
    );
    assert_eq!(incomplete_warns(&r).len(), 1);
}

#[test]
fn the_incomplete_warning_is_short_however_many_listings_are_bad() {
    let mut s = app(vec![import("zzz.dll", false)]);
    s.prefix_root = Some("/prefix".into());
    s.backend =
        Ok(FakeBackend::new().with_dll_dirs((0..MAX_DLL_DIRS + 5).map(|i| PathBuf::from(format!("/w{i}"))).collect()));
    for i in 0..MAX_DLL_DIRS {
        s.host = s
            .host
            .dir(&format!("/w{i}"), &["a.dll"])
            .errors(&format!("/w{i}"), 100_000 + i);
    }
    s.host = s
        .host
        .dir("/prefix/drive_c/windows/system32", &[])
        .unreadable("/prefix/drive_c/windows/system32")
        .dir("/prefix/drive_c/windows/syswow64", &[])
        .unreadable("/prefix/drive_c/windows/syswow64");
    s.app_dir = Some(Err(ListError::Unreadable));
    let r = s.run();
    let warns = incomplete_warns(&r);
    assert_eq!(warns.len(), 1, "{:#?}", r.checks);
    assert!(
        warns[0].text.chars().count() <= 300,
        "{}",
        warns[0].text.chars().count()
    );
    assert!(warns[0].text.contains("and "), "the tail is counted: {}", warns[0].text);
    assert_tame(&warns[0].text);
}

// ---------------------------------------------------------------- ASCII case folding only

#[test]
fn unicode_lookalikes_do_not_fold_to_ascii_dll_names() {
    let mut s = app(vec![
        import("KERNEL32.dll", false),            // a real match
        import("\u{212A}ERNEL32.dll", false),     // Kelvin sign: `to_lowercase` would make this `kernel32.dll`
        import("WIN\u{131}NET.dll", false),       // dotless i
        import("W\u{130}N\u{130}NET.dll", false), // dotted capital I (Turkish)
        import("WININET.DLL", false),
        import("\u{17F}hell32.dll", false), // long s
    ]);
    s.host = s.host.dir(WINE_DLLS, &["kernel32.dll", "wininet.dll", "shell32.dll"]);
    let r = s.run();
    let m = missing_line(&r);
    assert!(m.text.contains("4 imported DLLs"), "{}", m.text);
    // (printable non-ASCII letters are shown as they are: the Kelvin sign looks like a K)
    for bad in ['\u{212A}', '\u{131}', '\u{130}', '\u{17F}'] {
        assert!(m.text.contains(bad), "{bad:?} missing from {}", m.text);
    }
    assert!(
        !m.text.contains("\"KERNEL32.dll\"") && !m.text.contains("WININET"),
        "{}",
        m.text
    );
    // and on the listing side: a FILE named with a Kelvin sign does not satisfy `kernel32.dll`
    let mut s = app(vec![import("kernel32.dll", false)]);
    s.host = s.host.dir(WINE_DLLS, &[]);
    s.app_dir = Some(Ok(listing(&["\u{212A}ernel32.dll"])));
    let r = s.run();
    assert_eq!(missing_line(&r).status, Status::Warn, "{:#?}", r.checks);
    // ASCII case-insensitivity still works on both sides
    let mut s = app(vec![import("KeRnEl32.DLL", false)]);
    s.host = s.host.dir(WINE_DLLS, &["KERNEL32.dll"]);
    assert_eq!(imports_of(&s.run())[0].status, Status::Ok);
}

#[test]
fn duplicates_are_folded_only_ascii_wise() {
    let r = app(vec![
        import("\u{212A}a.dll", false),
        import("ka.dll", false),
        import("KA.DLL", false),
    ])
    .run();
    let m = missing_line(&r);
    assert!(
        m.text.starts_with("2 imported DLLs"),
        "the Kelvin name is a different name: {}",
        m.text
    );
}

// ---------------------------------------------------------------- an incomplete prefix

#[test]
fn a_prefix_without_drive_c_is_an_incomplete_prefix_warning() {
    let r = with_prefix(PrefixState::Incomplete("drive_c missing".into()));
    let c = of(&r, Area::Prefix);
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].status, Status::Warn);
    assert!(
        c[0].text.contains("incomplete prefix (drive_c missing)"),
        "{}",
        c[0].text
    );
    assert_eq!(r.verdict, Verdict::MayFail);
    let r = with_prefix(PrefixState::Incomplete("\x1b[31m\u{202e}".repeat(200)));
    assert_tame(&of(&r, Area::Prefix)[0].text);
    assert!(of(&r, Area::Prefix)[0].text.chars().count() <= 300);
}

#[test]
fn api_set_names_are_counted_ascii_case_insensitively_only() {
    let r = app(vec![
        import("api-ms-win-core-k-l1-1-0.dll", false),
        import("API-MS-WIN-CORE-K-L1-1-0.DLL", false),
        import("api-ms-win-core-\u{212A}-l1-1-0.dll", false), // Kelvin sign: a different name
    ])
    .run();
    let c = imports_of(&r);
    assert_eq!(c.len(), 1);
    assert!(c[0].text.contains("(2 API-set names not verified"), "{}", c[0].text);
}

// ------------------------------------------------------------------------------ app home and archives

const HOME_GONE: &str = "app home directory failed: missing: this app was not prepared by this version, reinstall it";

#[test]
fn a_missing_app_home_is_a_program_failure_with_the_reinstall_text() {
    let mut s = app(vec![]);
    s.app_home = Some(Err(HOME_GONE.into()));
    let r = s.run();
    let c = one(&r, Area::Program, "app home");
    assert_eq!(c.status, Status::Fail);
    assert!(c.text.contains("reinstall it"), "{}", c.text);
    assert_eq!(r.verdict, Verdict::Fail);
    // The program check itself is untouched and there is exactly one home line.
    assert_eq!(one(&r, Area::Program, "program found").status, Status::Ok);
    assert_eq!(of(&r, Area::Program).len(), 2, "{:#?}", of(&r, Area::Program));
}

#[test]
fn a_usable_app_home_or_none_adds_no_check() {
    for home in [Some(Ok(())), None] {
        let mut s = app(vec![]);
        s.app_home = home;
        let r = s.run();
        assert_eq!(of(&r, Area::Program).len(), 1, "{:#?}", of(&r, Area::Program));
        assert_ne!(r.verdict, Verdict::Fail, "{:#?}", r.checks);
    }
}

#[test]
fn a_hostile_app_home_text_is_cleaned_and_shortened() {
    let mut s = app(vec![]);
    s.app_home = Some(Err(format!("app home\x1b]0;x\x07\u{202e} {}", "y".repeat(600))));
    let r = s.run();
    let c = one(&r, Area::Program, "app home");
    assert_tame(&c.text);
    assert!(c.text.chars().count() <= 300, "{}", c.text.chars().count());
}

#[test]
fn a_zip_archive_is_a_warning_that_says_to_install_it_not_a_failure() {
    let s = sc();
    let env = |k: &str| s.host.env.get(k).map(OsString::from);
    let r = doctor(DoctorInput {
        subject: Subject::File { path: "a.zip".into() },
        host_arch: "x86_64",
        env: &env,
        fs: &s.host,
        backend: Ok(s.backend.as_ref().unwrap() as &dyn CompatBackend),
        pe: PeState::Archive,
        program: None,
        app_dir: None,
        prefix: PrefixState::NotApplicable,
        app_home: None,
        prefix_root: None,
        vulkan: None,
        vulkan_min: None,
    });
    let c = one(&r, Area::Pe, "zip archive");
    assert_eq!(c.status, Status::Warn);
    assert!(
        c.text.contains("install it first") && c.text.contains("runtime install"),
        "{}",
        c.text
    );
    assert_ne!(r.verdict, Verdict::Fail, "{:#?}", r.checks);
    assert!(r.checks.iter().all(|c| c.status != Status::Fail), "{:#?}", r.checks);
}
