//! The backend conformance suite (`rt_core::backend::conformance`) over the test `FakeBackend` and a null backend
//! that knows nothing of Wine, deliberately broken backends that each fail exactly one check, the proof that the
//! null backend installs and runs an app through the unmodified `rt_core::install` and `rt_core::run`, and the
//! no-plugin source scan.
use rt_core::backend::conformance::{Failure, Scratch, live_checks, static_checks};
use rt_core::backend::{Capabilities, Want, inside_drive_c};
use rt_core::pe::{Arch, Subsystem};
use rt_core::{AppEnv, BackendError, CompatBackend, FakeBackend, InstallOpts, Launcher, RunOptions, RunOpts, Store};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Spec Decision B6: `/bin/sh -c <script> <exe> <args...>`, `prepare` creates `drive_c/` only, nothing else.
struct NullBackend {
    script: &'static str,
}

const NULL_CAPABILITIES: Capabilities = Capabilities {
    arches: &[Arch::X86_64],
    subsystems: &[Subsystem::Gui, Subsystem::Console],
    dotnet: false,
    installers: false,
    dependency_packages: false,
    sandboxable: false,
};

impl CompatBackend for NullBackend {
    fn id(&self) -> &'static str {
        "null"
    }
    fn version(&self) -> Result<String, BackendError> {
        Ok("null-1".into())
    }
    fn capabilities(&self) -> Capabilities {
        NULL_CAPABILITIES
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        fs::create_dir_all(env.drive_c()).map_err(|source| BackendError::Io {
            what: "create drive_c",
            source,
        })
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        _opts: &RunOpts,
    ) -> Result<Command, BackendError> {
        let exe = inside_drive_c(env, exe, "executable", Want::File)?;
        let cwd = inside_drive_c(env, cwd, "working directory", Want::Dir)?;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(self.script).arg(exe).args(args).current_dir(cwd);
        Ok(cmd)
    }
    fn stop(&self, _env: &AppEnv) -> Result<(), BackendError> {
        Ok(())
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}

fn null(script: &'static str) -> NullBackend {
    NullBackend { script }
}

fn checks(b: &dyn CompatBackend) -> Vec<&'static str> {
    let tmp = tempfile::tempdir().unwrap();
    let f = static_checks(b, &Scratch::new(tmp.path()));
    f.iter().map(|f| f.check).collect()
}

fn assert_passes(what: &str, failures: Vec<Failure>) {
    let text: Vec<String> = failures.iter().map(ToString::to_string).collect();
    assert!(failures.is_empty(), "{what} fails:\n{}", text.join("\n"));
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    fs::read(&p).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"))
}

// ---------------------------------------------------------------- the suite over the good backends

#[test]
fn the_null_and_the_fake_backend_pass_the_static_checks() {
    for (what, b) in [
        ("null", &null("exit 0") as &dyn CompatBackend),
        ("fake", &FakeBackend::new()),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        assert_passes(what, static_checks(b, &Scratch::new(tmp.path())));
    }
}

#[test]
fn the_null_and_the_fake_backend_pass_the_live_checks() {
    for (what, b) in [
        ("null", &null("exit 7") as &dyn CompatBackend),
        ("fake", &FakeBackend::with_script("exit 7")),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        assert_passes(what, live_checks(b, &Scratch::new(tmp.path()), &launcher(), b"MZ", 7));
    }
    // A wrong expected code is a failure, not a pass.
    let tmp = tempfile::tempdir().unwrap();
    let f = live_checks(&null("exit 3"), &Scratch::new(tmp.path()), &launcher(), b"MZ", 7);
    assert_eq!(f.iter().map(|f| f.check).collect::<Vec<_>>(), ["exit-code"], "{f:?}");
}

// ---------------------------------------------------------------- broken backends fail exactly their check

#[derive(Clone, Copy)]
enum Break {
    RelativeProgram,
    AcceptsDotDot,
    ChangesArgs,
    SettleDropsArgs,
    BadId,
    SetsLdPreload,
    WritesOnCommand,
    WrongCwd,
    EmptyCapabilities,
    RelativeDllDir,
    FollowsFinalSymlink,
    SandboxableWithoutPrefix,
    InstallersWithoutSandbox,
}

struct Broken(Break);

impl CompatBackend for Broken {
    fn id(&self) -> &'static str {
        match self.0 {
            Break::BadId => "Wine!",
            _ => "broken",
        }
    }
    fn version(&self) -> Result<String, BackendError> {
        Ok("1".into())
    }
    fn capabilities(&self) -> Capabilities {
        match self.0 {
            Break::EmptyCapabilities => Capabilities {
                arches: &[],
                ..NULL_CAPABILITIES
            },
            Break::SandboxableWithoutPrefix => Capabilities {
                sandboxable: true,
                ..NULL_CAPABILITIES
            },
            Break::InstallersWithoutSandbox => Capabilities {
                installers: true,
                ..NULL_CAPABILITIES
            },
            _ => NULL_CAPABILITIES,
        }
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        null("").prepare(env)
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<Command, BackendError> {
        if matches!(self.0, Break::AcceptsDotDot) && exe.components().any(|c| c.as_os_str() == "..") {
            return Ok(Command::new("/bin/true"));
        }
        // Resolves a final link itself (as a backend that canonicalises first would) and checks the target only
        // lexically: a link inside `drive_c` to a file outside passes.
        if matches!(self.0, Break::FollowsFinalSymlink)
            && fs::symlink_metadata(exe).is_ok_and(|m| m.file_type().is_symlink())
            && exe.starts_with(env.drive_c())
        {
            let mut c = Command::new("/bin/sh");
            c.arg("-c")
                .arg("exit 0")
                .arg(fs::canonicalize(exe).unwrap())
                .current_dir(cwd);
            return Ok(c);
        }
        let mut cmd = null("exit 0").command(env, exe, cwd, args, opts)?;
        match self.0 {
            Break::RelativeProgram => {
                let mut c = Command::new("sh");
                c.args(cmd.get_args()).current_dir(cwd);
                cmd = c;
            }
            Break::ChangesArgs => {
                let mut c = Command::new("/bin/sh");
                let n = cmd.get_args().count();
                c.args(cmd.get_args().take(n - 1)).current_dir(cwd);
                cmd = c;
            }
            Break::SetsLdPreload => {
                cmd.env("LD_PRELOAD", "/x.so");
            }
            Break::WritesOnCommand => {
                let _ = fs::write(env.root().join("config/touched"), b"x");
            }
            Break::WrongCwd => {
                cmd.current_dir(env.drive_c());
            }
            _ => {}
        }
        Ok(cmd)
    }
    fn stop(&self, _env: &AppEnv) -> Result<(), BackendError> {
        Ok(())
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        match self.0 {
            Break::RelativeDllDir => vec!["lib/wine".into()],
            _ => vec![],
        }
    }
    fn settle(&self, cmd: Command) -> Command {
        match self.0 {
            Break::SettleDropsArgs => Command::new(cmd.get_program()),
            _ => cmd,
        }
    }
}

#[test]
fn each_broken_backend_fails_exactly_its_check() {
    for (b, want) in [
        (Break::RelativeProgram, "command-program-absolute"),
        (Break::AcceptsDotDot, "outside-dotdot"),
        (Break::ChangesArgs, "command-args-verbatim"),
        (Break::SettleDropsArgs, "settle-keeps-argv"),
        (Break::BadId, "id"),
        (Break::SetsLdPreload, "command-no-loader-vars"),
        (Break::WritesOnCommand, "command-no-side-effect"),
        (Break::WrongCwd, "command-cwd"),
        (Break::EmptyCapabilities, "capabilities"),
        (Break::RelativeDllDir, "dll-dirs-absolute"),
        (Break::FollowsFinalSymlink, "outside-symlink"),
        (Break::SandboxableWithoutPrefix, "command-sandboxable"),
        (Break::InstallersWithoutSandbox, "capabilities"),
    ] {
        assert_eq!(checks(&Broken(b)), [want]);
    }
}

#[test]
fn a_failure_names_its_check_and_is_bounded() {
    let tmp = tempfile::tempdir().unwrap();
    let f = static_checks(&Broken(Break::BadId), &Scratch::new(tmp.path()));
    let text = f[0].to_string();
    assert!(text.starts_with("id: "), "{text}");
    assert!(text.contains("\"Wine!\""), "{text}");
}

// ---------------------------------------------------------------- the seam is backend-neutral

#[test]
fn the_null_backend_installs_and_runs_an_app_through_the_unmodified_services() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::new(tmp.path().join("apps")).unwrap();
    let input = tmp.path().join("hello64.exe");
    fs::write(&input, fixture("hello64.exe")).unwrap();
    let b = null("echo \"null backend ran $0\" >&2; exit 0");
    let out = rt_core::install(&store, &b, &input, &InstallOpts::default()).unwrap();
    let env = store.get(&out.id).unwrap();
    let md = store.read_metadata(&env).unwrap();
    assert_eq!(
        (md.backend.id.as_str(), md.backend.version.as_str()),
        ("null", "null-1")
    );
    assert!(
        !env.prefix().join("system.reg").exists(),
        "nothing Wine-shaped was made"
    );

    let ran = rt_core::run(&store, &b, &launcher(), out.id.as_str(), &[], &RunOptions::default()).unwrap();
    assert_eq!(ran.exit_code, 0);
    let log = fs::read_to_string(&ran.log_path).unwrap();
    assert!(
        log.contains("null backend ran ") && log.contains("hello64.exe"),
        "{log}"
    );

    // The same app under another backend is refused by the existing second guard.
    let e = rt_core::run(
        &store,
        &FakeBackend::new(),
        &launcher(),
        out.id.as_str(),
        &[],
        &RunOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(e, rt_core::RunAppError::BackendMismatch { .. }), "{e:?}");
}

#[test]
fn the_null_backend_refuses_what_its_capabilities_exclude_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let apps = tmp.path().join("apps");
    let store = Store::new(&apps).unwrap();
    let b = null("exit 0");
    // An x86 program on an x86-64-only backend.
    let x86 = tmp.path().join("hello32.exe");
    fs::write(&x86, fixture("hello32.exe")).unwrap();
    let e = rt_core::install(&store, &b, &x86, &InstallOpts::default()).unwrap_err();
    assert!(matches!(e, rt_core::InstallError::Unsupported(_)), "{e:?}");
    // The installer pipeline.
    let nsis = tmp.path().join("hello-nsis.exe");
    fs::write(&nsis, fixture("hello-nsis.exe")).unwrap();
    let opts = rt_installer::InstallerOpts {
        silent: true,
        allow_network: false,
        exe_override: None,
        runtime_exe: PathBuf::from("/nonexistent/runtime"),
    };
    let e = rt_installer::install_via_installer(&store, &b, launcher(), &nsis, opts).unwrap_err();
    assert!(matches!(e, rt_installer::InstallerError::Unsupported(_)), "{e:?}");
    assert!(
        !apps.exists() || fs::read_dir(&apps).unwrap().next().is_none(),
        "an app was created"
    );
    // Dependency packages and Wine Mono: refused by the same flags (the orchestrator and run tests use
    // `FakeBackend::with_capabilities` with each one off).
    let caps = b.capabilities();
    assert!(!caps.dependency_packages && !caps.dotnet && !caps.installers);
}

// ---------------------------------------------------------------- no plugins

/// Spec Decision B7: no dynamic loading in any runtime process. A legitimate future use is a deliberate edit of
/// this list with a `docs/SECURITY.md` entry.
#[test]
fn no_crate_source_loads_code_dynamically() {
    const BANNED: &[&str] = &["dlopen", "dlsym", "libloading", "RTLD_"];
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for c in fs::read_dir(&crates).unwrap() {
        let src = c.unwrap().path().join("src");
        if src.is_dir() {
            walk(&src, &mut files);
        }
    }
    assert!(files.len() > 100, "the scan found too few files: {}", files.len());
    let mut hits = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        for (n, line) in text.lines().enumerate() {
            for b in BANNED {
                if line.contains(b) {
                    hits.push(format!("{}:{}: {b}", f.display(), n + 1));
                }
            }
        }
    }
    assert!(hits.is_empty(), "dynamic loading in the sources:\n{}", hits.join("\n"));
}
