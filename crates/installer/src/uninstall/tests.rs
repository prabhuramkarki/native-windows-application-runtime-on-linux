use super::*;
use crate::sandbox::find_bwrap_on_path;
use rt_core::{AppId, FakeBackend, Store};
use std::fs;

fn env_with_msiexec() -> (tempfile::TempDir, AppEnv) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::new(tmp.path().join("apps")).unwrap();
    let env = store.create(&AppId::parse("t").unwrap()).unwrap();
    let backend = FakeBackend::new();
    backend.prepare(&env).unwrap();
    let msiexec = env.drive_c().join("windows/system32/msiexec.exe");
    fs::create_dir_all(msiexec.parent().unwrap()).unwrap();
    fs::write(&msiexec, b"MZ").unwrap();
    (tmp, env)
}

fn md_with_uninstall(env: &AppEnv, command: Option<&str>) -> Metadata {
    let exe = WinPath::parse("C:\\Program Files\\t\\t.exe").unwrap();
    let mut md = Metadata::new(
        env.id().clone(),
        "T".into(),
        None,
        "x86_64",
        &exe,
        rt_core::BackendInfo {
            id: "fake".into(),
            version: "1".into(),
        },
        "gui",
    );
    md.installer = Some(rt_core::InstallerMeta {
        family: "msi".into(),
        product_name: Some("T".into()),
        uninstall_command: command.map(str::to_owned),
    });
    md
}

fn require_real_bwrap() -> Option<std::path::PathBuf> {
    let require = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    match find_bwrap_on_path() {
        Some(p) => Some(p),
        None if require => panic!("bwrap not found on $PATH and RUNTIME_REQUIRE_BWRAP is set"),
        None => {
            eprintln!("SKIP: bwrap not found on $PATH; the real-sandbox uninstall tests need bubblewrap installed");
            None
        }
    }
}

/// This test binary: it runs the real `sandbox-init` shim (`crate::sandbox`'s `TEST_SHIM`).
fn runtime_exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap()
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

/// `FakeBackend::command` hardcodes `/bin/sh`; `InstallerSandbox::RO_BINDS` does not include `/bin` (see the
/// identical comment in `crate::pipeline::tests`). `extra_ro_binds` (Ruling 3) is the fix; unlike
/// `crate::pipeline`, `uninstall` takes `SandboxOpts` from its caller rather than building it from
/// `backend.dll_dirs()` itself, so a real-run test must build it explicitly with [`opts_for`].
fn fake_backend(script: &str) -> FakeBackend {
    FakeBackend::with_script(script).with_dll_dirs(vec![std::path::PathBuf::from("/bin")])
}

fn opts_for(backend: &FakeBackend) -> SandboxOpts {
    SandboxOpts {
        extra_ro_binds: backend.dll_dirs(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------- split_command_line

#[test]
fn split_command_line_handles_quoted_and_bare_programs() {
    assert_eq!(split_command_line("MsiExec.exe /X{GUID}"), ["MsiExec.exe", "/X{GUID}"]);
    assert_eq!(
        split_command_line("\"C:\\Program Files\\App\\uninstall.exe\" /S"),
        ["C:\\Program Files\\App\\uninstall.exe", "/S"]
    );
    assert_eq!(split_command_line("   "), Vec::<String>::new());
    assert_eq!(split_command_line(""), Vec::<String>::new());
    assert_eq!(split_command_line("\"unterminated"), ["unterminated"]);
    assert_eq!(split_command_line("solo.exe"), ["solo.exe"]);
    assert_eq!(
        split_command_line("  \"C:\\a b\\c.exe\"   --flag  val  "),
        ["C:\\a b\\c.exe", "--flag", "val"]
    );
}

/// Never panics, and never reads past the end of the string, on any byte sequence a hostile installer could
/// have written into `UninstallString` (control characters, NUL, a lone quote, only whitespace, absurdly long
/// input, non-ASCII, an unterminated quote at every position).
#[test]
fn split_command_line_never_panics_on_hostile_input() {
    let cases: Vec<String> = vec![
        "\0".repeat(10),
        "\"".repeat(5000),
        " ".repeat(100_000),
        "a\"b\"c\"d".to_string(),
        "\u{202e}\u{200b}\"C:\\a\u{1b}[31m\\b.exe\" /S\u{7}".to_string(),
        "\u{e9}".repeat(10_000),
        "\"".to_string() + &"x".repeat(1_000_000),
    ];
    for c in cases {
        let tokens = split_command_line(&c);
        assert!(tokens.iter().all(|t| t.len() <= c.len()), "a token grew past the input");
    }
    // A fuzz over a small hostile alphabet: only that the call returns, ever, for any shape.
    let alphabet: Vec<char> = " \"\\/\0\n\t\u{1b}aZ.exe~".chars().collect();
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = (next() % 50) as usize;
        let s: String = (0..len)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        let _ = split_command_line(&s);
    }
}

// ---------------------------------------------------------------- no recorded uninstaller: a documented limit

#[test]
fn no_uninstall_command_recorded_is_none_with_no_warnings() {
    let (_tmp, env) = env_with_msiexec();
    let backend = FakeBackend::new();
    // A portable-exe-shaped app: no `installer` field at all (schema v1, or never went through this pipeline).
    let exe = WinPath::parse("C:\\Program Files\\t\\t.exe").unwrap();
    let portable = Metadata::new(
        env.id().clone(),
        "T".into(),
        None,
        "x86_64",
        &exe,
        rt_core::BackendInfo {
            id: "fake".into(),
            version: "1".into(),
        },
        "gui",
    );
    assert_eq!(portable.installer, None);
    let outcome = uninstall(
        &backend,
        &launcher(),
        &env,
        &portable,
        SandboxOpts::default(),
        &runtime_exe(),
    );
    assert_eq!(outcome, UninstallOutcome::default());
    assert_eq!(outcome.uninstaller_succeeded, None);
    assert!(outcome.warnings.is_empty());

    // Same result when `installer` is present but carries no uninstall command (an installer that registered
    // none, e.g. `hello.msi` has no such row in its own `Property` table).
    let with_family_no_command = md_with_uninstall(&env, None);
    let outcome = uninstall(
        &backend,
        &launcher(),
        &env,
        &with_family_no_command,
        SandboxOpts::default(),
        &runtime_exe(),
    );
    assert_eq!(outcome, UninstallOutcome::default());
}

// ---------------------------------------------------------------- resolving the recorded command

#[test]
fn an_unresolvable_uninstall_command_is_a_warning_not_a_panic() {
    let (_tmp, env) = env_with_msiexec();
    let backend = FakeBackend::new();
    for bad in ["", "   ", "D:\\outside\\uninstall.exe", "not-even-a-windows-path"] {
        let md = md_with_uninstall(&env, Some(bad));
        let outcome = uninstall(&backend, &launcher(), &env, &md, SandboxOpts::default(), &runtime_exe());
        assert_eq!(outcome.uninstaller_succeeded, Some(false), "{bad:?}: {outcome:?}");
        assert_eq!(outcome.warnings.len(), 1, "{bad:?}: {outcome:?}");
    }
}

#[test]
fn a_command_naming_a_missing_program_is_a_warning_not_a_panic() {
    let (_tmp, env) = env_with_msiexec();
    let backend = FakeBackend::new();
    let md = md_with_uninstall(&env, Some("C:\\Program Files\\t\\does-not-exist.exe"));
    let outcome = uninstall(&backend, &launcher(), &env, &md, SandboxOpts::default(), &runtime_exe());
    assert_eq!(outcome.uninstaller_succeeded, Some(false));
    assert_eq!(outcome.warnings.len(), 1, "{outcome:?}");
}

// ---------------------------------------------------------------- real runs (need a real bwrap)

#[test]
fn a_real_msiexec_uninstall_command_runs_sandboxed_and_reports_success() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = env_with_msiexec();
    let backend = fake_backend("exit 0");
    let md = md_with_uninstall(&env, Some("MsiExec.exe /X{8965C2A7-9312-4D38-A0C4-76FAE288CAA7}"));
    let outcome = uninstall(&backend, &launcher(), &env, &md, opts_for(&backend), &runtime_exe());
    assert_eq!(outcome.uninstaller_succeeded, Some(true), "{outcome:?}");
    assert!(outcome.warnings.is_empty(), "{outcome:?}");
}

#[test]
fn a_real_exe_uninstall_command_that_fails_reports_failure_not_a_panic() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = env_with_msiexec();
    let uninstaller = env.drive_c().join("Program Files/t");
    fs::create_dir_all(&uninstaller).unwrap();
    fs::write(uninstaller.join("uninstall.exe"), b"MZ").unwrap();
    let backend = fake_backend("exit 7");
    let md = md_with_uninstall(&env, Some("\"C:\\Program Files\\t\\uninstall.exe\" /S"));
    let outcome = uninstall(&backend, &launcher(), &env, &md, opts_for(&backend), &runtime_exe());
    assert_eq!(outcome.uninstaller_succeeded, Some(false), "{outcome:?}");
    assert_eq!(outcome.warnings.len(), 1, "{outcome:?}");
    assert!(outcome.warnings[0].contains("exited with"), "{outcome:?}");
    assert!(outcome.warnings[0].contains('7'), "{outcome:?}");
}

#[test]
fn missing_bwrap_is_a_warning_not_a_panic() {
    // Cannot force a real absence of bwrap portably (find_bwrap_on_path reads the real $PATH), but a program
    // this pipeline can never resolve (outside drive_c) exercises the same "never a panic, always a warning"
    // contract as a missing bwrap would, without needing to mutate global process state.
    let (_tmp, env) = env_with_msiexec();
    let backend = FakeBackend::new();
    let md = md_with_uninstall(&env, Some("C:\\Windows\\..\\..\\etc\\passwd"));
    let outcome = uninstall(&backend, &launcher(), &env, &md, SandboxOpts::default(), &runtime_exe());
    assert_eq!(outcome.uninstaller_succeeded, Some(false));
    assert_eq!(outcome.warnings.len(), 1, "{outcome:?}");
}

/// Phase 5B Task 6 fix round 1: an unusable runtime executable is reported as the sandbox's refusal, and the
/// uninstaller is never started.
#[test]
fn an_unusable_runtime_executable_is_reported_as_the_sandboxs_refusal_and_nothing_runs() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = env_with_msiexec();
    let backend = fake_backend("exit 0");
    let md = md_with_uninstall(&env, Some("MsiExec.exe /X{8965C2A7-9312-4D38-A0C4-76FAE288CAA7}"));
    let outcome = uninstall(
        &backend,
        &launcher(),
        &env,
        &md,
        opts_for(&backend),
        Path::new("runtime"),
    );
    assert_eq!(outcome.uninstaller_succeeded, Some(false), "{outcome:?}");
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.contains("refused") && w.contains("not an absolute path")),
        "{outcome:?}"
    );
    assert!(
        !backend
            .calls()
            .iter()
            .any(|c| matches!(c, rt_core::Call::Command { .. })),
        "{:?}",
        backend.calls()
    );
}

/// A backend that records, at each `command()` (the step right before the uninstaller is spawned), whether the app
/// root already held the `ran-sandboxed` marker.
struct MarkerProbe {
    inner: FakeBackend,
    seen: std::sync::Mutex<Vec<bool>>,
}

impl CompatBackend for MarkerProbe {
    fn capabilities(&self) -> rt_core::backend::Capabilities {
        self.inner.capabilities()
    }
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn version(&self) -> Result<String, rt_core::BackendError> {
        self.inner.version()
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), rt_core::BackendError> {
        self.inner.prepare(env)
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &std::path::Path,
        cwd: &std::path::Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<std::process::Command, rt_core::BackendError> {
        self.seen
            .lock()
            .unwrap()
            .push(env.root().join(rt_sandbox::MARKER).exists());
        self.inner.command(env, exe, cwd, args, opts)
    }
    fn stop(&self, env: &AppEnv) -> Result<(), rt_core::BackendError> {
        self.inner.stop(env)
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        self.inner.dll_dirs()
    }
}

/// Phase 5B final review: the vendor uninstaller runs sandboxed Windows code with a read-write prefix, so the app is
/// marked BEFORE the uninstaller command is built and spawned.
#[test]
fn the_app_is_marked_before_the_uninstaller_starts() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = env_with_msiexec();
    let inner = fake_backend("exit 0");
    let opts = opts_for(&inner);
    let backend = MarkerProbe {
        inner,
        seen: std::sync::Mutex::new(Vec::new()),
    };
    assert!(!env.root().join(rt_sandbox::MARKER).exists());
    let md = md_with_uninstall(&env, Some("MsiExec.exe /X{8965C2A7-9312-4D38-A0C4-76FAE288CAA7}"));
    let outcome = uninstall(&backend, &launcher(), &env, &md, opts, &runtime_exe());
    assert_eq!(outcome.uninstaller_succeeded, Some(true), "{outcome:?}");
    assert_eq!(
        *backend.seen.lock().unwrap(),
        [true],
        "marked before the uninstaller command"
    );
}

/// The mark fails closed: when it cannot be written, the uninstaller is never started.
#[test]
fn a_marker_that_cannot_be_written_prevents_the_uninstaller() {
    let Some(_bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = env_with_msiexec();
    let backend = fake_backend("exit 0");
    let md = md_with_uninstall(&env, Some("MsiExec.exe /X{8965C2A7-9312-4D38-A0C4-76FAE288CAA7}"));
    fs::set_permissions(env.root(), std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
    let outcome = uninstall(&backend, &launcher(), &env, &md, opts_for(&backend), &runtime_exe());
    fs::set_permissions(env.root(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    assert_eq!(outcome.uninstaller_succeeded, Some(false), "{outcome:?}");
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.contains("could not record") && w.contains("was not run")),
        "{outcome:?}"
    );
    assert!(
        !backend
            .calls()
            .iter()
            .any(|c| matches!(c, rt_core::Call::Command { .. })),
        "{:?}",
        backend.calls()
    );
}
