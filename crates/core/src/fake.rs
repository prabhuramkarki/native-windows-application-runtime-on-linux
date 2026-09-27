//! `FakeBackend`: a [`CompatBackend`] test double that runs `/bin/sh` scripts instead of Wine, so install, run and
//! exit-code flows are testable without Wine.
//!
//! Only compiled under `cfg(any(test, feature = "testing"))`; dependents enable the `testing` feature through a
//! dev-dependency only, so it is never in a default or release build.
//!
//! `command` refuses an exe or cwd outside `drive_c` like every backend (`backend::inside_drive_c`), so the exe must
//! be a real file below `drive_c` (a test writes one). POSIX only: it builds `/bin/sh -c <script> <exe> <args...>`,
//! so inside the script `$0` is the exe path and
//! `"$@"` are the arguments verbatim (no shell ever parses them). Scripts can check the child's environment with
//! `/usr/bin/env >&2` (stderr goes to the log file), and exit codes with `exit N`. Like a real backend it sets
//! `WINEPREFIX` on the command, so tests can prove that the launcher re-applies backend variables.
use crate::backend::{Capabilities, Want, inside_drive_c};
use crate::{AppEnv, AppId, BackendError, CompatBackend, RunOpts};
use pe::{Arch, Subsystem};
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, PoisonError};

/// One recorded call on a [`FakeBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Prepare {
        app: AppId,
    },
    Command {
        app: AppId,
        exe: PathBuf,
        cwd: PathBuf,
        args: Vec<OsString>,
        debug: bool,
        dotnet: bool,
    },
    Stop {
        app: AppId,
    },
}

#[derive(Debug)]
pub struct FakeBackend {
    script: String,
    fail_prepare: bool,
    dll_dirs: Vec<PathBuf>,
    capabilities: Capabilities,
    calls: Mutex<Vec<Call>>,
}

/// [`FakeBackend`]'s default capabilities: both architectures and subsystems, every feature.
pub const FAKE_CAPABILITIES: Capabilities = Capabilities {
    arches: &[Arch::X86, Arch::X86_64],
    subsystems: &[Subsystem::Gui, Subsystem::Console],
    dotnet: true,
    installers: true,
    dependency_packages: true,
};

impl Default for FakeBackend {
    fn default() -> Self {
        FakeBackend::new()
    }
}

impl FakeBackend {
    /// Runs `exit 0`.
    pub fn new() -> FakeBackend {
        FakeBackend::with_script("exit 0")
    }

    /// `command` runs this `/bin/sh` script.
    pub fn with_script(script: &str) -> FakeBackend {
        FakeBackend {
            script: script.to_owned(),
            fail_prepare: false,
            dll_dirs: Vec::new(),
            capabilities: FAKE_CAPABILITIES,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// `prepare` leaves a partial prefix (`prefix/` only) and fails.
    pub fn failing_prepare(mut self) -> FakeBackend {
        self.fail_prepare = true;
        self
    }

    pub fn with_dll_dirs(mut self, dirs: Vec<PathBuf>) -> FakeBackend {
        self.dll_dirs = dirs;
        self
    }

    /// Declares `capabilities` instead of [`FAKE_CAPABILITIES`] (the refusals by capability are tested with it).
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> FakeBackend {
        self.capabilities = capabilities;
        self
    }

    /// Every call so far, oldest first.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn record(&self, c: Call) {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).push(c);
    }
}

impl CompatBackend for FakeBackend {
    fn id(&self) -> &'static str {
        "fake"
    }

    fn version(&self) -> Result<String, BackendError> {
        Ok("fake-1.0".into())
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.record(Call::Prepare { app: env.id().clone() });
        let io = |what, source| BackendError::Io { what, source };
        let mut dirs = DirBuilder::new();
        dirs.recursive(true).mode(0o700);
        dirs.create(env.prefix()).map_err(|e| io("create prefix", e))?;
        if self.fail_prepare {
            return Err(BackendError::failed("fake prepare", b"configured to fail"));
        }
        dirs.create(env.drive_c()).map_err(|e| io("create drive_c", e))?;
        fs::write(env.prefix().join(".fake-prepared"), b"1").map_err(|e| io("write marker", e))
    }

    fn command(
        &self,
        env: &AppEnv,
        exe_unix: &Path,
        cwd_unix: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<Command, BackendError> {
        self.record(Call::Command {
            app: env.id().clone(),
            exe: exe_unix.to_owned(),
            cwd: cwd_unix.to_owned(),
            args: args.to_vec(),
            debug: opts.debug,
            dotnet: opts.dotnet,
        });
        // The contract's containment, as every backend keeps it (`inside_drive_c`).
        let exe_unix = inside_drive_c(env, exe_unix, "executable", Want::File)?;
        let cwd_unix = inside_drive_c(env, cwd_unix, "working directory", Want::Dir)?;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(&self.script)
            .arg(exe_unix)
            .args(args)
            .current_dir(cwd_unix)
            .env("WINEPREFIX", env.prefix());
        Ok(cmd)
    }

    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.record(Call::Stop { app: env.id().clone() });
        Ok(())
    }

    fn dll_dirs(&self) -> Vec<PathBuf> {
        self.dll_dirs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Launcher, LogSink, Store};
    use std::fs;

    fn env() -> (tempfile::TempDir, AppEnv) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        let env = store.create(&AppId::parse("t").unwrap()).unwrap();
        (tmp, env)
    }

    /// `drive_c/app.exe` (created, with `drive_c`, if missing).
    fn exe(env: &AppEnv) -> PathBuf {
        fs::create_dir_all(env.drive_c()).unwrap();
        let exe = env.drive_c().join("app.exe");
        fs::write(&exe, b"MZ").unwrap();
        exe
    }

    fn run_log(b: &FakeBackend, env: &AppEnv, args: &[OsString]) -> (Option<i32>, String) {
        let cmd = b
            .command(env, &exe(env), &env.drive_c(), args, &RunOpts::default())
            .unwrap();
        let l = Launcher::with_host_env([("PATH", "/usr/bin:/bin")]);
        let r = l.spawn(cmd, env, LogSink::LogOnly).unwrap();
        let path = r.log_path().to_path_buf();
        let code = r.wait().unwrap().code();
        (code, fs::read_to_string(path).unwrap())
    }

    #[test]
    fn prepare_creates_the_marker_layout_and_is_recorded() {
        let (_t, env) = env();
        let b = FakeBackend::new();
        b.prepare(&env).unwrap();
        assert!(env.drive_c().is_dir());
        assert!(env.prefix().join(".fake-prepared").is_file());
        b.prepare(&env).unwrap(); // idempotent
        assert_eq!(b.calls(), vec![Call::Prepare { app: env.id().clone() }; 2]);
    }

    #[test]
    fn a_failing_prepare_leaves_a_partial_prefix_and_reports_an_error() {
        let (_t, env) = env();
        let b = FakeBackend::new().failing_prepare();
        let e = b.prepare(&env).unwrap_err();
        assert!(matches!(e, BackendError::Failed { .. }), "{e:?}");
        assert!(env.prefix().is_dir());
        assert!(!env.drive_c().exists());
        assert_eq!(b.calls().len(), 1);
    }

    #[test]
    fn command_records_its_arguments_and_stop_is_recorded() {
        let (_t, env) = env();
        let b = FakeBackend::new();
        b.prepare(&env).unwrap();
        let args = vec![OsString::from("a b"), OsString::from("--x")];
        let exe = exe(&env);
        b.command(
            &env,
            &exe,
            &env.drive_c(),
            &args,
            &RunOpts {
                debug: true,
                dotnet: false,
            },
        )
        .unwrap();
        b.stop(&env).unwrap();
        assert_eq!(
            b.calls()[1..],
            [
                Call::Command {
                    app: env.id().clone(),
                    exe,
                    cwd: env.drive_c(),
                    args,
                    debug: true,
                    dotnet: false
                },
                Call::Stop { app: env.id().clone() }
            ]
        );
        assert_eq!(b.id(), "fake");
        assert_eq!(b.version().unwrap(), "fake-1.0");
        assert!(b.dll_dirs().is_empty());
        assert_eq!(
            FakeBackend::new().with_dll_dirs(vec!["/d".into()]).dll_dirs(),
            [PathBuf::from("/d")]
        );
    }

    #[test]
    fn the_command_refuses_an_exe_or_cwd_outside_drive_c() {
        let (_t, env) = env();
        let b = FakeBackend::new();
        let inside = exe(&env);
        fs::write(env.prefix().join("evil.exe"), b"MZ").unwrap();
        for (e, cwd) in [
            (env.prefix().join("evil.exe"), env.drive_c()),
            (env.drive_c().join("../evil.exe"), env.drive_c()),
            (inside.clone(), env.prefix()),
        ] {
            let r = b.command(&env, &e, &cwd, &[], &RunOpts::default());
            assert!(
                matches!(r, Err(BackendError::OutsideDriveC { .. })),
                "{e:?} {cwd:?}: {r:?}"
            );
        }
    }

    #[test]
    fn the_command_runs_the_script_and_exit_codes_pass_through() {
        let (_t, env) = env();
        let b = FakeBackend::with_script("exit 7");
        b.prepare(&env).unwrap();
        assert_eq!(run_log(&b, &env, &[]).0, Some(7));
        let b = FakeBackend::new();
        assert_eq!(run_log(&b, &env, &[]).0, Some(0));
    }

    #[test]
    fn args_reach_the_script_verbatim_and_no_shell_parses_them() {
        let (_t, env) = env();
        let b = FakeBackend::with_script(r#"echo "$0" >&2; printf '<%s>\n' "$@" >&2"#);
        b.prepare(&env).unwrap();
        let args: Vec<OsString> = ["a b", "$(touch pwned)", "x;y", "l1\nl2", "'q'", "`id`", "*", "-n"]
            .map(OsString::from)
            .to_vec();
        let (code, log) = run_log(&b, &env, &args);
        assert_eq!(code, Some(0));
        let log = log
            .strip_prefix(&format!("{}\n", exe(&env).display()))
            .unwrap_or_else(|| panic!("$0 is not the exe: {log}"));
        let want = "<a b>\n<$(touch pwned)>\n<x;y>\n<l1\nl2>\n<'q'>\n<`id`>\n<*>\n<-n>\n";
        assert_eq!(log, want);
        assert!(!env.drive_c().join("pwned").exists());
    }

    #[test]
    fn the_command_sets_the_backend_prefix_and_cwd() {
        let (_t, env) = env();
        let b = FakeBackend::with_script("pwd >&2; echo \"$WINEPREFIX\" >&2");
        b.prepare(&env).unwrap();
        let (_, log) = run_log(&b, &env, &[]);
        let mut lines = log.lines();
        let cwd = fs::canonicalize(env.drive_c()).unwrap();
        assert_eq!(fs::canonicalize(lines.next().unwrap()).unwrap(), cwd);
        assert_eq!(lines.next().unwrap(), env.prefix().to_str().unwrap());
    }
}
