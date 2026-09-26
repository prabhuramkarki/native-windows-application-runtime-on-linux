//! The two building blocks every sandboxed installer run shares: [`stage_file`] (copy a file into `drive_c`, the
//! only place anything is ever run from) and [`run_sandboxed`] (one command through the backend, settled, inside
//! [`InstallerSandbox`], waited for). Phase 3's install pipeline and Phase 4's dependency installer
//! (`rt_deps::install_installer`) both call exactly these, so the sandbox wiring exists once.
use crate::pipeline::InstallerError;
use crate::sandbox::{InstallerSandbox, SandboxOpts};
use rt_core::{AppEnv, CompatBackend, Launcher, LogSink, RunOpts, WinPath, join_new};
use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

/// How often [`run_sandboxed`] looks at a child that has a deadline.
const POLL: Duration = Duration::from_millis(50);

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> InstallerError {
    move |source| InstallerError::Io { what, source }
}

/// Copies `src` to `<dir>\<file_name>` inside `env`'s `drive_c` and returns that file's `WinPath`. `dir` is a
/// `C:\...` path; it is created (`0755`) as needed. Containment as in Phase 2's `install::place`: [`join_new`]
/// refuses a symlink at any existing component, `create_new` (`O_EXCL`) never overwrites and never follows a
/// symlink at the destination itself; the file is `0644`. `file_name` must be exactly one path component.
pub fn stage_file(env: &AppEnv, dir: &str, file_name: &str, src: &mut dyn Read) -> Result<WinPath, InstallerError> {
    let dir_winpath = WinPath::parse(dir)?;
    let dest_winpath = WinPath::parse(&format!("{dir}\\{file_name}"))?;
    if dest_winpath.components().len() != dir_winpath.components().len() + 1
        || dest_winpath.components().last().map(String::as_str) != Some(file_name)
    {
        return Err(InstallerError::BadFileName(
            "the name is not a single path component".into(),
        ));
    }
    let drive_c = env.drive_c();
    let dest_dir = join_new(&drive_c, &dir_winpath)?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&dest_dir)
        .map_err(io_err("cannot create the installer staging directory"))?;
    let dest = join_new(&drive_c, &dest_winpath)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&dest)
        .map_err(io_err("cannot create the installer file"))?;
    io::copy(src, &mut out).map_err(io_err("cannot write the installer file"))?;
    Ok(dest_winpath)
}

/// Runs `exe_unix` with `args` (each one argv element) through `backend.command` (cwd `drive_c`), wrapped by
/// [`CompatBackend::settle`] BEFORE the sandbox sees it (a `--unshare-pid` sandbox kills a lingering `wineserver`
/// the instant its direct child exits, so the wait for it must happen inside the same process tree), then inside
/// `sandbox` (with `opts`), and waits.
///
/// `deadline: None` waits as long as it takes (Phase 3: an interactive installer GUI can take any time).
/// `Some(d)`: once `d` has passed the sandbox is killed and reaped and `Ok(None)` is returned. Killing `bwrap`
/// kills the whole tree: `--die-with-parent` and the PID namespace take every process inside with it, a
/// `wineserver` included (its registry flush may be lost; the caller treats the run as failed).
#[allow(clippy::too_many_arguments)]
pub fn run_sandboxed(
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    env: &AppEnv,
    sandbox: &InstallerSandbox,
    exe_unix: &Path,
    args: &[OsString],
    opts: SandboxOpts,
    deadline: Option<Duration>,
) -> Result<Option<ExitStatus>, InstallerError> {
    let sandboxed = launcher
        .clone()
        .with_sandbox(sandbox.clone().for_launcher(env.clone(), opts));
    let cmd = backend.command(env, exe_unix, &env.drive_c(), args, &RunOpts::default())?;
    let cmd = backend.settle(cmd);
    let mut running = sandboxed.spawn(cmd, env, LogSink::LogOnly)?;
    let wait_err = io_err("cannot wait for the installer process");
    let Some(deadline) = deadline else {
        return running.wait().map(Some).map_err(wait_err);
    };
    // `None` = a deadline too far away to represent: wait as long as it takes.
    let end = Instant::now().checked_add(deadline);
    loop {
        match running.try_wait() {
            Ok(Some(_)) => return running.wait().map(Some).map_err(wait_err),
            Ok(None) => {}
            Err(e) => {
                let _ = running.kill();
                let _ = running.wait();
                return Err(wait_err(e));
            }
        }
        if end.is_some_and(|end| Instant::now() >= end) {
            // Kill, then reap: a killed child that is never waited for stays a zombie.
            let _ = running.kill();
            let _ = running.wait();
            return Ok(None);
        }
        std::thread::sleep(POLL);
    }
}
