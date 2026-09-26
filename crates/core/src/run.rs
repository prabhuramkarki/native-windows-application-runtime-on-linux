//! The run service: turns a target (an installed app id, or a path to a program that is installed first) into a
//! running child and its exit status.
//!
//! ```text
//! target --classify--> id ---------------------------> Store::get + read_metadata
//!                  \-> path --install::install-------/        |
//!                                                   known-values checks (architecture, backend, environment)
//!                                                             |
//!                          winpath::resolve_under(drive_c, metadata.executable) + regular-file check
//!                                                             |
//!                  backend.command(env, exe, cwd, args, RunOpts{debug}) --> Launcher::spawn(.., sink) --> wait
//! ```
//!
//! [`find_target`] does the first step alone (no backend needed: a front end reports "no such app" before it looks
//! for Wine) and [`resolve_program`] the middle (`get` to regular-file check; `doctor` uses it too). When the
//! target was a file, a failure after its install is wrapped in [`RunAppError::AfterInstall`], which names the new
//! app and says how to remove it.
//!
//! **Untrusted input.** The target text, `metadata.json` and the file system below the app directory are all
//! untrusted. A path or command is never built from a free metadata string: `architecture`, `backend.id` and
//! `environment` are only compared with known values, and the executable is a canonical `WinPath` mapped with
//! `resolve_under` (no symlinks, contained in `drive_c`) that must be a regular file. `subsystem` is not used.
//! Arguments reach the backend as `OsString`s exactly as given; nothing here (or in `Launcher`) invokes a shell.
//!
//! **`debug`** is one flag with two effects, taken from the same [`RunOptions`]: it is passed to
//! `CompatBackend::command` (verbose backend logging) and it selects the [`LogSink`] (`Tee` to the terminal
//! next to the log file, else `LogOnly`), so the two can never disagree.
//!
//! **Ctrl-C.** The service does not handle signals. [`start`] and [`Started::wait`] are separate so a front end
//! can ignore SIGINT while it waits (the terminal delivers Ctrl-C to the whole foreground process group, so the
//! child sees it; the front end must survive to report the child's status) and can call [`Started::kill`]
//! for a timeout. [`run`] is `start` + `wait`.
//!
//! **Sandbox.** [`RunOptions::sandbox`] is attached to the ONE spawn of the program (`launcher.with_sandbox`);
//! everything else keeps the plain launcher: the install of a file target, and the backend's `prepare`/`stop`
//! helpers, which run through the backend's own launcher anyway. The sandboxed command is first wrapped in
//! `CompatBackend::settle`: a `--unshare-pid` sandbox kills every process of its PID namespace the moment the
//! program exits, so Wine's `wineserver` would die before it flushes the registry; `settle` waits for it INSIDE the
//! sandbox (the exit status stays the program's). A sandbox that refuses the command starts nothing
//! ([`LaunchError::Sandbox`]).
//!
//! No locking: `run` can race a concurrent `remove` of the same app (last writer wins, as everywhere in the store).
use crate::text::quote;
use crate::winpath::{ResolveError, WinPath, WinPathError, resolve_under};
use crate::{
    AppEnv, AppId, BackendError, CompatBackend, InstallError, InstallOpts, InstallOutcome, LaunchError, Launcher,
    LogSink, Metadata, RunOpts, Running, Sandbox, Store, StoreError, install,
};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;

/// What the run service takes besides the target and the arguments.
#[derive(Clone, Default)]
pub struct RunOptions {
    /// Verbose backend logging and the child's stderr also on the terminal (see the module docs).
    pub debug: bool,
    /// The sandbox of the program's own process (see the module docs); `None`: none.
    pub sandbox: Option<Arc<dyn Sandbox>>,
}

/// How a target string is read (Ruling 1 of the plan): a string containing `/` or ending in `.exe`/`.zip` (any
/// case) is a PATH, everything else an app id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Path,
    Id,
}

pub fn classify(target: &str) -> TargetKind {
    let lower = target.to_lowercase();
    if target.contains('/') || lower.ends_with(".exe") || lower.ends_with(".zip") {
        TargetKind::Path
    } else {
        TargetKind::Id
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunAppError {
    #[error("no app named {id} is installed (see `runtime list`; to install a program: `runtime install <file>`)")]
    NotInstalled { id: String },
    #[error(
        "no such file: {path} (an app id is a name from `runtime list`; to install a program: `runtime install <file>`)"
    )]
    NoSuchFile { path: String },
    #[error("app {id}: metadata field `{field}` has an unexpected value {value}")]
    BadMetadata {
        id: AppId,
        field: &'static str,
        value: String,
    },
    #[error("app {id} was installed for backend {recorded}, but this is backend {current}")]
    BackendMismatch {
        id: AppId,
        recorded: String,
        current: &'static str,
    },
    #[error(
        "app {id}: its program {exe} cannot be found or used in the environment ({why}); `runtime repair` is not implemented yet: remove the app with `runtime remove {id}` and install it again"
    )]
    ExecutableMissing { id: AppId, exe: String, why: String },
    #[error("app {id}: {source}")]
    Path {
        id: AppId,
        #[source]
        source: WinPathError,
    },
    /// The file WAS installed (and stays installed) but starting it failed: the message says how to undo that.
    #[error("{source}; the program was already installed as {id}: undo that with `runtime remove {id}`")]
    AfterInstall {
        id: AppId,
        #[source]
        source: Box<RunAppError>,
    },
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("{0}")]
    Install(#[from] InstallError),
    #[error("{0}")]
    Backend(#[from] BackendError),
    #[error("{0}")]
    Launch(#[from] LaunchError),
    #[error("cannot wait for the program: {0}")]
    Wait(#[source] io::Error),
}

/// A started program. It must be waited for ([`Started::wait`]) or killed and then waited for.
#[must_use = "a Started program must be waited for"]
pub struct Started {
    pub id: AppId,
    /// `Some` when the target was a file that had to be installed first.
    pub installed: Option<InstallOutcome>,
    running: Running,
}

/// How a program ended.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub id: AppId,
    pub installed: Option<InstallOutcome>,
    pub status: ExitStatus,
    /// `status.code()`, or 128 + the signal number for a program killed by a signal.
    pub exit_code: i32,
    pub log_path: PathBuf,
    /// The log file stopped accepting writes (only observable with `debug`, see `Finished`).
    pub log_write_failed: bool,
    /// The terminal writer of `debug` failed.
    pub terminal_write_failed: bool,
}

/// The exit code a shell would report: the program's own, or 128 + the signal number.
pub fn exit_code(status: ExitStatus) -> i32 {
    status.code().or_else(|| status.signal().map(|s| 128 + s)).unwrap_or(1)
}

/// Test seams: the directory relative targets are read against and the terminal writer of `debug`.
pub(crate) struct Env<'a> {
    pub base: &'a Path,
    pub terminal: &'a dyn Fn() -> Box<dyn Write + Send>,
}

pub fn start(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    target: &str,
    args: &[OsString],
    opts: &RunOptions,
) -> Result<Started, RunAppError> {
    let terminal = || -> Box<dyn Write + Send> { Box::new(io::stderr()) };
    let env = Env {
        base: Path::new("."),
        terminal: &terminal,
    };
    start_in(store, backend, launcher, target, args, opts, &env)
}

pub fn run(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    target: &str,
    args: &[OsString],
    opts: &RunOptions,
) -> Result<RunOutcome, RunAppError> {
    start(store, backend, launcher, target, args, opts)?.wait()
}

impl Started {
    pub fn log_path(&self) -> &Path {
        self.running.log_path()
    }

    /// The pid of the started process (with a sandbox: of the sandbox's own process, e.g. `bwrap`).
    pub fn pid(&self) -> u32 {
        self.running.id()
    }

    /// SIGKILLs the program (see `Running::kill`); still call [`wait`](Self::wait) afterwards.
    pub fn kill(&mut self) -> io::Result<()> {
        self.running.kill()
    }

    pub fn wait(self) -> Result<RunOutcome, RunAppError> {
        let log_path = self.running.log_path().to_owned();
        let done = self.running.wait_report().map_err(RunAppError::Wait)?;
        Ok(RunOutcome {
            id: self.id,
            installed: self.installed,
            status: done.status,
            exit_code: exit_code(done.status),
            log_path,
            log_write_failed: done.log_write_failed,
            terminal_write_failed: done.terminal_write_failed,
        })
    }
}

pub(crate) fn start_in(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    target: &str,
    args: &[OsString],
    opts: &RunOptions,
    env: &Env<'_>,
) -> Result<Started, RunAppError> {
    let (id, installed) = match find_target(store, target, env.base)? {
        Target::Installed(id) => (id, None),
        Target::File(file) => {
            let outcome = install(store, backend, &file, &InstallOpts::default())?;
            (outcome.id.clone(), Some(outcome))
        }
    };
    match launch(store, backend, launcher, &id, args, opts, env) {
        Ok(running) => Ok(Started { id, installed, running }),
        // The install is done and stays: a failure now must not leave an app the user never heard of.
        Err(e) if installed.is_some() => Err(RunAppError::AfterInstall {
            id,
            source: Box::new(e),
        }),
        Err(e) => Err(e),
    }
}

fn launch(
    store: &Store,
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    id: &AppId,
    args: &[OsString],
    opts: &RunOptions,
    env: &Env<'_>,
) -> Result<Running, RunAppError> {
    let p = resolve_program(store, id, backend.id())?;
    // One flag, two effects: the backend's verbosity and the sink.
    let run_opts = RunOpts { debug: opts.debug };
    let sink = if opts.debug {
        LogSink::Tee((env.terminal)())
    } else {
        LogSink::LogOnly
    };
    let cmd = backend.command(&p.env, &p.exe, &p.cwd, args, &run_opts)?;
    // The program only (module docs, "Sandbox"): the backend's helpers never see this launcher.
    Ok(match &opts.sandbox {
        Some(sandbox) => launcher
            .clone()
            .with_sandbox(sandbox.clone())
            .spawn(backend.settle(cmd), &p.env, sink)?,
        None => launcher.spawn(cmd, &p.env, sink)?,
    })
}

/// An installed app's program, checked and mapped into the host file system.
#[derive(Debug, Clone)]
pub struct ResolvedProgram {
    pub env: AppEnv,
    /// Read with `Store::read_metadata` (validated, its id is the directory's) and passed the known-values checks.
    pub metadata: Metadata,
    /// The program's host path: contained in `drive_c`, no symlink on the way, a regular file.
    pub exe: PathBuf,
    /// The directory of `exe` (the program's working directory).
    pub cwd: PathBuf,
}

/// Everything `run` checks before it starts an installed app, shared with `doctor`: the app exists, its
/// metadata is valid and passes the known-values checks (see the module docs; `backend_id` is the current
/// backend's), and its executable resolves to a regular file inside `drive_c`. Reads only; nothing is spawned.
pub fn resolve_program(store: &Store, id: &AppId, backend_id: &'static str) -> Result<ResolvedProgram, RunAppError> {
    let env = match store.get(id) {
        Ok(env) => env,
        Err(StoreError::NotFound) => return Err(RunAppError::NotInstalled { id: id.to_string() }),
        Err(e) => return Err(e.into()),
    };
    // `read_metadata`, not just `get`: it validates the file and that its id is the directory's.
    let metadata = store.read_metadata(&env)?;
    check_known(id, &metadata, backend_id)?;

    let exe_text =
        WinPath::parse(&metadata.executable).map_err(|source| RunAppError::Path { id: id.clone(), source })?;
    let unusable = |why: String| RunAppError::ExecutableMissing {
        id: id.clone(),
        exe: quote(&metadata.executable),
        why,
    };
    // Contained in `drive_c`, no symlink on the way; the last component may still be a directory or special file.
    let exe = resolve_under(&env.drive_c(), &exe_text).map_err(|e: ResolveError| unusable(e.to_string()))?;
    match fs::symlink_metadata(&exe) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(unusable("not a regular file".into())),
        Err(e) => return Err(unusable(e.to_string())),
    }
    let cwd = exe
        .parent()
        .ok_or_else(|| unusable("it has no directory".into()))?
        .to_owned();
    Ok(ResolvedProgram {
        env,
        metadata,
        exe,
        cwd,
    })
}

/// What a target names (see [`find_target`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Installed(AppId),
    /// A file (not yet installed), joined onto the base directory.
    File(PathBuf),
}

/// Which app or file the target names (see [`TargetKind`]); an installed app always wins over a file of the same
/// name. Needs no backend, so a front end can report "no such app" before it looks for Wine.
pub fn find_target(store: &Store, target: &str, base: &Path) -> Result<Target, RunAppError> {
    let file = base.join(target);
    let no_such_file = || RunAppError::NoSuchFile { path: quote(target) };
    let file_or_missing = |file: PathBuf| {
        if file.exists() {
            Ok(Target::File(file))
        } else {
            Err(no_such_file())
        }
    };
    if target.is_empty() {
        return Err(no_such_file());
    }
    if classify(target) == TargetKind::Path {
        return file_or_missing(file);
    }
    let Ok(id) = AppId::parse(target) else {
        return file_or_missing(file);
    };
    match store.get(&id) {
        Ok(_) => Ok(Target::Installed(id)),
        Err(StoreError::NotFound) if file.exists() => Ok(Target::File(file)),
        Err(StoreError::NotFound) => Err(RunAppError::NotInstalled { id: id.to_string() }),
        Err(e) => Err(e.into()),
    }
}

/// The known-values checks of the module docs on `md`. `Metadata::validate` (inside `read_metadata`) checks the
/// architecture too; it is repeated here because this is the place that acts on it.
fn check_known(id: &AppId, md: &Metadata, backend_id: &'static str) -> Result<(), RunAppError> {
    let bad = |field: &'static str, value: &str| RunAppError::BadMetadata {
        id: id.clone(),
        field,
        value: quote(value),
    };
    if !matches!(md.architecture.as_str(), "x86" | "x86_64") {
        return Err(bad("architecture", &md.architecture));
    }
    if md.backend.id != backend_id {
        return Err(RunAppError::BackendMismatch {
            id: id.clone(),
            recorded: quote(&md.backend.id),
            current: backend_id,
        });
    }
    if md.environment != "default" {
        return Err(bad("environment", &md.environment));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
