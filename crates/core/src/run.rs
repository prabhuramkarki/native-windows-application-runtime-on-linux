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
//! No locking: `run` can race a concurrent `remove` of the same app (last writer wins, as everywhere in the store).
use crate::text::quote;
use crate::winpath::{ResolveError, WinPath, WinPathError, resolve_under};
use crate::{
    AppId, BackendError, CompatBackend, InstallError, InstallOpts, InstallOutcome, LaunchError, Launcher, LogSink,
    Metadata, RunOpts, Running, Store, StoreError, install,
};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

/// What the run service takes besides the target and the arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Verbose backend logging and the child's stderr also on the terminal (see the module docs).
    pub debug: bool,
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
    let (id, installed) = resolve_target(store, backend, target, env.base)?;
    let app = store.get(&id)?;
    // `read_metadata`, not just `get`: it validates the file and that its id is the directory's.
    let md = store.read_metadata(&app)?;
    check_known(&id, &md, backend.id())?;

    let exe_text = WinPath::parse(&md.executable).map_err(|source| RunAppError::Path { id: id.clone(), source })?;
    let unusable = |why: String| RunAppError::ExecutableMissing {
        id: id.clone(),
        exe: quote(&md.executable),
        why,
    };
    // Contained in `drive_c`, no symlink on the way; the last component may still be a directory or special file.
    let exe = resolve_under(&app.drive_c(), &exe_text).map_err(|e: ResolveError| unusable(e.to_string()))?;
    match fs::symlink_metadata(&exe) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(unusable("not a regular file".into())),
        Err(e) => return Err(unusable(e.to_string())),
    }
    let cwd = exe.parent().ok_or_else(|| unusable("it has no directory".into()))?;

    // One flag, two effects: the backend's verbosity and the sink.
    let run_opts = RunOpts { debug: opts.debug };
    let sink = if opts.debug {
        LogSink::Tee((env.terminal)())
    } else {
        LogSink::LogOnly
    };
    let cmd = backend.command(&app, &exe, cwd, args, &run_opts)?;
    let running = launcher.spawn(cmd, &app, sink)?;
    Ok(Started { id, installed, running })
}

/// Which app the target names, installing the file first when it is one (see [`TargetKind`]). An installed app
/// always wins over a file of the same name.
fn resolve_target(
    store: &Store,
    backend: &dyn CompatBackend,
    target: &str,
    base: &Path,
) -> Result<(AppId, Option<InstallOutcome>), RunAppError> {
    let file = base.join(target);
    let install_file = || -> Result<(AppId, Option<InstallOutcome>), RunAppError> {
        let outcome = install(store, backend, &file, &InstallOpts::default())?;
        Ok((outcome.id.clone(), Some(outcome)))
    };
    let no_such_file = || RunAppError::NoSuchFile { path: quote(target) };
    if target.is_empty() {
        return Err(no_such_file());
    }
    if classify(target) == TargetKind::Path {
        return if file.exists() {
            install_file()
        } else {
            Err(no_such_file())
        };
    }
    let Ok(id) = AppId::parse(target) else {
        return if file.exists() {
            install_file()
        } else {
            Err(no_such_file())
        };
    };
    match store.get(&id) {
        Ok(_) => Ok((id, None)),
        Err(StoreError::NotFound) if file.exists() => install_file(),
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
