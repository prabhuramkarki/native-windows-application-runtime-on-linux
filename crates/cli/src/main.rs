mod analyze;
mod compat;
mod deps;
mod display;
mod doctor;
mod graphics;
mod install;
mod list;
mod logs;
mod permissions;
mod remove;
mod run;
mod safe;
mod sandbox;
mod uninstall;

use clap::{Parser, Subcommand};
use rt_core::{Launcher, Store};
use std::{ffi::OsString, io::IsTerminal, io::Write, path::PathBuf, process::ExitCode};

pub(crate) type CmdError = Box<dyn std::error::Error>;

#[derive(Subcommand)]
enum GraphicsCmd {
    /// The Vulkan devices `vulkaninfo` lists and whether they are usable for DXVK/VKD3D (runs `vulkaninfo`, bounded)
    Info,
}

#[derive(Parser)]
#[command(name = "runtime", version, about = "Run Windows applications on Linux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect a Windows binary or installer (header-based, extension ignored)
    Analyze {
        file: PathBuf,
        /// Machine-readable output. Strings carry raw file content: only control characters below
        /// U+0020 are escaped (by JSON itself); C1 controls and bidi characters are emitted as is.
        /// Sanitise before displaying them.
        #[arg(long)]
        json: bool,
    },
    /// Install a portable .exe, a .zip archive, or a .msi/.exe installer into its own environment (needs Wine).
    /// Which one a file is is decided by its content, never its extension.
    Install {
        file: PathBuf,
        /// Display name (the app id is derived from it); default: the program's product name or file name.
        /// Not used for a .msi/.exe installer: its own name is used instead.
        #[arg(long)]
        name: Option<String>,
        /// For an archive: the program, as a path inside the archive (e.g. `bin/app.exe`). For a .msi/.exe
        /// installer: the app's own executable, as a path inside the installed prefix (e.g.
        /// `Program Files\App\app.exe`), skipping automatic discovery entirely.
        #[arg(long)]
        exe: Option<String>,
        /// Installer only: run it non-interactively with its standard silent-install flags (default: show its
        /// own GUI)
        #[arg(long)]
        silent: bool,
        /// Installer only: allow it network access while it runs (default: no network at all, not even loopback)
        #[arg(long)]
        network: bool,
    },
    /// Run an installed app, or install a .exe/.zip file first and run it (needs Wine and bubblewrap).
    /// The program runs in the app's sandbox (see `runtime sandbox <app>` and `runtime permissions <app>`).
    /// The exit code is the program's (128+N when it was killed by signal N).
    Run {
        /// An app id from `runtime list`, or a path (contains `/` or ends in .exe/.zip) to install and run
        target: String,
        /// Verbose Wine logging; the program's stderr also goes to the terminal (it is always kept in the log)
        #[arg(long)]
        debug: bool,
        /// Run WITHOUT the sandbox, with your full access (this run only; says so on stderr)
        #[arg(long)]
        unsandboxed: bool,
        /// Arguments for the program, passed as they are (write them after `--`)
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// List the installed apps
    List {
        /// Machine-readable output: an array of {id, name, version, architecture, executable, created}
        #[arg(long)]
        json: bool,
    },
    /// Check the system, an installed app or a file for problems (read-only: nothing is installed or changed).
    /// With no argument only the system is checked (Wine, host architecture, Vulkan, display, audio); with an app
    /// id its program and prefix too; a file (contains `/` or ends in .exe/.zip) is analysed but NOT installed.
    /// Exit code 1 when a check FAILS (a warning is not a failure).
    Doctor {
        /// An app id from `runtime list`, or a path to a program
        target: Option<String>,
        /// Machine-readable output: {subject, verdict, checks: [{area, status, text}]}. `area`, `status` and
        /// `verdict` are stable; `text` is prose for people, may change, and must not be parsed. Strings carry
        /// untrusted content: C1 controls and bidi characters are written as \uXXXX escapes.
        #[arg(long)]
        json: bool,
    },
    /// Stop an app's Wine processes and delete the app and its environment (takes an app id, never a path)
    Remove { app: String },
    /// Run an app's recorded installer uninstall command (if any), then delete the app and its environment
    /// regardless (takes an app id, never a path). An app with no recorded uninstaller (a portable-exe install,
    /// or one made before this existed) just has its environment removed, same as `runtime remove`.
    Uninstall { app: String },
    /// Show what an app needs from the runtime's package manifest (DXVK, the VC++ runtime, ...), and install it.
    /// `runtime deps <app>` only prints the plan (no network, no changes); `--install` downloads and installs it.
    /// Consent-gated packages print their licence text and ask first; without a terminal, `--yes <pkg>` consents
    /// for that package (the text is still printed). A package you do not consent to is skipped with everything
    /// that needs it; the packages it needs itself still install. `runtime deps list` shows the manifest,
    /// `runtime deps cache [--clear]` the download cache. Exit code 1 when anything failed or was skipped.
    Deps(deps::DepsArgs),
    /// Show or set the Wine graphics driver of an app (`auto` is Wine's own choice; `wayland` is experimental in
    /// Wine 10.0 and needs a Wayland session and a Wine built with it). Setting needs the app to be stopped.
    Display {
        /// An app id from `runtime list`
        app: String,
        /// The driver to set; without it the current one is shown
        #[arg(value_parser = ["auto", "x11", "wayland"])]
        choice: Option<String>,
    },
    /// Show or change what an app's sandbox may reach (`permissions.toml`): network (default deny), display, audio
    /// and gpu (default on) and host directories (default none). `--set network=allow`, `--set gpu=off`,
    /// `--set fs+=/abs/dir:ro|rw`, `--set fs-=/abs/dir` (repeatable; all are checked before anything is written);
    /// `--reset` returns to the default. Changing needs the app to be stopped. `$HOME`, `/`, the runtime's data
    /// directory and secret directories (`~/.ssh`, `~/.gnupg`, ...) can never be granted.
    Permissions {
        /// An app id from `runtime list`
        app: String,
        /// Change one permission: network=allow|deny, display|audio|gpu=on|off, fs+=/abs/dir:ro|rw, fs-=/abs/dir
        #[arg(long = "set", value_name = "EXPR")]
        set: Vec<String>,
        /// Delete the app's permissions.toml (back to the default)
        #[arg(long)]
        reset: bool,
        /// Machine-readable output: {network, display, audio, gpu, filesystem: [{path, access}]}
        #[arg(long)]
        json: bool,
    },
    /// Show what an app's sandbox would be (needs no Wine; starts nothing): whether bubblewrap works, the
    /// profile, what the host lacks, what the profile cannot enforce, and the full bubblewrap command line
    Sandbox {
        /// An app id from `runtime list`
        app: String,
    },
    /// Show what the host's graphics stack offers (`runtime graphics info`)
    #[command(subcommand)]
    Graphics(GraphicsCmd),
    /// Show the compatibility matrix: what was really run, on which Wine, and how it went (needs no Wine or
    /// network). The same table is `docs/COMPAT.md`.
    Compat {
        /// Machine-readable output: an array of {app, version, status, wine, gpu, graphics, evidence, notes}
        /// (absent optional fields are null)
        #[arg(long)]
        json: bool,
    },
    /// Show the newest log of an app (its last run's stderr)
    Logs {
        app: String,
        /// How many lines from the end (1-1000)
        #[arg(long, default_value_t = logs::DEFAULT_LINES)]
        lines: u32,
    },
}

/// The apps store under `$RUNTIME_DATA_DIR` (or the XDG default).
pub(crate) fn store() -> Result<Store, CmdError> {
    Ok(Store::new(rt_core::apps_dir()?)?)
}

/// The system Wine, with `launcher` for its helper processes (`run` spawns with the same launcher).
pub(crate) fn backend(launcher: &Launcher) -> Result<backend_wine::WineBackend, CmdError> {
    Ok(backend_wine::WineBackend::discover_with(launcher.clone())?)
}

/// Best-effort: deletes `id`'s `.desktop` entry and hicolor icons (`rt_desktop::entry::remove`), warning (never
/// failing) on error. Shared by `remove` and `uninstall` so the two removal commands cannot drift apart on this
/// again — both must clean up desktop integration, exactly like both already stop the backend and remove the
/// store unconditionally.
pub(crate) fn remove_desktop_entry(id: &rt_core::AppId) {
    if let Err(e) = rt_desktop::entry::remove(id) {
        safe::warn(&format!("could not remove this app's desktop menu entry: {e}"));
    }
}

/// Refuses while a `wineserver` still serves `env`'s prefix after the caller's `wineserver -k`, and when that cannot
/// be checked (fail closed). A SANDBOXED app's server is out of `-k`'s reach (its socket is in the sandbox's private
/// `/tmp`) but visible in the host's `/proc`; deleting its prefix under it would leave it running on a deleted tree.
/// A server that is still shutting down gets two seconds.
pub(crate) fn refuse_if_running(env: &rt_core::AppEnv) -> Result<(), CmdError> {
    let id = env.id();
    for attempt in 0..=20 {
        let pids = rt_deps::wineservers_for(&env.prefix())
            .map_err(|e| format!("cannot check whether {id} is running: {e}; nothing was removed"))?;
        match pids.first() {
            None => return Ok(()),
            Some(pid) if attempt == 20 => {
                return Err(format!(
                    "{id} is running (wineserver pid {pid}); quit it (Ctrl-C its `runtime run`) first; nothing was \
                     removed"
                )
                .into());
            }
            Some(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    unreachable!("the last attempt returns")
}

/// Writes to stdout; a closed pipe (`| head`) is the reader's choice, not an error.
pub(crate) fn emit(text: &str) -> Result<(), CmdError> {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("RUNTIME_LOG"))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // Usage errors echo what the user typed: sanitise it like everything else.
        Err(e) if e.use_stderr() => {
            eprint!("{}", safe::safe_lines(&e.render().to_string()));
            return ExitCode::from(2);
        }
        Err(e) => e.exit(), // --help / --version
    };
    let result = match cli.cmd {
        Cmd::Analyze { file, json } => analyze::run(&file, json).map(|()| 0),
        Cmd::Install {
            file,
            name,
            exe,
            silent,
            network,
        } => install::run(&file, name, exe, silent, network),
        Cmd::Run {
            target,
            debug,
            unsandboxed,
            args,
        } => run::run(&target, &args, debug, unsandboxed),
        Cmd::Doctor { target, json } => doctor::run(target.as_deref(), json),
        Cmd::List { json } => list::run(json).map(|()| 0),
        Cmd::Remove { app } => remove::run(&app).map(|()| 0),
        Cmd::Uninstall { app } => uninstall::run(&app).map(|()| 0),
        Cmd::Logs { app, lines } => logs::run(&app, lines).map(|()| 0),
        Cmd::Deps(args) => deps::run(args),
        Cmd::Display { app, choice } => display::run(&app, choice.as_deref()).map(|()| 0),
        Cmd::Permissions { app, set, reset, json } => permissions::run(&app, &set, reset, json).map(|()| 0),
        Cmd::Sandbox { app } => sandbox::run(&app).map(|()| 0),
        Cmd::Compat { json } => compat::run(json).map(|()| 0),
        Cmd::Graphics(GraphicsCmd::Info) => graphics::info(),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", safe::safe(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}
