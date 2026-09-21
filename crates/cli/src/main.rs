mod analyze;
mod install;
mod list;
mod logs;
mod remove;
mod run;
mod safe;

use clap::{Parser, Subcommand};
use rt_core::{Launcher, Store};
use std::{ffi::OsString, io::IsTerminal, io::Write, path::PathBuf, process::ExitCode};

/// What every command that runs Windows code tells the user (the real boundary is Phase 5).
pub(crate) const SANDBOX_NOTE: &str =
    "note: Windows applications run WITHOUT a sandbox until Phase 5 (see docs/SECURITY.md)";

pub(crate) type CmdError = Box<dyn std::error::Error>;

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
    /// Install a portable .exe or a .zip archive into its own environment (needs Wine)
    Install {
        file: PathBuf,
        /// Display name (the app id is derived from it); default: the program's product name or file name
        #[arg(long)]
        name: Option<String>,
        /// For an archive: the program, as a path inside the archive (e.g. `bin/app.exe`)
        #[arg(long)]
        exe: Option<String>,
    },
    /// Run an installed app, or install a .exe/.zip file first and run it (needs Wine).
    /// The exit code is the program's (128+N when it was killed by signal N).
    Run {
        /// An app id from `runtime list`, or a path (contains `/` or ends in .exe/.zip) to install and run
        target: String,
        /// Verbose Wine logging; the program's stderr also goes to the terminal (it is always kept in the log)
        #[arg(long)]
        debug: bool,
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
    /// Stop an app's Wine processes and delete the app and its environment (takes an app id, never a path)
    Remove { app: String },
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
        Cmd::Install { file, name, exe } => install::run(&file, name, exe).map(|()| 0),
        Cmd::Run { target, debug, args } => run::run(&target, &args, debug),
        Cmd::List { json } => list::run(json).map(|()| 0),
        Cmd::Remove { app } => remove::run(&app).map(|()| 0),
        Cmd::Logs { app, lines } => logs::run(&app, lines).map(|()| 0),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", safe::safe(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}
