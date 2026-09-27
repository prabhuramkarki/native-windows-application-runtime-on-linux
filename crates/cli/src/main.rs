mod analyze;
mod deps;
mod display;
mod doctor;
mod graphics;
mod install;
mod list;
mod logs;
mod permissions;
mod remove;
mod rpc;
mod run;
mod safe;
mod sandbox;
mod sandbox_init;
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
    /// and gpu (default on), host directories (default none) and resource limits. `--set network=allow`,
    /// `--set gpu=off`, `--set fs+=/abs/dir:ro|rw`, `--set fs-=/abs/dir`, `--set memory=<MiB>|off`,
    /// `--set cpu=<percent>|off`, `--set tasks=<n>|unlimited|default` (repeatable; all are checked before anything is
    /// written);
    /// `--reset` returns to the default. Changing needs the app to be stopped. `$HOME`, `/`, the runtime's data
    /// directory and secret directories (`~/.ssh`, `~/.gnupg`, ...) can never be granted.
    Permissions {
        /// An app id from `runtime list`
        app: String,
        /// Change one permission: network=allow|deny, display|audio|gpu=on|off, fs+=/abs/dir:ro|rw, fs-=/abs/dir,
        /// memory=<MiB>|off, cpu=<percent>|off, tasks=<n>|unlimited|default
        #[arg(long = "set", value_name = "EXPR")]
        set: Vec<String>,
        /// Delete the app's permissions.toml (back to the default)
        #[arg(long)]
        reset: bool,
        /// Machine-readable output: {network, display, audio, gpu, filesystem: [{path, access}], limits: {memory_mb,
        /// cpu_percent, tasks, tasks_default}}
        #[arg(long)]
        json: bool,
    },
    /// Show what an app's sandbox would be (needs no Wine; starts nothing but throwaway probes): whether bubblewrap
    /// and systemd user scopes work, the profile and its resource limits, what the host lacks, what the profile
    /// cannot enforce, and the full command line (systemd-run and bubblewrap)
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
    /// Call a method of a running `runtimed` and print its result as JSON (a raw tool for debugging and scripts;
    /// the methods are in docs/API.md). Exit code 1 on an error reply or when no daemon answers. No other command
    /// needs the daemon.
    Rpc {
        /// The method, e.g. `rpc.version`, `apps.list`, `apps.get`
        method: String,
        /// Its params as one JSON object, e.g. '{"id": "notepad"}'
        params: Option<String>,
        /// The daemon's socket (default: $XDG_RUNTIME_DIR/runtime/runtimed.sock)
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Whether a `runtimed` answers on its socket, and which API version it speaks. Exit code 1 when none does.
    DaemonStatus {
        /// The daemon's socket (default: $XDG_RUNTIME_DIR/runtime/runtimed.sock)
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// The sandbox's own launcher (runs inside bubblewrap; see `rt_sandbox::init`). Not for people.
    #[command(hide = true, disable_help_flag = true)]
    SandboxInit {
        /// The argument block the sandbox renderer built, passed on unparsed
        #[arg(allow_hyphen_values = true, trailing_var_arg = true, num_args = 0..)]
        args: Vec<OsString>,
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

/// This executable, for the installer sandbox's `sandbox-init` shim (`rt_installer::InstallerSandbox::new`). The
/// library checks it (absolute, not `(deleted)`, a resolvable file, outside the data directory) and refuses to run
/// the installer otherwise; an unknown path is passed as the empty path, which it refuses.
pub(crate) fn runtime_exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_default()
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

/// `runtime compat [--json]`: the bundled matrix (`rt_api::compat`), rendered.
fn compat(json: bool) -> Result<(), CmdError> {
    let c = rt_api::compat::bundled();
    emit(&if json {
        rt_api::compat::render_json(c)
    } else {
        rt_api::compat::render_table(c)
    })
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
        Cmd::Compat { json } => compat(json).map(|()| 0),
        Cmd::Graphics(GraphicsCmd::Info) => graphics::info(),
        Cmd::Rpc { method, params, socket } => rpc::rpc(&method, params.as_deref(), socket),
        Cmd::DaemonStatus { socket } => rpc::status(socket),
        Cmd::SandboxInit { args } => sandbox_init::run(&args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", safe::safe(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

/// The parser is the oracle for `runtimed`'s argv (`rt_api::jobs::JobSpec::argv`): with hostile values, every shape
/// parses to exactly the intended command. [`daemon_argv::check`] matches `JobSpec` without a wildcard arm, so a new
/// variant does not compile until its argv is checked here.
#[cfg(test)]
mod daemon_argv {
    use super::{Cli, Cmd};
    use clap::Parser;
    use rt_api::jobs::{Driver, JobSpec};
    use rt_core::AppId;
    use std::ffi::OsString;

    fn parse(spec: &JobSpec) -> Cmd {
        Cli::try_parse_from(std::iter::once("runtime".into()).chain(spec.argv()))
            .unwrap_or_else(|e| panic!("{spec:?}: {e}"))
            .cmd
    }

    fn id(s: &str) -> AppId {
        AppId::parse(s).unwrap()
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// `spec` parses to exactly the command it means (every flag it does not set stays off).
    fn check(spec: &JobSpec) {
        let cmd = parse(spec);
        match spec {
            JobSpec::Run { app, args } => {
                let Cmd::Run {
                    target,
                    debug,
                    unsandboxed,
                    args: a,
                } = cmd
                else {
                    panic!("{spec:?}: not run")
                };
                assert_eq!((target.as_str(), debug, unsandboxed), (app.as_str(), false, false));
                assert_eq!(a, args.iter().map(OsString::from).collect::<Vec<_>>());
            }
            JobSpec::Install {
                path,
                name,
                exe,
                silent,
                network,
            } => {
                let Cmd::Install {
                    file,
                    name: n,
                    exe: e,
                    silent: si,
                    network: ne,
                } = cmd
                else {
                    panic!("{spec:?}: not install")
                };
                assert_eq!((&file, &n, &e, si, ne), (path, name, exe, *silent, *network));
            }
            JobSpec::Remove { app } => {
                let Cmd::Remove { app: a } = cmd else {
                    panic!("{spec:?}: not remove")
                };
                assert_eq!(a, app.as_str());
            }
            JobSpec::DepsInstall { app, plan_digest, yes } => {
                let Cmd::Deps(a) = cmd else {
                    panic!("{spec:?}: not deps")
                };
                assert!(a.sub.is_none(), "{spec:?}: routed to a subcommand");
                assert_eq!(
                    (
                        a.app.as_deref(),
                        a.install,
                        &a.yes,
                        a.plan_digest.as_deref(),
                        a.discard_interrupted
                    ),
                    (Some(app.as_str()), true, yes, Some(plan_digest.as_str()), None)
                );
            }
            JobSpec::PermissionsSet { app, set } => {
                let Cmd::Permissions {
                    app: a,
                    set: s,
                    reset,
                    json,
                } = cmd
                else {
                    panic!("{spec:?}: not permissions")
                };
                assert_eq!((a.as_str(), &s, reset, json), (app.as_str(), set, false, false));
            }
            JobSpec::PermissionsReset { app } => {
                let Cmd::Permissions {
                    app: a,
                    set,
                    reset,
                    json,
                } = cmd
                else {
                    panic!("{spec:?}: not permissions")
                };
                assert_eq!((a.as_str(), set.len(), reset, json), (app.as_str(), 0, true, false));
            }
            JobSpec::DisplaySet { app, driver } => {
                let Cmd::Display { app: a, choice } = cmd else {
                    panic!("{spec:?}: not display")
                };
                assert_eq!((a.as_str(), choice.as_deref()), (app.as_str(), Some(driver.as_str())));
            }
        }
    }

    #[test]
    fn every_job_spec_parses_as_intended_with_hostile_values() {
        let hostile = ["-x", "--", ";", "--unsandboxed", "--debug", "$(id)", "a b"];
        let mut specs = vec![
            JobSpec::Run {
                app: id("notepad"),
                args: strings(&hostile),
            },
            JobSpec::Run {
                app: id("notepad"),
                args: vec![],
            },
            JobSpec::Remove { app: id("a-b") },
            JobSpec::PermissionsSet {
                app: id("a"),
                set: strings(&["--reset", "--json", "--", "network=allow"]),
            },
            JobSpec::PermissionsReset { app: id("a") },
        ];
        for (name, exe, silent, network) in [
            (Some("--network"), Some("--silent"), false, false),
            (Some("-n"), Some("--"), true, false),
            (None, Some("a=b --network"), false, true),
            (None, None, false, false),
        ] {
            specs.push(JobSpec::Install {
                path: "/-x/My Setup.exe".into(),
                name: name.map(String::from),
                exe: exe.map(String::from),
                silent,
                network,
            });
        }
        for driver in [Driver::Auto, Driver::X11, Driver::Wayland] {
            specs.push(JobSpec::DisplaySet { app: id("a"), driver });
        }
        // `list` and `cache` are also `deps` subcommands: after `--` they are the app.
        for (app, yes) in [
            ("notepad", vec![]),
            ("notepad", strings(&["vcrun2022", "-p", "--install", "--"])),
            ("list", vec![]),
            ("cache", strings(&["x"])),
        ] {
            specs.push(JobSpec::DepsInstall {
                app: id(app),
                plan_digest: "ab".repeat(32),
                yes,
            });
        }
        let mut kinds: Vec<_> = specs.iter().map(|s| format!("{:?}", s.kind())).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), 7, "one sample per variant at least: {kinds:?}");
        specs.iter().for_each(check);
    }
}
