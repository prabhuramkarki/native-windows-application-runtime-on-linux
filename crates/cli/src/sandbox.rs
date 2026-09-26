//! The app sandbox as the CLI uses it (`rt_sandbox`): building it for `runtime run`, `runtime sandbox <app>`
//! (what the sandbox of an app would be, without running anything), the doctor check, and the launcher for the
//! Wine helpers that start a session in an app's prefix.
//!
//! **`run`.** bwrap must be on `PATH` and [`rt_sandbox::probe`] must really create a sandbox, or nothing starts
//! (fail closed; `--unsandboxed` is the per-run way out). The profile is the app's `permissions.toml` (the default
//! profile when it has none); a file target is a NEW app (the install creates it inside `rt_core::start`), which
//! has no `permissions.toml` yet, so it gets the default profile. The `AppSandbox` finds the app again from the
//! command's `WINEPREFIX` and refuses a command of another shape, so a profile loaded for one app can never be
//! rendered around another's prefix. [`RunSandbox`] renders BEFORE the spawn (`Sandbox::try_wrap`: a refusal is
//! an error, never the fail-closed stub), prints what the profile cannot enforce (`note: ...`, one line each) and
//! records [`MARKER`]. The profile's resource limits wrap the run in a `systemd-run --user` scope (`rt_sandbox`'s
//! renderer, "Limits"); whether scopes work is probed once per command (`RealHost::scopes`) and shown by `runtime
//! sandbox` (a `limits:` section) and `doctor` (one check, a warning at worst).
//!
//! **Helpers in a prefix the app has written.** A sandboxed program can write its own prefix: registry `Run` keys
//! and services, `DllOverrides` naming a native DLL it dropped. The next Wine session in that prefix runs them, and
//! outside the sandbox that is the user's full access (Wine's `\\?\unix\` paths reach every host file). So once an
//! app has run sandboxed ([`MARKER`] in its app root, which the sandbox never shows the program), the helpers that
//! start a Wine session in its prefix (`reg.exe` for `runtime display` and archive packages of `runtime deps
//! --install`) run through the SAME `AppSandbox` ([`helper_launcher`]); installer packages and uninstallers already
//! run in the installer sandbox. `wineserver -k` is not a Wine session (no Windows code runs). What stays
//! unsandboxed: `runtime run --unsandboxed` (it says so), and apps that never ran sandboxed. See docs/SECURITY.md.
//!
//! The probes and the status of `runtime sandbox` / `doctor` are gathered by `rt_api::host::sandbox`; this module
//! builds the run's sandbox, the helper launcher, and formats.
use crate::CmdError;
use crate::safe::safe;
use rt_api::host::sandbox::{profile, summary, working_bwrap};
use rt_core::{AppEnv, CompatBackend, Launcher, Sandbox, Store, Target};
use rt_sandbox::{Access, AppSandbox, Limits, Permissions, RealHost, Tasks};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// In the app root: sandboxed Windows code has run in this app's prefix (module docs; `rt_sandbox::MARKER`).
pub(crate) use rt_sandbox::MARKER;

const INSTALL_HINT: &str =
    "Install bubblewrap (`sudo apt install bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)";

fn app_sandbox(bwrap: PathBuf, perms: Permissions, backend: &dyn CompatBackend) -> AppSandbox {
    AppSandbox::new(bwrap, perms, backend.dll_dirs(), Arc::new(RealHost))
}

/// The sandbox of `runtime run` for `found` (module docs), or the error that stops the run, and whether it sets a
/// memory limit (a run it renders then has one: an explicit limit is applied or the run is refused).
pub(crate) fn for_run(
    store: &Store,
    found: &Target,
    backend: &dyn CompatBackend,
) -> Result<(Arc<dyn Sandbox>, bool), CmdError> {
    let bwrap = working_bwrap().map_err(|why| format!("cannot start the sandbox: {why}. {INSTALL_HINT}"))?;
    let perms = match found {
        Target::Installed(id) => {
            profile(&store.get(id)?)
                .map_err(|e| format!("cannot start the sandbox: {e}"))?
                .0
        }
        Target::File(_) => Permissions::default(),
    };
    let memory = perms.limits.memory_mb.is_some();
    Ok((Arc::new(RunSandbox(app_sandbox(bwrap, perms, backend))), memory))
}

/// `runtime run`'s sandbox: [`AppSandbox`] plus the notes and the marker (module docs).
struct RunSandbox(AppSandbox);

impl Sandbox for RunSandbox {
    fn wrap(&self, cmd: Command) -> Command {
        self.0.wrap(cmd)
    }

    fn try_wrap(&self, cmd: Command) -> Result<Command, String> {
        let out = self.0.render(&cmd).map_err(|e| e.to_string())?;
        print_hardening_caveat();
        for c in self.0.caveats(&cmd) {
            eprintln!("note: {}", safe(&c));
        }
        // `render` accepted the shape `<root>/prefix`, so the parent is the app root.
        let root = env_of(&cmd, "WINEPREFIX").and_then(|p| Path::new(p).parent());
        let marked = root
            .ok_or_else(|| "no app root".to_owned())
            .and_then(|r| rt_sandbox::mark(r).map_err(|e| e.to_string()));
        marked.map_err(|e| format!("cannot record that the app runs sandboxed ({e})"))?;
        Ok(out)
    }
}

fn env_of<'a>(cmd: &'a Command, name: &str) -> Option<&'a OsStr> {
    cmd.get_envs().find(|(k, _)| *k == name).and_then(|(_, v)| v)
}

/// `launcher` for Wine helpers that start a session in `env`'s prefix: behind the app's own sandbox once the app
/// has run sandboxed (module docs), else `launcher` itself. Fails closed when that sandbox cannot be built.
pub(crate) fn helper_launcher(
    env: &AppEnv,
    launcher: &Launcher,
    backend: &dyn CompatBackend,
) -> Result<Launcher, CmdError> {
    let refuse_unknown = |why: String| format!("cannot tell whether {} has run in the sandbox: {why}", env.id());
    if !marked(std::fs::symlink_metadata(env.root().join(MARKER))).map_err(refuse_unknown)? {
        return Ok(launcher.clone());
    }
    let refuse = |why: String| {
        format!(
            "{} has run in the sandbox (its prefix was written by a sandboxed program or installer), so its Wine helpers \
             must run sandboxed too, but {why}; nothing was changed",
            env.id()
        )
    };
    let bwrap = working_bwrap().map_err(|why| refuse(format!("the sandbox cannot start: {why}")))?;
    let (perms, _) = profile(env).map_err(refuse)?;
    Ok(launcher
        .clone()
        .with_sandbox(Arc::new(app_sandbox(bwrap, perms, backend))))
}

/// Whether the app is marked, from the marker's `lstat`: only "it does not exist" is unmarked. Anything at that
/// path (a file, or something the runtime never writes there: a directory, a link) counts as marked, the safe
/// answer; an error other than NotFound cannot be judged and is refused (fail closed).
fn marked(lstat: std::io::Result<std::fs::Metadata>) -> Result<bool, String> {
    match lstat {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// The one-line hardening caveat to print at the start of any command that runs Windows code (`rt_sandbox::hardening`
/// finds it): on a host with no Landlock and Yama `ptrace_scope` 0 the seccomp filter can be shed through
/// `/proc/1/mem` ([`rt_sandbox::BYPASS_CAVEAT`]). `None` when the host has no such gap. Pure (takes the probed
/// `Hardening`) so it is unit-tested without the host.
fn hardening_note(h: &rt_sandbox::Hardening) -> Option<String> {
    h.caveat.as_deref().map(|c| format!("note: {}", safe(c)))
}

/// Prints [`hardening_note`] for this host, if any, once. Called at the start of a run and of every command that runs
/// Windows code in the installer sandbox, so the caveat is not buried in `doctor`/`runtime sandbox` alone.
pub(crate) fn print_hardening_caveat() {
    if let Some(note) = hardening_note(&rt_sandbox::hardening()) {
        eprintln!("{note}");
    }
}

/// `runtime sandbox`'s limits section: whether scopes work here, then each limit and where it comes from.
fn limits_section(l: &Limits, scopes: &Result<rt_sandbox::ScopeSupport, String>) -> String {
    let mut out = match scopes {
        Ok(s) => format!(
            "limits: systemd-run --user works ({}; cgroup controllers: {})\n",
            safe(&s.systemd_run.to_string_lossy()),
            safe(&s.controllers.join(" "))
        ),
        Err(why) => format!("limits: UNAVAILABLE: {}\n", safe(why)),
    };
    let set = "permissions.toml, mandatory";
    out += &match l.tasks {
        Tasks::Default => format!("  tasks: {} (default, best effort)\n", rt_sandbox::DEFAULT_TASKS),
        Tasks::Max(n) => format!("  tasks: {n} ({set})\n"),
        Tasks::Unlimited => "  tasks: no limit (permissions.toml)\n".to_owned(),
    };
    out += &match l.memory_mb {
        Some(m) => format!("  memory: {m} MiB, no swap ({set})\n"),
        None => "  memory: no limit\n".to_owned(),
    };
    out += &match l.cpu_percent {
        Some(c) => format!("  cpu: {c}% of one CPU ({set})\n"),
        None => "  cpu: no limit\n".to_owned(),
    };
    out
}

/// `'text'` for a POSIX shell.
fn shell_quote(s: &OsStr) -> String {
    format!("'{}'", s.to_string_lossy().replace('\'', r"'\''"))
}

/// `runtime sandbox <app>`: bwrap, the profile, what is left out or cannot be enforced, and the command `run`
/// would start. Starts nothing (bwrap is probed); Wine is used only to describe the command when it is found.
pub fn run(app: &str) -> Result<(), CmdError> {
    let store = crate::store()?;
    let env = crate::deps::app_env(&store, app)?;
    crate::emit(&format_status(&env, &rt_api::host::sandbox::status(&store, &env)?))
}

/// The report of `runtime sandbox`. Every untrusted piece goes through `safe`; the line breaks are this function's own.
fn format_status(env: &AppEnv, st: &rt_api::host::sandbox::Status) -> String {
    let mut out = match &st.bwrap {
        Ok(b) => format!("bubblewrap: {} works\n", safe(&b.to_string_lossy())),
        Err(why) => format!(
            "bubblewrap: UNAVAILABLE: {}; `runtime run` refuses to start this app\n",
            safe(why)
        ),
    };
    let h = &st.hardening;
    out += &format!("{}\n{}\n", safe(&h.seccomp), safe(&h.landlock));
    if let Some(c) = &h.caveat {
        out += &format!("note: {}\n", safe(c));
    }
    match &st.shim {
        Some(exe) => {
            out += &format!(
                "shim: {} sandbox-init (bound read-only inside; applies Landlock and seccomp, then runs the program)\n",
                safe(&exe.to_string_lossy())
            )
        }
        None => out += "shim: UNAVAILABLE: the runtime executable cannot be resolved; `runtime run` refuses\n",
    }
    out += &format!("profile ({}): {}\n", st.source, summary(&st.profile));
    for g in &st.profile.filesystem {
        let access = if g.access == Access::Rw { "rw" } else { "ro" };
        out += &format!("  host directory {} ({access})\n", safe(&g.path.to_string_lossy()));
    }
    out += &limits_section(&st.profile.limits, &st.scopes);
    if let Err(e) = &st.wine {
        out += &format!(
            "Wine: not found ({}); the command below shows `wine` and no Wine directories\n",
            safe(e)
        );
    }
    if let Some(e) = &st.refused {
        out += &format!("REFUSED: {}\n", safe(e));
    }
    for s in &st.skipped {
        out += &format!("skipped: {}\n", safe(s));
    }
    for c in &st.caveats {
        out += &format!("note: {}\n", safe(c));
    }
    out += &format!(
        "warning: `runtime run --unsandboxed {}` would run whatever this app wrote into its prefix (registry Run \
         keys, DLL overrides) with your full access\n",
        env.id()
    );
    // Each argument escaped on its own: a newline inside one can never start a line of its own.
    let argv: Vec<String> = st.argv.iter().map(|a| safe(&shell_quote(a))).collect();
    out += &format!("command: {}\n", argv.join(" "));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_marker_is_unmarked_and_other_errors_refuse() {
        use std::io::{Error, ErrorKind};
        assert_eq!(marked(Err(Error::from(ErrorKind::NotFound))), Ok(false));
        assert!(marked(Err(Error::from(ErrorKind::PermissionDenied))).is_err());
        assert_eq!(
            marked(std::fs::symlink_metadata("/")),
            Ok(true),
            "a directory counts as marked"
        );
    }

    #[test]
    fn the_hardening_note_is_shown_only_when_the_host_has_the_bypass_gap() {
        let mut h = rt_sandbox::hardening();
        h.caveat = Some(rt_sandbox::BYPASS_CAVEAT.to_owned());
        let note = hardening_note(&h).expect("a note when the caveat is present");
        assert!(note.starts_with("note: ") && note.contains(rt_sandbox::BYPASS_CAVEAT));
        h.caveat = None;
        assert_eq!(hardening_note(&h), None);
    }

    #[test]
    fn shell_quote_survives_quotes_and_spaces() {
        assert_eq!(shell_quote(OsStr::new("a b")), "'a b'");
        assert_eq!(shell_quote(OsStr::new("it's")), r"'it'\''s'");
    }
}
