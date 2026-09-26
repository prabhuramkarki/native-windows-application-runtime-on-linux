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
use crate::CmdError;
use crate::safe::safe;
use rt_core::{AppEnv, CompatBackend, Launcher, RunOpts, Sandbox, Store, Target};
use rt_sandbox::{Access, AppSandbox, Host, Limits, Network, Permissions, RealHost, Tasks, load, load_opt_raw};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// In the app root: this app has run in the sandbox at least once (module docs).
pub(crate) const MARKER: &str = "ran-sandboxed";

const INSTALL_HINT: &str =
    "Install bubblewrap (`sudo apt install bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)";

/// bwrap on `PATH` that can really create a sandbox, or why not.
fn working_bwrap() -> Result<PathBuf, String> {
    let bwrap = rt_sandbox::find_bwrap_on_path().ok_or("bwrap is not on PATH")?;
    rt_sandbox::probe(&bwrap)?;
    Ok(bwrap)
}

/// The app's profile (the default without a `permissions.toml`), or why it is refused.
fn profile(env: &AppEnv) -> Result<(Permissions, &'static str), String> {
    let refused = |e: rt_sandbox::PermError| {
        format!(
            "the app's permissions.toml is refused: {e} (`runtime permissions {} --reset` deletes it)",
            env.id()
        )
    };
    // The grants are only checked against the host (which needs `HOME`) when there is a file.
    if load_opt_raw(env.root()).map_err(refused)?.is_none() {
        return Ok((Permissions::default(), "default"));
    }
    let ctx = crate::permissions::ctx().map_err(|e| e.to_string())?;
    Ok((load(env.root(), &ctx).map_err(refused)?, "permissions.toml"))
}

fn app_sandbox(bwrap: PathBuf, perms: Permissions, backend: &dyn CompatBackend) -> AppSandbox {
    AppSandbox::new(bwrap, perms, backend.dll_dirs(), Arc::new(RealHost))
}

/// `network deny, display on, audio on, gpu on, 0 host directories`.
fn summary(p: &Permissions) -> String {
    let on = |b: bool| if b { "on" } else { "off" };
    let n = p.filesystem.len();
    format!(
        "network {}, display {}, audio {}, gpu {}, {n} host director{}",
        if p.network == Network::Allow { "allow" } else { "deny" },
        on(p.display),
        on(p.audio),
        on(p.gpu),
        if n == 1 { "y" } else { "ies" }
    )
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
        for c in self.0.caveats(&cmd) {
            eprintln!("note: {}", safe(&c));
        }
        // `render` accepted the shape `<root>/prefix`, so the parent is the app root.
        let root = env_of(&cmd, "WINEPREFIX").and_then(|p| Path::new(p).parent());
        let marked = root.ok_or_else(|| "no app root".to_owned()).and_then(|r| {
            OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(r.join(MARKER))
                .map_err(|e| e.to_string())
        });
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
            "{} has run in the sandbox, so its Wine helpers must run sandboxed too, but {why}; nothing was changed",
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

/// `doctor`'s hardening input: seccomp and Landlock in one phrase, `Err` when either is not fully there.
pub(crate) fn doctor_hardening() -> Result<String, String> {
    let h = rt_sandbox::hardening();
    let text = match &h.caveat {
        // First, so the 300-byte cut never drops it.
        Some(c) => format!("{c}; {}; {}", h.seccomp, h.landlock),
        None => format!("{}; {}", h.seccomp, h.landlock),
    };
    if h.complete && h.caveat.is_none() {
        Ok(text)
    } else {
        Err(text)
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

/// `doctor`'s limits input: `systemd-run --user` scopes work, or why not and what that means (with `env`: for that
/// app, whose explicit limits then refuse every run).
pub(crate) fn doctor_limits(env: Option<&AppEnv>) -> Result<String, String> {
    // An unreadable profile is the sandbox check's warning; here it counts as the default.
    let limits = env
        .and_then(|e| profile(e).ok())
        .map(|(p, _)| p.limits)
        .unwrap_or_default();
    let refused = |e: &AppEnv| format!("runs of {} will be refused", e.id());
    let not_applied = "the default task limit (fork-bomb guard) is not applied";
    match RealHost.scopes() {
        Ok(s) => match limits
            .controllers()
            .into_iter()
            .find(|c| !s.controllers.iter().any(|h| h == c))
        {
            None => Ok(format!(
                "limits: systemd-run --user available (cgroup controllers: {})",
                s.controllers.join(" ")
            )),
            Some(c) => Err(match env {
                Some(e) if limits.explicit() => format!(
                    "limits: systemd-run --user available, but {}: the {c} cgroup controller is not available to \
                     your user session",
                    refused(e)
                ),
                _ => format!("limits: the {c} cgroup controller is not available to your user session; {not_applied}"),
            }),
        },
        Err(why) => Err(match env {
            Some(e) if limits.explicit() => format!(
                "limits: unavailable: {why}; {} (its permissions.toml sets limits)",
                refused(e)
            ),
            _ => format!("limits: unavailable: {why}; {not_applied}"),
        }),
    }
}

/// `doctor`'s sandbox input: bwrap works (with `env`: and the app's profile in a few words), or why not.
pub(crate) fn doctor_state(env: Option<&AppEnv>) -> Result<Option<String>, String> {
    working_bwrap().map_err(|why| format!("unavailable: {why}"))?;
    env.map(|env| profile(env).map(|(p, _)| summary(&p)))
        .transpose()
        .map_err(|why| format!("cannot read the profile: {why}"))
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
    let mut out = String::new();
    let bwrap = match working_bwrap() {
        Ok(b) => {
            out += &format!("bubblewrap: {} works\n", safe(&b.to_string_lossy()));
            b
        }
        Err(why) => {
            out += &format!(
                "bubblewrap: UNAVAILABLE: {}; `runtime run` refuses to start this app\n",
                safe(&why)
            );
            rt_sandbox::find_bwrap_on_path().unwrap_or_else(|| PathBuf::from("bwrap"))
        }
    };
    let h = rt_sandbox::hardening();
    out += &format!("{}\n{}\n", safe(&h.seccomp), safe(&h.landlock));
    if let Some(c) = &h.caveat {
        out += &format!("note: {}\n", safe(c));
    }
    match RealHost.runtime_exe() {
        Some(exe) => {
            out += &format!(
                "shim: {} sandbox-init (bound read-only inside; applies Landlock and seccomp, then runs the program)\n",
                safe(&exe.to_string_lossy())
            )
        }
        None => out += "shim: UNAVAILABLE: the runtime executable cannot be resolved; `runtime run` refuses\n",
    }
    let (perms, source) = profile(&env)?;
    out += &format!("profile ({source}): {}\n", summary(&perms));
    for g in &perms.filesystem {
        let access = if g.access == Access::Rw { "rw" } else { "ro" };
        out += &format!("  host directory {} ({access})\n", safe(&g.path.to_string_lossy()));
    }
    out += &limits_section(&perms.limits, &RealHost.scopes());
    let launcher = Launcher::new();
    let p = rt_core::resolve_program(&store, env.id(), backend_wine::BACKEND_ID)?;
    // The command `run` builds (backend command, settled, host environment rules); without Wine, its shape.
    let (cmd, dll_dirs) = match crate::backend(&launcher) {
        Ok(b) => (
            b.settle(b.command(&p.env, &p.exe, &p.cwd, &[], &RunOpts::default())?),
            b.dll_dirs(),
        ),
        Err(e) => {
            out += &format!(
                "Wine: not found ({}); the command below shows `wine` and no Wine directories\n",
                safe(&e.to_string())
            );
            let mut c = Command::new("wine");
            c.arg(&p.exe)
                .current_dir(&p.cwd)
                .env("WINEPREFIX", env.prefix())
                .env("HOME", backend_wine::app_home(&env));
            (c, vec![])
        }
    };
    let cmd = launcher.finalize(cmd);
    let sb = AppSandbox::new(bwrap, perms, dll_dirs, Arc::new(RealHost));
    if let Err(e) = sb.render(&cmd) {
        out += &format!("REFUSED: {}\n", safe(&e.to_string()));
    }
    for s in sb.skipped(&cmd) {
        out += &format!("skipped: {}\n", safe(&s));
    }
    for c in sb.caveats(&cmd) {
        out += &format!("note: {}\n", safe(&c));
    }
    out += &format!(
        "warning: `runtime run --unsandboxed {}` would run whatever this app wrote into its prefix (registry Run \
         keys, DLL overrides) with your full access\n",
        env.id()
    );
    // Each argument escaped on its own: a newline inside one can never start a line of its own.
    let argv: Vec<String> = sb.argv_preview(&cmd).iter().map(|a| safe(&shell_quote(a))).collect();
    out += &format!("command: {}\n", argv.join(" "));
    // Every untrusted piece above went through `safe`; the line breaks are this function's own.
    crate::emit(&out)
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
    fn shell_quote_survives_quotes_and_spaces() {
        assert_eq!(shell_quote(OsStr::new("a b")), "'a b'");
        assert_eq!(shell_quote(OsStr::new("it's")), r"'it'\''s'");
    }

    #[test]
    fn summary_names_every_switch_and_counts_grants() {
        let mut p = Permissions::default();
        assert_eq!(
            summary(&p),
            "network deny, display on, audio on, gpu on, 0 host directories"
        );
        p.network = Network::Allow;
        p.gpu = false;
        p.filesystem.push(rt_sandbox::FsGrant {
            path: "/srv/x".into(),
            access: Access::Ro,
        });
        assert_eq!(
            summary(&p),
            "network allow, display on, audio on, gpu off, 1 host directory"
        );
    }
}
