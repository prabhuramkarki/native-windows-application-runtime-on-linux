//! [`InstallerSandbox`]: a minimal `bwrap` profile for running an installer helper with nothing on the real
//! filesystem but its own app.
//!
//! **Scope.** This is narrower than a general-purpose sandbox: it exists so that Phase 3's installer helpers
//! (unpacking/copying installer payloads, running a silent `.exe`/`.msi` installer) do not get the run of the
//! host the way a plain Wine run still does (`docs/SECURITY.md`, "Phase 2 is NOT a sandbox"). It is wired into
//! [`rt_core::Launcher::wrap`] via [`InstallerSandbox::for_launcher`], the ONE existing spawn point, so a caller
//! keeps using `Launcher::spawn`/`run_helper` rather than a second `Command::spawn` path.
//!
//! **The profile** (everything not listed here is invisible): the app's own `prefix` (which contains
//! `drive_c`), read-write, at the same path; [`RO_BINDS`] plus [`SandboxOpts::extra_ro_binds`] read-only (a
//! fixed, documented set — not the real Wine binary's dependency closure, see [`RO_BINDS`]'s docs); a fresh,
//! private `/tmp`; a fresh `/proc` and `/dev`; an empty scratch directory standing in for `$HOME` (never the
//! real one — see [`home_path`]); a fresh PID/UTS/IPC namespace; a new session (`--new-session`, detaches the
//! real controlling terminal); the network namespace unshared unless [`SandboxOpts::allow_network`];
//! `--die-with-parent`; never `--dev-bind`. `docs/SECURITY.md` has the honest "what this does NOT stop" list.
//! The prefix bind and the `$HOME` tmpfs are ordered relative to each other at runtime (never a fixed order):
//! see [`InstallerSandbox::wrap`]'s own comment on why.
//!
//! [`InstallerSandbox::wrap`] is a pure argv-builder: given the already-finalized [`Command`] (final program,
//! args, env and cwd — see `rt_core::launch`'s module docs), it returns a NEW `Command` that runs `bwrap` with
//! that program/args after `--`, and the exact same env and cwd carried over (a brand-new `Command` otherwise
//! inherits the calling process's own environment, which must never leak into the sandboxed child). It never
//! spawns anything itself, so it is unit-testable with only `Command` introspection (`get_program`, `get_args`,
//! `get_envs`, `get_current_dir`), the same pattern `backend-wine`'s `command()` tests use.
use rt_core::{AppEnv, Sandbox};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// The fixed, read-only bind set every sandboxed installer command gets, besides its own `prefix`. This is
/// deliberately NOT a walk of the real Wine binary's shared-library dependency closure (`ldd`-style); a fixed,
/// documented set is what the plan asks for and what a system Wine package normally needs (its own binaries and
/// libraries, plus the distro's `/etc/alternatives` symlinks such as `/usr/bin/wine` -> `/etc/alternatives/wine`).
/// A directory that does not exist on this distro is silently skipped (`--ro-bind-try`), never an error.
///
/// ponytail: this only covers a Wine install rooted under one of these four paths (true for a distro package).
/// WineHQ's own official packages commonly install to `/opt/wine-stable/...`, outside all of them; a Wine there
/// would fail to `execvp` inside the sandbox. Fixing that generally means walking the discovered Wine binary's
/// own install root/dependency closure, which is out of THIS task's scope (the plan's own wording reads as
/// "this fixed set is enough" for now) — Task 6, which actually knows the discovered Wine path
/// (`backend_wine::discover::Found`), should pass its install root through [`SandboxOpts::extra_ro_binds`]
/// when it is outside this fixed set, rather than this crate growing a second binary-discovery mechanism.
pub const RO_BINDS: [&str; 4] = ["/usr", "/lib", "/lib64", "/etc/alternatives"];

/// The path used as `$HOME` inside the sandbox when the wrapped command's own finalized env has none. Nothing
/// on the host is ever bound there: only an empty `tmpfs`, so a program that insists on some `$HOME` existing
/// gets one, but finds it empty.
const FALLBACK_HOME: &str = "/home/sandbox";

/// Per-run choices [`InstallerSandbox::wrap`] does not hard-code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxOpts {
    /// `false` (the default): the network namespace is unshared, so the sandboxed process has no network at
    /// all (not even loopback to the host). Installers that need to phone home for a redistributable are out
    /// of scope for Phase 3 (its target is offline-only installers); set this once Phase 4 needs it.
    pub allow_network: bool,
    /// Extra paths bound read-only besides [`RO_BINDS`] (`--ro-bind-try`, so a missing one is skipped, not an
    /// error). For a Wine install outside the fixed set (see [`RO_BINDS`]'s docs), e.g. a WineHQ package under
    /// `/opt/wine-stable`.
    pub extra_ro_binds: Vec<PathBuf>,
}

/// A `bwrap`-backed sandbox for one installer helper invocation. Cheap to clone (`bwrap` is a `PathBuf`).
#[derive(Debug, Clone)]
pub struct InstallerSandbox {
    bwrap: PathBuf,
}

impl InstallerSandbox {
    /// `bwrap` is the path to the `bwrap` binary (see [`find_bwrap`] to locate it).
    pub fn new(bwrap: impl Into<PathBuf>) -> InstallerSandbox {
        InstallerSandbox { bwrap: bwrap.into() }
    }

    pub fn bwrap_path(&self) -> &Path {
        &self.bwrap
    }

    /// The pure argv-builder (module docs). `cmd` must already be finalized (its env and cwd are copied over
    /// verbatim); `env` names the app whose `prefix` is bound read-write.
    pub fn wrap(&self, cmd: Command, env: &AppEnv, opts: &SandboxOpts) -> Command {
        let home = home_path(&cmd);
        let prefix = env.prefix();

        let mut out = Command::new(&self.bwrap);
        out.arg("--die-with-parent");
        // Detaches the sandboxed process from the real controlling terminal (a new session/process group), so
        // it cannot use TIOCSTI-style terminal escapes to inject input back into the host's tty. Fine for a
        // non-interactive installer helper (this profile's only target, see the module docs); this is why
        // `Launcher::spawn`'s interactive-console-program path is not something this sandbox is meant for.
        out.arg("--new-session");
        out.arg("--unshare-pid");
        out.arg("--unshare-uts");
        out.arg("--unshare-ipc");
        if !opts.allow_network {
            out.arg("--unshare-net");
        }
        out.arg("--proc").arg("/proc");
        out.arg("--dev").arg("/dev");
        out.arg("--tmpfs").arg("/tmp");
        for dir in RO_BINDS {
            out.arg("--ro-bind-try").arg(dir).arg(dir);
        }
        for dir in &opts.extra_ro_binds {
            out.arg("--ro-bind-try").arg(dir).arg(dir);
        }
        // Order matters: a LATER bwrap mount wins over an EARLIER one at the same or a nested path (verified
        // against real bwrap 0.11.1). `home` is normally unrelated to `prefix` (`backend_wine::app_home` makes
        // it a sibling), but if a caller ever hands `wrap` a `HOME` that is `prefix` itself or an ancestor
        // directory of it, mounting the empty `$HOME` tmpfs AFTER the prefix bind would silently swallow the
        // whole prefix (this was a real, reproduced bug: the two binds were previously always emitted in the
        // same fixed order). So: whichever of the two is the ancestor-or-equal is mounted FIRST, and the
        // more specific one (or, in a plain tie, the prefix bind, since containment of the app's own data
        // matters more than a cosmetic empty `$HOME`) is mounted LAST, so it is what is actually visible.
        if prefix.starts_with(&home) {
            out.arg("--tmpfs").arg(&home);
            out.arg("--bind").arg(&prefix).arg(&prefix);
        } else {
            out.arg("--bind").arg(&prefix).arg(&prefix);
            out.arg("--tmpfs").arg(&home);
        }
        out.arg("--");
        out.arg(cmd.get_program());
        out.args(cmd.get_args());

        // A brand-new `Command` otherwise inherits THIS process's real environment (cargo's, the CLI's, ...);
        // it must see exactly what `cmd` was finalized to, nothing more. `get_envs()` is the complete map after
        // `env_clear` + explicit `.env()` calls (see `rt_core::launch`'s own `envs()` test helper).
        out.env_clear();
        for (k, v) in cmd.get_envs() {
            match v {
                Some(v) => {
                    out.env(k, v);
                }
                None => {
                    out.env_remove(k);
                }
            }
        }
        if let Some(dir) = cmd.get_current_dir() {
            out.current_dir(dir);
        }
        out
    }

    /// Adapts this sandbox to `rt_core`'s [`Sandbox`] hook, bound to one app and one set of options: `Sandbox`'s
    /// own `wrap(cmd)` takes no other parameters, so they are captured here for `Launcher::with_sandbox`.
    pub fn for_launcher(self, env: AppEnv, opts: SandboxOpts) -> Arc<dyn Sandbox> {
        Arc::new(Bound {
            sandbox: self,
            env,
            opts,
        })
    }
}

struct Bound {
    sandbox: InstallerSandbox,
    env: AppEnv,
    opts: SandboxOpts,
}

impl Sandbox for Bound {
    fn wrap(&self, cmd: Command) -> Command {
        self.sandbox.wrap(cmd, &self.env, &self.opts)
    }
}

/// `cmd`'s own finalized `HOME`, or [`FALLBACK_HOME`] if it set none.
fn home_path(cmd: &Command) -> PathBuf {
    cmd.get_envs()
        .find(|(k, _)| *k == OsStr::new("HOME"))
        .and_then(|(_, v)| v)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(FALLBACK_HOME))
}

/// A regular, executable file (after following symlinks); `false` on any error, the same probe shape as
/// `backend-wine::discover`.
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Looks for `bwrap` on `$PATH`, the way a shell would (absolute directories only, first match wins). Injected
/// `env`/`is_file` make this unit-testable without touching the real filesystem; [`find_bwrap_on_path`] is the
/// real-filesystem convenience.
pub fn find_bwrap(
    env: &impl Fn(&str) -> Option<std::ffi::OsString>,
    is_file: &impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let path = env("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("bwrap"))
        .find(|candidate| is_file(candidate))
}

/// [`find_bwrap`] over the real environment and filesystem; `None` means `bwrap` is not installed (callers of
/// the real-`bwrap` tests skip loudly rather than failing the suite on a machine without it).
pub fn find_bwrap_on_path() -> Option<PathBuf> {
    find_bwrap(&|k| std::env::var_os(k), &is_executable_file)
}

#[cfg(test)]
mod tests;
